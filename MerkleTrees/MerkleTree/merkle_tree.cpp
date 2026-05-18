#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include <stdexcept>
#include <cstdint>
#include <memory>

#include "../../Interfaces/merkle_client.h"
#include "../../Interfaces/merkle_tree_interface.h"
#include "../../utils/SHA256/sha256.h"


using namespace std;

static string Hash(const string& v) {
    return picosha2::hash256_hex_string(v);
}

inline string ComputeLeafHash(const string& key, const string& value) {
    return picosha2::hash256_hex_string(key + Hash(value));
}

inline string ComputeInnerHash(const string& left, const string& right) {
    return picosha2::hash256_hex_string(left + right);
}


class MerkleTree : public IMerkleTree {
public:
    MerkleTree() = default;
    MerkleTree(const vector<KeyValue>& data) {
        Build(data);
    }

    void Build(const vector<KeyValue>& data) override {
        leaves_ = data;
        if (Size() == 0) {
            root_ = nullptr;
        } else {
            root_ = Rebuild(0, Size()-1);
        }
    }

    string GetRootHash() const override {
        return root_ == nullptr ? string() : root_->hash;
    }

    void Update(size_t index, const string& new_value) override {
        CheckIndex(index);
        leaves_[index].value = new_value;
        Update(index, root_);
    }

    void Insert(const KeyValue& kv) override {
        leaves_.push_back(kv);
        if (Size() == 0) {
            root_ = nullptr;
        } else {
            root_ = Rebuild(0, Size()-1);
        }
    }

    void Delete(size_t index) override {
        CheckIndex(index);
        leaves_.erase(leaves_.begin() + index);
        if (Size() == 0) {
            root_ = nullptr;
        } else {
            root_ = Rebuild(0, Size()-1);
        }
    }

    string GetValue(size_t index) const override {
        CheckIndex(index);
        return leaves_[index].value;
    }

    MerkleProof GetMerkleProof(size_t index) const override {
        CheckIndex(index);
        MerkleProof proof;
        if (root_ == nullptr) {
            return proof;
        }
        shared_ptr<Node> cur_node = root_;
        while (cur_node->left_child != nullptr) {
            if (index <= cur_node->left_child->right) {
                proof.push_back({cur_node->right_child->hash, ProofDirection::RIGHT});
                cur_node = cur_node->left_child;
            } else {
                proof.push_back({cur_node->left_child->hash, ProofDirection::LEFT});
                cur_node = cur_node->right_child;
            }
        }
        reverse(proof.begin(), proof.end());
        return proof;
    }

    size_t Size() const override {
        return leaves_.size();
    }

    const string& GetKey(size_t index) const {
        CheckIndex(index);
        return leaves_[index].key;
    }

private:
    struct Node {
        size_t left, right;
        string hash;
        shared_ptr <Node> left_child = nullptr;
        shared_ptr <Node> right_child = nullptr;
    };

    vector<KeyValue> leaves_;
    shared_ptr<Node> root_ = nullptr;

    void CheckIndex(size_t index) const {
        if (index >= leaves_.size())
            throw out_of_range("MerkleTree: index out of range");
    }

    shared_ptr<Node> Rebuild(size_t left, size_t right) {
        shared_ptr<Node> curNode = make_shared<Node>();
        curNode->left = left;
        curNode->right = right;
        if (left == right) {
            curNode->hash = ComputeLeafHash(leaves_[left].key, leaves_[left].value);
            return curNode;
        }
        size_t mid = left + (right - left) / 2;
        curNode->left_child = Rebuild(left, mid);
        curNode->right_child = Rebuild(mid+1, right);
        curNode->hash = ComputeInnerHash(curNode->left_child->hash, curNode->right_child->hash);
        return curNode;
    }

    void Update(size_t index, shared_ptr<Node> curNode) {
        if (curNode->left == curNode->right) {
            curNode->hash = ComputeLeafHash(leaves_[index].key, leaves_[index].value);
            return;
        }
        if (index <= curNode->left_child->right) {
            Update(index, curNode->left_child);
            curNode->hash = ComputeInnerHash(curNode->left_child->hash, curNode->right_child->hash);
        } else {
            Update(index, curNode->right_child);
            curNode->hash = ComputeInnerHash(curNode->left_child->hash, curNode->right_child->hash);
        }
    }
};


// Полный клиент SPV-протокола

class FullClient : public IFullClient {
public:
    FullClient() = default;

    void Build(const vector<KeyValue>& data) override {
        tree_.Build(data);
        RebuildIndex();
    }

    string GetRootHash() const override {
        return tree_.GetRootHash();
    }

    void Update(const KeyValue& kv) override {
        auto it = key_to_index_.find(kv.key);
        if (it == key_to_index_.end()) {
            tree_.Insert(kv);
            const size_t new_index = tree_.Size() - 1;
            key_to_index_[kv.key] = new_index;
        } else {
            tree_.Update(it->second, kv.value);
        }
    }

    void Delete(const string& key) override {
        auto it = key_to_index_.find(key);
        if (it == key_to_index_.end()) {
            throw out_of_range("FullClient: key not found");
        }
        size_t index = it->second;
        key_to_index_.erase(it);
        tree_.Delete(index);
        for (auto& kv : key_to_index_) {
            if (kv.second > index) --kv.second;
        }
    }

    vector<uint8_t> RequestProof(const string& key) override {
        auto it = key_to_index_.find(key);
        if (it == key_to_index_.end()) {
            return {};
        }
        return Serialize(tree_.GetMerkleProof(it->second));
    }

private:
    MerkleTree tree_;
    map<string, size_t> key_to_index_;

    void RebuildIndex() {
        key_to_index_.clear();
        for (size_t i = 0; i < tree_.Size(); ++i) {
            key_to_index_[tree_.GetKey(i)] = i;
        }
    }

    static vector<uint8_t> Serialize(const MerkleProof& proof) {
        vector<uint8_t> buf;
        buf.reserve(proof.size() * 65);
        for (const auto& node : proof) {
            buf.push_back(static_cast<uint8_t>(node.direction));
            buf.insert(buf.end(), node.hash.begin(), node.hash.end());
        }
        return buf;
    }
};


// Лёгкий клиент SPV-протокола

class LightClient : public ILightClient {
public:
    void SetRootHash(const string& root_hash) override {
        root_hash_ = root_hash;
    }

    bool VerifyProof(const KeyValue& kv, const vector<uint8_t>& proof_bytes) const override {
        const MerkleProof proof = Deserialize(proof_bytes);
        string current = ComputeLeafHash(kv.key, kv.value);
        for (const auto& node : proof) {
            if (node.direction == ProofDirection::LEFT) {
                current = ComputeInnerHash(node.hash, current);
            } else {
                current = ComputeInnerHash(current, node.hash);
            }
        }
        return current == root_hash_;
    }

private:
    string root_hash_;

    static MerkleProof Deserialize(const vector<uint8_t>& buf) {
        constexpr size_t kNodeSize = 1 + 64;
        MerkleProof proof;
        if (buf.size() % kNodeSize != 0) return proof;
        proof.reserve(buf.size() / kNodeSize);
        for (size_t i = 0; i < buf.size(); i += kNodeSize) {
            ProofNode node;
            node.direction = (buf[i] == 0x00) ? ProofDirection::LEFT
                                              : ProofDirection::RIGHT;
            node.hash.assign(buf.begin() + i + 1,
                             buf.begin() + i + 1 + 64);
            proof.push_back(move(node));
        }
        return proof;
    }
};

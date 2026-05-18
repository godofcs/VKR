#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <stdexcept>
#include <cstdint>

#include "../../utils/SHA256/sha256.h"
#include "../../Interfaces/merkle_tree_interface.h"
#include "../../Interfaces/merkle_client.h"

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

class VectorMerkleTree : public IMerkleTree {
public:
    VectorMerkleTree() = default;
    VectorMerkleTree(const vector<KeyValue>& data) {
        Build(data);
    }

    void Build(const vector<KeyValue>& data) override {
        leaves_ = data;
        Rebuild();
    }

    string GetRootHash() const override {
        return tree_.empty() ? string() : tree_[1];
    }

    void Update(size_t index, const string& new_value) override {
        CheckIndex(index);
        leaves_[index].value = new_value;
        size_t pos = leaf_offset_ + index;
        tree_[pos] = ComputeLeafHash(leaves_[index].key, leaves_[index].value);
        for (pos /= 2; pos >= 1; pos /= 2) {
            tree_[pos] = ComputeInnerHash(tree_[2 * pos], tree_[2 * pos + 1]);
            if (pos == 1) break;
        }
    }

    void Insert(const KeyValue& kv) override {
        leaves_.push_back(kv);
        Rebuild();
    }

    void Delete(size_t index) override {
        CheckIndex(index);
        leaves_.erase(leaves_.begin() + index);
        Rebuild();
    }

    string GetValue(size_t index) const override {
        CheckIndex(index);
        return leaves_[index].value;
    }

    MerkleProof GetMerkleProof(size_t index) const override {
        CheckIndex(index);
        MerkleProof proof;
        size_t pos = leaf_offset_ + index;
        while (pos > 1) {
            const bool is_left_child = (pos % 2 == 0);
            const size_t sibling     = is_left_child ? pos + 1 : pos - 1;
            const ProofDirection dir = is_left_child ? ProofDirection::RIGHT
                                                     : ProofDirection::LEFT;
            proof.push_back({tree_[sibling], dir});
            pos /= 2;
        }
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
    vector<KeyValue> leaves_;
    vector<string> tree_;
    size_t leaf_offset_ = 0;

    void CheckIndex(size_t index) const {
        if (index >= leaves_.size())
            throw out_of_range("MerkleTree: index out of range");
    }

    void Rebuild() {
        if (leaves_.empty()) {
            tree_.clear();
            leaf_offset_ = 0;
            return;
        }
        size_t leaf_count = 1;
        while (leaf_count < leaves_.size()) leaf_count *= 2;
        leaf_offset_ = leaf_count;
        tree_.resize(2 * leaf_count);

        for (size_t i = 0; i < leaves_.size(); ++i) {
            tree_[leaf_count + i] = ComputeLeafHash(leaves_[i].key, leaves_[i].value);
        }

        const string empty_hash = picosha2::hash256_hex_string(string());
        for (size_t i = leaves_.size(); i < leaf_count; ++i) {
            tree_[leaf_count + i] = empty_hash;
        }

        for (size_t i = leaf_count - 1; i >= 1; --i) {
            tree_[i] = ComputeInnerHash(tree_[2 * i], tree_[2 * i + 1]);
        }
    }
};


// Полный клиент SPV-протокола

class FullClient : public IFullClient {
public:
    FullClient() = default;

    void Build(const vector<KeyValue>& data) {
        tree_.Build(data);
        RebuildIndex();
    }

    string GetRootHash() const {
        return tree_.GetRootHash();
    }

    void Update(const KeyValue& kv) {
        auto it = key_to_index_.find(kv.key);
        if (it == key_to_index_.end()) {
            tree_.Insert(kv);
            const size_t new_index = tree_.Size() - 1;
            key_to_index_[kv.key] = new_index;
        } else {
            tree_.Update(it->second, kv.value);
        }
    }

    void Delete(const string& key) {
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

    vector<uint8_t> RequestProof(const string& key) {
        auto it = key_to_index_.find(key);
        if (it == key_to_index_.end()) {
            return {};
        }
        return Serialize(tree_.GetMerkleProof(it->second));
    }

private:
    VectorMerkleTree tree_;
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
    void SetRootHash(const string& root_hash) {
        root_hash_ = root_hash;
    }

    bool VerifyProof(const KeyValue& kv, const vector<uint8_t>& proof_bytes) const {
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

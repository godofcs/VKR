#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <memory> 
#include <string_view>

#include "../../Interfaces/merkle_client.h"
#include "../../Interfaces/merkle_trie_interface.h"
#include "../../utils/SHA256/sha256.h"

using namespace std;

static string Hash(const string& v) {
    return picosha2::hash256_hex_string(v);
}

inline string ComputeLeafHash(const string& key, const string& value) {
    return picosha2::hash256_hex_string(key + Hash(value));
}

inline string ComputeNodeHash(const array<string_view, 16>& arr) {
    picosha2::hash256_one_by_one hasher;

    for (const auto& str: arr) {
        hasher.process(str.begin(), str.end());
    }
    
    hasher.finish();
    return picosha2::get_hash_hex_string(hasher);
}

class RadixMerkleTree : public IMerkleTree {
private:
    struct Node {
        string hash;
        string value;
        array <shared_ptr<Node>, 16> children;
    };
    shared_ptr <Node> root_ = nullptr;
    string rezult_;
    array <string_view, 16> prev_hash_;
    
    void Update(shared_ptr<Node> cur_node, const KeyValue& kv, size_t ind) {
        if (ind == kv.key.size()) {
            cur_node->value = kv.value;
            cur_node->hash = ComputeLeafHash(kv.key, kv.value);
            return;
        }
        size_t symb = 0;
        if ('0' <= kv.key[ind] && kv.key[ind] <= '9') symb = kv.key[ind] - '0';
        if ('a' <= kv.key[ind] && kv.key[ind] <= 'f') symb = kv.key[ind] - 'a' + 10;
        if (cur_node->children[symb] == nullptr) {
            cur_node->children[symb] = make_shared<Node>();
        }
        Update(cur_node->children[symb], kv, ind+1);
        for (size_t i = 0; i < 16; ++i) {
            if (cur_node->children[i] == nullptr) {
                prev_hash_[i] = "";
            } else {
                prev_hash_[i] = cur_node->children[i]->hash;
            }
        }
        cur_node->hash = ComputeNodeHash(prev_hash_);
    }

    shared_ptr<Node> Delete(shared_ptr<Node> cur_node, const string& key, size_t ind) {
        if (cur_node == nullptr) {
            return nullptr;
        }
        if (ind == key.size()) {
            return nullptr;
        }
        size_t symb = 0;
        if ('0' <= key[ind] && key[ind] <= '9') symb = key[ind] - '0';
        if ('a' <= key[ind] && key[ind] <= 'f') symb = key[ind] - 'a' + 10;
        cur_node->children[symb] = Delete(cur_node->children[symb], key, ind+1);
        bool is_empty = true;
        for (const auto& it: cur_node->children) {
            if (it != nullptr) {
                is_empty = false;
                break;
            }
        }
        if (is_empty) {
            return nullptr;
        }
        for (size_t i = 0; i < 16; ++i) {
            if (cur_node->children[i] == nullptr) {
                prev_hash_[i] = "";
            } else {
                prev_hash_[i] = cur_node->children[i]->hash;
            }
        }
        cur_node->hash = ComputeNodeHash(prev_hash_);
        return cur_node;
    }

    void Get(shared_ptr<Node> cur_node, const string& key, size_t ind) {
        if (cur_node == nullptr) {
            rezult_ = "";
            return;
        }
        if (ind == key.size()) {
            rezult_ = cur_node->value;
            return;
        }
        size_t symb = 0;
        if ('0' <= key[ind] && key[ind] <= '9') symb = key[ind] - '0';
        if ('a' <= key[ind] && key[ind] <= 'f') symb = key[ind] - 'a' + 10;
        Get(cur_node->children[symb], key, ind+1);
    }

public:
    RadixMerkleTree() {
        root_ = make_shared<Node>();
    };

    RadixMerkleTree(const vector <KeyValue>& data) {
        Build(data);
    }

    ~RadixMerkleTree() override = default;

    void Build(const vector<KeyValue>& data) override {
        root_ = make_shared<Node>();
        for (const auto& kv: data) {
            Update(kv);
        }
    }

    string GetRootHash() const override {
        if (root_ == nullptr) {
            return string();
        }
        return root_->hash;
    }

    void Delete(const string& key) override {
        root_ = Delete(root_, key, 0) ;
    }

    void Update(const KeyValue& kv) override {
        if (root_ == nullptr) {
            root_ = make_shared<Node>();
        }
        Update(root_, kv, 0);
    }

    MerkleProof GetMerkleProof(const string& key) override {
        MerkleProof proof;
        shared_ptr<Node> cur_node = root_;
        size_t ind = 0;
        vector <string> empty_hash(16);
        while (cur_node != nullptr && ind != key.size()) {
            size_t symb = 0;
            if ('0' <= key[ind] && key[ind] <= '9') symb = key[ind] - '0';
            if ('a' <= key[ind] && key[ind] <= 'f') symb = key[ind] - 'a' + 10;
            proof.push_back({empty_hash, symb});
            for (size_t i = 0; i < 16; ++i) {
                if (i == symb) {
                    continue;
                } else if (cur_node->children[i] == nullptr) {
                    proof.back().hash[i] = string();
                } else {
                    proof.back().hash[i] = cur_node->children[i]->hash;
                }
            }
            ++ind;
            cur_node = cur_node->children[symb];
        }
        reverse(proof.begin(), proof.end());
        return proof;
    }

    string GetValue(const string& key) override {
        rezult_.clear();
        Get(root_, key, 0);
        return rezult_;
    }
};


// Полный клиент SPV-протокола

class FullClient : public IFullClient {
public:
    FullClient() = default;

    void Build(const vector<KeyValue>& data) {
        tree_.Build(data);
    }

    string GetRootHash() const {
        return tree_.GetRootHash();
    }

    void Update(const KeyValue& kv) {
        tree_.Update(kv);
    }

    void Delete(const string& key) {
        tree_.Delete(key);
    }

    vector<uint8_t> RequestProof(const string& key) {
        return Serialize(tree_.GetMerkleProof(key));
    }

private:
    RadixMerkleTree tree_;

    static void WriteUInt32(vector<uint8_t>& buf, uint32_t v) {
        buf.push_back(static_cast<uint8_t>(v          & 0xff));
        buf.push_back(static_cast<uint8_t>((v >>  8)  & 0xff));
        buf.push_back(static_cast<uint8_t>((v >> 16)  & 0xff));
        buf.push_back(static_cast<uint8_t>((v >> 24)  & 0xff));
    }

    static vector<uint8_t> Serialize(const MerkleProof& proof) {
        vector<uint8_t> buf;
        buf.push_back(static_cast<uint8_t>(proof.size()));
        for (const auto& node : proof) {
            buf.push_back(static_cast<uint8_t>(node.hash.size()));
            for (const auto& s : node.hash) {
                buf.push_back(static_cast<uint8_t>(s.size()));
                buf.insert(buf.end(), s.begin(), s.end());
            }
            buf.push_back(static_cast<uint8_t>(node.proof_hash_ind));
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
        array<string_view, 16> cur_hash;
        for (const auto& node : proof) {
            for (size_t ind = 0; ind < 16; ++ind) {
                cur_hash[ind] = node.hash[ind];
            }
            cur_hash[node.proof_hash_ind] = current;
            current = ComputeNodeHash(cur_hash);
        }
        return current == root_hash_;
    }

private:
    string root_hash_;

    static uint32_t ReadUInt32(const vector<uint8_t>& buf, size_t& pos) {
        uint32_t v =
              static_cast<uint32_t>(buf[pos])
            | (static_cast<uint32_t>(buf[pos + 1]) <<  8)
            | (static_cast<uint32_t>(buf[pos + 2]) << 16)
            | (static_cast<uint32_t>(buf[pos + 3]) << 24);
        pos += 4;
        return v;
    }

    static MerkleProof Deserialize(const vector<uint8_t>& buf) {
        MerkleProof proof;
        if (buf.size() < 1) return proof;
        size_t pos = 0;
        uint32_t num_nodes = static_cast<uint32_t>(buf[pos]);
        ++pos;
        proof.reserve(num_nodes);
        for (uint32_t i = 0; i < num_nodes; ++i) {
            if (pos + 1 > buf.size()) return MerkleProof();
            uint32_t num_hashes = static_cast<uint32_t>(buf[pos]);
            ++pos;
            ProofNode node;
            node.hash.reserve(num_hashes);
            for (uint32_t j = 0; j < num_hashes; ++j) {
                if (pos + 1 > buf.size()) return MerkleProof();
                uint32_t len = buf[pos];
                ++pos;
                if (pos + len > buf.size()) return MerkleProof();
                node.hash.emplace_back(buf.begin() + pos,
                                       buf.begin() + pos + len);
                pos += len;
            }
            if (pos + 1 > buf.size()) return MerkleProof();
            node.proof_hash_ind = buf[pos];
            ++pos;
            proof.push_back(move(node));
        }
        return proof;
    }
};


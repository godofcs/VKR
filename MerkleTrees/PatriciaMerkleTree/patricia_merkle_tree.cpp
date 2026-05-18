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

inline string HashArrayOfStrings(const vector<string_view>& arr, size_t size) {
    picosha2::hash256_one_by_one hasher;

    for (size_t i = 0; i < size; ++i) {
        hasher.process(arr[i].begin(), arr[i].end());
    }
    
    hasher.finish();
    return picosha2::get_hash_hex_string(hasher);
}

class PatriciaMerkleTree : public IMerkleTree {
private:
    enum class NodeType : unsigned char {
        BRANCH = 0,
        EXTENSION = 1,
        LEAF = 2
    };

    enum class DeletedType : unsigned char {
        NOT_DELETED = 0,
        DELETED = 1,
        UPDATED = 2,
        USELESS_BRANCH = 3
    };

    struct Node {
        NodeType type;
        string hash;
        string value;
        string path;
        vector <shared_ptr<Node>> children;
    };

    shared_ptr <Node> root_ = nullptr;
    string rezult_;
    shared_ptr <Node> rezult_node_ = nullptr;
    string pref_;
    vector <string_view> prev_hash_{17};

    shared_ptr<Node> CreateNode(NodeType type) {
        shared_ptr<Node> node = make_shared<Node>();
        node->type = type;
        if (type == NodeType::BRANCH) {
            node->children.resize(16, nullptr);
        } else if (type == NodeType::EXTENSION) {
            node->children.resize(1, nullptr);
        } else if (type == NodeType::LEAF) {
            // as a precaution
        }
        return node;
    }

    void CommonPrefix(const string& cur_str, const string& new_str, size_t st_ind) {
        pref_.clear();
        for (size_t i = 0; i < cur_str.size() && st_ind + i < new_str.size(); ++i) {
            if (cur_str[i] != new_str[st_ind+i]) {
                break;
            }
            pref_.push_back(cur_str[i]);
        }
    }

    void UpdateHash(shared_ptr<Node> cur_node, const string& key) {
        if (cur_node->type == NodeType::BRANCH) {
            for (size_t i = 0; i < 16; ++i) {
                if (cur_node->children[i] == nullptr) {
                    prev_hash_[i] = "";
                } else {
                    prev_hash_[i] = cur_node->children[i]->hash;
                }
            }
            prev_hash_[16] = cur_node->value;
            cur_node->hash = HashArrayOfStrings(prev_hash_, 17);
        } else if (cur_node->type == NodeType::LEAF) {
            prev_hash_[0] = cur_node->value;
            prev_hash_[1] = key;
            prev_hash_[2] = cur_node->path;
            cur_node->hash = HashArrayOfStrings(prev_hash_, 3);
        } else if (cur_node->type == NodeType::EXTENSION) {
            prev_hash_[0] = cur_node->path;
            prev_hash_[1] = cur_node->children[0]->hash;
            cur_node->hash = HashArrayOfStrings(prev_hash_, 2);
        }
    }

    inline size_t FromCharToInt(const char c) {
        size_t symb = 0;
        if ('0' <= c && c <= '9') symb = c - '0';
        if ('a' <= c && c <= 'f') symb = c - 'a' + 10;
        return symb;
    }

    inline char FromIntToChar(const size_t ind) {
        char symb = '0';
        if (0 <= ind && ind <= 9) symb = '0' + ind;
        if (10 <= ind && ind <= 15) symb = 'a' + ind - 10;
        return symb;
    }
    
    shared_ptr<Node> Update(shared_ptr<Node> cur_node, const KeyValue& kv, size_t ind) {
        if (cur_node == nullptr) {
            cur_node = CreateNode(NodeType::LEAF);
            cur_node->value = kv.value;
            for (size_t i = 0; i + ind < kv.key.size(); ++i) {
                cur_node->path.push_back(kv.key[i+ind]);
            }
            UpdateHash(cur_node, kv.key);
            return cur_node;
        }

        if (cur_node->type == NodeType::LEAF) {
            CommonPrefix(cur_node->path, kv.key, ind);
            if (pref_.size() == cur_node->path.size() && kv.key.size() == pref_.size() + ind) {
                cur_node->value = kv.value;
                UpdateHash(cur_node, kv.key);
                return cur_node;             
            } else {
                shared_ptr<Node> new_node = nullptr;
                if (!pref_.empty()) {
                    new_node = CreateNode(NodeType::EXTENSION);
                    new_node->path = pref_;
                }
                shared_ptr<Node> new_branc_node = CreateNode(NodeType::BRANCH);

                new_branc_node = Update(new_branc_node, kv, ind + pref_.size());

                string cur_path;
                for (size_t i = 0; i < ind; ++i) {
                    cur_path.push_back(kv.key[i]);
                }
                cur_path += cur_node->path;
                new_branc_node = Update(new_branc_node, {cur_path, cur_node->value}, ind + pref_.size());

                if (new_node == nullptr) {
                    return new_branc_node;
                }

                new_node->children[0] = new_branc_node;
                UpdateHash(new_node, kv.key);
                return new_node;
            }
        } else if (cur_node->type == NodeType::EXTENSION) {
            CommonPrefix(cur_node->path, kv.key, ind);
            if (pref_.size() == cur_node->path.size()) {
                cur_node->children[0] = Update(cur_node->children[0], kv, ind + pref_.size());
                UpdateHash(cur_node, kv.key);
                return cur_node;
            } else {
                shared_ptr<Node> pref_extension_node = nullptr;
                if (!pref_.empty()) {
                    pref_extension_node = CreateNode(NodeType::EXTENSION);
                    pref_extension_node->path = pref_;
                }

                shared_ptr<Node> new_node = CreateNode(NodeType::BRANCH);

                size_t next_symb = FromCharToInt(cur_node->path[pref_.size()]);
                if (cur_node->path.size() == pref_.size()+1) {
                    new_node->children[next_symb] = cur_node->children[0];
                } else {
                    shared_ptr<Node> new_extension_node = CreateNode(NodeType::EXTENSION);
                    for (size_t i = pref_.size() + 1; i < cur_node->path.size(); ++i) {
                        new_extension_node->path.push_back(cur_node->path[i]);
                    }
                    new_extension_node->children[0] = cur_node->children[0];
                    UpdateHash(new_extension_node, kv.key);
                    new_node->children[next_symb] = new_extension_node;
                }

                new_node = Update(new_node, kv, ind+pref_.size());
                UpdateHash(new_node, kv.key);
                if (pref_extension_node == nullptr) {
                    return new_node;
                }
                pref_extension_node->children[0] = new_node;
                UpdateHash(pref_extension_node, kv.key);
                return pref_extension_node;
            }
        } else if (cur_node->type == NodeType::BRANCH) {
            if (ind == kv.key.size()) {
                cur_node->value = kv.value;
            } else {
                size_t next_symb = FromCharToInt(kv.key[ind]);
                cur_node->children[next_symb] = Update(cur_node->children[next_symb], kv, ind+1);
            }
            UpdateHash(cur_node, kv.key);
            return cur_node;
        }
        return cur_node;
    }

    pair<DeletedType, shared_ptr<Node>> Delete(shared_ptr<Node> cur_node, const string& key, size_t ind) {
        if (cur_node == nullptr) {
            return {DeletedType::NOT_DELETED, nullptr};
        }

        if (cur_node->type == NodeType::LEAF) {
            CommonPrefix(cur_node->path, key, ind);
            if (cur_node->path.size() != pref_.size()) {
                return {DeletedType::NOT_DELETED, nullptr};
            }
            return {DeletedType::DELETED, nullptr};
        } else if (cur_node->type == NodeType::EXTENSION) {
            CommonPrefix(cur_node->path, key, ind);
            if (cur_node->path.size() != pref_.size()) {
                return {DeletedType::NOT_DELETED, nullptr};
            }
            auto rez = Delete(cur_node->children[0], key, ind + pref_.size());
            if (rez.first == DeletedType::NOT_DELETED) {
                return rez;
            } else if (rez.first == DeletedType::DELETED) {
                // impossible
                return rez;
            } else if (rez.first == DeletedType::UPDATED) {
                cur_node->children[0] = rez.second;
                UpdateHash(cur_node, key);
                return {DeletedType::UPDATED, cur_node};
            } else if (rez.first == DeletedType::USELESS_BRANCH) {
                if (rez.second->type == NodeType::LEAF) {
                    rez.second->path = cur_node->path + rez.second->path;
                    string cur_path;
                    for (size_t i = 0; i < ind; ++i) {
                        cur_path.push_back(key[i]);
                    }
                    cur_path += rez.second->path;
                    UpdateHash(rez.second, cur_path);
                    return {DeletedType::USELESS_BRANCH, rez.second};
                } else if (rez.second->type == NodeType::EXTENSION) {
                    rez.second->path = cur_node->path + rez.second->path;
                    UpdateHash(rez.second, key);
                    return {DeletedType::UPDATED, rez.second};
                } else if (rez.second->type == NodeType::BRANCH) {
                    cur_node->children[0] = rez.second;
                    UpdateHash(cur_node, key);
                    return {DeletedType::UPDATED, cur_node};
                }
            }
        } else if (cur_node->type == NodeType::BRANCH) {
            if (ind == key.size()) {
                cur_node->value.clear();
            } else {
                size_t next_symb = FromCharToInt(key[ind]);
                auto rez = Delete(cur_node->children[next_symb], key, ind+1);
                if (rez.first == DeletedType::NOT_DELETED) {
                    return rez;
                }
                cur_node->children[next_symb] = rez.second;
            }
            int cnt_branch = 0, branch_ind = -1;
            for (size_t i = 0; i < 16; ++i) {
                if (cur_node->children[i] != nullptr) {
                    ++cnt_branch;
                    branch_ind = i;
                }
            }
            UpdateHash(cur_node, key);
            if (cnt_branch >= 2 || (cnt_branch == 1 && !cur_node->value.empty())) {
                return {DeletedType::UPDATED, cur_node};
            } else if (cnt_branch == 1 && cur_node->value.empty()) {
                if (cur_node->children[branch_ind]->type == NodeType::LEAF) {
                    char symb = FromIntToChar(branch_ind);
                    cur_node->children[branch_ind]->path = symb + cur_node->children[branch_ind]->path;
                    string cur_path;
                    for (size_t i = 0; i < ind; ++i) {
                        cur_path.push_back(key[i]);
                    }
                    cur_path += cur_node->children[branch_ind]->path;
                    UpdateHash(cur_node->children[branch_ind], cur_path);
                    return {DeletedType::USELESS_BRANCH, cur_node->children[branch_ind]};
                } else if (cur_node->children[branch_ind]->type == NodeType::EXTENSION) {
                    char symb = FromIntToChar(branch_ind);
                    cur_node->children[branch_ind]->path = symb + cur_node->children[branch_ind]->path;
                    UpdateHash(cur_node->children[branch_ind], key);
                    return {DeletedType::USELESS_BRANCH, cur_node->children[branch_ind]};
                } else if (cur_node->children[branch_ind]->type == NodeType::BRANCH) {
                    shared_ptr<Node> new_node = CreateNode(NodeType::EXTENSION);
                    char symb = FromIntToChar(branch_ind);
                    new_node->path = symb;
                    new_node->children[0] = cur_node->children[branch_ind];
                    UpdateHash(new_node, key);
                    return {DeletedType::USELESS_BRANCH, new_node};
                }
            } else if (cnt_branch == 0 && !cur_node->value.empty()) {
                shared_ptr<Node> new_node = CreateNode(NodeType::LEAF);
                new_node->value = cur_node->value;
                string cur_path;
                for (size_t i = 0; i < ind; ++i) {
                    cur_path.push_back(key[i]);
                }
                UpdateHash(new_node, cur_path);
                return {DeletedType::USELESS_BRANCH, new_node};
            } else if (cnt_branch == 0 && cur_node->value.empty()) {
                return {DeletedType::DELETED, nullptr};
            }
            return {DeletedType::UPDATED, cur_node};
        }
        return {DeletedType::NOT_DELETED, nullptr};
    }

    void Get(shared_ptr<Node> cur_node, const string& key, size_t ind) {
        if (cur_node == nullptr) {
            return;
        }
        if (cur_node->type == NodeType::LEAF) {
            CommonPrefix(cur_node->path, key, ind);
            if (key.size() == pref_.size() + ind) {
                rezult_ = cur_node->value;
            }
        } else if (cur_node->type == NodeType::EXTENSION) {
            CommonPrefix(cur_node->path, key, ind);
            if (pref_.size() == cur_node->path.size()) {
                Get(cur_node->children[0], key, ind + pref_.size());
            }
        } else if (cur_node->type == NodeType::BRANCH) {
            if (ind == key.size()) {
                rezult_ = cur_node->value;
            } else {
                size_t next_symb = FromCharToInt(key[ind]);
                Get(cur_node->children[next_symb], key, ind+1);
            }
        }
    }

public:
    PatriciaMerkleTree() {
        root_ = nullptr;
    };

    PatriciaMerkleTree(const vector <KeyValue>& data) {
        Build(data);
    }

    ~PatriciaMerkleTree() override = default;

    void Build(const vector<KeyValue>& data) override {
        root_ = nullptr;
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
        if (root_ == nullptr) {
            return;
        }
        auto rez = Delete(root_, key, 0);
        if (rez.first == DeletedType::DELETED) {
            root_ = nullptr;
        } else if (rez.first == DeletedType::UPDATED || rez.first == DeletedType::USELESS_BRANCH) {
            root_ = rez.second;
        }
    }

    void Update(const KeyValue& kv) override {
        root_ = Update(root_, kv, 0);
    }

    MerkleProof GetMerkleProof(const string& key) override {
        MerkleProof proof;
        shared_ptr<Node> cur_node = root_;
        size_t ind = 0;
        while (cur_node != nullptr) {
            proof.push_back({{}, 0});
            if (cur_node->type == NodeType::LEAF) {
                CommonPrefix(cur_node->path, key, ind);
                if (pref_.size() != cur_node->path.size()) {
                    break;
                }
                proof.back().hash.push_back(string());
                proof.back().hash.push_back(string());
                proof.back().hash.push_back(cur_node->path);
                proof.back().proof_hash_ind = 0;
                break;
            } else if (cur_node->type == NodeType::EXTENSION) {
                CommonPrefix(cur_node->path, key, ind);
                if (pref_.size() != cur_node->path.size()) {
                    break;
                }
                proof.back().hash.push_back(cur_node->path);
                proof.back().hash.push_back(string());
                proof.back().proof_hash_ind = 1;
                cur_node = cur_node->children[0];
                ind += pref_.size();
            } else if (cur_node->type == NodeType::BRANCH) {
                for (size_t i = 0; i < 16; ++i) {
                    proof.back().hash.push_back(cur_node->children[i] != nullptr ? cur_node->children[i]->hash : string());
                }
                proof.back().hash.push_back(cur_node->value);

                if (ind == key.size()) {
                    proof.back().proof_hash_ind = 16;
                    break;
                }

                size_t next_symb = FromCharToInt(key[ind]);
                cur_node = cur_node->children[next_symb];
                ind += 1;
                proof.back().proof_hash_ind = next_symb;
            }
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
    PatriciaMerkleTree tree_;

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
        string current;
        vector<string_view> cur_hash(17);
        for (const auto& node : proof) {
            for (size_t ind = 0; ind < node.hash.size(); ++ind) {
                cur_hash[ind] = node.hash[ind];
            }
            if (node.proof_hash_ind == 0 && node.hash.size() == 3) {
                cur_hash[0] = kv.value;
                cur_hash[1] = kv.key;
            } else if (node.proof_hash_ind == 16) {
                cur_hash[16] = kv.value;
            } else if (!current.empty()){
                cur_hash[node.proof_hash_ind] = current;
            } else {
                break;
            }
            current = HashArrayOfStrings(cur_hash, node.hash.size());
        }
        return current == root_hash_;
    }

private:
    string root_hash_;

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
                uint32_t len = static_cast<uint32_t>(buf[pos]);
                ++pos;
                if (pos + len > buf.size()) return MerkleProof();
                node.hash.emplace_back(buf.begin() + pos,
                                       buf.begin() + pos + len);
                pos += len;
            }
            if (pos + 1 > buf.size()) return MerkleProof();
            node.proof_hash_ind = static_cast<uint32_t>(buf[pos]);
            ++pos;
            proof.push_back(move(node));
        }
        return proof;
    }
};

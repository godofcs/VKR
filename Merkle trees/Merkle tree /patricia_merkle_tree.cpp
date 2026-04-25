#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <memory> 
#include <string_view>

#include "../Interfaces/merkle_trie_interface.h"
#include "../utils/SHA256/sha256.h"
#include "../utils/string_sum.cpp"

using namespace std;

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
    string pref_;
    vector <string_view> prev_hash_{17};

    string HashArrayOfStrings(const vector<string_view>& arr, int size) {
        picosha2::hash256_one_by_one hasher;
    
        for (int i = 0; i < size; ++i) {
            hasher.process(arr[i].begin(), arr[i].end());
        }
        
        hasher.finish();
        return picosha2::get_hash_hex_string(hasher);
    }

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

    void CommonPrefix(const string& cur_str, const string& new_str, int st_ind) {
        pref_.clear();
        for (int i = 0; i < cur_str.size() && st_ind + i < new_str.size(); ++i) {
            if (cur_str[i] != new_str[st_ind+i]) {
                break;
            }
            pref_.push_back(cur_str[i]);
        }
    }

    void UpdateHash(shared_ptr<Node> cur_node, const string& key) {
        if (cur_node->type == NodeType::BRANCH) {
            for (int i = 0; i < 16; ++i) {
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

    inline int FromCharToInt(const char c) {
        int symb = 0;
        if ('0' <= c && c <= '9') symb = c - '0';
        if ('a' <= c && c <= 'f') symb = c - 'a' + 10;
        return symb;
    }

    inline char FromIntToChar(const int ind) {
        char symb = '0';
        if (0 <= ind && ind <= 9) symb = '0' + ind;
        if (10 <= ind && ind <= 15) symb = 'a' + ind - 10;
        return symb;
    }
    
    shared_ptr<Node> Update(shared_ptr<Node> cur_node, const KeyValue& key_value, int ind) {
        if (cur_node == nullptr) {
            cur_node = CreateNode(NodeType::LEAF);
            cur_node->value = key_value.value;
            for (int i = 0; i + ind < key_value.key.size(); ++i) {
                cur_node->path.push_back(key_value.key[i+ind]);
            }
            UpdateHash(cur_node, key_value.key);
            return cur_node;
        }

        if (cur_node->type == NodeType::LEAF) {
            CommonPrefix(cur_node->path, key_value.key, ind);
            if (pref_.size() == cur_node->path.size() && key_value.key.size() == pref_.size() + ind) {
                cur_node->value = key_value.value;
                UpdateHash(cur_node, key_value.key);
                return cur_node;             
            } else {
                shared_ptr<Node> new_node = nullptr;
                if (!pref_.empty()) {
                    new_node = CreateNode(NodeType::EXTENSION);
                    new_node->path = pref_;
                }
                shared_ptr<Node> new_branc_node = CreateNode(NodeType::BRANCH);

                new_branc_node = Update(new_branc_node, key_value, ind + pref_.size());

                string cur_path;
                for (int i = 0; i < ind; ++i) {
                    cur_path.push_back(key_value.key[i]);
                }
                cur_path += cur_node->path;
                new_branc_node = Update(new_branc_node, {cur_path, cur_node->value}, ind + pref_.size());

                if (new_node == nullptr) {
                    return new_branc_node;
                }

                new_node->children[0] = new_branc_node;
                UpdateHash(new_node, key_value.key);
                return new_node;
            }
        } else if (cur_node->type == NodeType::EXTENSION) {
            CommonPrefix(cur_node->path, key_value.key, ind);
            if (pref_.size() == cur_node->path.size()) {
                cur_node->children[0] = Update(cur_node->children[0], key_value, ind + pref_.size());
                UpdateHash(cur_node, key_value.key);
                return cur_node;
            } else {
                shared_ptr<Node> pref_extension_node = nullptr;
                if (!pref_.empty()) {
                    pref_extension_node = CreateNode(NodeType::EXTENSION);
                    pref_extension_node->path = pref_;
                }

                shared_ptr<Node> new_node = CreateNode(NodeType::BRANCH);

                int next_symb = FromCharToInt(cur_node->path[pref_.size()]);
                if (cur_node->path.size() == pref_.size()+1) {
                    new_node->children[next_symb] = cur_node->children[0];
                } else {
                    shared_ptr<Node> new_extension_node = CreateNode(NodeType::EXTENSION);
                    for (int i = pref_.size() + 1; i < cur_node->path.size(); ++i) {
                        new_extension_node->path.push_back(cur_node->path[i]);
                    }
                    new_extension_node->children[0] = cur_node->children[0];
                    UpdateHash(new_extension_node, key_value.key);
                    new_node->children[next_symb] = new_extension_node;
                }

                new_node = Update(new_node, key_value, ind+pref_.size());
                UpdateHash(new_node, key_value.key);
                if (pref_extension_node == nullptr) {
                    return new_node;
                }
                pref_extension_node->children[0] = new_node;
                UpdateHash(pref_extension_node, key_value.key);
                return pref_extension_node;
            }
        } else if (cur_node->type == NodeType::BRANCH) {
            if (ind == key_value.key.size()) {
                cur_node->value = key_value.value;
            } else {
                int next_symb = FromCharToInt(key_value.key[ind]);
                cur_node->children[next_symb] = Update(cur_node->children[next_symb], key_value, ind+1);
            }
            UpdateHash(cur_node, key_value.key);
            return cur_node;
        }
        return cur_node;
    }

    pair<DeletedType, shared_ptr<Node>> Delete(shared_ptr<Node> cur_node, const string& key, int ind) {
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
                return rez;
            } else if (rez.first == DeletedType::UPDATED) {
                cur_node->children[0] = rez.second;
                UpdateHash(cur_node, key);
                return {DeletedType::UPDATED, cur_node};
            } else if (rez.first == DeletedType::USELESS_BRANCH) {
                if (rez.second->type == NodeType::LEAF) {
                    rez.second->path = cur_node->path + rez.second->path;
                    string cur_path;
                    for (int i = 0; i < ind; ++i) {
                        cur_path.push_back(key[i]);
                    }
                    cur_path += rez.second->path;
                    UpdateHash(rez.second, cur_path);
                    return {DeletedType::UPDATED, rez.second};
                } else if (rez.second->type == NodeType::EXTENSION) {
                    rez.second->path = cur_node->path + rez.second->path;
                    UpdateHash(rez.second, key);
                    return {DeletedType::UPDATED, rez.second};
                } else if (rez.second->type == NodeType::BRANCH) {
                    // impossible
                    assert(true && "rez.second->type == NodeType::BRANCH when rez.first == DeletedType::USELESS_BRANCH");
                    return {DeletedType::UPDATED, cur_node};
                }
            }
        } else if (cur_node->type == NodeType::BRANCH) {
            if (ind == key.size()) {
                cur_node->value.clear();
            } else {
                int next_symb = FromCharToInt(key[ind]);
                auto rez = Delete(cur_node->children[next_symb], key, ind+1);
                if (rez.first == DeletedType::NOT_DELETED) {
                    return rez;
                }
                cur_node->children[next_symb] = rez.second;
            }
            int cnt_branch = 0, branch_ind = -1;
            for (int i = 0; i < 16; ++i) {
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
                    for (int i = 0; i < ind; ++i) {
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
            } else if (cnt_branch == 0) {
                shared_ptr<Node> new_node = CreateNode(NodeType::LEAF);
                new_node->value = cur_node->value;
                string cur_path;
                for (int i = 0; i < ind; ++i) {
                    cur_path.push_back(key[i]);
                }
                UpdateHash(new_node, cur_path);
                return {DeletedType::USELESS_BRANCH, new_node};
            }
            return {DeletedType::UPDATED, cur_node};
        }
        return {DeletedType::NOT_DELETED, nullptr};
    }

    bool Verify(shared_ptr<Node> cur_node, const string& key, int ind) {
        if (cur_node == nullptr) {
            return false;
        }
        if (cur_node->type == NodeType::LEAF) {
            CommonPrefix(cur_node->path, key, ind);
            if (key.size() == pref_.size() + ind) {
                return true;
            }
            return false;
        } else if (cur_node->type == NodeType::EXTENSION) {
            CommonPrefix(cur_node->path, key, ind);
            if (pref_.size() == cur_node->path.size()) {
                return Verify(cur_node->children[0], key, ind + pref_.size());
            }
            return false;
        } else if (cur_node->type == NodeType::BRANCH) {
            if (ind == key.size()) {
                return cur_node->value.empty();
            }
            int next_symb = FromCharToInt(key[ind]);
            return Verify(cur_node->children[next_symb], key, ind+1);
        }
        return false;
    }

    void Get(shared_ptr<Node> cur_node, const string& key, int ind) {
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
                int next_symb = FromCharToInt(key[ind]);
                Get(cur_node->children[next_symb], key, ind+1);
            }
        }
    }

public:
    PatriciaMerkleTree() {
        root_ = nullptr;
    };

    ~PatriciaMerkleTree() override = default;

    PatriciaMerkleTree(const vector <KeyValue>& key_value_data) {
        root_ = make_shared<Node>();
        for (const auto& key_value: key_value_data) {
            UpdateValue(key_value);
        }
    }

    string GetRootHash() override {
        if (root_ == nullptr) {
            return "";
        }
        return root_->hash;
    }

    void DeleteValue(const string& key) override {
        if (root_ == nullptr) {
            return;
        }
        auto rez = Delete(root_, key, 0);
        if (rez.first == DeletedType::DELETED) {
            root_ = nullptr;
        }
    }

    void UpdateValue(const KeyValue& key_value) override {
        root_ = Update(root_, key_value, 0);
    }

    bool VerifyValue(const string& key) override {
        return Verify(root_, key, 0);
    }

    string GetValue(const string& key) override {
        rezult_.clear();
        Get(root_, key, 0);
        return rezult_;
    }
};


int main() {
    PatriciaMerkleTree tr;
    KeyValue key_value;
    string key = "key1";
    key_value.key = picosha2::hash256_hex_string(key);
    key_value.value = "val1";
    tr.UpdateValue(key_value);
    cout << "Root_hash: " << tr.GetRootHash() << "\n";
    cout << "get: " << tr.GetValue(key_value.key) << "\n";
    cout << "\n";
    key = "key2";
    key_value.key = picosha2::hash256_hex_string(key);
    key_value.value = "val2";
    tr.UpdateValue(key_value);
    cout << "Root_hash: " << tr.GetRootHash() << "\n";
    cout << "get: " << tr.GetValue(key_value.key) << "\n";
    cout << "\n";
    key = "key3";
    key_value.key = picosha2::hash256_hex_string(key);
    key_value.value = "val3";
    tr.UpdateValue(key_value);
    cout << "Root_hash: " << tr.GetRootHash() << "\n";
    cout << "get: " << tr.GetValue(key_value.key) << "\n";
    cout << "\n";
    key = "key4";
    key_value.key = picosha2::hash256_hex_string(key);
    key_value.value = "val4";
    tr.UpdateValue(key_value);
    cout << "Root_hash: " << tr.GetRootHash() << "\n";
    cout << "get: " << tr.GetValue(key_value.key) << "\n";
    cout << "\n";
    key = "key5";
    key_value.key = picosha2::hash256_hex_string(key);
    key_value.value = "val5";
    tr.UpdateValue(key_value);
    cout << "Root_hash: " << tr.GetRootHash() << "\n";
    cout << "get: " << tr.GetValue(key_value.key) << "\n";
    cout << "\n";
    
    cout << "Root_hash: " << tr.GetRootHash() << "\n";
    key = "key3";
    if (tr.VerifyValue(picosha2::hash256_hex_string(key))) {
        cout << "Verify Val3: " << tr.GetValue(picosha2::hash256_hex_string(key)) << "\n";
    }
    tr.DeleteValue(picosha2::hash256_hex_string(key));
    if (tr.VerifyValue(picosha2::hash256_hex_string(key))) {
        cout << "Verify Val3: " << tr.GetValue(picosha2::hash256_hex_string(key)) << "\n";
    }
    cout << "Root_hash: " << tr.GetRootHash() << "\n";
    key = "key2";
    if (tr.VerifyValue(picosha2::hash256_hex_string(key))) {
        cout << "Verify Val2: " << tr.GetValue(picosha2::hash256_hex_string(key)) << "\n";
    }
    key = "key1";
    if (tr.VerifyValue(picosha2::hash256_hex_string(key))) {
        cout << "Verify Val1: " << tr.GetValue(picosha2::hash256_hex_string(key)) << "\n";
    }
    tr.DeleteValue(picosha2::hash256_hex_string(key));
    if (tr.VerifyValue(picosha2::hash256_hex_string(key))) {
        cout << "Verify Val1: " << tr.GetValue(picosha2::hash256_hex_string(key)) << "\n";
    }
    key = "key2";
    if (tr.VerifyValue(picosha2::hash256_hex_string(key))) {
        cout << "Verify Val2: " << tr.GetValue(picosha2::hash256_hex_string(key)) << "\n";
    }
}

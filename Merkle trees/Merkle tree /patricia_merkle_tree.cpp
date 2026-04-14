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

class RadixMerkleTree : public IMerkleTree {
private:
    enum class NodeType : unsigned char {
        BRANCH = 0,
        EXTENSION = 1,
        LEAF = 2
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
        } else {
            prev_hash_[0] = cur_node->value;
            prev_hash_[1] = cur_node->path;
            if (cur_node->children[0] == nullptr) {
                prev_hash_[2] = "";
            } else {
                prev_hash_[2] = cur_node->children[0]->hash;
            }
            cur_node->hash = HashArrayOfStrings(prev_hash_, 2);
        }
    }

    inline int FromCharToInt(const char c) {
        int symb = 0;
        if ('0' <= c && c <= '9') symb = c - '0';
        if ('a' <= c && c <= 'f') symb = c - 'a' + 10;
        return symb;
    }
    
    shared_ptr<Node> Update(shared_ptr<Node> cur_node, const KeyValue& key_value, int ind) {
        if (cur_node == nullptr) {
            cur_node = make_shared<Node>();
            cur_node->type = NodeType::LEAF;
            cur_node->value = key_value.value;
            for (int i = 0; i + ind < key_value.key.size(); ++i) {
                cur_node->path.push_back(key_value.key[i+ind]);
            }
            UpdateHash(cur_node, key_value.key);
            return cur_node;
        }

        if (cur_node->type == NodeType::LEAF) {
            CommonPrefix(cur_node->path, key_value.key, ind);
            if (pref_ == cur_node->path && key_value.key.size() == pref_.size() + ind) {
                cur_node->value = key_value.value;
                UpdateHash(cur_node, key_value.key);
                return cur_node;
            } else if (pref_.empty()) {
                shared_ptr<Node> new_node = make_shared<Node>();
                new_node->type = NodeType::BRANCH;
                new_node->children.resize(16, nullptr);
                if (cur_node->path.empty()) {
                    new_node->value = cur_node->value;
                } else {
                    int next_symb = FromCharToInt(cur_node->path[0]);
                    new_node->children[next_symb] = Update(new_node->children[next_symb], {cur_node->path, cur_node->value}, 1);
                }
                if (key_value.key.size() == ind) {
                    new_node->value = key_value.value;
                } else {
                    int next_symb = FromCharToInt(key_value.key[ind]);
                    new_node->children[next_symb] = Update(new_node->children[next_symb], key_value, ind + 1);
                }
                UpdateHash(new_node, new_node->value);
                return new_node;              
            } else {
                shared_ptr<Node> new_node = make_shared<Node>();
                new_node->type = NodeType::EXTENSION;
                new_node->path = pref_;
                new_node->children.resize(1, nullptr);

                if (pref_ == cur_node->path) {
                    new_node->value = cur_node->value;
                    new_node->children[0] = Update(new_node->children[0], key_value, ind + pref_.size());
                } else {
                    shared_ptr<Node> new_branc_node = make_shared<Node>();
                    new_branc_node->type = NodeType::BRANCH;
                    new_branc_node->children.resize(16, nullptr);
                    new_node->children[0] = new_branc_node;
                    new_node->children[0] = Update(new_node->children[0], key_value, ind + pref_.size());
                    new_node->children[0] = Update(new_node->children[0], {cur_node->path, cur_node->value}, pref_.size());
                }
                UpdateHash(new_node, key_value.key);
                return new_node;
            }
        } else if (cur_node->type == NodeType::EXTENSION) {
            CommonPrefix(cur_node->path, key_value.key, ind);
            if (pref_ == cur_node->path) {
                if (key_value.key.size() == ind + pref_.size()) {
                    cur_node->value = key_value.value;
                } else {
                    cur_node->children[0] = Update(cur_node->children[0], key_value, ind + pref_.size());
                }
                UpdateHash(cur_node, key_value.key);
                return cur_node;
            } else if (pref_.empty()) {
                shared_ptr<Node> new_node = make_shared<Node>();
                new_node->type = NodeType::BRANCH;
                new_node->children.resize(16, nullptr);

                int next_symb = FromCharToInt(cur_node->path[0]);
                new_node->children[next_symb] = Update(new_node->children[next_symb], {cur_node->path, cur_node->value}, 1);

                if (key_value.key.size() == ind) {
                    new_node->value = key_value.value;
                } else {
                    int next_symb = FromCharToInt(key_value.key[ind]);
                    new_node->children[next_symb] = Update(new_node->children[next_symb], key_value, ind + 1);
                }
                UpdateHash(new_node, new_node->value);
                return new_node; 
            } else {
                
                
            }
        }


        if (ind == key_value.key.size()) {
            cur_node->value = key_value.value;
            prev_hash_[0] = key_value.value;
            prev_hash_[1] = key_value.key;
            cur_node->hash = HashArrayOfStrings(prev_hash_, 2);
            return;
        }
        int symb = 0;
        if ('0' <= key_value.key[ind] && key_value.key[ind] <= '9') symb = key_value.key[ind] - '0';
        if ('a' <= key_value.key[ind] && key_value.key[ind] <= 'f') symb = key_value.key[ind] - 'a' + 10;
        if (cur_node->children[symb] == nullptr) {
            cur_node->children[symb] = make_shared<Node>();
        }
        Update(cur_node->children[symb], key_value, ind+1);
        for (int i = 0; i < 16; ++i) {
            if (cur_node->children[i] == nullptr) {
                prev_hash_[i] = "";
            } else {
                prev_hash_[i] = cur_node->children[i]->hash;
            }
        }
        cur_node->hash = HashArrayOfStrings(prev_hash_);
    }

    shared_ptr<Node> Delete(shared_ptr<Node> cur_node, const string& key, int ind) {
        if (cur_node == nullptr) {
            return nullptr;
        }
        if (ind == key.size()) {
            return nullptr;
        }
        int symb = 0;
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
        for (int i = 0; i < 16; ++i) {
            if (cur_node->children[i] == nullptr) {
                prev_hash_[i] = "";
            } else {
                prev_hash_[i] = cur_node->children[i]->hash;
            }
        }
        cur_node->hash = HashArrayOfStrings(prev_hash_);
        return cur_node;
    }

    void Verify(shared_ptr<Node> cur_node, const string& key, int ind) {
        if (cur_node == nullptr) {
            return;
        }
        if (ind == key.size()) {
            rezult_ = key;
            return;
        }
        int symb = 0;
        if ('0' <= key[ind] && key[ind] <= '9') symb = key[ind] - '0';
        if ('a' <= key[ind] && key[ind] <= 'f') symb = key[ind] - 'a' + 10;
        Verify(cur_node->children[symb], key, ind+1);
        for (int i = 0; i < 16; ++i) {
            if (i == symb) {
                prev_hash_[i] = rezult_;
            } else if (cur_node->children[i] == nullptr) {
                prev_hash_[i] = "";
            } else {
                prev_hash_[i] = cur_node->children[i]->hash;
            }
        }
        rezult_ = HashArrayOfStrings(prev_hash_);
    }

    void Get(shared_ptr<Node> cur_node, const string& key, int ind) {
        if (cur_node == nullptr) {
            rezult_ = "";
            return;
        }
        if (ind == key.size()) {
            rezult_ = cur_node->value;
            return;
        }
        int symb = 0;
        if ('0' <= key[ind] && key[ind] <= '9') symb = key[ind] - '0';
        if ('a' <= key[ind] && key[ind] <= 'f') symb = key[ind] - 'a' + 10;
        Get(cur_node->children[symb], key, ind+1);
    }

public:
    RadixMerkleTree() {
        root_ = make_shared<Node>();
    };

    ~RadixMerkleTree() override = default;

    RadixMerkleTree(const vector <KeyValue>& key_value_data) {
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
        root_ = Delete(root_, key, 0) ;
    }

    void UpdateValue(const KeyValue& key_value) override {
        Update(root_, key_value, 0);
    }

    bool VerifyValue(const string& key) override {
        Verify(root_, key, 0);
        return GetRootHash() == rezult_;
    }

    string GetValue(const string& key) override {
        Get(root_, key, 0);
        return rezult_;
    }
};


int main() {
    RadixMerkleTree tr;
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

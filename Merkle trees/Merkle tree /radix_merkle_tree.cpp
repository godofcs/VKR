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
    struct Node {
        string hash;
        string value;
        array <shared_ptr<Node>, 16> children;
    };
    shared_ptr <Node> root_ = nullptr;
    string rezult_;
    array <string_view, 16> prev_hash_;


    string hash_array_of_strings(const array<string_view, 16>& arr) {
        picosha2::hash256_one_by_one hasher;
    
        for (const auto& str: arr) {
            hasher.process(str.begin(), str.end());
        }
        
        hasher.finish();
        return picosha2::get_hash_hex_string(hasher);
    }
    
    void Update(shared_ptr<Node> cur_node, const KeyValue& key_value, int ind) {
        if (ind == key_value.key.size()) {
            cur_node->value = key_value.value;
            cur_node->hash = key_value.key;
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
        cur_node->hash = hash_array_of_strings(prev_hash_);
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
        cur_node->hash = hash_array_of_strings(prev_hash_);
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
        rezult_ = hash_array_of_strings(prev_hash_);
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

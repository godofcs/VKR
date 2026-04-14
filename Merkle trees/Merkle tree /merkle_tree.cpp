#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <memory> 

#include "../Interfaces/merkle_tree_interface.h"
#include "../utils/SHA256/sha256.h"
#include "../utils/string_sum.cpp"

using namespace std;

class MerkleTree : public IMerkleTree {
private:
    struct Node {
        int left, right;
        string hash;
        shared_ptr<Node> left_child = nullptr;
        shared_ptr<Node> right_child = nullptr;
    };

    vector <KeyValue> keyValueData_;
    shared_ptr<Node> root_ = nullptr;
    string rezult_;
    
    shared_ptr<Node> Build(int left, int right) {
        shared_ptr<Node> curNode = make_shared<Node>();
        curNode->left = left;
        curNode->right = right;
        if (left == right) {
            curNode->hash = keyValueData_[left].key;
            return curNode;
        }
        int mid = left + (right - left) / 2;
        curNode->left_child = Build(left, mid);
        curNode->right_child = Build(mid+1, right);
        curNode->hash = picosha2::hash256_hex_string(sum(curNode->left_child->hash, curNode->right_child->hash));
        return curNode;
    }

    void Verify(shared_ptr<Node> cur, int ind, string& key) {
        if (cur->left == cur->right) {
            rezult_ = key;
            return;
        }
        if (ind <= cur->left_child->right) {
            Verify(cur->left_child, ind, key);
            rezult_ = picosha2::hash256_hex_string(sum(rezult_, cur->right_child->hash));
        } else {
            Verify(cur->right_child, ind, key);
            rezult_ = picosha2::hash256_hex_string(sum(cur->left_child->hash, rezult_));
        }
    }

public:
    MerkleTree() = default;
    ~MerkleTree() override = default;
    MerkleTree(vector <KeyValue>& keyValueData) : keyValueData_(keyValueData) {
        root_ = Build(0, keyValueData.size()-1);
    }

    string GetRootHash() override {
        if (root_ == nullptr) {
            return "";
        }
        return root_->hash;
    }

    void DeleteValue(int index) override {
        assert(index < keyValueData_.size() && "Index out of range");

        keyValueData_.erase(keyValueData_.begin() + index);
        root_ = Build(0, keyValueData_.size()-1);  
    }

    void UpdateValue(KeyValue& key_value, int index) override {
        assert(index <= keyValueData_.size() && "Index out of range");
        if (index == keyValueData_.size()) {
            keyValueData_.push_back(key_value);
        } else {
            keyValueData_[index] = key_value;
        }
        root_ = Build(0, keyValueData_.size()-1); 
    }

    bool VerifyValue(int index, string& key) override {
        assert(index < keyValueData_.size() && "Index out of range");
        Verify(root_, index, key);
        return GetRootHash() == rezult_;
    }

    string GetValue(int index) override {
        assert(index < keyValueData_.size() && "Index out of range");
        return keyValueData_[index].value;
    }
};


int main() {
    MerkleTree tr;
    /*
    string key = "key1";
    KeyValue keyVal = {picosha2::hash256_hex_string(key), "val1"};
    tr.UpdateValue(keyVal, 0);
    */
}

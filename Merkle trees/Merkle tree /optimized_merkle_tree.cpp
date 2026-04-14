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
    vector <KeyValue> keyValueData_;
    vector <string> hashTree_;
    string rezult_;
    
    void Build(int tind, int left, int right) {
        if (left == right) {
            hashTree_[tind] = keyValueData_[left].key;
            return;
        }
        int mid = left + (right - left) / 2;
        Build(tind*2, left, mid);
        Build(tind*2+1, mid+1, right);
        hashTree_[tind] = picosha2::hash256_hex_string(sum(hashTree_[tind*2], hashTree_[tind*2+1]));
    }

    void Verify(int tind, int left, int right, int ind, string& key) {
        if (left == right) {
            rezult_ = key;
            return;
        }
        int mid = left + (right - left) / 2;
        if (ind <= mid) {
            Verify(tind*2, left, mid, ind, key);
            rezult_ = picosha2::hash256_hex_string(sum(rezult_, hashTree_[tind*2+1]));
        } else {
            Verify(tind*2+1, mid+1, right, ind, key);
            rezult_ = picosha2::hash256_hex_string(sum(hashTree_[tind*2], rezult_));
        }
    }

public:
    MerkleTree() = default;
    ~MerkleTree() override = default;
    MerkleTree(vector <KeyValue>& keyValueData) : keyValueData_(keyValueData) {
        hashTree_.clear();
        hashTree_.resize(4*keyValueData.size());
        Build(1, 0, keyValueData.size()-1);
    }

    string GetRootHash() override {
        if (hashTree_.empty()) {
            return "";
        }
        return hashTree_[1];
    }

    void DeleteValue(int index) override {
        assert(index < keyValueData_.size() && "Index out of range");

        keyValueData_.erase(keyValueData_.begin() + index);
        hashTree_.clear();
        hashTree_.resize(4*keyValueData_.size());
        Build(1, 0, keyValueData_.size()-1);  
    }

    void UpdateValue(KeyValue& key_value, int index) override {
        assert(index <= keyValueData_.size() && "Index out of range");
        if (index == keyValueData_.size()) {
            keyValueData_.push_back(key_value);
        } else {
            keyValueData_[index] = key_value;
        }
        hashTree_.clear();
        hashTree_.resize(4*keyValueData_.size());
        Build(1, 0, keyValueData_.size()-1); 
    }

    bool VerifyValue(int index, string& key) override {
        assert(index < keyValueData_.size() && "Index out of range");
        Verify(1, 0, keyValueData_.size(), index, key);
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

#pragma once

#include <vector>
#include <string>
#include "../utils/struct.h"

using namespace std;

struct ProofNode {
    vector<string> hash;
    size_t proof_hash_ind;
};

using MerkleProof = vector<ProofNode>;

class IMerkleTree {
public:
    IMerkleTree() = default;
    IMerkleTree(const vector <KeyValue>& kv) {};
    virtual ~IMerkleTree() = default;
    virtual void Build(const vector<KeyValue>& data) = 0;
    virtual string GetRootHash() const = 0;
    virtual void Update(const KeyValue& key_value) = 0;
    virtual void Delete(const string& key) = 0;
    virtual string GetValue(const string& key) = 0;
    virtual MerkleProof GetMerkleProof(const string& key) = 0;
};

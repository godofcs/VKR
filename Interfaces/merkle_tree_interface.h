#pragma once

#include <vector>
#include <string>
#include "../utils/struct.h"

using namespace std;

enum class ProofDirection : uint8_t {
    LEFT  = 0,
    RIGHT = 1,
};

struct ProofNode {
    string hash;
    ProofDirection direction;
};

using MerkleProof = vector<ProofNode>;

class IMerkleTree {
public:
    virtual ~IMerkleTree() = default;
    virtual void Build(const vector<KeyValue>& data) = 0;
    virtual string GetRootHash() const = 0;
    virtual void Update(size_t index, const string& new_value) = 0;
    virtual void Insert(const KeyValue& kv) = 0;
    virtual void Delete(size_t index) = 0;
    virtual string GetValue(size_t index) const = 0;
    virtual MerkleProof GetMerkleProof(size_t index) const = 0;
    virtual size_t Size() const = 0;
};
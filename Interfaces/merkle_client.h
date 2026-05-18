#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "../utils/struct.h"
using namespace std;


class IFullClient {
public:
    virtual ~IFullClient() = default;

    virtual void Build(const vector<KeyValue>& data) = 0;
    virtual string GetRootHash() const = 0;
    virtual void Update(const KeyValue& kv) = 0;
    virtual void Delete(const string& key) = 0;
    virtual vector<uint8_t> RequestProof(const string& key) = 0;
};


class ILightClient {
public:
    virtual ~ILightClient() = default;

    virtual void SetRootHash(const string& root_hash) = 0;
    virtual bool VerifyProof(const KeyValue& kv, const vector<uint8_t>& proof_bytes) const = 0;
};

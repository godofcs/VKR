#include <vector>
#include <string>
#include "../utils/struct.h"

using namespace std;

class IMerkleTree {
public:
    IMerkleTree() = default;
    IMerkleTree(const vector <KeyValue>& key_value_data) {};
    virtual string GetRootHash() = 0;
    virtual void DeleteValue(const string& key) = 0;
    virtual void UpdateValue(const KeyValue& key_value) = 0;
    virtual bool VerifyValue(const string& key) = 0;
    virtual string GetValue(const string& key) = 0;
    virtual ~IMerkleTree() = default;
};

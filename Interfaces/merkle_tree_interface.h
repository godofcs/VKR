#include <vector>
#include <string>
#include "../utils/struct.h"

using namespace std;

class IMerkleTree {
public:
    IMerkleTree() = default;
    IMerkleTree(vector <KeyValue>& key_value_data) {};
    virtual ~IMerkleTree() = default;
    virtual string GetRootHash() = 0;
    virtual void DeleteValue(int index) = 0;
    virtual void UpdateValue(KeyValue& key_value, int index) = 0;
    virtual bool VerifyValue(int index, string& key) = 0;
    virtual string GetValue(int index) = 0;
};

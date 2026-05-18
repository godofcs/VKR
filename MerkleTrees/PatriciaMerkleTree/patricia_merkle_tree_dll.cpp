#include "patricia_merkle_tree.cpp"


extern "C" {

IFullClient* CreateMerkleFullClient() {
    return new FullClient();
}

ILightClient* CreateMerkleLightClient() {
    return new LightClient();
}

void DestroyMerkleFullClient(IFullClient* ptr) {
    delete ptr;
}

void DestroyMerkleLightClient(ILightClient* ptr) {
    delete ptr;
}

}

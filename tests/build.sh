#!/usr/bin/env bash
# ============================================================================
#  Сборка стенда и всех доступных динамических библиотек реализаций.
# ============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

CXX="${CXX:-g++}"
CXXFLAGS="-std=c++17 -O2 -Wall"

build_lib() {
    local src_dir="$1"
    local src_file="$2"
    local out_name="$3"

    local src="$src_dir/$src_file"
    local out="$src_dir/$out_name"

    if [[ ! -f "$src" ]]; then
        echo "  skip $out_name : no source $src"
        return
    fi
    echo "  build $out_name"
    "$CXX" $CXXFLAGS -fPIC -shared "$src" -o "$out"
}

echo "[1/3] Building dynamic libraries"
build_lib "$ROOT/MerkleTrees/MerkleTree" "merkle_tree_dll.cpp" "libmerkle_tree.so"
build_lib "$ROOT/MerkleTrees/OptimizedMerkleTree" "optimized_merkle_tree_dll.cpp" "liboptimized_merkle_tree.so"
build_lib "$ROOT/MerkleTrees/RadixMerkleTree" "radix_merkle_tree_dll.cpp" "libradix_merkle_tree.so"
build_lib "$ROOT/MerkleTrees/PatriciaMerkleTree" "patricia_merkle_tree_dll.cpp" "libpatricia_merkle_tree.so"

echo "[2/3] Building test stand"
"$CXX" $CXXFLAGS "$HERE/test_stand.cpp" -ldl -o "$HERE/test_stand"

echo "[3/3] Building comparison stand (analyzer module)"
"$CXX" $CXXFLAGS "$HERE/compare_stand.cpp" -ldl -o "$HERE/compare_stand"

echo "Done."

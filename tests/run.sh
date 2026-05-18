#!/usr/bin/env bash
# ============================================================================
#  Прогон тестового стенда на всех собранных динамических библиотеках.
#
#  Использование:
#    ./run.sh                        # размеры по умолчанию (1000, 10000), 10 повторов
#    ./run.sh "1000,10000,100000"   # свои размеры
#    ./run.sh "1000,10000" 200      # размеры + число повторов
# ============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$(cd "$HERE/.." && pwd)/MerkleTrees"

SIZES="${1:-1000,10000}"
REPEATS="${2:-10}"

if [[ ! -x "$HERE/test_stand" ]]; then
    echo "test_stand not built. Run ./build.sh first." >&2
    exit 1
fi

shopt -s nullglob
libs=("$LIB_DIR"/*/lib*.so)

if (( ${#libs[@]} == 0 )); then
    echo "No .so libraries found in $LIB_DIR" >&2
    exit 2
fi

for lib in "${libs[@]}"; do
    echo
    "$HERE/test_stand" "$lib" "$SIZES" "$REPEATS"
done

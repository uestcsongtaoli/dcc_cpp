#!/usr/bin/env bash
# Build dcc_encrypt.
# - macOS  → dynamic linking (default)
# - Linux  → static libstdc++/libgcc (portable binary)
#
# Usage:
#   ./build.sh             # Release build
#   ./build.sh --debug     # Debug build
#   ./build.sh --clean     # wipe build/ first
#   ./build.sh --jobs N    # parallel jobs (default: all cores)

set -euo pipefail

BUILD_TYPE="Release"
CLEAN=0
JOBS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug) BUILD_TYPE="Debug"; shift ;;
        --clean) CLEAN=1; shift ;;
        --jobs)  JOBS="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

OS="$(uname -s)"
if [[ -z "$JOBS" ]]; then
    if [[ "$OS" == "Darwin" ]]; then
        JOBS="$(sysctl -n hw.logicalcpu)"
    else
        JOBS="$(nproc)"
    fi
fi

if [[ $CLEAN -eq 1 && -d build ]]; then
    echo "Cleaning build/ ..."
    rm -rf build
fi

if [[ "$OS" == "Darwin" ]]; then
    echo "Platform: macOS — dynamic build"
    cmake -B build -DCMAKE_BUILD_TYPE="$BUILD_TYPE"
else
    echo "Platform: Linux — static runtime build"
    cmake -B build -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DSTATIC_RUNTIME=ON
fi

cmake --build build -j"$JOBS"

echo ""
echo "Done: $(ls -lh build/dcc_encrypt)"

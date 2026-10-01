#!/bin/bash
set -e

# Default to the directory containing this script.
IDFUZZ=${IDFUZZ:-$(cd "$(dirname "$0")" && pwd)}

cd "$IDFUZZ"
make clean all

# llvm_mode's self-test compiles a program with the IDFuzz pass, which appends
# to the files in $TMP_DIR. Point it at a scratch directory so a real
# campaign's analysis files are not polluted.
BUILD_TMP=$(mktemp -d)
TMP_DIR=$BUILD_TMP make -C llvm_mode clean all
rm -rf "$BUILD_TMP"

for pass in llvm-pass-getCSAdditionalTargets llvm-pass-getFunctionName; do
    mkdir -p "$IDFUZZ/$pass/build"
    cd "$IDFUZZ/$pass/build"
    cmake ..
    make
done

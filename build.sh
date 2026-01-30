#!/bin/bash

make clean all
cd ./llvm_mode
make clean all

cd $IDFUZZ/llvm-pass-getCSAdditionalTargets
mkdir build
cd build
cmake ..
make

cd $IDFUZZ/llvm-pass-getFunctionName
mkdir build
cd build
cmake ..
make


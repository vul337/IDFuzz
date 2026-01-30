## Build
```bash
mkdir build
cd build
cmake ..
make
```

## Run
```bash
clang -g -S -emit-llvm test/helloworld.c -o test/helloworld.ll
opt -load build/getFunctionName/libgetFunctionName.so -getFunctionName test/helloworld.ll
```

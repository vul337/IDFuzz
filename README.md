# IDFuzz

This is the official code repository for the research paper *IDFuzz: Intelligent Directed Grey-box Fuzzing* (USENIX Security 2025). The artifacts for the paper are also available at [https://doi.org/10.5281/zenodo.13753907](https://doi.org/10.5281/zenodo.13753907). 

IDFuzz is an intelligent input mutation solution for directed fuzzing which leverages a neural network model to learn from historically mutated inputs and extracts useful experience that can guide input mutation towards the target code.

## Environment Requirements

- **OS**: Ubuntu 20.04.4 LTS
- **Clang**: 10.0.0-4ubuntu1
- **LLVM**: 10.0.0
- **GNU Make**: 4.2.1
- **Python**: 3.8

For a complete environment setup, please refer to the Dockerfile in the `docker/` directory.

## Pipeline

1. Build IDFuzz.
```shell
   git clone https://github.com/vul337/IDFuzz.git
   cd IDFuzz
   export IDFUZZ=$PWD
   ./build.sh
```

2. Setup directory containing temporary files.
```shell
   mkdir temp
   export TMP_DIR=$PWD/temp
   # Write BBtargets.txt and print targets.
   echo "Targets:"
   cat $TMP_DIR/BBtargets.txt
```

3. Compile the target using [`gllvm`](https://github.com/SRI-CSL/gllvm) to extract `target.bc`, then place it under the `$TMP_DIR` directory.

4. Generate the function call graph `callgraph.dot`.
```shell
   cd $TMP_DIR
   opt -dot-callgraph target.bc
```

5. Generate `FunctionsOfTargets.txt`.
```shell
   opt -load $IDFUZZ/llvm-pass-getFunctionName/build/getFunctionName/libgetFunctionName.so -getFunctionName target.bc
```

6. Generate `DominatorsOfTargetFunctions.txt`.
```shell
   python3 $IDFUZZ/py/parse_cg.py
```

7. Generate `BBtargets-inter.txt`. 
```shell
   opt -load $IDFUZZ/llvm-pass-getCSAdditionalTargets/build/getCSAdditionalTargets/libgetCSAdditionalTargets.so -getCSAdditionalTargets target.bc
```

8. Compile the target program using `afl-clang-fast` generated in step 1, setting `CFLAGS="-flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"`.
```shell
   export CC=$IDFUZZ/afl-clang-fast
   export CXX=$IDFUZZ/afl-clang-fast++
   export CFLAGS="-flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
   export CXXFLAGS="-flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
   # Then compile your target program
```

9. Use `gen_dom_graph.py` to generate an interprocedural dominator graph for each basic block (bb) target: list of (edge, level).
```shell
   python3 $IDFUZZ/py/gen_dom_graph.py
```

10. Run IDFuzz.
```shell
   ./fuzz.sh [PUT_NAME] [INPUT_DIR] [OUTPUT_DIR] [SHM_ID] [TIMEOUT] [ARGS]
```

   **Parameters:**
   - `PUT_NAME`: Name of the target program (default: `objdump`)
   - `INPUT_DIR`: Input seed directory (default: `in`)
   - `OUTPUT_DIR`: Fuzzing output directory (default: `out`)
   - `SHM_ID`: Shared memory ID for fuzzer-NN communication (default: `5`)
   - `TIMEOUT`: Fuzzing timeout (default: `5m`)
   - `ARGS`: Arguments for the target program (default: `-SD @@`)

   **Example:**
```shell
   ./fuzz.sh readelf seeds out 5 10m "-a @@"
```

   **What the script does:**
   - Starts the AFL fuzzer (output displayed in terminal)
   - Waits 60 seconds for initialization
   - Automatically starts the neural network (logs to `$TMP_DIR/nn.log`)

   **Monitor neural network output:**
```shell
   tail -f $TMP_DIR/nn.log
```

## Tips

We provide an example directory at `./temp` for your reference. This example contains properly formatted files to help you:
   - Verify that no files are missing
   - Understand the expected content structure

   **Improving fuzzing effectiveness:**

   Due to limitations of static analysis tools, the automatically generated files may have incomplete content (e.g., missing target locations, incomplete call graphs). For better directed fuzzing results, you can:
   - Examine vulnerability reports (e.g., ASan crash reports)
   - Manually add missing targets to the corresponding files
   - Follow the content structure shown in `./temp` example files

## Citation

If you use IDFuzz in your research, please cite our paper:
```bibtex
@inproceedings{chen2025idfuzz,
  title={$\{$IDFuzz$\}$: Intelligent Directed Grey-box Fuzzing},
  author={Chen, Yiyang and Zhang, Chao and Wang, Long and Zhu, Wenyu and Luo, Changhua and Gui, Nuoqi and Ma, Zheyu and Zhang, Xingjian and Su, Bingkai},
  booktitle={34th USENIX Security Symposium (USENIX Security 25)},
  pages={6219--6238},
  year={2025}
}
```

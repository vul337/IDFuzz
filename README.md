# IDFuzz

This is the official code repository for the research paper *IDFuzz: Intelligent Directed Grey-box Fuzzing* (USENIX Security 2025). The artifacts for the paper are also available at [https://doi.org/10.5281/zenodo.13753907](https://doi.org/10.5281/zenodo.13753907).

IDFuzz is an intelligent input mutation solution for directed fuzzing which leverages a neural network model to learn from historically mutated inputs and extracts useful experience that can guide input mutation towards the target code.

## Environment Requirements

- **OS**: Ubuntu 20.04.4 LTS
- **Clang**: 10.0.0-4ubuntu1
- **LLVM**: 10.0.0
- **GNU Make**: 4.2.1
- **Python**: 3.8
- **gllvm**: v1.3.1 (extracts the target's whole-program bitcode)

### Docker

The Dockerfile in `docker/` sets up this environment with pinned package versions and builds IDFuzz from your local copy of the repository, so local changes are included. Build it from the repository root:
```shell
docker build -f docker/Dockerfile -t idfuzz .
docker run -it idfuzz
```

If `proxy.golang.org` or `go.dev` is not reachable, point the build at mirrors:
```shell
docker build -f docker/Dockerfile \
    --build-arg GOPROXY=https://goproxy.cn,direct \
    --build-arg GO_DL_BASE=https://golang.google.cn/dl \
    -t idfuzz .
```

Inside the container IDFuzz is at `/IDFuzz`, with `$IDFUZZ` already set.

## Target Limit

**IDFuzz supports at most 16 targets** (lines in `BBtargets.txt`) per campaign. Each target is tracked as one bit in a 16-bit field of `dom_bits_depth.txt`, so a 17th target would corrupt the data of the others. Every line of `BBtargets.txt` uses a target slot, including blank or malformed lines. `idfuzz.sh` stops with an error if the file has more than 16 lines.

## Pipeline

The example below fuzzes `readelf`; adapt the paths and build commands to your target.

**1. Build IDFuzz.** Skip this step in the Docker image.
```shell
git clone https://github.com/vul337/IDFuzz.git
cd IDFuzz
export IDFUZZ=$PWD
./build.sh
```

**2. Create a working directory and list the targets.** `$TMP_DIR` holds all intermediate files of one campaign. Use a new directory for every campaign. The repository's `temp/` is an example to compare against, not a place to work in.
```shell
mkdir -p ~/campaigns/readelf
export TMP_DIR=~/campaigns/readelf
# One <file>:<line> per line, at most 16. The file name is matched by basename.
echo "readelf.c:7300" > $TMP_DIR/BBtargets.txt
```

**3. Extract the whole-program bitcode with [gllvm](https://github.com/SRI-CSL/gllvm).** Build with `-g`, so that target lines can be mapped to code.
```shell
cd /path/to/binutils
CC=gclang CXX=gclang++ CFLAGS="-g" ./configure && make
get-bc -o $TMP_DIR/target.bc binutils/readelf
```

**4. Run the static analysis:** call graph, functions containing the targets, their dominators, and call-site targets.
```shell
$IDFUZZ/idfuzz.sh analyze $TMP_DIR/target.bc
```

**5. Build the instrumented target with `afl-clang-fast`.** Pass your usual build command after `--`. The script sets `CC` and `CXX` and adds the required LTO flags to `CFLAGS` and `CXXFLAGS`. The build must include debug information (`-g`), or the instrumentation pass cannot find the targets.
```shell
cd /path/to/a/clean/copy/of/binutils
CFLAGS="-g" $IDFUZZ/idfuzz.sh instrument -- sh -c './configure && make'
```

**6. Merge the results** into an interprocedural dominator graph for each target (`dom_bits_depth.txt`).
```shell
$IDFUZZ/idfuzz.sh finalize
```

Steps 4–6 each delete the outputs they are about to regenerate, so results from an earlier build are never mixed in. They then check the results and warn, for example, when a target line was not found in the bitcode or did not get a key edge. A target without a key edge can still be approached, but IDFuzz cannot detect when it is reached. See [What idfuzz.sh runs](#what-idfuzzsh-runs) for the underlying commands.

**7. Run IDFuzz.** Run `fuzz.sh` from the directory containing the instrumented program, with `IDFUZZ` and `TMP_DIR` still set.
```shell
cd /path/to/a/clean/copy/of/binutils/binutils
$IDFUZZ/fuzz.sh readelf seeds out "" 10m "-a @@"
```

`fuzz.sh [PUT_NAME] [INPUT_DIR] [OUTPUT_DIR] [SHM_ID] [TIME] [ARGS]`:

| Parameter | Meaning | Default |
|---|---|---|
| `PUT_NAME` | Program under test, relative to the current directory | `objdump` |
| `INPUT_DIR` | Initial seed directory | `in` |
| `OUTPUT_DIR` | Fuzzer output directory | `out` |
| `SHM_ID` | Key of the shared memory between the fuzzer and the neural network. Pass `""` to use the default. | derived from the script's PID |
| `TIME` | Time to exploitation: gradient-guided mutation and network training start after this time (`s`, `m`, `h` or `d` suffix) | `10m` |
| `ARGS` | Arguments of the target program, with `@@` for the input file | `-SD @@` |

The script starts the fuzzer in the foreground and, 60 seconds later, the neural network in the background. Follow the network's progress with:
```shell
tail -f $TMP_DIR/nn.log
```

Concurrent campaigns must use different shared memory keys. The default key is different for every run. The fuzzer refuses a key that another live process is using, and replaces a segment left behind by a crashed run. If the neural network exits or stops answering, the fuzzer carries on with its normal mutations.

## Configuration

These environment variables are optional.

| Variable | Read by | Meaning | Default |
|---|---|---|---|
| `IDFUZZ_NN_TIMEOUT_MS` | `afl-fuzz` | How long the fuzzer waits for the network to answer a query before falling back to normal mutation | `5000` |
| `IDFUZZ_LR` | `nn-dom.py` | Learning rate | `1e-3` |
| `IDFUZZ_EPOCHS` | `nn-dom.py` | Maximum training epochs per retraining | `100` |
| `IDFUZZ_PATIENCE` | `nn-dom.py` | Stop training after this many epochs without validation improvement (`0` disables early stopping) | `5` |
| `IDFUZZ_QUALITY_GATE` | `nn-dom.py` | Discard a model that does not beat a constant predictor on held-out seeds; the fuzzer then uses normal mutation until the next retraining (`0` disables the check) | `1` |
| `OPT`, `PYTHON` | `idfuzz.sh` | `opt` and Python interpreter to use | `opt`, `python3` |

**Reproducing the paper:** the training defaults above differ from the prototype used in the paper. To reproduce its setting, run with:
```shell
export IDFUZZ_LR=1e-5 IDFUZZ_EPOCHS=5 IDFUZZ_PATIENCE=0 IDFUZZ_QUALITY_GATE=0
```

## Known Limitations

- **At most 16 targets** per campaign; see [Target Limit](#target-limit).
- **Targets in blocks with no successor get no key edge**, so IDFuzz cannot detect that they were reached. This applies to lines that call `abort()` or `exit()`, throw an exception, or sit in a function's final return block. `idfuzz.sh instrument` warns about such targets. Moving the target to the condition that leads there gives a key edge, but it is then counted as reached whenever that condition is evaluated.
- **Indirect calls** are not part of the call graph, so a target reachable only through a function pointer gets no interprocedural dominator chain.
- **Edge IDs change between builds.** The instrumented binary and `dom_bits_depth.txt` must come from the same build. Rebuild only with `idfuzz.sh instrument` followed by `idfuzz.sh finalize`.
- **Coverage map collisions.** Edge IDs are random within a 65,536-entry map. On very large targets some edges share an ID, which can make an ordinary edge look like a dominator edge.
- **Only the first 1024 bytes** of each input are used by the neural network.

## What idfuzz.sh runs

If you run the steps by hand, start each run with fresh output files. The analysis passes overwrite their outputs, but the instrumentation pass appends once per compiled file, so delete `DominatorsOfTargets.txt` and `ins.txt` from `$TMP_DIR` before every instrumented build.

`idfuzz.sh analyze` (step 4):
```shell
cd $TMP_DIR
opt -dot-callgraph -disable-output target.bc    # writes callgraph.dot
opt -load $IDFUZZ/llvm-pass-getFunctionName/build/getFunctionName/libgetFunctionName.so \
    -getFunctionName -disable-output target.bc          # writes FunctionsOfTargets.txt
python3 $IDFUZZ/py/parse_cg.py                          # writes DominatorsOfTargetFunctions.txt
opt -load $IDFUZZ/llvm-pass-getCSAdditionalTargets/build/getCSAdditionalTargets/libgetCSAdditionalTargets.so \
    -getCSAdditionalTargets -disable-output target.bc   # writes BBtargets-inter.txt
```

`idfuzz.sh instrument` (step 5):
```shell
rm -f $TMP_DIR/DominatorsOfTargets.txt $TMP_DIR/ins.txt
export CC=$IDFUZZ/afl-clang-fast
export CXX=$IDFUZZ/afl-clang-fast++
export CFLAGS="$CFLAGS -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
export CXXFLAGS="$CXXFLAGS -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
# then your build command; writes DominatorsOfTargets.txt
```

`idfuzz.sh finalize` (step 6):
```shell
cd $TMP_DIR
python3 $IDFUZZ/py/gen_dom_graph.py    # writes dom_bits_depth.txt
```

## Tips

The repository's `temp/` directory contains a complete set of intermediate files for a `readelf` target. Compare your `$TMP_DIR` with it to check that no file is missing and that the contents have the expected structure.

Static analysis can miss target locations or call-graph edges. For better directed fuzzing results, you can:
- examine vulnerability reports (for example ASan crash reports) for the exact crash location and call stack;
- add missing targets or call sites to the corresponding files by hand, following the structure of the files in `temp/`.

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

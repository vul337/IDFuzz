#!/bin/bash
# IDFuzz preparation driver: runs the static-analysis and post-build steps of
# the pipeline, clears stale outputs before each step, and checks the results.
#
#   ./idfuzz.sh analyze [target.bc]        steps 4-7 (call graph, target functions,
#                                          dominators, call-site targets)
#   ./idfuzz.sh instrument -- <build cmd>  step 8 (build the target with afl-clang-fast)
#   ./idfuzz.sh finalize                   step 9 (merge into dom_bits_depth.txt)
#
# Needs TMP_DIR (containing BBtargets.txt). IDFUZZ defaults to this script's
# directory; OPT and PYTHON default to "opt" and "python3".
set -euo pipefail

IDFUZZ=${IDFUZZ:-$(cd "$(dirname "$0")" && pwd)}
OPT=${OPT:-opt}
PYTHON=${PYTHON:-python3}
MAX_TARGETS=16 # gen_dom_graph.py packs per-target bits into 16-bit halves

die() { echo "[-] $*" >&2; exit 1; }
warn() { echo "[!] $*" >&2; WARNINGS=$((WARNINGS + 1)); }
ok() { echo "[+] $*"; }
WARNINGS=0

[ -n "${TMP_DIR:-}" ] || die "TMP_DIR is not set"
[ -d "$TMP_DIR" ] || die "TMP_DIR=$TMP_DIR is not a directory"
TMP_DIR=$(cd "$TMP_DIR" && pwd)
export TMP_DIR

# Targets as the analysis passes see them: basename:line.
read_targets() {
    local f=$TMP_DIR/BBtargets.txt n=0 lineno=0 line
    [ -s "$f" ] || die "$f is missing or empty; write one <file>:<line> target per line"
    TARGETS=()
    while IFS= read -r line || [ -n "$line" ]; do
        lineno=$((lineno + 1))
        line=${line%$'\r'}
        n=$((n + 1)) # gen_dom_graph.py gives every line a target index, even malformed ones
        if [[ ! "$line" =~ ^[^:]+:[0-9]+$ ]]; then
            warn "BBtargets.txt line $lineno is not <file>:<line> ('$line'); it is ignored but still uses a target slot"
            continue
        fi
        TARGETS+=("${line##*/}")
    done < "$f"
    [ "$n" -le "$MAX_TARGETS" ] || die "BBtargets.txt has $n lines; IDFuzz supports at most $MAX_TARGETS targets"
    [ "${#TARGETS[@]}" -gt 0 ] || die "BBtargets.txt has no valid targets"
}

summary() {
    if [ "$WARNINGS" -gt 0 ]; then
        echo "[!] $1 finished with $WARNINGS warning(s); see above"
    else
        ok "$1 finished"
    fi
}

# has_line_prefix FILE PREFIX: some line of FILE starts with PREFIX (literally).
has_line_prefix() {
    [ -f "$1" ] && awk -v p="$2" 'index($0, p) == 1 { found = 1; exit } END { exit !found }' "$1"
}

cmd_analyze() {
    local bc=${1:-$TMP_DIR/target.bc}
    [ -f "$bc" ] || die "bitcode $bc not found (extract it with gllvm's get-bc)"
    bc=$(cd "$(dirname "$bc")" && pwd)/$(basename "$bc")
    read_targets

    # Everything derived from the bitcode or from these files is now stale.
    rm -f "$TMP_DIR"/callgraph.dot "$TMP_DIR"/*.callgraph.dot \
          "$TMP_DIR"/FunctionsOfTargets.txt "$TMP_DIR"/DominatorsOfTargetFunctions.txt \
          "$TMP_DIR"/BBtargets-inter.txt "$TMP_DIR"/DominatorsOfTargets.txt \
          "$TMP_DIR"/ins.txt "$TMP_DIR"/dom_bits_depth.txt

    echo "[*] Step 4: call graph"
    (cd "$TMP_DIR" && "$OPT" -dot-callgraph -disable-output "$bc")
    # LLVM <= 13 writes callgraph.dot, newer versions <module>.callgraph.dot.
    if [ ! -f "$TMP_DIR/callgraph.dot" ]; then
        local dot
        dot=$(ls "$TMP_DIR"/*.callgraph.dot 2>/dev/null | head -1 || true)
        [ -n "$dot" ] || die "opt did not produce a call graph"
        mv "$dot" "$TMP_DIR/callgraph.dot"
    fi

    echo "[*] Step 5: functions containing the targets"
    "$OPT" -load "$IDFUZZ/llvm-pass-getFunctionName/build/getFunctionName/libgetFunctionName.so" \
        -getFunctionName -disable-output "$bc" 2>"$TMP_DIR/getFunctionName.log" \
        || die "getFunctionName failed; see $TMP_DIR/getFunctionName.log"
    local t
    for t in "${TARGETS[@]}"; do
        has_line_prefix "$TMP_DIR/FunctionsOfTargets.txt" "$t," \
            || warn "target $t was not found in the bitcode (built without -g? no code on that line?)"
    done

    echo "[*] Step 6: dominators of the target functions"
    (cd "$TMP_DIR" && "$PYTHON" "$IDFUZZ/py/parse_cg.py" > "$TMP_DIR/parse_cg.log") \
        || die "parse_cg.py failed; see $TMP_DIR/parse_cg.log"
    for t in "${TARGETS[@]}"; do
        if has_line_prefix "$TMP_DIR/FunctionsOfTargets.txt" "$t,"; then
            has_line_prefix "$TMP_DIR/DominatorsOfTargetFunctions.txt" "$t," \
                || warn "no call-graph dominator chain for target $t (indirect callee or dead code?)"
        fi
    done

    echo "[*] Step 7: call-site targets"
    "$OPT" -load "$IDFUZZ/llvm-pass-getCSAdditionalTargets/build/getCSAdditionalTargets/libgetCSAdditionalTargets.so" \
        -getCSAdditionalTargets -disable-output "$bc" 2>"$TMP_DIR/getCSAdditionalTargets.log" \
        || die "getCSAdditionalTargets failed; see $TMP_DIR/getCSAdditionalTargets.log"
    while IFS= read -r line; do
        warn "$line"
    done < <(grep "^warning:" "$TMP_DIR/getCSAdditionalTargets.log" || true)
    ok "$(wc -l < "$TMP_DIR/BBtargets-inter.txt") call-site target(s) in BBtargets-inter.txt"

    summary "analyze"
}

cmd_instrument() {
    [ "${1:-}" = "--" ] && shift
    [ $# -gt 0 ] || die "usage: $0 instrument -- <build command>"
    read_targets
    [ -f "$TMP_DIR/BBtargets-inter.txt" ] || warn "BBtargets-inter.txt is missing; run '$0 analyze' first"

    # The pass appends once per compiled file, so the files must start empty.
    rm -f "$TMP_DIR/DominatorsOfTargets.txt" "$TMP_DIR/ins.txt" "$TMP_DIR/dom_bits_depth.txt"

    local lto="-flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
    echo "[*] Step 8: building with afl-clang-fast: $*"
    CC="$IDFUZZ/afl-clang-fast" CXX="$IDFUZZ/afl-clang-fast++" \
        CFLAGS="${CFLAGS:+$CFLAGS }$lto" CXXFLAGS="${CXXFLAGS:+$CXXFLAGS }$lto" \
        "$@"

    [ -s "$TMP_DIR/DominatorsOfTargets.txt" ] \
        || die "the build wrote no DominatorsOfTargets.txt; was it compiled with afl-clang-fast?"
    local t
    for t in "${TARGETS[@]}"; do
        grep -qF "| Level: -1 | Target: $t |" "$TMP_DIR/DominatorsOfTargets.txt" \
            || warn "no key edge was instrumented for target $t"
    done
    summary "instrument"
}

cmd_finalize() {
    read_targets
    [ -s "$TMP_DIR/DominatorsOfTargets.txt" ] || die "DominatorsOfTargets.txt is missing; run '$0 instrument' first"
    rm -f "$TMP_DIR/dom_bits_depth.txt"

    echo "[*] Step 9: interprocedural dominator graph"
    (cd "$TMP_DIR" && "$PYTHON" "$IDFUZZ/py/gen_dom_graph.py" > "$TMP_DIR/gen_dom_graph.log") \
        || die "gen_dom_graph.py failed; see $TMP_DIR/gen_dom_graph.log"
    [ -s "$TMP_DIR/dom_bits_depth.txt" ] || die "dom_bits_depth.txt is empty; see $TMP_DIR/gen_dom_graph.log"

    # Key edges carry their target's bit (BBtargets.txt line order) in the high 16 bits.
    local idx=0 line
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}
        if [[ "$line" =~ ^[^:]+:[0-9]+$ ]]; then
            awk -F'[:,]' -v bit=$((1 << (idx + 16))) \
                'BEGIN { found = 0 } { if (int($3 / bit) % 2 == 1) found = 1 } END { exit !found }' \
                "$TMP_DIR/dom_bits_depth.txt" \
                || warn "target ${line##*/} has no key edge in dom_bits_depth.txt; it cannot be detected as reached"
        fi
        idx=$((idx + 1))
    done < "$TMP_DIR/BBtargets.txt"
    ok "$(wc -l < "$TMP_DIR/dom_bits_depth.txt") dominator edge(s) in dom_bits_depth.txt"
    summary "finalize"
}

case "${1:-}" in
    analyze) shift; cmd_analyze "$@" ;;
    instrument) shift; cmd_instrument "$@" ;;
    finalize) shift; cmd_finalize "$@" ;;
    *) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac

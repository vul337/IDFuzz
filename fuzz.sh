#!/bin/bash
set -e

PUT_NAME=${1:-"objdump"}
INPUT_DIR=${2:-"in"}
OUTPUT_DIR=${3:-"out"}
SHM_ID=${4:-5}
TIMEOUT=${5:-"5m"}
ARGS=${6:-"-SD @@"}
NN_LOG=$TMP_DIR/nn.log

cleanup() {
    echo -e "\nStopping all processes..."
    kill $FUZZER_PID $NN_PID 2>/dev/null || true
    exit 0
}
trap cleanup SIGINT SIGTERM

echo "Starting IDFuzz fuzzer..."
echo "Neural network will start in 60 seconds and log to: $NN_LOG"
echo "=========================================="
echo ""

$IDFUZZ/afl-fuzz -G -K $SHM_ID -d -m none -z exp -c $TIMEOUT \
    -i $INPUT_DIR -o $OUTPUT_DIR ./$PUT_NAME $ARGS &
FUZZER_PID=$!

(
    sleep 60
    echo ""
    echo "=========================================="
    echo "[$(date '+%H:%M:%S')] Starting Neural Network (log: $NN_LOG)"
    echo "=========================================="
    echo ""
    python3 $IDFUZZ/py/nn-dom.py $PUT_NAME $OUTPUT_DIR $SHM_ID > $NN_LOG 2>&1
) &
NN_PID=$!

wait $FUZZER_PID
cleanup

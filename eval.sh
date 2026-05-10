#!/usr/bin/env bash
# autoresearch evaluation script
#
# Agent runs:  ./eval.sh > run.log 2>&1
# Agent greps:
#   grep "^wall_ms:"     run.log   # server-side wall clock (ms) — PRIMARY metric, lower=better
#   grep "^client_ms:"   run.log   # client-side wall clock (ms) — secondary
#   grep "^success:"     run.log   # must be 100
#   grep "^eval_status:" run.log   # "ok" on success; reason string on failure

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT=8080
OUTPUT_DIR=""
SERVER_LOG=""
SERVER_PID=""

cleanup() {
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
    [[ -n "$SERVER_PID" ]] && wait "$SERVER_PID" 2>/dev/null || true
    [[ -n "$OUTPUT_DIR" && -d "$OUTPUT_DIR" ]] && rm -rf "$OUTPUT_DIR"
    [[ -n "$SERVER_LOG" && -f "$SERVER_LOG" ]] && rm -f "$SERVER_LOG"
    local stray
    stray=$(lsof -ti tcp:"$PORT" 2>/dev/null || true)
    [[ -n "$stray" ]] && kill "$stray" 2>/dev/null || true
}
trap cleanup EXIT

# ── Step 1: Build ─────────────────────────────────────────────────────────────
echo "=== [1/3] BUILD ==="
if ! "$SCRIPT_DIR/build.sh"; then
    echo "---"
    echo "eval_status: build_failed"
    exit 1
fi

# ── Step 2: Verify correctness ────────────────────────────────────────────────
echo ""
echo "=== [2/3] VERIFY ==="
if ! "$SCRIPT_DIR/verify_sm4.sh"; then
    echo "---"
    echo "eval_status: verify_failed"
    exit 2
fi

# ── Step 3: Benchmark ─────────────────────────────────────────────────────────
echo ""
echo "=== [3/3] BENCHMARK ==="

CSV_PATH="$SCRIPT_DIR/data/table_data.csv"
if [[ ! -f "$CSV_PATH" ]]; then
    echo "CSV not found: $CSV_PATH"
    echo "---"
    echo "eval_status: csv_missing"
    exit 3
fi

OUTPUT_DIR=$(mktemp -d /tmp/dcc_eval_XXXXXX)
SERVER_LOG=$(mktemp /tmp/dcc_server_XXXXXX.log)

# Kill any stray server on the port
stray=$(lsof -ti tcp:"$PORT" 2>/dev/null || true)
[[ -n "$stray" ]] && { kill "$stray" 2>/dev/null || true; sleep 0.3; }

# Start server, redirect its output to a temp log (captures [BATCH] stats)
DCC_CSV_PATH="$CSV_PATH" \
DCC_OUTPUT_DIR="$OUTPUT_DIR/" \
DCC_CALLBACK_URL=skip \
DCC_EXPECT_REQS=100 \
    "$SCRIPT_DIR/build/dcc_encrypt" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

# Wait for server to be ready
echo "Waiting for server on port $PORT ..."
ready=0
for i in $(seq 1 40); do
    if curl -sf "http://localhost:$PORT/health" >/dev/null 2>&1; then
        ready=1; break
    fi
    sleep 0.25
done

if [[ $ready -eq 0 ]]; then
    echo "Server failed to start. Server log:"
    cat "$SERVER_LOG"
    echo "---"
    echo "eval_status: server_failed"
    exit 4
fi
echo "Server ready."
echo ""

# Run benchmark — captures client-side wall-clock timing
bench_out=$(python3 "$SCRIPT_DIR/bench_encrypt.py" 2>&1)
echo "$bench_out"

# Wait for server [BATCH] line: printed only after all 100 jobs complete.
# Server responds 200 immediately then processes async, so [BATCH] may appear
# after bench_encrypt.py has already returned.
echo ""
echo "Waiting for [BATCH] summary from server ..."
batch_line=""
for i in $(seq 1 480); do  # up to 120 s
    batch_line=$(grep "^\[BATCH\]" "$SERVER_LOG" 2>/dev/null | tail -1 || true)
    [[ -n "$batch_line" ]] && break
    sleep 0.25
done

echo ""
echo "--- server log ---"
cat "$SERVER_LOG"
echo "--- end server log ---"

# ── Extract metrics ───────────────────────────────────────────────────────────

# server-side: [BATCH] 100/100 done  wall=114ms  | req ...
# Extract the integer after "wall=" and before "ms"
wall_ms=""
if [[ -n "$batch_line" ]]; then
    wall_ms=$(echo "$batch_line" | sed 's/.*wall=\([0-9]*\)ms.*/\1/')
fi

# client-side: "  整体耗时(ms) : 114.64"
client_ms=$(echo "$bench_out" | grep "整体耗时" | \
    sed 's/.*: *//' | tr -d '[:space:]')

# success / failure counts
success=$(echo "$bench_out" | grep "成功" | head -1 | \
    sed 's/.*: *//' | tr -d '[:space:]')
failed=$(echo "$bench_out" | grep "失败" | head -1 | \
    sed 's/.*: *//' | tr -d '[:space:]')

# ── Summary block (agent greps from run.log) ──────────────────────────────────
echo ""
echo "---"
echo "wall_ms:      ${wall_ms:-0}"
echo "client_ms:    ${client_ms:-0}"
echo "success:      ${success:-0}"
echo "failed:       ${failed:-0}"

if [[ -z "$wall_ms" ]]; then
    echo "eval_status:  no_batch_line"
    exit 5
elif [[ "${failed:-1}" != "0" ]]; then
    echo "eval_status:  partial_failure"
    exit 6
else
    echo "eval_status:  ok"
fi

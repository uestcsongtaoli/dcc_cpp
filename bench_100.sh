#!/usr/bin/env bash
# 100-concurrent-request benchmark.
# Restarts the server with DCC_EXPECT_REQS=100 so it prints batch wall-clock
# stats on completion, then runs bench_encrypt.py.
#
# Usage:
#   ./bench_100.sh [options]
#
# Options:
#   --csv    PATH   Input CSV  (default: ./table_data.csv)
#   --out    DIR    Output dir (default: /tmp/dcc_bench/)
#   --no-restart    Skip server restart (use already-running server)
#   --debug         Enable DCC_DEBUG=1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CSV_PATH="${DCC_CSV_PATH:-$SCRIPT_DIR/data/table_data.csv}"
OUTPUT_DIR="${DCC_OUTPUT_DIR:-/tmp/dcc_bench/}"
RESTART=1
DEBUG="${DCC_DEBUG:-0}"
PORT=8080

while [[ $# -gt 0 ]]; do
    case "$1" in
        --csv)         CSV_PATH="$2"; shift 2 ;;
        --out)         OUTPUT_DIR="$2"; shift 2 ;;
        --no-restart)  RESTART=0; shift ;;
        --debug)       DEBUG=1; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Check Python + aiohttp
if ! python3 -c "import aiohttp" 2>/dev/null; then
    echo "aiohttp not found. Install: pip3 install aiohttp"
    exit 1
fi

if [[ $RESTART -eq 1 ]]; then
    DCC_CSV_PATH="$CSV_PATH" \
    DCC_OUTPUT_DIR="$OUTPUT_DIR" \
    DCC_EXPECT_REQS=100 \
    DCC_DEBUG="$DEBUG" \
        "$SCRIPT_DIR/run_server.sh" --csv "$CSV_PATH" --out "$OUTPUT_DIR" --reqs 100
else
    # Verify server is up
    if ! curl -sf "http://localhost:$PORT/health" >/dev/null 2>&1; then
        echo "Server is not running on port $PORT. Start with ./run_server.sh or omit --no-restart."
        exit 1
    fi
    echo "Using existing server on port $PORT."
fi

echo ""
echo "Running bench_encrypt.py (100 concurrent requests) ..."
echo "────────────────────────────────────────────────────────"
python3 "$SCRIPT_DIR/bench_encrypt.py"

#!/usr/bin/env bash
# Start dcc_encrypt in the background.
#
# Usage:
#   ./run_server.sh [options]
#
# Options:
#   --csv     PATH   Input CSV path   (default: ./table_data.csv)
#   --out     DIR    Output directory  (default: /tmp/dcc_out/)
#   --port    PORT   Listen port       (default: 8080, informational only — binary uses 8080 always)
#   --reqs    N      DCC_EXPECT_REQS   (default: 100; set to 0 to disable batch stats)
#   --debug          Enable DCC_DEBUG=1 verbose logging
#   --fg             Run in foreground (don't detach)
#
# Env overrides (take precedence over flags):
#   DCC_CSV_PATH, DCC_OUTPUT_DIR, DCC_CALLBACK_URL, DCC_TEAM_CODE, DCC_EXPECT_REQS, DCC_DEBUG

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/.server.pid"
BINARY="$SCRIPT_DIR/build/dcc_encrypt"

CSV_PATH="${DCC_CSV_PATH:-$SCRIPT_DIR/data/table_data.csv}"
OUTPUT_DIR="${DCC_OUTPUT_DIR:-/tmp/dcc_out/}"
CALLBACK_URL="${DCC_CALLBACK_URL:-skip}"
TEAM_CODE="${DCC_TEAM_CODE:-}"
EXPECT_REQS="${DCC_EXPECT_REQS:-100}"
DEBUG="${DCC_DEBUG:-0}"
PORT=8080
FOREGROUND=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --csv)   CSV_PATH="$2";    shift 2 ;;
        --out)   OUTPUT_DIR="$2";  shift 2 ;;
        --port)  PORT="$2";        shift 2 ;;
        --reqs)  EXPECT_REQS="$2"; shift 2 ;;
        --debug) DEBUG=1;          shift   ;;
        --fg)    FOREGROUND=1;     shift   ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ ! -x "$BINARY" ]]; then
    echo "Binary not found: $BINARY"
    echo "Run ./build.sh first."
    exit 1
fi
if [[ ! -f "$CSV_PATH" ]]; then
    echo "CSV not found: $CSV_PATH"
    exit 1
fi

# Kill any existing instance on port $PORT
existing=$(lsof -ti tcp:"$PORT" 2>/dev/null || true)
if [[ -n "$existing" ]]; then
    echo "Stopping existing process on port $PORT (pid $existing) ..."
    kill "$existing" 2>/dev/null || true
    sleep 0.5
fi

mkdir -p "$OUTPUT_DIR"

echo "Starting dcc_encrypt ..."
echo "  CSV:      $CSV_PATH"
echo "  Output:   $OUTPUT_DIR"
echo "  Callback: $CALLBACK_URL"
echo "  Expect:   $EXPECT_REQS requests"
echo "  Debug:    $DEBUG"

export DCC_CSV_PATH="$CSV_PATH"
export DCC_OUTPUT_DIR="$OUTPUT_DIR"
export DCC_CALLBACK_URL="$CALLBACK_URL"
export DCC_EXPECT_REQS="$EXPECT_REQS"
export DCC_DEBUG="$DEBUG"
[[ -n "$TEAM_CODE" ]] && export DCC_TEAM_CODE="$TEAM_CODE"

if [[ $FOREGROUND -eq 1 ]]; then
    exec "$BINARY"
fi

LOG_FILE="$SCRIPT_DIR/server.log"
"$BINARY" >"$LOG_FILE" 2>&1 &
SERVER_PID=$!
echo "$SERVER_PID" > "$PID_FILE"
echo "  PID:      $SERVER_PID  (saved to .server.pid)"
echo "  Log:      $LOG_FILE"

# Wait for server to be ready
echo -n "Waiting for port $PORT ..."
for i in $(seq 1 40); do
    if curl -sf "http://localhost:$PORT/health" >/dev/null 2>&1; then
        echo " ready."
        exit 0
    fi
    echo -n "."
    sleep 0.25
done
echo ""
echo "Server did not become ready. Check server.log for details."
exit 1

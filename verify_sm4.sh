#!/usr/bin/env bash
# SM4 correctness verification script
# Tests that the server's SM4-CBC output matches known-good reference data.
#
# Usage:
#   ./verify_sm4.sh [options]
#
# Options:
#   --binary PATH    Path to dcc_encrypt binary (default: ./build/dcc_encrypt)
#   --input  PATH    Input CSV path           (default: ./data/test_input.csv)
#   --expected DIR   Expected outputs dir     (default: ./data/expected)
#   --port   PORT    Server port              (default: 8081)
#   --keep           Keep server running after test

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
BINARY="${BINARY:-./build/dcc_encrypt}"
INPUT_CSV="${INPUT_CSV:-./data/test_input.csv}"
EXPECTED_DIR="${EXPECTED_DIR:-./data/expected}"
PORT="${PORT:-8081}"
KEEP_SERVER=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)   BINARY="$2";       shift 2 ;;
        --input)    INPUT_CSV="$2";    shift 2 ;;
        --expected) EXPECTED_DIR="$2"; shift 2 ;;
        --port)     PORT="$2";         shift 2 ;;
        --keep)     KEEP_SERVER=1;     shift   ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
info() { echo -e "${YELLOW}[INFO]${NC} $*"; }

# ── Test cases ────────────────────────────────────────────────────────────────
# Each entry: "REQUEST_ID|SM4_KEY|FIELDS_JSON_ARRAY"
# Add more rows here to extend the test suite.
declare -a TESTS=(
    "REQ_001|8656ae6acdb820f3|[\"trans_id\",\"secret_code\"]"
)

# ── Validate prerequisites ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$(cd "$SCRIPT_DIR" && realpath "$BINARY" 2>/dev/null || echo "$BINARY")"
INPUT_CSV="$(cd "$SCRIPT_DIR" && realpath "$INPUT_CSV" 2>/dev/null || echo "$INPUT_CSV")"
EXPECTED_DIR="$(cd "$SCRIPT_DIR" && realpath "$EXPECTED_DIR" 2>/dev/null || echo "$EXPECTED_DIR")"

if [[ ! -x "$BINARY" ]]; then
    echo "Binary not found or not executable: $BINARY"
    echo "Build first: cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j4"
    exit 1
fi
if [[ ! -f "$INPUT_CSV" ]]; then
    echo "Input CSV not found: $INPUT_CSV"
    exit 1
fi
if [[ ! -d "$EXPECTED_DIR" ]]; then
    echo "Expected outputs directory not found: $EXPECTED_DIR"
    exit 1
fi

# ── Output directory (temp) ───────────────────────────────────────────────────
OUTPUT_DIR="$(mktemp -d /tmp/dcc_verify_XXXXXX)"
SERVER_PID=""

cleanup() {
    if [[ -n "$SERVER_PID" && "$KEEP_SERVER" -eq 0 ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$OUTPUT_DIR"
}
trap cleanup EXIT

# ── Kill any existing server on this port ─────────────────────────────────────
existing_pid=$(lsof -ti tcp:"$PORT" 2>/dev/null || true)
if [[ -n "$existing_pid" ]]; then
    info "Stopping existing process on port $PORT (pid $existing_pid)"
    kill "$existing_pid" 2>/dev/null || true
    sleep 0.5
fi

# ── Start the server ──────────────────────────────────────────────────────────
info "Starting server: $BINARY"
info "  CSV:    $INPUT_CSV"
info "  Output: $OUTPUT_DIR"

DCC_CSV_PATH="$INPUT_CSV" \
DCC_OUTPUT_DIR="$OUTPUT_DIR/" \
DCC_CALLBACK_URL=skip \
    "$BINARY" &
SERVER_PID=$!

# Wait for server to be ready (health check, up to 10 s)
info "Waiting for server on port $PORT ..."
ready=0
for i in $(seq 1 40); do
    if curl -sf "http://localhost:$PORT/health" >/dev/null 2>&1; then
        ready=1; break
    fi
    sleep 0.25
done
if [[ $ready -eq 0 ]]; then
    fail "Server did not become ready within 10 seconds"
    exit 1
fi
info "Server ready."

# ── Run test cases ────────────────────────────────────────────────────────────
PASS=0; FAIL=0

for test_entry in "${TESTS[@]}"; do
    IFS='|' read -r req_id sm4_key fields_json <<< "$test_entry"

    expected_file="$EXPECTED_DIR/$req_id.csv"
    if [[ ! -f "$expected_file" ]]; then
        fail "[$req_id] Expected output not found: $expected_file"
        (( FAIL++ )) || true
        continue
    fi

    info "Running [$req_id]  key=$sm4_key  fields=$fields_json"

    payload="{\"requestId\":\"$req_id\",\"sm4Key\":\"$sm4_key\",\"ip\":\"127.0.0.1\",\"fieldsToEncrypt\":$fields_json}"

    http_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "http://localhost:$PORT/encrypt" \
        -H "Content-Type: application/json" \
        -d "$payload")

    if [[ "$http_status" != "200" ]]; then
        fail "[$req_id] HTTP $http_status (expected 200)"
        (( FAIL++ )) || true
        continue
    fi

    # Wait for output file (server processes asynchronously, up to 30 s)
    out_file="$OUTPUT_DIR/$req_id.csv"
    found=0
    for i in $(seq 1 120); do
        if [[ -f "$out_file" ]]; then
            found=1; break
        fi
        sleep 0.25
    done

    if [[ $found -eq 0 ]]; then
        fail "[$req_id] Output file not produced: $out_file"
        (( FAIL++ )) || true
        continue
    fi

    if diff -q "$expected_file" "$out_file" >/dev/null 2>&1; then
        ok "[$req_id] Output matches expected."
        (( PASS++ )) || true
    else
        fail "[$req_id] Output differs from expected."
        echo "  Expected: $expected_file"
        echo "  Got:      $out_file"
        diff "$expected_file" "$out_file" | head -20
        (( FAIL++ )) || true
    fi
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────"
echo -e "Results: ${GREEN}${PASS} passed${NC}  ${RED}${FAIL} failed${NC}  (total $((PASS + FAIL)))"
echo "────────────────────────────────────────"

[[ $FAIL -eq 0 ]]

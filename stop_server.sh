#!/usr/bin/env bash
# Stop the background dcc_encrypt server.
# Uses .server.pid if available, otherwise falls back to lsof on port 8080.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/.server.pid"
PORT=8080

stopped=0

if [[ -f "$PID_FILE" ]]; then
    pid=$(cat "$PID_FILE")
    if kill -0 "$pid" 2>/dev/null; then
        echo "Stopping dcc_encrypt (pid $pid) ..."
        kill "$pid"
        wait "$pid" 2>/dev/null || true
        stopped=1
    fi
    rm -f "$PID_FILE"
fi

# Fallback: any remaining process on port
remaining=$(lsof -ti tcp:"$PORT" 2>/dev/null || true)
if [[ -n "$remaining" ]]; then
    echo "Stopping remaining process on port $PORT (pid $remaining) ..."
    kill "$remaining" 2>/dev/null || true
    stopped=1
fi

if [[ $stopped -eq 1 ]]; then
    echo "Server stopped."
else
    echo "No running server found."
fi

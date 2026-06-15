#!/usr/bin/env bash
set -euo pipefail
mkdir -p logs
./server --host 0.0.0.0 --port 9000 --mode weak --log logs/server.log &
PID=$!; sleep 1
./client --host 127.0.0.1 --port 9000 --mode weak --message "Hello Diffie-Hellman AES-GCM"
sleep 1; kill $PID 2>/dev/null || true
cat logs/server.log

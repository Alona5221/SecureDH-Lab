#!/usr/bin/env bash
set -euo pipefail
mkdir -p logs
./server --host 0.0.0.0 --port 9000 --mode weak --log logs/server.log & SPID=$!
sleep 1
./mitm --listen-port 9001 --target-host 127.0.0.1 --target-port 9000 --mode attack --log logs/mitm.log & MPID=$!
sleep 1
./client --host 127.0.0.1 --port 9001 --mode weak --message "My secret data"
sleep 1; kill $SPID $MPID 2>/dev/null || true
echo '--- mitm ---'; cat logs/mitm.log; echo '--- server ---'; cat logs/server.log

#!/usr/bin/env bash
set -euo pipefail
mkdir -p logs
rm -f logs/*.log psk.bin
./keygen --psk-file psk.bin --bytes 32
./server --host 0.0.0.0 --port 9000 --mode secure --psk-file psk.bin --rekey-msg 3 --log logs/server.log &
SPID=$!
sleep 1
./client --host 127.0.0.1 --port 9000 --mode secure --psk-file psk.bin --message "rekey demo" --repeat 8 --interval 300 --rekey-msg 3
sleep 1
kill $SPID 2>/dev/null || true
cat logs/server.log

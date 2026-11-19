#!/usr/bin/env bash
# Reproduce the numbers in docs/BENCHMARKS.md on your own machine.
# Sender and receiver run as separate processes over loopback TCP, like two devices.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release -q
G=./target/release/glide
W=$(mktemp -d); trap 'rm -rf "$W"; kill $(jobs -p) 2>/dev/null || true' EXIT
MB=${MB:-1024}

send() { # send <path> <listen> [extra args] ; waits until listening
  local log="$W/send.$RANDOM"; "$G" send "$1" --listen "$2" --key bench "${@:3}" 2>"$log" & 
  for _ in $(seq 200); do grep -q listening "$log" && break; sleep 0.05; done; }
recv() { "$G" recv --connect "$1" --key bench --out "$2" "${@:3}" 2>&1 | tr '\r' '\n' | grep -v '%' | sed '/^$/d'; }

echo "== machine"; "$G" bench
echo; echo "== 1 stream, ${MB} MB random data"
python3 -c "import os; open('$W/big.bin','wb').write(os.urandom($MB*1000000))"
send "$W/big.bin" 127.0.0.1:7901; recv 127.0.0.1:7901 "$W/o1"; cmp "$W/big.bin" "$W/o1/big.bin" && echo "  identical"
echo; echo "== 2 streams, shaped to 60 + 25 MB/s"
send "$W/big.bin" 127.0.0.1:7902,127.0.0.1:7903 --limit-mbs 60,25; recv 127.0.0.1:7902,127.0.0.1:7903 "$W/o2"
echo; echo "== same, stream 0 dies after 150 MB"
send "$W/big.bin" 127.0.0.1:7904,127.0.0.1:7905 --limit-mbs 60,25 --kill-after-mb 150,0; recv 127.0.0.1:7904,127.0.0.1:7905 "$W/o3"; cmp "$W/big.bin" "$W/o3/big.bin" && echo "  identical"
echo; echo "== delta: receiver has v1, v2 has 1 MB inserted at the start, 100 KB changed, 2 MB appended"
python3 - "$W" <<'PY'
import os, sys; w=sys.argv[1]; d=open(w+'/big.bin','rb').read(); m=len(d)//2
os.makedirs(w+'/v2', exist_ok=True); os.makedirs(w+'/o4', exist_ok=True)
open(w+'/v2/big.bin','wb').write(os.urandom(1_000_000)+d[:m]+os.urandom(100_000)+d[m+100_000:]+os.urandom(2_000_000))
open(w+'/o4/big.bin','wb').write(d)
PY
send "$W/v2/big.bin" 127.0.0.1:7906; recv 127.0.0.1:7906 "$W/o4"; cmp "$W/v2/big.bin" "$W/o4/big.bin" && echo "  identical"
echo; echo "== folder with the same 100 MB clip three times"
mkdir -p "$W/dup/a" "$W/dup/b"; head -c 100000000 "$W/big.bin" > "$W/dup/a/clip.mp4"; cp "$W/dup/a/clip.mp4" "$W/dup/b/copy.mp4"; cp "$W/dup/a/clip.mp4" "$W/dup/b/again.mp4"
send "$W/dup" 127.0.0.1:7907; recv 127.0.0.1:7907 "$W/o5"

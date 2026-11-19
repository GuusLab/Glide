# Benchmarks

Everything here is reproducible with one command:

```console
MB=1024 scripts/bench.sh
```

## Setup

- 2 vCPU cloud VM (x86_64, AES-NI, AVX2), Linux, Rust stable, release build with thin LTO
- Sender and receiver are separate processes on the same VM, connected over loopback TCP.
  They share the same two cores, so every end-to-end number is a floor.
- Throttled runs use the `--limit-mbs` test option, which shapes the sender's outgoing bytes.
- Random data, so compression never helps. Files are compared byte for byte after each run.

## Results (19 November 2026)

### Core, per CPU core

`glide bench`: seal (send) and open + BLAKE3 verify (receive) of 256 KiB blocks in memory.

| Suite | Send, 1 core | Send, all cores | Receive, 1 core | Receive, all cores |
| --- | --- | --- | --- | --- |
| AES-256-GCM | 1,089 MB/s | 1,987 MB/s | 919 MB/s | 1,702 MB/s |
| ChaCha20-Poly1305 | 955 MB/s | 1,679 MB/s | 714 MB/s | 1,408 MB/s |

In the browser (WebAssembly, V8, ChaCha20, one core): 136 MB/s for seal + open + BLAKE3 together.

### End to end

| Scenario | Data | Time | Throughput | Notes |
| --- | --- | --- | --- | --- |
| 1 stream | 1,024 MB | 2.38 s | 431 MB/s | identical; 548 to 619 MB/s on 512 MB runs |
| 2 streams, shaped 60 + 25 MB/s | 1,024 MB | 12.40 s | 82.6 MB/s | 97% of the ideal 85 MB/s; split 722 / 302 MB |
| Same, stream 0 killed at 150 MB | 1,024 MB | 35.01 s | 29.2 MB/s | stream 1 finished the job; identical |
| Delta: receiver has v1; v2 = 1 MB inserted at the start, 100 KB changed, 2 MB appended | 1,027 MB | 2.46 s | | 14.1 MB over the wire, 1,012.9 MB reused |
| Folder with the same 100 MB clip three times | 300 MB | 0.30 s | | 100 MB over the wire, 200 MB deduplicated |

### Reading these numbers

The protocol's ceiling on one core is above what Wi-Fi 6 or a typical USB connection delivers, so
on real devices the pipe sets the speed. Indexing (chunking + hashing) ran at about 1.4 GB/s on
this VM and runs on all cores.

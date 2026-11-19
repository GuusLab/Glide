// Smoke test for the WebAssembly core: seal a block, open it, catch a tampered byte, measure speed.
// node crates/glide-wasm/js/test.mjs   (after: cargo build --release --target wasm32-unknown-unknown)
import { readFileSync } from 'node:fs';
const url = new URL('../target/wasm32-unknown-unknown/release/glide_wasm.wasm', import.meta.url);
const { instance } = await WebAssembly.instantiate(readFileSync(url), {});
const g = instance.exports, mem = () => new Uint8Array(g.memory.buffer);
const hh = new TextEncoder().encode('handshake-hash');
let p = g.g_alloc(hh.length); mem().set(hh, p); g.g_key(2, p, hh.length); // 2 = ChaCha20-Poly1305
const N = 262144, buf = g.g_alloc(N + 16), out = g.g_alloc(32);
for (let i = 0; i < N; i++) mem()[buf + i] = (i * 31) % 251;
const plain = mem().slice(buf, buf + N);
const len = g.g_seal(7, 0, buf, N);
console.log('open after seal:', g.g_open(7, 0, N, buf, len) === N && mem().slice(buf, buf + N).every((v, i) => v === plain[i]));
g.g_seal(7, 0, buf, N); mem()[buf + 9] ^= 1;
console.log('tampered block refused:', g.g_open(7, 0, N, buf, len) === -1);
const t = performance.now(), rounds = 256;
for (let i = 0; i < rounds; i++) { const l = g.g_seal(i, 0, buf, N); g.g_open(i, 0, N, buf, l); g.g_hash(buf, N, out); }
console.log(`seal + open + BLAKE3: ${(rounds * N / 1e6 / ((performance.now() - t) / 1000)).toFixed(0)} MB/s on one core`);

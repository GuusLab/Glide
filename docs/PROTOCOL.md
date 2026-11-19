# Glide wire protocol, v0.3

Glide moves a set of files from a sender to a receiver over one or more reliable, ordered byte
streams. Each stream is independent: it can join late or drop at any time. This document is the
whole protocol.

Status: draft. Not yet audited. Breaking changes are possible before 1.0.

## 1. Keys

Both sides know a short secret out of band: the secret inside an on-screen code, or a PIN.

```
psk = BLAKE3.derive_key("nemi glide 2026 psk v1", secret)       // 32 bytes
```

## 2. Handshake (per stream)

`Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s`, receiver is the initiator.

Each handshake message is sent as `u16 length (big endian) || message`. Two messages, one each way.
A wrong PSK makes the responder fail on the first message; no data is ever sent.

After the handshake both sides take the Noise handshake hash `h` and derive the bulk key:

```
data_key = BLAKE3.derive_key("nemi glide 2026 data s2r", h)     // sender to receiver
```

The Noise transport state keeps encrypting control messages in both directions.

## 3. Frames

Every frame starts with a 16-byte header:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 1 | type: 1 = control, 2 = data |
| 1 | 1 | flags (data): bit 0 = zstd |
| 2 | 2 | reserved, zero |
| 4 | 4 | block id (data), big endian |
| 8 | 4 | plaintext length (data) |
| 12 | 4 | payload length |

**Control payload**: a sequence of `u16 length || Noise ciphertext`, each piece at most 65,000
plaintext bytes. The concatenated plaintext is one bincode-encoded message (section 4).

**Data payload**: the sealed block. AEAD over the (possibly compressed) block, 16-byte tag appended.

```
nonce = "GD" || 0x000000000000 || block_id (u32 big endian)     // 12 bytes
aad   = header bytes 0..12 with the payload length field excluded
```

The nonce is deterministic per block. Sending the same block again produces the same ciphertext,
which reveals nothing new. Suite: AES-256-GCM if both sides announced hardware AES, else
ChaCha20-Poly1305.

## 4. Messages

| Message | Direction | Content |
| --- | --- | --- |
| `Hello { want_manifest, hw_aes }` | R to S | first message on every stream |
| `Accept { suite }` | S to R | 1 = AES-256-GCM, 2 = ChaCha20-Poly1305 |
| `Manifest(..)` | S to R | only when `want_manifest` |
| `Request { ids: [u32] }` | R to S | blocks to send on this stream |
| `Done` | R to S | everything verified; the stream closes |

## 5. Manifest

```
Manifest {
  session:   [u8; 16],      // BLAKE3(bincode(files, chunks))[0..16]
  files:     [FileEntry { path, size, first, count }],
  chunks:    [Occ { file, off, len, block }],   // every occurrence, in file order
  blocks:    [[u8; 32]],    // unique BLAKE3 hashes; index = block id
  block_len: [u32],
  total:     u64,
}
```

Paths use `/` and are relative to the sent folder.

## 6. Chunking

1. Files over 64 MiB are split into segments at content-defined anchors. From each nominal offset
   `k * 64 MiB`, scan forward (at most 8 MiB) with the rolling hash
   `h = (h << 1) + GEAR[byte]` and cut after the first position (at least 64 bytes in) where
   `h >> 44 == 0`. `GEAR` is 256 values of splitmix64 seeded with `0x9E3779B97F4A7C15`.
2. Each segment is cut with FastCDC (2020), normalization level 1: min 64 KiB, average 256 KiB,
   max 1 MiB.
3. Every block is hashed with BLAKE3. Identical hashes share one block id.

Because both cut rules follow the content, an insertion or edit only changes the blocks around it.

## 7. Transfer

- The receiver opens stream 0 with `want_manifest = true`, the others with `false`.
- Before requesting anything it looks for wanted blocks in existing files: an older file at the
  same path (moved aside to `.glide-old-<name>`) and any seed folders. Matching blocks, verified by
  hash, are written locally.
- Each stream keeps up to 32 blocks requested and not yet received. When a block arrives, the
  stream requests the next one from a shared pool. Faster streams therefore carry more.
- Order: small files first by default, or file order front to back (sequential).
- Endgame: when the pool is empty, a stream may request a block that one other stream still has in
  flight. The first copy wins; the duplicate is dropped.
- A block is written only after the AEAD opens it, zstd (if flagged) expands it to exactly
  `plaintext length`, and its BLAKE3 hash matches `blocks[id]`. It is written to every occurrence.
- If a stream fails, its in-flight blocks return to the pool.

## 8. Resume

The receiver keeps `.glide-<session hex>` in the output folder: one bit per block id, little end
first, written every 64 verified blocks. A new receive with the same manifest loads it and skips
those blocks. The file is removed when the transfer completes.

## 9. Not in v0.3

RaptorQ symbols for one-way or lossy pipes, a receiver-to-sender direction for data, and
versioning negotiation. A `version` field arrives with the first breaking change.

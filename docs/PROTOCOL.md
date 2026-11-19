# Glide wire protocol, v0.4

Glide moves a set of files from a sender to a receiver over one or more reliable, ordered byte
streams. Each stream is independent: it can join late or drop at any time. This document is the
whole protocol.

Status: draft. Not yet audited. Breaking changes are possible before 1.0.

## 1. Keys

Both sides know a short secret out of band: the secret inside an on-screen code, or a PIN.

```
password = BLAKE3.derive_key("nemi glide 2026 psk v1", secret)  // 32 bytes
```

The password is never used as a key. It may be as weak as six digits, so it only ever goes into
a password-authenticated key exchange (section 2).

## 2. Handshake (per stream)

Every handshake message is sent as `u16 length (big endian) || message`. The receiver is side A
and the Noise initiator; the sender is side B and the responder.

**Step 1, SPAKE2** (Ed25519 group, identities `"glide receiver"` and `"glide sender"`). Each side
sends its 33-byte SPAKE2 message and reads the other's; neither waits for the other first.

```
k   = SPAKE2.finish(their message)                              // 32 bytes
psk = BLAKE3.derive_key("nemi glide 2026 psk v2", k)
```

**Step 2, `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s`** with that `psk` and the prologue `glide/0.4`.
Two messages, one each way. The first one is the key confirmation: a responder whose secret
differs derived a different `psk` and cannot read it, so it closes the stream and no data is ever
sent. The prologue binds the protocol version, so two versions fail here rather than later.

Why two steps: a PIN used directly as the Noise pre-shared key can be found offline from one
recorded handshake, by trying every PIN against the tag of the first message. SPAKE2 exposes
nothing a guess can be tested against. What is left is one online guess per connection, which the
sender counts: a listener should stop after a small number of failed handshakes (the command line
tool stops at 20).

Every failure in either step is reported as the same error, and a side that receives nothing
gives up after 20 seconds.

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
nonce = "GD" || flags || 0x0000000000 || block_id (u32 big endian)   // 12 bytes
aad   = header bytes 0..12 with the payload length field excluded
```

The nonce is deterministic per block and per form. Sending the same block again in the same form
produces the same ciphertext, which reveals nothing new. The flags are in the nonce because the
sender may send one block compressed and, when it is asked again, raw: two plaintexts that must
never meet under one nonce. Suite: AES-256-GCM if both sides announced hardware AES, else
ChaCha20-Poly1305. A suite value or a flag bit the receiver does not know is an error, never a
default.

Limits a reader enforces before it trusts anything: a data payload is 16 to `1 MiB + 16` bytes and
its plaintext length at most 1 MiB; a control payload is at most 1 GiB and is decrypted piece by
piece as it arrives, so a forged length never becomes an allocation.

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
  session:   [u8; 16],      // see below
  files:     [FileEntry { path, size, first, count }],
  chunks:    [Occ { file, off, len, block }],   // every occurrence, in file order
  blocks:    [[u8; 32]],    // unique BLAKE3 hashes; index = block id
  block_len: [u32],
  total:     u64,
}
```

```
session = BLAKE3.derive_key("nemi glide 2026 session v2",
                            bincode(files, chunks, blocks, block_len))[0..16]
```

The session id covers the hashes as well as the layout, so a file whose content changed never
shares resume state with its earlier version.

Paths use `/` and are relative to the sent folder. The sender does not follow symbolic links.

**The receiver trusts none of it.** Before it creates a single file it checks that:

- `session` equals the value it computes itself;
- `blocks` and `block_len` have the same length, and every block length is 1 to 1 MiB;
- every path is relative, non-empty and at most 4096 bytes, with no empty, `.` or `..` component,
  no backslash, no control character, and no component starting with `.glide-`; on Windows also no
  reserved device name, no `<>:"|?*`, and no trailing dot or space;
- no path appears twice;
- each file's chunks are the next `count` entries of `chunks`, belong to that file, start at
  offset 0, follow each other without gap or overlap, each have the length of the block they name,
  and add up to exactly `size`;
- every chunk is used, and `total` is the sum of the sizes.

When it creates the files it follows no symbolic link: every folder on the way must be a real
folder and the file itself a regular file or absent.

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
- A block that fails this three times ends the transfer.
- The sender refuses a receiver with more than 64 blocks requested and not yet sent on a stream.
- If a stream fails, its in-flight blocks return to the pool.

## 8. Resume

The receiver keeps `.glide-<session hex>` in the output folder: one bit per block id, little end
first, written every 64 verified blocks. A new receive with the same manifest loads it and skips
those blocks. The file is removed when the transfer completes.

The state is a hint, not a fact. Before it is believed, every block it marks as present is read
back from the output files and hashed, in every place it occurs; a block that is not there in full
is fetched again.

## 9. Not in v0.4

RaptorQ symbols for one-way or lossy pipes, a receiver-to-sender direction for data, and
version negotiation. The version is fixed by the Noise prologue: v0.4 does not interoperate with
v0.3.

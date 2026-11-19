//! # Glide
//!
//! A fast, transport-agnostic file transfer protocol. Give it any reliable byte streams
//! (TCP, Wi-Fi Aware, Multipeer, Wi-Fi Direct, USB, WebRTC) and it moves files over all of
//! them at once, encrypted, verified block by block, resumable, and sending only what the
//! receiver does not already have.
//!
//! ```no_run
//! # async fn demo(a: tokio::net::TcpStream, b: tokio::net::TcpStream) -> anyhow::Result<()> {
//! let key = glide::Key::from_secret("482913");           // the code on screen, or a PIN
//! // sender
//! let sender = glide::Sender::new("holiday-photos/")?;
//! let k = key.clone();
//! tokio::spawn(async move { sender.serve(a, &k).await });
//! // receiver, over as many streams as you have
//! let report = glide::receive(vec![b], &key, "inbox/", Default::default()).await?;
//! # Ok(()) }
//! ```
//!
//! Wire: SPAKE2 on the shared secret, then a Noise NNpsk0 handshake keyed with its result, per
//! stream, then 16-byte framed messages. Control frames are Noise-encrypted; data blocks are
//! sealed with AES-256-GCM (both sides have hardware AES) or ChaCha20-Poly1305, keyed from the
//! handshake hash. Files are cut with FastCDC (64 KiB to
//! 1 MiB, 256 KiB average) and every unique block is BLAKE3-addressed. The receiver pulls:
//! each stream keeps 32 blocks in flight, so faster streams simply ask more often.

#![forbid(unsafe_code)]

use anyhow::{anyhow, bail, Result};
use glide_core::*;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use zeroize::Zeroize;

pub use glide_core;

const NOISE: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
/// The protocol version, bound into every handshake as the Noise prologue. Two sides that disagree
/// about it fail the handshake cleanly instead of misreading each other's frames.
const PROLOGUE: &[u8] = b"glide/0.4";
/// A peer that connects and then says nothing is dropped after this long, so a listener cannot be
/// held open by connections that never finish the handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
/// Upper bound on one control message (the manifest is the only large one). The bytes are
/// decrypted piece by piece as they arrive, so memory only ever grows with authenticated data.
const MAX_CONTROL: usize = 1 << 30;
/// Blocks a receiver may have requested and not yet been sent, per stream. An honest receiver
/// never exceeds `WINDOW`; the sender refuses a peer that queues more than this.
const MAX_PENDING: usize = WINDOW * 2;
/// A block that fails verification this many times ends the transfer. Without the limit a sender
/// whose file changed under it (or a hostile one) would be asked for the same block forever.
const MAX_BLOCK_FAILURES: u8 = 3;
/// Longest relative path a manifest may carry.
const MAX_PATH: usize = 4096;
/// Blocks in flight per stream.
pub const WINDOW: usize = 32;
const CDC_MIN: u32 = 64 * 1024;
const CDC_AVG: u32 = 256 * 1024;
const CDC_MAX: u32 = MAX_BLOCK as u32;
/// Files are chunked in independent segments of this size, on all cores at once.
const SEGMENT: u64 = 64 * 1024 * 1024;

// ================================================================== positioned I/O

/// Positional read and write that work on Unix and Windows alike.
trait At {
    fn read_exact_at(&self, buf: &mut [u8], off: u64) -> std::io::Result<()>;
    fn write_all_at(&self, buf: &[u8], off: u64) -> std::io::Result<()>;
}
#[cfg(unix)]
impl At for File {
    fn read_exact_at(&self, buf: &mut [u8], off: u64) -> std::io::Result<()> {
        std::os::unix::fs::FileExt::read_exact_at(self, buf, off)
    }
    fn write_all_at(&self, buf: &[u8], off: u64) -> std::io::Result<()> {
        std::os::unix::fs::FileExt::write_all_at(self, buf, off)
    }
}
#[cfg(windows)]
impl At for File {
    fn read_exact_at(&self, mut buf: &mut [u8], mut off: u64) -> std::io::Result<()> {
        use std::os::windows::fs::FileExt;
        while !buf.is_empty() {
            match self.seek_read(buf, off)? {
                0 => return Err(std::io::ErrorKind::UnexpectedEof.into()),
                n => {
                    buf = &mut buf[n..];
                    off += n as u64;
                }
            }
        }
        Ok(())
    }
    fn write_all_at(&self, mut buf: &[u8], mut off: u64) -> std::io::Result<()> {
        use std::os::windows::fs::FileExt;
        while !buf.is_empty() {
            match self.seek_write(buf, off)? {
                0 => return Err(std::io::ErrorKind::WriteZero.into()),
                n => {
                    buf = &buf[n..];
                    off += n as u64;
                }
            }
        }
        Ok(())
    }
}

// ================================================================== public API

/// The shared secret, hashed to 32 bytes. Derive it from whatever both sides know: the secret
/// inside the on-screen code, or a short PIN typed on one device.
///
/// It is never used as a key directly. Each stream runs SPAKE2 on it first, so somebody who
/// records or intercepts a handshake gets no way to test guesses offline: every guess at a short
/// PIN costs one live connection, which the application can count and cut off. The bytes are
/// wiped when the key is dropped, and the type has no `Debug` on purpose.
#[derive(Clone)]
pub struct Key(pub [u8; 32]);
impl Key {
    pub fn from_secret(secret: &str) -> Key {
        Key(blake3::derive_key("nemi glide 2026 psk v1", secret.as_bytes()))
    }
}
impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The handshake did not complete: the other side has a different secret, speaks another protocol
/// version, sent garbage, or went quiet. Deliberately one error for all of them, so a peer learns
/// nothing from which one it was. A listener should count these: each is one guess at the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeFailed;
impl std::fmt::Display for HandshakeFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("handshake failed: wrong key, or the other side speaks another version")
    }
}
impl std::error::Error for HandshakeFailed {}

/// The sending side: scans and chunks a file or folder once, then serves any number of streams.
#[derive(Clone)]
pub struct Sender {
    src: Arc<Source>,
}

impl Sender {
    pub fn new(path: impl AsRef<Path>) -> Result<Sender> {
        Ok(Sender { src: Arc::new(Source::build(path.as_ref())?) })
    }
    pub fn manifest(&self) -> &Manifest {
        &self.src.manifest
    }
    /// Serve one stream until the receiver is done or the stream drops. Returns bytes sent.
    pub async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(&self, stream: S, key: &Key) -> Result<u64> {
        serve_link(Link::handshake(stream, key, false).await?, self.src.clone()).await
    }
}

/// In which order blocks are fetched.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Order {
    /// Small files first, so most files land in the first seconds.
    #[default]
    SmallFirst,
    /// File by file, front to back, so media can play while it arrives.
    Sequential,
}

/// Progress callback: (bytes done, bytes total).
pub type Progress = Arc<dyn Fn(u64, u64) + Send + Sync>;

#[derive(Default, Clone)]
pub struct Options {
    /// Extra files or folders to reuse blocks from (old versions, a photo library).
    pub seeds: Vec<PathBuf>,
    pub order: Order,
    pub progress: Option<Progress>,
}

/// What happened, byte by byte.
#[derive(Default, Debug, Clone)]
pub struct Report {
    pub files: usize,
    /// Size of everything that arrived.
    pub total: u64,
    /// Bytes that were duplicates inside the transfer and crossed the wire once.
    pub deduplicated: u64,
    /// Bytes reused from files the receiver already had.
    pub reused: u64,
    /// Bytes that came over the streams, before and after compression.
    pub received: u64,
    pub wire: u64,
    pub per_stream: Vec<u64>,
    pub elapsed: Duration,
}
impl Report {
    pub fn mb_per_sec(&self) -> f64 {
        self.received as f64 / 1e6 / self.elapsed.as_secs_f64().max(1e-9)
    }
}

/// Receive into `out` over every stream at once. Streams may drop; the rest carry on.
/// If the transfer stops, calling `receive` again with the same files resumes it.
pub async fn receive<S, P>(streams: Vec<S>, key: &Key, out: P, opts: Options) -> Result<Report>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    P: AsRef<Path>,
{
    let mut links = Vec::new();
    for s in streams {
        links.push(Link::handshake(s, key, true).await?);
    }
    receive_links(links, out.as_ref().to_path_buf(), opts).await
}

// ================================================================== messages

/// One file: its content is `chunks[first .. first + count]`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub first: u32,
    pub count: u32,
}
/// One place a block sits. `block` indexes the unique block list.
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct Occ {
    pub file: u32,
    pub off: u64,
    pub len: u32,
    pub block: u32,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Manifest {
    pub session: [u8; 16],
    pub files: Vec<FileEntry>,
    pub chunks: Vec<Occ>,
    /// Unique BLAKE3 hashes: the unit of transfer.
    pub blocks: Vec<[u8; 32]>,
    pub block_len: Vec<u32>,
    pub total: u64,
}
#[derive(Serialize, Deserialize, Debug)]
enum Msg {
    Hello { want_manifest: bool, hw_aes: bool },
    Accept { suite: u8 },
    Manifest(Manifest),
    Request { ids: Vec<u32> },
    Done,
}

// ================================================================== link

type Rd = BufReader<Box<dyn AsyncRead + Unpin + Send>>;
type Wr = Box<dyn AsyncWrite + Unpin + Send>;

struct Link {
    rd: Rd,
    wr: Wr,
    noise: snow::TransportState,
    hh: Vec<u8>,
}
enum Frame {
    Msg(Msg),
    Data { flags: u8, id: u32, plain_len: u32, sealed: Vec<u8> },
}

impl Link {
    /// Every way the handshake can go wrong is reported as the same `HandshakeFailed`.
    async fn handshake<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        stream: S,
        key: &Key,
        initiator: bool,
    ) -> Result<Link> {
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, Self::handshake_inner(stream, key, initiator)).await {
            Ok(Ok(link)) => Ok(link),
            _ => Err(HandshakeFailed.into()),
        }
    }
    async fn handshake_inner<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        stream: S,
        key: &Key,
        initiator: bool,
    ) -> Result<Link> {
        use spake2::{Ed25519Group, Identity, Password, Spake2};
        let (r, w) = tokio::io::split(stream);
        let mut rd: Rd = BufReader::with_capacity(1 << 20, Box::new(r));
        let mut wr: Wr = Box::new(w);

        // Step 1, SPAKE2. The secret may be a six-digit PIN, and a PIN used as a pre-shared key
        // directly can be found offline from one recorded handshake (try all million, compare the
        // tag). SPAKE2 turns it into a strong per-stream key without ever exposing anything a
        // guess can be tested against, so the only attack left is one online guess per connection.
        let (ida, idb) = (Identity::new(b"glide receiver"), Identity::new(b"glide sender"));
        let pw = Password::new(key.0);
        let (pake, mine) = if initiator {
            Spake2::<Ed25519Group>::start_a(&pw, &ida, &idb)
        } else {
            Spake2::<Ed25519Group>::start_b(&pw, &ida, &idb)
        };
        put16(&mut wr, &mine).await?;
        let theirs = get16(&mut rd, 64).await?;
        let mut shared = pake.finish(&theirs).map_err(|_| anyhow!("pake"))?;
        let mut psk = blake3::derive_key("nemi glide 2026 psk v2", &shared);
        shared.zeroize();

        // Step 2, Noise NNpsk0 keyed with the SPAKE2 result. Its first message is the key
        // confirmation: a responder whose secret differs cannot read it.
        let built = {
            let b = snow::Builder::new(NOISE.parse()?).prologue(PROLOGUE).psk(0, &psk);
            if initiator {
                b.build_initiator()
            } else {
                b.build_responder()
            }
        };
        psk.zeroize();
        let mut hs = built?;
        let mut buf = [0u8; 256];
        if initiator {
            let n = hs.write_message(&[], &mut buf)?;
            put16(&mut wr, &buf[..n]).await?;
            let m = get16(&mut rd, 128).await?;
            hs.read_message(&m, &mut buf)?;
        } else {
            let m = get16(&mut rd, 128).await?;
            hs.read_message(&m, &mut buf)?;
            let n = hs.write_message(&[], &mut buf)?;
            put16(&mut wr, &buf[..n]).await?;
        }
        let hh = hs.get_handshake_hash().to_vec();
        Ok(Link { rd, wr, noise: hs.into_transport_mode()?, hh })
    }
    async fn send_msg(&mut self, m: &Msg) -> Result<()> {
        let plain = bincode::serialize(m)?;
        let mut payload = Vec::with_capacity(plain.len() + 64);
        let mut out = vec![0u8; 65535];
        for p in plain.chunks(65000) {
            let n = self.noise.write_message(p, &mut out)?;
            payload.extend_from_slice(&(n as u16).to_be_bytes());
            payload.extend_from_slice(&out[..n]);
        }
        if payload.len() > MAX_CONTROL {
            bail!("control message too large");
        }
        self.wr.write_all(&control_header(payload.len() as u32)).await?;
        self.wr.write_all(&payload).await?;
        self.wr.flush().await?;
        Ok(())
    }
    async fn recv(&mut self) -> Result<Frame> {
        read_frame(&mut self.rd, &mut self.noise).await
    }
    fn data_key(&self, suite: u8) -> Result<DataKey> {
        let suite = Suite::from_wire(suite).ok_or_else(|| anyhow!("unknown cipher suite"))?;
        Ok(derive_data_key(suite, &self.hh, "s2r"))
    }
}
async fn read_frame(rd: &mut Rd, noise: &mut snow::TransportState) -> Result<Frame> {
    let mut h = [0u8; HDR];
    rd.read_exact(&mut h).await?;
    let hd = parse_header(&h);
    let len = hd.len as usize;
    match hd.kind {
        // Nothing in a header is authenticated yet, so the length it claims is never used to
        // allocate. A control message is read and decrypted one Noise piece (at most 64 KiB) at a
        // time: a forged length costs the forger a failed decrypt, not our memory.
        T_CONTROL => {
            if len > MAX_CONTROL {
                bail!("frame too large");
            }
            let (mut plain, mut piece, mut out, mut left) = (Vec::new(), vec![0u8; 65535], vec![0u8; 65535], len);
            while left > 0 {
                if left < 2 {
                    bail!("bad control frame");
                }
                let mut l = [0u8; 2];
                rd.read_exact(&mut l).await?;
                let n = u16::from_be_bytes(l) as usize;
                left -= 2;
                if n < 16 || n > left {
                    bail!("bad control frame");
                }
                rd.read_exact(&mut piece[..n]).await?;
                left -= n;
                let k = noise.read_message(&piece[..n], &mut out).map_err(|_| anyhow!("decrypt failed"))?;
                plain.extend_from_slice(&out[..k]);
            }
            Ok(Frame::Msg(bincode::deserialize(&plain)?))
        }
        // A sealed block is at most one block plus its tag: compression is only kept when it wins.
        T_DATA => {
            if !(16..=MAX_BLOCK + 16).contains(&len) || hd.plain_len as usize > MAX_BLOCK || hd.flags & !F_KNOWN != 0 {
                bail!("bad data frame");
            }
            let mut payload = vec![0u8; len];
            rd.read_exact(&mut payload).await?;
            Ok(Frame::Data { flags: hd.flags, id: hd.id, plain_len: hd.plain_len, sealed: payload })
        }
        _ => bail!("unknown frame"),
    }
}
async fn put16(w: &mut Wr, b: &[u8]) -> Result<()> {
    w.write_all(&(b.len() as u16).to_be_bytes()).await?;
    w.write_all(b).await?;
    w.flush().await?;
    Ok(())
}
async fn get16(r: &mut Rd, max: usize) -> Result<Vec<u8>> {
    let mut l = [0u8; 2];
    r.read_exact(&mut l).await?;
    let n = u16::from_be_bytes(l) as usize;
    if n > max {
        bail!("handshake message too large");
    }
    let mut b = vec![0u8; n];
    r.read_exact(&mut b).await?;
    Ok(b)
}

// ================================================================== chunking

/// Gear table for the rolling hash that places segment boundaries (deterministic, from splitmix64).
const GEAR: [u64; 256] = {
    let (mut t, mut x, mut i) = ([0u64; 256], 0x9E37_79B9_7F4A_7C15u64, 0);
    while i < 256 {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        t[i] = z ^ (z >> 31);
        i += 1;
    }
    t
};
/// First content-defined anchor at or after `off`: a rolling gear hash with its top 20 bits zero
/// (one in a million positions). The same bytes give the same anchor wherever they sit in the file,
/// so segments line up again right after an insertion.
fn anchor(f: &File, off: u64, size: u64) -> Result<u64> {
    let len = (8u64 << 20).min(size - off) as usize;
    let mut buf = vec![0u8; len];
    f.read_exact_at(&mut buf, off)?;
    let mut h = 0u64;
    for (i, b) in buf.iter().enumerate() {
        h = (h << 1).wrapping_add(GEAR[*b as usize]);
        if i >= 64 && h >> 44 == 0 {
            return Ok(off + i as u64 + 1);
        }
    }
    Ok(off)
}

/// Cut a file into blocks. Big files are split into ~64 MiB segments at content-defined anchors and
/// the segments are chunked with FastCDC on all cores at once: parallel speed, and an edit or
/// insertion still only changes the blocks around it.
fn chunk_file(path: &Path) -> Result<Vec<(u64, u32, [u8; 32])>> {
    let size = std::fs::metadata(path)?.len();
    if size == 0 {
        return Ok(vec![]);
    }
    let f = File::open(path)?;
    let mut bounds: Vec<u64> =
        (1..size.div_ceil(SEGMENT)).into_par_iter().map(|k| anchor(&f, k * SEGMENT, size)).collect::<Result<_>>()?;
    bounds.insert(0, 0);
    bounds.push(size);
    bounds.dedup();
    let parts: Vec<Vec<(u64, u32, [u8; 32])>> = bounds
        .par_windows(2)
        .map(|w| {
            let (start, len) = (w[0], (w[1] - w[0]) as usize);
            let mut buf = vec![0u8; len];
            f.read_exact_at(&mut buf, start)?;
            Ok(fastcdc::v2020::FastCDC::new(&buf, CDC_MIN, CDC_AVG, CDC_MAX)
                .map(|c| {
                    (
                        start + c.offset as u64,
                        c.length as u32,
                        *blake3::hash(&buf[c.offset..c.offset + c.length]).as_bytes(),
                    )
                })
                .collect())
        })
        .collect::<Result<_>>()?;
    Ok(parts.concat())
}
fn walk(base: &Path, dir: &Path, out: &mut Vec<(PathBuf, String)>) -> Result<()> {
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let p = e.path();
        if p.file_name().is_some_and(|n| n.to_string_lossy().starts_with(".glide-")) {
            continue;
        }
        // The entry's own type, not what it points at. A symlink is never followed: one that
        // leaves the folder would send files the person never chose to share, and one that points
        // back up would walk forever.
        let t = e.file_type()?;
        if t.is_dir() {
            walk(base, &p, out)?;
        } else if t.is_file() {
            out.push((p.clone(), p.strip_prefix(base)?.to_string_lossy().replace('\\', "/")));
        }
    }
    Ok(())
}
fn list(root: &Path) -> Result<Vec<(PathBuf, String)>> {
    let mut l = Vec::new();
    if root.is_file() {
        l.push((root.to_path_buf(), root.file_name().unwrap_or_default().to_string_lossy().to_string()));
    } else if root.is_dir() {
        walk(root, root, &mut l)?;
        l.sort_by(|a, b| a.1.cmp(&b.1));
    } else {
        bail!("{} not found", root.display());
    }
    Ok(l)
}

// ================================================================== manifest checks

/// The session id names the resume state, so it has to cover everything a block's content depends
/// on: the hashes too, not only the layout. Two versions of a file that happen to cut at the same
/// offsets would otherwise share one resume state, and the second transfer would keep blocks of
/// the first. The receiver computes this itself and never takes the sender's word for it.
fn session_id(files: &[FileEntry], chunks: &[Occ], blocks: &[[u8; 32]], block_len: &[u32]) -> Result<[u8; 16]> {
    let mut h = blake3::Hasher::new_derive_key("nemi glide 2026 session v2");
    h.update(&bincode::serialize(&(files, chunks, blocks, block_len))?);
    let mut session = [0u8; 16];
    session.copy_from_slice(&h.finalize().as_bytes()[..16]);
    Ok(session)
}

#[cfg(windows)]
fn hostile_here(c: &str) -> bool {
    let stem = c.split('.').next().unwrap_or("").to_ascii_uppercase();
    let device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit());
    device || c.ends_with('.') || c.ends_with(' ') || c.chars().any(|ch| "<>:\"|?*".contains(ch))
}
#[cfg(not(windows))]
fn hostile_here(_: &str) -> bool {
    false
}

/// Turn a path from a manifest into one that is certain to stay inside the output folder.
/// The sender chose these bytes, so nothing about them is trusted: no absolute paths, no `..`,
/// no empty or `.` components, no backslashes (a separator on Windows), no control characters,
/// and nothing that would collide with Glide's own `.glide-` bookkeeping files.
fn safe_path(path: &str) -> Result<PathBuf> {
    let refuse = || anyhow!("unsafe path in manifest: {path:?}");
    if path.is_empty() || path.len() > MAX_PATH {
        return Err(refuse());
    }
    let mut p = PathBuf::new();
    for c in path.split('/') {
        if c.is_empty()
            || c == "."
            || c == ".."
            || c.starts_with(".glide-")
            || c.chars().any(|ch| ch.is_control() || ch == '\\')
            || hostile_here(c)
        {
            return Err(refuse());
        }
        p.push(c);
    }
    Ok(p)
}

/// Check everything a manifest claims before a single byte of it is acted on, and return the
/// output path of every file. A manifest comes from the other side: every index in it is used to
/// index memory and every offset to position a write, so each one is proven in range here, once,
/// rather than trusted at the place it is used.
fn validate(m: &Manifest) -> Result<Vec<PathBuf>> {
    let bad = |what: &str| anyhow!("invalid manifest: {what}");
    let n = m.blocks.len();
    if n != m.block_len.len() || n > u32::MAX as usize || m.chunks.len() > u32::MAX as usize {
        return Err(bad("block tables do not match"));
    }
    if m.block_len.iter().any(|l| *l == 0 || *l as usize > MAX_BLOCK) {
        return Err(bad("block size out of range"));
    }
    if m.session != session_id(&m.files, &m.chunks, &m.blocks, &m.block_len)? {
        return Err(bad("session id does not match the content"));
    }
    let (mut paths, mut seen) = (Vec::with_capacity(m.files.len()), HashSet::new());
    let (mut next, mut total) = (0usize, 0u64);
    for (fi, f) in m.files.iter().enumerate() {
        let p = safe_path(&f.path)?;
        if !seen.insert(p.clone()) {
            return Err(bad("the same path twice"));
        }
        paths.push(p);
        // A file's chunks are one contiguous run of the chunk list, in order, and tile the file
        // exactly: no gap, no overlap, nothing past the end.
        let end = next.checked_add(f.count as usize).filter(|e| *e <= m.chunks.len());
        let Some(end) = end.filter(|_| f.first as usize == next) else {
            return Err(bad("file chunk range out of bounds"));
        };
        let mut off = 0u64;
        for o in &m.chunks[next..end] {
            let known = m.block_len.get(o.block as usize);
            if o.file as usize != fi || o.off != off || known != Some(&o.len) {
                return Err(bad("chunk does not fit its file"));
            }
            off += o.len as u64;
        }
        if off != f.size {
            return Err(bad("chunks do not add up to the file size"));
        }
        next = end;
        total = total.checked_add(f.size).ok_or_else(|| bad("total size overflows"))?;
    }
    if next != m.chunks.len() || total != m.total {
        return Err(bad("totals do not match"));
    }
    Ok(paths)
}

/// The place a file goes, reached without following a single symlink. Every folder on the way
/// must be a real folder (created here if missing) and the file itself a regular file or absent.
/// A link planted in the output folder would otherwise redirect a write to wherever it points.
fn dest_path(out: &Path, rel: &Path, create: bool) -> Result<PathBuf> {
    let refuse = |p: &Path| anyhow!("refusing to write through {}: not a plain file or folder", p.display());
    let mut p = out.to_path_buf();
    let mut parts = rel.components().peekable();
    while let Some(c) = parts.next() {
        p.push(c);
        let last = parts.peek().is_none();
        match std::fs::symlink_metadata(&p) {
            Ok(md) if last && md.file_type().is_file() => {}
            Ok(md) if !last && md.file_type().is_dir() => {}
            Ok(_) => return Err(refuse(&p)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !last && create {
                    std::fs::create_dir(&p)?;
                } else if !last {
                    // Nothing below a missing folder can exist yet, so there is nothing to check.
                    return Ok(out.join(rel));
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(p)
}

// ================================================================== sender

struct Source {
    manifest: Manifest,
    files: Vec<File>,
    first: Vec<Occ>,
    raw: Vec<AtomicBool>,
}

impl Source {
    fn build(root: &Path) -> Result<Source> {
        let entries = list(root)?;
        let cut: Vec<_> = entries.iter().map(|(p, _)| chunk_file(p)).collect::<Result<_>>()?;
        let mut index: HashMap<[u8; 32], u32> = HashMap::new();
        let (mut blocks, mut block_len, mut chunks, mut fes, mut files, mut first) =
            (vec![], vec![], vec![], vec![], vec![], vec![]);
        let mut total = 0;
        for (fi, ((p, rel), cs)) in entries.iter().zip(cut).enumerate() {
            let start = chunks.len() as u32;
            for (off, len, h) in &cs {
                let b = *index.entry(*h).or_insert_with(|| {
                    blocks.push(*h);
                    block_len.push(*len);
                    blocks.len() as u32 - 1
                });
                let o = Occ { file: fi as u32, off: *off, len: *len, block: b };
                if b as usize == first.len() {
                    first.push(o);
                }
                chunks.push(o);
            }
            let size = std::fs::metadata(p)?.len();
            fes.push(FileEntry { path: rel.clone(), size, first: start, count: cs.len() as u32 });
            files.push(File::open(p)?);
            total += size;
        }
        let session = session_id(&fes, &chunks, &blocks, &block_len)?;
        let raw = (0..fes.len()).map(|_| AtomicBool::new(false)).collect();
        Ok(Source { manifest: Manifest { session, files: fes, chunks, blocks, block_len, total }, files, first, raw })
    }
    /// Read a block, compress it if the file has been compressing well, seal it.
    fn prepare(&self, key: &DataKey, id: u32) -> Result<(u8, u32, Vec<u8>)> {
        let o = *self.first.get(id as usize).ok_or_else(|| anyhow!("bad block id"))?;
        let fi = o.file as usize;
        let mut buf = vec![0u8; o.len as usize];
        self.files[fi].read_exact_at(&mut buf, o.off)?;
        let mut flags = 0;
        if !(self.raw[fi].load(Ordering::Relaxed) && !id.is_multiple_of(64)) {
            match zstd::bulk::compress(&buf, 1) {
                Ok(z) if z.len() * 100 < buf.len() * 95 => {
                    buf = z;
                    flags = F_ZSTD;
                    self.raw[fi].store(false, Ordering::Relaxed);
                }
                _ => self.raw[fi].store(true, Ordering::Relaxed),
            }
        }
        buf.reserve(16);
        key.seal(id, flags, o.len, &mut buf);
        Ok((flags, o.len, buf))
    }
}

/// Sender pipeline: one task reads requests, all cores prepare blocks, one task writes them.
async fn serve_link(mut l: Link, src: Arc<Source>) -> Result<u64> {
    let (want, peer_aes) = match l.recv().await? {
        Frame::Msg(Msg::Hello { want_manifest, hw_aes }) => (want_manifest, hw_aes),
        _ => bail!("expected hello"),
    };
    let suite = if peer_aes && has_hw_aes() { Suite::Aes256Gcm } else { Suite::ChaCha20Poly1305 } as u8;
    l.send_msg(&Msg::Accept { suite }).await?;
    if want {
        l.send_msg(&Msg::Manifest(src.manifest.clone())).await?;
    }
    let key = Arc::new(l.data_key(suite)?);
    let Link { mut rd, mut wr, mut noise, .. } = l;
    let (tx, mut ready) = tokio::sync::mpsc::unbounded_channel::<Result<(u32, u8, u32, Vec<u8>)>>();
    // Blocks requested and not yet written. A receiver that asks faster than it reads would
    // otherwise have the sender read, compress and queue the whole transfer in memory.
    let pending = Arc::new(AtomicUsize::new(0));
    let queued = pending.clone();
    let reader = tokio::spawn(async move {
        loop {
            match read_frame(&mut rd, &mut noise).await? {
                Frame::Msg(Msg::Request { ids }) => {
                    if queued.fetch_add(ids.len(), Ordering::SeqCst) + ids.len() > MAX_PENDING {
                        bail!("receiver requested more blocks than it reads");
                    }
                    for id in ids {
                        let (s, k, tx) = (src.clone(), key.clone(), tx.clone());
                        rayon::spawn(move || {
                            let _ = tx.send(s.prepare(&k, id).map(|(f, n, b)| (id, f, n, b)));
                        });
                    }
                }
                Frame::Msg(Msg::Done) => return Ok::<(), anyhow::Error>(()),
                _ => bail!("unexpected frame"),
            }
        }
    });
    let mut sent = 0u64;
    while let Some(r) = ready.recv().await {
        let (id, f, n, b) = r?;
        wr.write_all(&data_header(f, id, n, b.len() as u32)).await?;
        wr.write_all(&b).await?;
        pending.fetch_sub(1, Ordering::SeqCst);
        sent += b.len() as u64;
        if ready.is_empty() {
            wr.flush().await?;
        }
    }
    reader.await??;
    Ok(sent)
}

// ================================================================== receiver

struct Sched {
    have: Vec<bool>,
    have_count: usize,
    pool: Vec<u32>, // stack, next block on top
    in_flight: HashMap<u32, HashSet<usize>>,
    processing: HashSet<u32>,
    per_stream: Vec<u64>,
    received: u64,
    wire: u64,
    done_bytes: u64,
    state: PathBuf,
    dirty: usize,
    fails: HashMap<u32, u8>,
    /// Set when a block has failed verification too often; every stream stops on it.
    fatal: bool,
}
impl Sched {
    fn done(&self) -> bool {
        self.have_count == self.have.len()
    }
    /// Next block for a stream: from the pool, or in the endgame one another stream still has in flight.
    fn take(&mut self, s: usize) -> Option<u32> {
        if let Some(id) = self.pool.pop() {
            self.in_flight.entry(id).or_default().insert(s);
            return Some(id);
        }
        let id = self.in_flight.iter().filter(|(_, ss)| !ss.contains(&s) && ss.len() < 2).map(|(id, _)| *id).min()?;
        self.in_flight.get_mut(&id)?.insert(s);
        Some(id)
    }
    fn drop_stream(&mut self, s: usize) {
        let back: Vec<u32> = self
            .in_flight
            .iter_mut()
            .filter_map(|(id, ss)| {
                ss.remove(&s);
                ss.is_empty().then_some(*id)
            })
            .collect();
        for id in back {
            self.in_flight.remove(&id);
            if !self.have[id as usize] {
                self.pool.push(id);
            }
        }
    }
    fn arrived(&mut self, id: u32) -> bool {
        if self.have.get(id as usize).copied().unwrap_or(true) || !self.processing.insert(id) {
            return false;
        }
        self.in_flight.remove(&id);
        true
    }
    fn finish(&mut self, s: usize, id: u32, ok: bool, len: usize, wire: usize) {
        self.processing.remove(&id);
        if !ok {
            let f = self.fails.entry(id).or_insert(0);
            *f += 1;
            if *f >= MAX_BLOCK_FAILURES {
                self.fatal = true;
            }
            self.pool.push(id);
            return;
        }
        self.have[id as usize] = true;
        self.have_count += 1;
        self.per_stream[s] += len as u64;
        self.received += len as u64;
        self.wire += wire as u64;
        self.done_bytes += len as u64;
        self.dirty += 1;
        if self.dirty >= 64 || self.done() {
            self.save();
        }
    }
    fn save(&mut self) {
        self.dirty = 0;
        if self.done() {
            let _ = std::fs::remove_file(&self.state);
            return;
        }
        let mut b = vec![0u8; self.have.len().div_ceil(8)];
        for (i, h) in self.have.iter().enumerate() {
            if *h {
                b[i / 8] |= 1 << (i % 8);
            }
        }
        let _ = std::fs::write(&self.state, b);
    }
}

/// Destination files, and for every unique block every place it goes.
struct Dest {
    files: Vec<File>,
    places: Vec<Vec<(u32, u64)>>,
}
impl Dest {
    fn write(&self, id: u32, data: &[u8]) -> Result<()> {
        for &(f, off) in &self.places[id as usize] {
            self.files[f as usize].write_all_at(data, off)?;
        }
        Ok(())
    }
}

struct Prepared {
    sched: Sched,
    dest: Dest,
    moved: Vec<PathBuf>,
    reused: u64,
}

/// Lay out the output folder. Old versions of incoming files are moved aside and, with any extra
/// seeds, chunked: every block found there is copied locally instead of crossing a stream.
fn prepare(m: &Manifest, out: &Path, opts: &Options, streams: usize) -> Result<Prepared> {
    // Nothing on disk is touched until the whole manifest has been proven sane and every
    // destination has been proven to be a plain path inside the output folder.
    let rels = validate(m)?;
    std::fs::create_dir_all(out)?;
    for rel in &rels {
        dest_path(out, rel, false)?;
    }
    let n = m.blocks.len();
    let state = out.join(format!(".glide-{}", m.session.iter().map(|b| format!("{b:02x}")).collect::<String>()));
    let mut have = vec![false; n];
    let resuming = match std::fs::read(&state) {
        Ok(b) if b.len() == n.div_ceil(8) => {
            for (i, h) in have.iter_mut().enumerate() {
                *h = b[i / 8] & (1 << (i % 8)) != 0;
            }
            true
        }
        _ => false,
    };
    let mut seeds: Vec<PathBuf> = Vec::new();
    let mut moved = Vec::new();
    if !resuming {
        for rel in &rels {
            let p = out.join(rel);
            if std::fs::symlink_metadata(&p).is_ok_and(|md| md.file_type().is_file()) {
                let aside =
                    p.with_file_name(format!(".glide-old-{}", p.file_name().unwrap_or_default().to_string_lossy()));
                std::fs::rename(&p, &aside)?;
                seeds.push(aside.clone());
                moved.push(aside);
            }
        }
    }
    for s in &opts.seeds {
        seeds.extend(list(s)?.into_iter().map(|x| x.0));
    }
    let mut files = Vec::new();
    for (f, rel) in m.files.iter().zip(&rels) {
        let p = dest_path(out, rel, true)?;
        let file = std::fs::OpenOptions::new().create(true).truncate(false).read(true).write(true).open(&p)?;
        if file.metadata()?.len() != f.size {
            file.set_len(f.size)?;
        }
        files.push(file);
    }
    let mut places = vec![Vec::new(); n];
    for o in &m.chunks {
        places[o.block as usize].push((o.file, o.off));
    }
    let dest = Dest { files, places };
    // The resume state is a claim, not a fact: it is written before the data it describes is
    // known to be on disk, and the files may have been edited, truncated or replaced since. So
    // every block it says we have is read back and hashed, in every place it sits, and a block
    // that is not there in full is simply fetched again.
    if resuming {
        let stale: Vec<u32> = m
            .chunks
            .par_iter()
            .filter(|o| have[o.block as usize])
            .filter_map(|o| {
                let mut buf = vec![0u8; o.len as usize];
                let read = dest.files[o.file as usize].read_exact_at(&mut buf, o.off);
                (read.is_err() || blake3::hash(&buf).as_bytes() != &m.blocks[o.block as usize]).then_some(o.block)
            })
            .collect();
        for b in stale {
            have[b as usize] = false;
        }
    }
    let mut reused = 0u64;
    let wanted: HashMap<[u8; 32], u32> =
        m.blocks.iter().enumerate().filter(|(i, _)| !have[*i]).map(|(i, h)| (*h, i as u32)).collect();
    if !wanted.is_empty() {
        for p in &seeds {
            let Ok(cs) = chunk_file(p) else { continue };
            let f = File::open(p)?;
            for (off, len, h) in cs {
                let Some(&id) = wanted.get(&h) else { continue };
                if have[id as usize] {
                    continue;
                }
                let mut buf = vec![0u8; len as usize];
                f.read_exact_at(&mut buf, off)?;
                if blake3::hash(&buf).as_bytes() != &m.blocks[id as usize] {
                    continue;
                }
                dest.write(id, &buf)?;
                have[id as usize] = true;
                reused += len as u64;
            }
        }
    }
    let mut order: Vec<usize> = (0..m.files.len()).collect();
    if opts.order == Order::SmallFirst {
        order.sort_by_key(|&i| m.files[i].size);
    }
    let mut seen = vec![false; n];
    let mut ids = Vec::new();
    for fi in order {
        let f = &m.files[fi];
        for o in &m.chunks[f.first as usize..(f.first + f.count) as usize] {
            let b = o.block as usize;
            if !have[b] && !seen[b] {
                seen[b] = true;
                ids.push(o.block);
            }
        }
    }
    ids.reverse();
    let have_count = have.iter().filter(|h| **h).count();
    let done_bytes = (0..n).filter(|&i| have[i]).map(|i| m.block_len[i] as u64).sum();
    let sched = Sched {
        have,
        have_count,
        pool: ids,
        in_flight: HashMap::new(),
        processing: HashSet::new(),
        per_stream: vec![0; streams],
        received: 0,
        wire: 0,
        done_bytes,
        state,
        dirty: 0,
        fails: HashMap::new(),
        fatal: false,
    };
    Ok(Prepared { sched, dest, moved, reused })
}

fn open_block(
    key: &DataKey,
    m: &Manifest,
    dest: &Dest,
    flags: u8,
    id: u32,
    plain_len: u32,
    mut buf: Vec<u8>,
) -> Result<usize> {
    if plain_len != m.block_len[id as usize] {
        bail!("bad length");
    }
    key.open(id, flags, plain_len, &mut buf).map_err(|_| anyhow!("auth failed"))?;
    let data = if flags & F_ZSTD != 0 { zstd::bulk::decompress(&buf, plain_len as usize)? } else { buf };
    if data.len() != plain_len as usize || blake3::hash(&data).as_bytes() != &m.blocks[id as usize] {
        bail!("hash mismatch");
    }
    dest.write(id, &data)?;
    Ok(data.len())
}

async fn receive_links(mut links: Vec<Link>, out: PathBuf, opts: Options) -> Result<Report> {
    if links.is_empty() {
        bail!("no streams");
    }
    let t0 = Instant::now();
    let hw = has_hw_aes();
    links[0].send_msg(&Msg::Hello { want_manifest: true, hw_aes: hw }).await?;
    let suite0 = match links[0].recv().await? {
        Frame::Msg(Msg::Accept { suite }) => suite,
        _ => bail!("expected accept"),
    };
    let m = match links[0].recv().await? {
        Frame::Msg(Msg::Manifest(m)) => m,
        _ => bail!("expected manifest"),
    };
    let m = Arc::new(m);
    let (m2, o2, op2, n) = (m.clone(), out.clone(), opts.clone(), links.len());
    let Prepared { sched, dest, moved, reused } =
        tokio::task::spawn_blocking(move || prepare(&m2, &o2, &op2, n)).await??;
    let sched = Arc::new(Mutex::new(sched));
    let dest = Arc::new(dest);
    let permits = Arc::new(tokio::sync::Semaphore::new(64));
    let unique: u64 = m.block_len.iter().map(|l| *l as u64).sum();
    let mut tasks = Vec::new();
    for (s, mut l) in links.into_iter().enumerate() {
        let (sched, dest, m, permits) = (sched.clone(), dest.clone(), m.clone(), permits.clone());
        tasks.push(tokio::spawn(async move {
            let r: Result<()> = async {
                let suite = if s == 0 {
                    suite0
                } else {
                    l.send_msg(&Msg::Hello { want_manifest: false, hw_aes: hw }).await?;
                    match l.recv().await? {
                        Frame::Msg(Msg::Accept { suite }) => suite,
                        _ => bail!("expected accept"),
                    }
                };
                let key = Arc::new(l.data_key(suite)?);
                let mut outstanding = 0;
                loop {
                    let ids: Vec<u32> = {
                        let mut g = sched.lock().unwrap();
                        if g.fatal {
                            bail!("a block failed verification {MAX_BLOCK_FAILURES} times");
                        }
                        (outstanding..WINDOW).filter_map(|_| g.take(s)).collect()
                    };
                    outstanding += ids.len();
                    if !ids.is_empty() {
                        l.send_msg(&Msg::Request { ids }).await?;
                    }
                    if outstanding == 0 {
                        if sched.lock().unwrap().done() {
                            let _ = l.send_msg(&Msg::Done).await;
                            return Ok(());
                        }
                        tokio::time::sleep(Duration::from_millis(2)).await;
                        continue;
                    }
                    let permit = permits.clone().acquire_owned().await?;
                    let Frame::Data { flags, id, plain_len, sealed } = l.recv().await? else {
                        bail!("unexpected frame")
                    };
                    outstanding -= 1;
                    if !sched.lock().unwrap().arrived(id) {
                        continue;
                    }
                    let wire = sealed.len();
                    let (k, m, d, sc) = (key.clone(), m.clone(), dest.clone(), sched.clone());
                    rayon::spawn(move || {
                        let r = open_block(&k, &m, &d, flags, id, plain_len, sealed);
                        sc.lock().unwrap().finish(s, id, r.is_ok(), *r.as_ref().unwrap_or(&0), wire);
                        drop(permit);
                    });
                }
            }
            .await;
            if r.is_err() {
                sched.lock().unwrap().drop_stream(s);
            }
            r
        }));
    }
    while !tasks.iter().all(|t| t.is_finished()) {
        if let Some(p) = &opts.progress {
            let d = sched.lock().unwrap().done_bytes;
            p(d, unique);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut errs = Vec::new();
    for t in tasks {
        if let Err(e) = t.await? {
            errs.push(e.to_string());
        }
    }
    let _ = permits.acquire_many(64).await;
    let g = sched.lock().unwrap();
    if !g.done() {
        bail!("incomplete (resume by receiving again); streams failed: {}", errs.join("; "));
    }
    for p in moved {
        let _ = std::fs::remove_file(p);
    }
    if let Some(p) = &opts.progress {
        p(unique, unique);
    }
    Ok(Report {
        files: m.files.len(),
        total: m.total,
        deduplicated: m.total.saturating_sub(unique),
        reused,
        received: g.received,
        wire: g.wire,
        per_stream: g.per_stream.clone(),
        elapsed: t0.elapsed(),
    })
}

// ================================================================== tests

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("glide-unit-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    fn source(d: &Path) -> Source {
        std::fs::create_dir_all(d.join("src/sub")).unwrap();
        std::fs::write(d.join("src/a.bin"), vec![7u8; 300_000]).unwrap();
        std::fs::write(d.join("src/sub/b.txt"), b"hello").unwrap();
        std::fs::write(d.join("src/empty"), b"").unwrap();
        Source::build(&d.join("src")).unwrap()
    }
    /// Re-seal a tampered manifest the way a hostile sender would, so only the check under test
    /// can refuse it.
    fn resealed(mut m: Manifest) -> Manifest {
        m.session = session_id(&m.files, &m.chunks, &m.blocks, &m.block_len).unwrap();
        m
    }

    #[test]
    fn paths_that_leave_the_folder_are_refused() {
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../../x",
            "a//b",
            "a/./b",
            "a/",
            "..",
            "a\\b",
            "a\u{0}b",
            "a\nb",
            ".glide-old-x",
            "a/.glide-0011",
        ] {
            assert!(safe_path(bad).is_err(), "{bad:?} should be refused");
        }
        assert!(safe_path(&"a/".repeat(3000)).is_err());
        for good in ["a", "a/b/c.txt", ".hidden", "a..b", "...", "name with spaces.txt", "ünï/cødé"] {
            assert_eq!(safe_path(good).unwrap(), PathBuf::from(good));
        }
    }

    #[test]
    fn an_honest_manifest_passes() {
        let d = tmp("honest");
        let paths = validate(&source(&d).manifest).unwrap();
        assert_eq!(paths.len(), 3);
    }

    #[test]
    fn every_lie_in_a_manifest_is_caught() {
        let d = tmp("lies");
        let m = source(&d).manifest;
        let big = m.files.iter().position(|f| f.count > 0).unwrap();
        let ci = m.files[big].first as usize;
        type Lie = Box<dyn Fn(&mut Manifest)>;
        let lies: Vec<(&str, Lie)> = vec![
            ("path escapes", Box::new(move |m| m.files[big].path = "../../escape".into())),
            ("absolute path", Box::new(move |m| m.files[big].path = "/tmp/escape".into())),
            ("duplicate path", Box::new(|m| m.files[1].path = m.files[0].path.clone())),
            ("block index out of range", Box::new(move |m| m.chunks[ci].block = u32::MAX)),
            ("file index out of range", Box::new(move |m| m.chunks[ci].file = 99)),
            ("offset past the file", Box::new(move |m| m.chunks[ci].off = 1 << 40)),
            ("chunk length differs from block", Box::new(move |m| m.chunks[ci].len += 1)),
            ("chunk range overflows", Box::new(move |m| m.files[big].count = u32::MAX)),
            ("chunk range starts elsewhere", Box::new(move |m| m.files[big].first += 1)),
            ("size larger than chunks", Box::new(move |m| m.files[big].size += 1)),
            (
                "huge size on an empty file",
                Box::new(|m| m.files.iter_mut().find(|f| f.count == 0).unwrap().size = 1 << 62),
            ),
            ("oversized block", Box::new(|m| m.block_len[0] = MAX_BLOCK as u32 + 1)),
            ("zero block", Box::new(|m| m.block_len[0] = 0)),
            ("tables differ", Box::new(|m| m.block_len.push(1))),
            ("wrong total", Box::new(|m| m.total += 1)),
            ("stray chunk", Box::new(|m| m.chunks.push(m.chunks[0]))),
        ];
        for (what, lie) in lies {
            let mut bad = m.clone();
            lie(&mut bad);
            assert!(validate(&resealed(bad)).is_err(), "not caught: {what}");
        }
        let mut stale = m.clone();
        stale.blocks[0][0] ^= 1;
        assert!(validate(&stale).is_err(), "a session id that does not cover the hashes");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_in_the_output_folder_is_never_written_through() {
        let d = tmp("links");
        let (out, outside) = (d.join("out"), d.join("outside"));
        std::fs::create_dir_all(&out).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("victim"), b"untouched").unwrap();
        std::os::unix::fs::symlink(&outside, out.join("dir")).unwrap();
        std::os::unix::fs::symlink(outside.join("victim"), out.join("file")).unwrap();
        for create in [false, true] {
            assert!(dest_path(&out, Path::new("dir/new.txt"), create).is_err());
            assert!(dest_path(&out, Path::new("file"), create).is_err());
        }
        assert_eq!(dest_path(&out, Path::new("a/b/c.txt"), true).unwrap(), out.join("a/b/c.txt"));
        assert!(out.join("a/b").is_dir());
        assert!(!outside.join("new.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn the_sender_does_not_follow_symlinks() {
        let d = tmp("walk");
        std::fs::create_dir_all(d.join("src")).unwrap();
        std::fs::create_dir_all(d.join("private")).unwrap();
        std::fs::write(d.join("private/secret"), b"not shared").unwrap();
        std::fs::write(d.join("src/shared"), b"shared").unwrap();
        std::os::unix::fs::symlink(d.join("private"), d.join("src/link")).unwrap();
        std::os::unix::fs::symlink(d.join("private/secret"), d.join("src/file-link")).unwrap();
        std::os::unix::fs::symlink(d.join("src"), d.join("src/loop")).unwrap();
        let names: Vec<String> = list(&d.join("src")).unwrap().into_iter().map(|x| x.1).collect();
        assert_eq!(names, ["shared"]);
    }

    /// A sender that holds the right key and lies in its manifest: the receive fails and nothing
    /// is written outside the output folder.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_hostile_sender_cannot_write_outside_the_output_folder() {
        let d = tmp("hostile");
        let mut src = source(&d);
        let i = src.manifest.files.iter().position(|f| f.count > 0).unwrap();
        src.manifest.files[i].path = "../escaped.bin".into();
        src.manifest = resealed(src.manifest);
        let key = Key::from_secret("123456");
        let (client, server) = tokio::io::duplex(1 << 20);
        let (src, k) = (Arc::new(src), key.clone());
        tokio::spawn(async move {
            let _ = serve_link(Link::handshake(server, &k, false).await?, src).await;
            Ok::<(), anyhow::Error>(())
        });
        let r = receive(vec![client], &key, d.join("out"), Options::default()).await;
        assert!(r.unwrap_err().to_string().contains("unsafe path"));
        assert!(!d.join("escaped.bin").exists());
        assert!(!d.join("out").exists(), "nothing is created before the manifest is checked");
    }

    /// A receiver that asks for far more than it reads is cut off instead of being queued for.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_greedy_receiver_is_cut_off() {
        let d = tmp("greedy");
        let src = Arc::new(source(&d));
        let key = Key::from_secret("123456");
        let (client, server) = tokio::io::duplex(1 << 20);
        let k = key.clone();
        let serving = tokio::spawn(async move { serve_link(Link::handshake(server, &k, false).await?, src).await });
        let mut l = Link::handshake(client, &key, true).await.unwrap();
        l.send_msg(&Msg::Hello { want_manifest: false, hw_aes: false }).await.unwrap();
        l.send_msg(&Msg::Request { ids: vec![0; MAX_PENDING + 1] }).await.unwrap();
        assert!(serving.await.unwrap().is_err());
    }

    /// A manifest for a big transfer is several megabytes: it has to cross as one message, and a
    /// control frame that claims more than it carries has to fail rather than be waited for.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_large_manifest_crosses_and_a_forged_length_does_not() {
        let key = Key::from_secret("123456");
        let (a, b) = tokio::io::duplex(1 << 20);
        let k = key.clone();
        let far = tokio::spawn(async move { Link::handshake(b, &k, false).await });
        let (mut near, mut far) = (Link::handshake(a, &key, true).await.unwrap(), far.await.unwrap().unwrap());
        let n = 100_000u32;
        let m = Manifest {
            session: [0; 16],
            files: vec![],
            chunks: (0..n).map(|i| Occ { file: 0, off: i as u64, len: 1, block: i }).collect(),
            blocks: (0..n).map(|i| *blake3::hash(&i.to_be_bytes()).as_bytes()).collect(),
            block_len: vec![1; n as usize],
            total: 0,
        };
        let sent = m.clone();
        let sending = tokio::spawn(async move {
            far.send_msg(&Msg::Manifest(sent)).await.unwrap();
            far
        });
        let Frame::Msg(Msg::Manifest(got)) = near.recv().await.unwrap() else { panic!("expected a manifest") };
        assert_eq!((got.blocks, got.chunks.len()), (m.blocks, m.chunks.len()));

        let mut far = sending.await.unwrap();
        far.wr.write_all(&control_header(MAX_CONTROL as u32 + 1)).await.unwrap();
        far.wr.flush().await.unwrap();
        assert!(near.recv().await.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn handshake_failures_all_look_the_same() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let right = Key::from_secret("482913");
        let serving = tokio::spawn(async move { Link::handshake(b, &right, false).await.map(|_| ()) });
        let wrong = Link::handshake(a, &Key::from_secret("482914"), true).await.map(|_| ());
        assert!(wrong.unwrap_err().downcast_ref::<HandshakeFailed>().is_some());
        assert!(serving.await.unwrap().unwrap_err().downcast_ref::<HandshakeFailed>().is_some());

        // Garbage instead of a handshake.
        let (mut a, b) = tokio::io::duplex(1 << 16);
        let key = Key::from_secret("482913");
        let serving = tokio::spawn(async move { Link::handshake(b, &key, false).await.map(|_| ()) });
        a.write_all(&[0xff; 300]).await.unwrap();
        assert!(serving.await.unwrap().unwrap_err().downcast_ref::<HandshakeFailed>().is_some());
    }

    /// The handshake carries nothing a recorded copy can be tested against: two runs with the
    /// same secret share no bytes, so there is no fixed value for an offline guess to match.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_secret_never_keys_the_handshake_directly() {
        let key = Key::from_secret("482913");
        let mut seen = Vec::new();
        for _ in 0..2 {
            let (a, relay_a) = tokio::io::duplex(1 << 16);
            let (relay_b, b) = tokio::io::duplex(1 << 16);
            let (mut ar, mut aw) = tokio::io::split(relay_a);
            let (mut br, mut bw) = tokio::io::split(relay_b);
            let tap = Arc::new(Mutex::new(Vec::new()));
            let t = tap.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = ar.read(&mut buf).await {
                    if n == 0 || bw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    t.lock().unwrap().extend_from_slice(&buf[..n]);
                }
            });
            tokio::spawn(async move {
                let _ = tokio::io::copy(&mut br, &mut aw).await;
            });
            let k = key.clone();
            let serving = tokio::spawn(async move { Link::handshake(b, &k, false).await.map(|_| ()) });
            Link::handshake(a, &key, true).await.unwrap();
            serving.await.unwrap().unwrap();
            seen.push(tap.lock().unwrap().clone());
        }
        assert!(seen[0].len() > 80 && seen[0].len() == seen[1].len());
        let same = seen[0].iter().zip(&seen[1]).filter(|(x, y)| x == y).count();
        assert!(same < seen[0].len() / 2, "{same} of {} handshake bytes repeated", seen[0].len());
    }
}

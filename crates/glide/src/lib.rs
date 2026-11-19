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
//! Wire: Noise NNpsk0 handshake per stream, then 16-byte framed messages. Control frames are
//! Noise-encrypted; data blocks are sealed with AES-256-GCM (both sides have hardware AES) or
//! ChaCha20-Poly1305, keyed from the handshake hash. Files are cut with FastCDC (64 KiB to
//! 1 MiB, 256 KiB average) and every unique block is BLAKE3-addressed. The receiver pulls:
//! each stream keeps 32 blocks in flight, so faster streams simply ask more often.

use anyhow::{anyhow, bail, Result};
use glide_core::*;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

pub use glide_core;

const NOISE: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
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

/// The 32-byte pre-shared key. Derive it from whatever both sides know: the secret inside the
/// on-screen code, or a short PIN typed on one device.
#[derive(Clone)]
pub struct Key(pub [u8; 32]);
impl Key {
    pub fn from_secret(secret: &str) -> Key {
        Key(blake3::derive_key("nemi glide 2026 psk v1", secret.as_bytes()))
    }
}

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
    async fn handshake<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        stream: S,
        key: &Key,
        initiator: bool,
    ) -> Result<Link> {
        let (r, w) = tokio::io::split(stream);
        let mut rd: Rd = BufReader::with_capacity(1 << 20, Box::new(r));
        let mut wr: Wr = Box::new(w);
        let b = snow::Builder::new(NOISE.parse()?).psk(0, &key.0);
        let mut hs = if initiator { b.build_initiator()? } else { b.build_responder()? };
        let mut buf = [0u8; 256];
        let wrong = |_| anyhow!("handshake failed: wrong key");
        if initiator {
            let n = hs.write_message(&[], &mut buf)?;
            put16(&mut wr, &buf[..n]).await?;
            let m = get16(&mut rd).await?;
            hs.read_message(&m, &mut buf).map_err(wrong)?;
        } else {
            let m = get16(&mut rd).await?;
            hs.read_message(&m, &mut buf).map_err(wrong)?;
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
        self.wr.write_all(&control_header(payload.len() as u32)).await?;
        self.wr.write_all(&payload).await?;
        self.wr.flush().await?;
        Ok(())
    }
    async fn recv(&mut self) -> Result<Frame> {
        read_frame(&mut self.rd, &mut self.noise).await
    }
    fn data_key(&self, suite: u8) -> DataKey {
        derive_data_key(
            if suite == Suite::Aes256Gcm as u8 { Suite::Aes256Gcm } else { Suite::ChaCha20Poly1305 },
            &self.hh,
            "s2r",
        )
    }
}
async fn read_frame(rd: &mut Rd, noise: &mut snow::TransportState) -> Result<Frame> {
    let mut h = [0u8; HDR];
    rd.read_exact(&mut h).await?;
    let hd = parse_header(&h);
    if hd.len as usize > MAX_BLOCK + 65536 {
        bail!("frame too large");
    }
    let mut payload = vec![0u8; hd.len as usize];
    rd.read_exact(&mut payload).await?;
    match hd.kind {
        T_CONTROL => {
            let (mut plain, mut out, mut i) = (Vec::new(), vec![0u8; 65535], 0);
            while i + 2 <= payload.len() {
                let n = u16::from_be_bytes([payload[i], payload[i + 1]]) as usize;
                i += 2;
                if i + n > payload.len() {
                    bail!("bad control frame");
                }
                let k = noise.read_message(&payload[i..i + n], &mut out).map_err(|_| anyhow!("decrypt failed"))?;
                plain.extend_from_slice(&out[..k]);
                i += n;
            }
            Ok(Frame::Msg(bincode::deserialize(&plain)?))
        }
        T_DATA => Ok(Frame::Data { flags: hd.flags, id: hd.id, plain_len: hd.plain_len, sealed: payload }),
        _ => bail!("unknown frame"),
    }
}
async fn put16(w: &mut Wr, b: &[u8]) -> Result<()> {
    w.write_all(&(b.len() as u16).to_be_bytes()).await?;
    w.write_all(b).await?;
    w.flush().await?;
    Ok(())
}
async fn get16(r: &mut Rd) -> Result<Vec<u8>> {
    let mut l = [0u8; 2];
    r.read_exact(&mut l).await?;
    let mut b = vec![0u8; u16::from_be_bytes(l) as usize];
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
        let p = e?.path();
        if p.file_name().is_some_and(|n| n.to_string_lossy().starts_with(".glide-")) {
            continue;
        }
        if p.is_dir() {
            walk(base, &p, out)?;
        } else if p.is_file() {
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
        let mut h = blake3::Hasher::new();
        h.update(&bincode::serialize(&(&fes, &chunks))?);
        let mut session = [0u8; 16];
        session.copy_from_slice(&h.finalize().as_bytes()[..16]);
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
    let key = Arc::new(l.data_key(suite));
    let Link { mut rd, mut wr, mut noise, .. } = l;
    let (tx, mut ready) = tokio::sync::mpsc::unbounded_channel::<Result<(u32, u8, u32, Vec<u8>)>>();
    let reader = tokio::spawn(async move {
        loop {
            match read_frame(&mut rd, &mut noise).await? {
                Frame::Msg(Msg::Request { ids }) => {
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
    std::fs::create_dir_all(out)?;
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
        for f in &m.files {
            let p = out.join(&f.path);
            if p.is_file() {
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
    for f in &m.files {
        let p = out.join(&f.path);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
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
                let key = Arc::new(l.data_key(suite));
                let mut outstanding = 0;
                loop {
                    let ids: Vec<u32> = {
                        let mut g = sched.lock().unwrap();
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

//! `glide` command line: send, receive, and reproducible benchmarks.

use anyhow::{bail, Result};
use glide::{Key, Options, Order, Report, Sender};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};

const USAGE: &str = "\
glide: fast, offline, multi-stream file transfer

  glide send <file-or-folder> --listen <addr>[,<addr>...] --key <secret>
  glide recv --connect <addr>[,<addr>...] --key <secret> [--out DIR] [--seed DIR,...] [--order small|seq]
  glide bench                 crypto + hashing throughput of this machine
  glide bench-net [--mb N] [--streams N]   full protocol over loopback TCP

test shaping (sender): --limit-mbs 60,25   --kill-after-mb 150,0";

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}
fn nth(spec: &Option<String>, i: usize) -> Option<f64> {
    spec.as_ref()?.split(',').nth(i)?.trim().parse().ok().filter(|v: &f64| *v > 0.0)
}
fn mb(b: u64) -> f64 {
    b as f64 / 1e6
}

/// Wrap a TCP stream so its outgoing side is rate limited and/or cut after N bytes (tests only).
fn shaped(tcp: TcpStream, mbs: Option<f64>, kill: Option<u64>) -> DuplexStream {
    let (app, relay) = tokio::io::duplex(1 << 20);
    let (mut rr, mut rw) = tokio::io::split(relay);
    let (mut tr, mut tw) = tcp.into_split();
    tokio::spawn(async move {
        let (mut buf, t0, mut sent) = (vec![0u8; 64 * 1024], Instant::now(), 0u64);
        loop {
            let n = match rr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            sent += n as u64;
            if kill.is_some_and(|k| sent > k) {
                break;
            }
            if let Some(r) = mbs {
                let due = Duration::from_secs_f64(sent as f64 / (r * 1e6));
                if let Some(wait) = due.checked_sub(t0.elapsed()) {
                    tokio::time::sleep(wait).await;
                }
            }
            if tw.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = tw.shutdown().await;
    });
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut tr, &mut rw).await;
    });
    app
}

fn print_report(r: &Report) {
    eprintln!("\n  {} files, {:.1} MB in {:.2}s", r.files, mb(r.total), r.elapsed.as_secs_f64());
    eprintln!(
        "  received   {:>9.1} MB  {:>8.1} MB/s  ({:.1} MB on the wire)",
        mb(r.received),
        r.mb_per_sec(),
        mb(r.wire)
    );
    if r.deduplicated > 0 {
        eprintln!("  deduped    {:>9.1} MB  sent once", mb(r.deduplicated));
    }
    if r.reused > 0 {
        eprintln!("  reused     {:>9.1} MB  already on this device", mb(r.reused));
    }
    if r.per_stream.len() > 1 {
        for (i, b) in r.per_stream.iter().enumerate() {
            eprintln!("  stream {i}   {:>9.1} MB", mb(*b));
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("send") => {
            let path = PathBuf::from(args.get(2).cloned().unwrap_or_default());
            let key = Key::from_secret(&arg(&args, "--key").unwrap_or_default());
            let (limits, kills) = (arg(&args, "--limit-mbs"), arg(&args, "--kill-after-mb"));
            let t = Instant::now();
            let sender = Sender::new(&path)?;
            let m = sender.manifest();
            eprintln!(
                "ready: {} files, {:.1} MB, {} unique blocks, indexed in {:.2}s",
                m.files.len(),
                mb(m.total),
                m.blocks.len(),
                t.elapsed().as_secs_f64()
            );
            let mut handles = Vec::new();
            for (i, addr) in arg(&args, "--listen").unwrap_or("0.0.0.0:7001".into()).split(',').enumerate() {
                let l = TcpListener::bind(addr.trim()).await?;
                let (sender, key, lim, kill) =
                    (sender.clone(), key.clone(), nth(&limits, i), nth(&kills, i).map(|v| (v * 1e6) as u64));
                eprintln!("stream {i}: listening on {addr}");
                handles.push(tokio::spawn(async move {
                    loop {
                        let Ok((sock, peer)) = l.accept().await else { continue };
                        sock.set_nodelay(true).ok();
                        let (sender, key) = (sender.clone(), key.clone());
                        tokio::spawn(async move {
                            let r = if lim.is_some() || kill.is_some() {
                                sender.serve(shaped(sock, lim, kill), &key).await
                            } else {
                                sender.serve(sock, &key).await
                            };
                            match r {
                                Ok(b) => eprintln!("stream {i}: {peer} done, {:.1} MB sent", mb(b)),
                                Err(e) => eprintln!("stream {i}: {peer} ended: {e}"),
                            }
                        });
                    }
                }));
            }
            // Listeners run until the process is stopped.
            let _listeners = handles;
            std::future::pending::<()>().await;
        }
        Some("recv") => {
            let key = Key::from_secret(&arg(&args, "--key").unwrap_or_default());
            let mut streams = Vec::new();
            for a in arg(&args, "--connect").unwrap_or("127.0.0.1:7001".into()).split(',') {
                let s = TcpStream::connect(a.trim()).await?;
                s.set_nodelay(true).ok();
                streams.push(s);
            }
            let opts = Options {
                seeds: arg(&args, "--seed").map(|s| s.split(',').map(PathBuf::from).collect()).unwrap_or_default(),
                order: if arg(&args, "--order").as_deref() == Some("seq") {
                    Order::Sequential
                } else {
                    Order::SmallFirst
                },
                progress: Some(Arc::new(|d, t| {
                    eprint!("\r  {:>5.1}%  {:>8.1} / {:.1} MB   ", d as f64 * 100.0 / t.max(1) as f64, mb(d), mb(t))
                })),
            };
            let r = glide::receive(streams, &key, arg(&args, "--out").unwrap_or("received".into()), opts).await?;
            print_report(&r);
        }
        Some("bench") => bench_core(),
        Some("bench-net") => {
            let size: u64 = arg(&args, "--mb").and_then(|v| v.parse().ok()).unwrap_or(1024);
            let streams: usize = arg(&args, "--streams").and_then(|v| v.parse().ok()).unwrap_or(1);
            bench_net(size, streams).await?;
        }
        _ => bail!("{USAGE}"),
    }
    Ok(())
}

fn fill(buf: &mut [u8], seed: u64) {
    let mut x = seed | 1;
    for b in buf.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
}

fn bench_core() {
    use glide_core::*;
    use rayon::prelude::*;
    const B: usize = 256 * 1024;
    let n = 512;
    let data: Vec<Vec<u8>> = (0..n)
        .map(|i| {
            let mut v = vec![0u8; B];
            fill(&mut v, i as u64 + 1);
            v
        })
        .collect();
    let hashes: Vec<[u8; 32]> = data.iter().map(|d| *blake3::hash(d).as_bytes()).collect();
    println!("glide bench: {} cores, hardware AES {}", rayon::current_num_threads(), has_hw_aes());
    for (name, suite) in [("AES-256-GCM", Suite::Aes256Gcm), ("ChaCha20-Poly1305", Suite::ChaCha20Poly1305)] {
        let k = derive_data_key(suite, b"bench", "s2r");
        let send = |i: usize| {
            let mut b = data[i].clone();
            b.reserve(16);
            k.seal(i as u32, 0, B as u32, &mut b);
            b
        };
        let sealed: Vec<Vec<u8>> = (0..n).map(send).collect();
        let time = |f: &(dyn Fn(usize) + Sync), par: bool| {
            let t = Instant::now();
            if par {
                (0..n).into_par_iter().for_each(f)
            } else {
                (0..n).for_each(f)
            }
            (n * B) as f64 / 1e6 / t.elapsed().as_secs_f64()
        };
        let tx = |i: usize| {
            std::hint::black_box(send(i));
        };
        let rx = |i: usize| {
            let mut b = sealed[i].clone();
            k.open(i as u32, 0, B as u32, &mut b).unwrap();
            assert!(verify(&b, &hashes[i]));
        };
        println!(
            "  {name:<18} send {:>6.0} MB/s/core {:>7.0} MB/s all   receive {:>6.0} MB/s/core {:>7.0} MB/s all",
            time(&tx, false),
            time(&tx, true),
            time(&rx, false),
            time(&rx, true)
        );
    }
}

async fn bench_net(size_mb: u64, streams: usize) -> Result<()> {
    let dir = std::env::temp_dir().join(format!("glide-bench-{}", std::process::id()));
    let (src, out) = (dir.join("src"), dir.join("out"));
    std::fs::create_dir_all(&src)?;
    let file = src.join("payload.bin");
    let mut buf = vec![0u8; 8 << 20];
    let mut f = std::fs::File::create(&file)?;
    for i in 0..(size_mb * 1_000_000).div_ceil(buf.len() as u64) {
        fill(&mut buf, i + 7);
        std::io::Write::write_all(&mut f, &buf)?;
    }
    drop(f);
    let key = Key::from_secret("bench");
    let t = Instant::now();
    let sender = Sender::new(&src)?;
    let index = t.elapsed();
    let mut conns = Vec::new();
    for _ in 0..streams {
        let l = TcpListener::bind("127.0.0.1:0").await?;
        let addr = l.local_addr()?;
        let (s, k) = (sender.clone(), key.clone());
        tokio::spawn(async move {
            if let Ok((sock, _)) = l.accept().await {
                sock.set_nodelay(true).ok();
                let _ = s.serve(sock, &k).await;
            }
        });
        let c = TcpStream::connect(addr).await?;
        c.set_nodelay(true).ok();
        conns.push(c);
    }
    let r = glide::receive(conns, &key, &out, Options::default()).await?;
    let ok = same(&file, &out.join("payload.bin"))?;
    println!("glide bench-net: {:.0} MB, {} stream(s): indexed in {:.2}s ({:.0} MB/s), transfer {:.2}s = {:.0} MB/s, identical: {}",
        mb(r.total), streams, index.as_secs_f64(), mb(r.total) / index.as_secs_f64(), r.elapsed.as_secs_f64(), r.mb_per_sec(), ok);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
fn same(a: &Path, b: &Path) -> Result<bool> {
    let h = |p: &Path| -> Result<[u8; 32]> {
        let mut x = blake3::Hasher::new();
        x.update_reader(std::fs::File::open(p)?)?;
        Ok(*x.finalize().as_bytes())
    };
    Ok(h(a)? == h(b)?)
}

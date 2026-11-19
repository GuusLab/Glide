//! End-to-end tests over in-memory streams: no network, no sleeps, deterministic data.

use glide::{receive, Key, Options, Sender};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("glide-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}
fn write(p: &Path, data: &[u8]) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, data).unwrap();
}
fn same_tree(a: &Path, b: &Path) {
    for e in std::fs::read_dir(a).unwrap() {
        let p = e.unwrap().path();
        let q = b.join(p.file_name().unwrap());
        if p.is_dir() {
            same_tree(&p, &q)
        } else {
            assert_eq!(std::fs::read(&p).unwrap(), std::fs::read(&q).unwrap(), "{}", p.display());
        }
    }
}

/// Connect `n` in-memory streams to a sender. `cut[i] = Some(bytes)` drops stream i after that many bytes.
fn streams(sender: &Sender, key: &Key, cut: &[Option<usize>]) -> Vec<DuplexStream> {
    cut.iter()
        .map(|c| {
            let (client, server) = tokio::io::duplex(1 << 20);
            let (s, k) = (sender.clone(), key.clone());
            match *c {
                None => {
                    tokio::spawn(async move {
                        let _ = s.serve(server, &k).await;
                    });
                }
                Some(limit) => {
                    // relay that stops forwarding sender->receiver bytes after `limit`
                    let (inner_a, inner_b) = tokio::io::duplex(1 << 20);
                    tokio::spawn(async move {
                        let _ = s.serve(inner_b, &k).await;
                    });
                    let (mut ar, mut aw) = tokio::io::split(inner_a);
                    let (mut sr, mut sw) = tokio::io::split(server);
                    tokio::spawn(async move {
                        let _ = tokio::io::copy(&mut sr, &mut aw).await;
                    });
                    tokio::spawn(async move {
                        let (mut buf, mut sent) = (vec![0u8; 16384], 0);
                        while let Ok(n) = ar.read(&mut buf).await {
                            if n == 0 || sent + n > limit {
                                break;
                            }
                            sent += n;
                            if sw.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        let _ = sw.shutdown().await;
                    });
                }
            }
            client
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn folder_round_trip() {
    let d = tmp("folder");
    write(&d.join("src/a.bin"), &noise(3_000_000, 1));
    write(&d.join("src/notes/b.txt"), "glide ".repeat(200_000).as_bytes());
    write(&d.join("src/empty.txt"), b"");
    let key = Key::from_secret("123456");
    let s = Sender::new(d.join("src")).unwrap();
    let r = receive(streams(&s, &key, &[None]), &key, d.join("out"), Options::default()).await.unwrap();
    same_tree(&d.join("src"), &d.join("out"));
    assert_eq!(r.files, 3);
    assert!(r.wire < r.received, "text should compress");
}

#[tokio::test(flavor = "multi_thread")]
async fn many_streams_and_one_drops() {
    let d = tmp("multi");
    write(&d.join("src/big.bin"), &noise(24_000_000, 2));
    let key = Key::from_secret("k");
    let s = Sender::new(d.join("src")).unwrap();
    let r = receive(streams(&s, &key, &[None, Some(3_000_000), None]), &key, d.join("out"), Options::default())
        .await
        .unwrap();
    same_tree(&d.join("src"), &d.join("out"));
    assert_eq!(r.per_stream.len(), 3);
    assert!(r.per_stream[1] <= 3_000_000);
}

#[tokio::test(flavor = "multi_thread")]
async fn resume_after_total_failure() {
    let d = tmp("resume");
    write(&d.join("src/big.bin"), &noise(16_000_000, 3));
    let key = Key::from_secret("k");
    let s = Sender::new(d.join("src")).unwrap();
    let first = receive(streams(&s, &key, &[Some(6_000_000)]), &key, d.join("out"), Options::default()).await;
    assert!(first.is_err(), "the only stream died, so the first run is incomplete");
    let r = receive(streams(&s, &key, &[None]), &key, d.join("out"), Options::default()).await.unwrap();
    same_tree(&d.join("src"), &d.join("out"));
    assert!(r.received < 14_000_000, "second run fetched only what was missing ({} bytes)", r.received);
    assert!(std::fs::read_dir(d.join("out")).unwrap().all(|e| !e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".glide-")));
}

#[tokio::test(flavor = "multi_thread")]
async fn delta_sends_only_the_edit() {
    let d = tmp("delta");
    let v1 = noise(20_000_000, 4);
    let mut v2 = noise(500_000, 5);
    v2.extend_from_slice(&v1[..10_000_000]);
    v2.extend_from_slice(&noise(50_000, 6));
    v2.extend_from_slice(&v1[10_050_000..]);
    write(&d.join("src/video.mov"), &v2);
    write(&d.join("out/video.mov"), &v1);
    let key = Key::from_secret("k");
    let s = Sender::new(d.join("src")).unwrap();
    let r = receive(streams(&s, &key, &[None]), &key, d.join("out"), Options::default()).await.unwrap();
    same_tree(&d.join("src"), &d.join("out"));
    assert!(r.received < 2_500_000, "only the edit should cross: {} bytes", r.received);
    assert!(r.reused > 18_000_000);
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicates_cross_once() {
    let d = tmp("dedup");
    let clip = noise(8_000_000, 7);
    for n in ["a/clip.mp4", "b/copy.mp4", "c/again.mp4"] {
        write(&d.join("src").join(n), &clip);
    }
    let key = Key::from_secret("k");
    let s = Sender::new(d.join("src")).unwrap();
    let r = receive(streams(&s, &key, &[None]), &key, d.join("out"), Options::default()).await.unwrap();
    same_tree(&d.join("src"), &d.join("out"));
    assert_eq!(r.received, 8_000_000);
    assert_eq!(r.deduplicated, 16_000_000);
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_key_is_refused() {
    let d = tmp("key");
    write(&d.join("src/x.bin"), &noise(100_000, 8));
    let s = Sender::new(d.join("src")).unwrap();
    let st = streams(&s, &Key::from_secret("right"), &[None]);
    assert!(receive(st, &Key::from_secret("wrong"), d.join("out"), Options::default()).await.is_err());
}

/// The resume state says a block is there; the file says otherwise. The file wins.
#[tokio::test(flavor = "multi_thread")]
async fn resume_does_not_trust_its_own_state_file() {
    let d = tmp("resume-damaged");
    write(&d.join("src/big.bin"), &noise(16_000_000, 9));
    let key = Key::from_secret("k");
    let s = Sender::new(d.join("src")).unwrap();
    let first = receive(streams(&s, &key, &[Some(6_000_000)]), &key, d.join("out"), Options::default()).await;
    assert!(first.is_err());
    // Everything received so far is wiped from the file, while the state still claims it.
    std::fs::write(d.join("out/big.bin"), vec![0u8; 16_000_000]).unwrap();
    let r = receive(streams(&s, &key, &[None]), &key, d.join("out"), Options::default()).await.unwrap();
    same_tree(&d.join("src"), &d.join("out"));
    assert_eq!(r.received, 16_000_000, "every block was fetched again");
}

/// Same layout, different content: the second transfer must not inherit the first one's state.
#[tokio::test(flavor = "multi_thread")]
async fn a_changed_file_does_not_resume_the_old_one() {
    let d = tmp("resume-changed");
    let v1 = noise(16_000_000, 10);
    write(&d.join("src/big.bin"), &v1);
    let key = Key::from_secret("k");
    let s = Sender::new(d.join("src")).unwrap();
    assert!(receive(streams(&s, &key, &[Some(6_000_000)]), &key, d.join("out"), Options::default()).await.is_err());
    // Flip one byte per megabyte: the cut points stay where they were, the content does not.
    let mut v2 = v1.clone();
    for i in (500_000..v2.len()).step_by(1_000_000) {
        v2[i] ^= 0xff;
    }
    write(&d.join("src/big.bin"), &v2);
    let s2 = Sender::new(d.join("src")).unwrap();
    assert_ne!(s.manifest().session, s2.manifest().session);
    receive(streams(&s2, &key, &[None]), &key, d.join("out"), Options::default()).await.unwrap();
    same_tree(&d.join("src"), &d.join("out"));
}

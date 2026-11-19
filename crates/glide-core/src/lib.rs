//! Sans-I/O core of Glide: wire format and bulk crypto. No sockets, no async, no OS calls,
//! so the same code compiles natively and to WebAssembly.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;

pub const MAX_BLOCK: usize = 1024 * 1024;
pub const HDR: usize = 16;
pub const T_CONTROL: u8 = 1;
pub const T_DATA: u8 = 2;
pub const F_ZSTD: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Suite {
    Aes256Gcm = 1,
    ChaCha20Poly1305 = 2,
}

/// Does this machine have hardware AES? (AES-GCM wins with it, ChaCha20 wins without.)
pub fn has_hw_aes() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        return std::arch::is_x86_feature_detected!("aes") && std::arch::is_x86_feature_detected!("pclmulqdq");
    }
    #[cfg(target_arch = "aarch64")]
    {
        return std::arch::is_aarch64_feature_detected!("aes");
    }
    #[allow(unreachable_code)]
    false
}

/// A sealed block failed authentication: wrong key, or the bytes were changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthError;
impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("authentication failed")
    }
}
impl std::error::Error for AuthError {}

pub enum DataKey {
    Aes(Box<Aes256Gcm>),
    Cha(Box<ChaCha20Poly1305>),
}

/// Derive the bulk key for one direction from the Noise handshake hash.
pub fn derive_data_key(suite: Suite, handshake_hash: &[u8], direction: &str) -> DataKey {
    let mut ctx = String::from("nemi glide 2026 data ");
    ctx.push_str(direction);
    let k = blake3::derive_key(&ctx, handshake_hash);
    match suite {
        Suite::Aes256Gcm => DataKey::Aes(Box::new(Aes256Gcm::new_from_slice(&k).unwrap())),
        Suite::ChaCha20Poly1305 => DataKey::Cha(Box::new(ChaCha20Poly1305::new_from_slice(&k).unwrap())),
    }
}

/// Deterministic per-chunk nonce. Re-sending a chunk re-encrypts the same plaintext under the
/// same nonce, which gives the same ciphertext and leaks nothing new.
fn nonce(id: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0] = b'G';
    n[1] = b'D';
    n[8..].copy_from_slice(&id.to_be_bytes());
    n
}

/// Data frame header (16 bytes): type, flags, 2 reserved, chunk id, plain length, payload length.
pub fn data_header(flags: u8, id: u32, plain_len: u32, payload_len: u32) -> [u8; HDR] {
    let mut h = [0u8; HDR];
    h[0] = T_DATA;
    h[1] = flags;
    h[4..8].copy_from_slice(&id.to_be_bytes());
    h[8..12].copy_from_slice(&plain_len.to_be_bytes());
    h[12..16].copy_from_slice(&payload_len.to_be_bytes());
    h
}
pub fn control_header(payload_len: u32) -> [u8; HDR] {
    let mut h = [0u8; HDR];
    h[0] = T_CONTROL;
    h[12..16].copy_from_slice(&payload_len.to_be_bytes());
    h
}
pub struct Header {
    pub kind: u8,
    pub flags: u8,
    pub id: u32,
    pub plain_len: u32,
    pub len: u32,
}
pub fn parse_header(h: &[u8; HDR]) -> Header {
    Header {
        kind: h[0],
        flags: h[1],
        id: u32::from_be_bytes(h[4..8].try_into().unwrap()),
        plain_len: u32::from_be_bytes(h[8..12].try_into().unwrap()),
        len: u32::from_be_bytes(h[12..16].try_into().unwrap()),
    }
}

impl DataKey {
    /// Encrypt in place and append the 16-byte tag. The header fields are authenticated.
    pub fn seal(&self, id: u32, flags: u8, plain_len: u32, buf: &mut Vec<u8>) {
        let aad = data_header(flags, id, plain_len, 0);
        let n = nonce(id);
        match self {
            DataKey::Aes(k) => k.encrypt_in_place(Nonce::from_slice(&n), &aad[..12], buf).expect("seal"),
            DataKey::Cha(k) => {
                k.encrypt_in_place(chacha20poly1305::Nonce::from_slice(&n), &aad[..12], buf).expect("seal")
            }
        }
    }
    pub fn open(&self, id: u32, flags: u8, plain_len: u32, buf: &mut Vec<u8>) -> Result<(), AuthError> {
        let aad = data_header(flags, id, plain_len, 0);
        let n = nonce(id);
        match self {
            DataKey::Aes(k) => k.decrypt_in_place(Nonce::from_slice(&n), &aad[..12], buf).map_err(|_| AuthError),
            DataKey::Cha(k) => {
                k.decrypt_in_place(chacha20poly1305::Nonce::from_slice(&n), &aad[..12], buf).map_err(|_| AuthError)
            }
        }
    }
}

pub fn verify(data: &[u8], expected: &[u8; 32]) -> bool {
    blake3::hash(data).as_bytes() == expected
}

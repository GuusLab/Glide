//! Sans-I/O core of Glide: wire format and bulk crypto. No sockets, no async, no OS calls,
//! so the same code compiles natively and to WebAssembly.

#![forbid(unsafe_code)]

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;

pub const MAX_BLOCK: usize = 1024 * 1024;
pub const HDR: usize = 16;
pub const T_CONTROL: u8 = 1;
pub const T_DATA: u8 = 2;
pub const F_ZSTD: u8 = 1;
/// Every flag bit this version understands. A frame with any other bit set is refused.
pub const F_KNOWN: u8 = F_ZSTD;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Suite {
    Aes256Gcm = 1,
    ChaCha20Poly1305 = 2,
}
impl Suite {
    /// The suite a wire byte names, or `None` for a value this version does not know.
    /// An unknown value is never mapped to a default: the peer chose something we cannot do.
    pub fn from_wire(b: u8) -> Option<Suite> {
        match b {
            1 => Some(Suite::Aes256Gcm),
            2 => Some(Suite::ChaCha20Poly1305),
            _ => None,
        }
    }
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

/// Deterministic nonce per (block, flags). Re-sending a block re-encrypts the same plaintext under
/// the same nonce, which gives the same ciphertext and leaks nothing new.
///
/// The flags are part of the nonce on purpose. The sender decides per request whether a block goes
/// out compressed or raw, so the same block id can be sealed in two forms on one stream (a block
/// that failed verification is asked for again). Those are two different plaintexts, and under one
/// nonce that would hand an eavesdropper the XOR of the two and, with GCM, the authentication key.
/// With the flags in the nonce each form has its own, and each form is still deterministic.
fn nonce(id: u32, flags: u8) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0] = b'G';
    n[1] = b'D';
    n[2] = flags;
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
        let n = nonce(id, flags);
        match self {
            DataKey::Aes(k) => k.encrypt_in_place(Nonce::from_slice(&n), &aad[..12], buf).expect("seal"),
            DataKey::Cha(k) => {
                k.encrypt_in_place(chacha20poly1305::Nonce::from_slice(&n), &aad[..12], buf).expect("seal")
            }
        }
    }
    pub fn open(&self, id: u32, flags: u8, plain_len: u32, buf: &mut Vec<u8>) -> Result<(), AuthError> {
        if flags & !F_KNOWN != 0 {
            return Err(AuthError);
        }
        let aad = data_header(flags, id, plain_len, 0);
        let n = nonce(id, flags);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> [DataKey; 2] {
        [derive_data_key(Suite::Aes256Gcm, b"hh", "s2r"), derive_data_key(Suite::ChaCha20Poly1305, b"hh", "s2r")]
    }

    #[test]
    fn seal_then_open() {
        for k in keys() {
            let mut b = b"hello glide".to_vec();
            k.seal(7, 0, 11, &mut b);
            assert_eq!(b.len(), 11 + 16);
            k.open(7, 0, 11, &mut b).unwrap();
            assert_eq!(b, b"hello glide");
        }
    }

    #[test]
    fn every_authenticated_field_is_checked() {
        for k in keys() {
            let mut sealed = b"hello glide".to_vec();
            k.seal(7, 0, 11, &mut sealed);
            for (id, flags, len) in [(8, 0, 11), (7, F_ZSTD, 11), (7, 0, 12)] {
                assert!(k.open(id, flags, len, &mut sealed.clone()).is_err());
            }
            let mut flipped = sealed.clone();
            flipped[3] ^= 1;
            assert!(k.open(7, 0, 11, &mut flipped).is_err());
            assert!(k.open(7, 0x80, 11, &mut sealed.clone()).is_err(), "unknown flag bits are refused");
        }
    }

    /// The same block sealed raw and compressed must never share a keystream.
    #[test]
    fn raw_and_compressed_forms_use_different_nonces() {
        for k in keys() {
            let (mut a, mut b) = (vec![0u8; 64], vec![0u8; 64]);
            k.seal(7, 0, 64, &mut a);
            k.seal(7, F_ZSTD, 64, &mut b);
            assert_ne!(a[..64], b[..64]);
        }
    }

    #[test]
    fn unknown_suite_is_not_a_default() {
        assert_eq!(Suite::from_wire(1), Some(Suite::Aes256Gcm));
        assert_eq!(Suite::from_wire(2), Some(Suite::ChaCha20Poly1305));
        assert_eq!(Suite::from_wire(0), None);
        assert_eq!(Suite::from_wire(3), None);
    }
}

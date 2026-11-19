// Glide core for the web: the exact same core.rs as native, exported with a plain C ABI.

use glide_core::*;
use std::alloc::{alloc, dealloc, Layout};

#[no_mangle]
pub extern "C" fn g_alloc(n: usize) -> *mut u8 {
    unsafe { alloc(Layout::from_size_align_unchecked(n.max(1), 8)) }
}
#[no_mangle]
pub extern "C" fn g_free(p: *mut u8, n: usize) {
    unsafe { dealloc(p, Layout::from_size_align_unchecked(n.max(1), 8)) }
}

static mut KEY: Option<DataKey> = None;
/// suite 1 = AES-256-GCM, 2 = ChaCha20-Poly1305; key derived from a handshake hash
#[no_mangle]
pub extern "C" fn g_key(suite: u32, hh: *const u8, len: usize) {
    let h = unsafe { std::slice::from_raw_parts(hh, len) };
    let s = if suite == 1 { Suite::Aes256Gcm } else { Suite::ChaCha20Poly1305 };
    unsafe {
        KEY = Some(derive_data_key(s, h, "s2r"));
    }
}
/// open a sealed chunk in place (len includes the 16-byte tag); returns plain length or -1
#[allow(static_mut_refs)]
#[no_mangle]
pub extern "C" fn g_open(id: u32, flags: u32, plain_len: u32, p: *mut u8, len: usize) -> i32 {
    let mut v = unsafe { Vec::from_raw_parts(p, len, len) };
    let r = unsafe { KEY.as_ref().unwrap().open(id, flags as u8, plain_len, &mut v) };
    let n = v.len();
    std::mem::forget(v);
    if r.is_ok() {
        n as i32
    } else {
        -1
    }
}
/// seal in place: buffer must have room for 16 extra bytes (cap = len + 16)
#[allow(static_mut_refs)]
#[no_mangle]
pub extern "C" fn g_seal(id: u32, flags: u32, p: *mut u8, len: usize) -> usize {
    let mut v = unsafe { Vec::from_raw_parts(p, len, len + 16) };
    unsafe { KEY.as_ref().unwrap().seal(id, flags as u8, len as u32, &mut v) };
    let n = v.len();
    std::mem::forget(v);
    n
}
/// BLAKE3 of a buffer into out[32]
#[no_mangle]
pub extern "C" fn g_hash(p: *const u8, len: usize, out: *mut u8) {
    let h = blake3::hash(unsafe { std::slice::from_raw_parts(p, len) });
    unsafe { std::ptr::copy_nonoverlapping(h.as_bytes().as_ptr(), out, 32) };
}

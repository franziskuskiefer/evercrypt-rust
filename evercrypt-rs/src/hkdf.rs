//! HKDF
//!
//! This module implements HKDF on SHA 1 and SHA 2 (except for SHA 224).
//!
//! # Usage
//!
//! ```rust
//! use evercrypt::prelude::*;
//!
//! let key = [0x85, 0xa7, 0xcb, 0xaa, 0xe8, 0x25, 0xbb, 0x82, 0xc9, 0xb6, 0xf6, 0xc5, 0xc2, 0xaf, 0x5a, 0xc0, 0x3d, 0x1f, 0x6d, 0xaa, 0x63, 0xd2, 0xa9, 0x3c, 0x18, 0x99, 0x48, 0xec, 0x41, 0xb9, 0xde, 0xd9];
//! let data = [0xa5, 0x9b];
//! let expected_tag = [0x0f, 0xe2, 0xf1, 0x3b, 0xba, 0x21, 0x98, 0xf6, 0xdd, 0xa1, 0xa0, 0x84, 0xbe, 0x92, 0x8e, 0x30, 0x4e, 0x9c, 0xb1, 0x6a, 0x56, 0xbc, 0x0b, 0x7b, 0x93, 0x9a, 0x07, 0x32, 0x80, 0x24, 0x43, 0x73];
//! let len = 32;
//!
//! let tag = hmac(HmacMode::Sha256, &key, &data, Some(len));
//! assert_eq!(expected_tag[..], tag[..]);
//! ```

use evercrypt_sys::evercrypt_bindings::*;

use crate::hmac::{tag_size, Mode};

/// HKDF extract using hash function `mode`, `salt`, and the input key material `ikm`.
/// Returns the pre-key material in a vector of tag length.
pub fn extract(mode: Mode, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let mut prk = vec![0u8; tag_size(mode)];
    unsafe {
        EverCrypt_HKDF_extract(
            mode as u8,
            prk.as_mut_ptr(),
            salt.as_ptr() as _,
            salt.len() as u32,
            ikm.as_ptr() as _,
            ikm.len() as u32,
        );
    }
    prk
}

/// HKDF expand using hash function `mode`, pre-key material `prk`, `info`, and output length `okm_len`.
/// Returns the key material in a vector of length `okm_len`.
pub fn expand(mode: Mode, prk: &[u8], info: &[u8], okm_len: usize) -> Vec<u8> {
    if okm_len > 255 * tag_size(mode) {
        // Output size is too large. HACL doesn't catch this.
        return Vec::new();
    }
    let mut okm = vec![0u8; okm_len];
    unsafe {
        EverCrypt_HKDF_expand(
            mode as u8,
            okm.as_mut_ptr(),
            prk.as_ptr() as _,
            prk.len() as u32,
            info.as_ptr() as _,
            info.len() as u32,
            okm_len as u32,
        );
    }
    okm
}

/// HKDF using hash function `mode`, `salt`, input key material `ikm`, `info`, and output length `okm_len`.
/// Calls `extract` and `expand` with the given input.
/// Returns the key material in a vector of length `okm_len`.
pub fn hkdf(mode: Mode, salt: &[u8], ikm: &[u8], info: &[u8], okm_len: usize) -> Vec<u8> {
    let prk = extract(mode, salt, ikm);
    expand(mode, &prk, info, okm_len)
}

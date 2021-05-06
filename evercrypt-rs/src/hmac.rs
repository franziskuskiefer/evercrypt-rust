//! HMAC
//!
//! This module implements HMAC on SHA 1 and SHA 2 (except for SHA 224).
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

#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

use evercrypt_sys::evercrypt_bindings::*;

/// The HMAC mode defining the used hash function.
#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
pub enum Mode {
    Sha1 = Spec_Hash_Definitions_SHA1 as isize,
    // Not implemented
    // Sha224 = Spec_Hash_Definitions_SHA2_224 as isize,
    Sha256 = Spec_Hash_Definitions_SHA2_256 as isize,
    Sha384 = Spec_Hash_Definitions_SHA2_384 as isize,
    Sha512 = Spec_Hash_Definitions_SHA2_512 as isize,
}

#[deprecated(
    since = "0.0.10",
    note = "Please use tag_size instead. This alias will be removed with the first stable 0.1 release."
)]
pub fn get_tag_size(mode: Mode) -> usize {
    tag_size(mode)
}

/// Get the tag size for a given mode.
pub const fn tag_size(mode: Mode) -> usize {
    match mode {
        Mode::Sha1 => 20,
        Mode::Sha256 => 32,
        Mode::Sha384 => 48,
        Mode::Sha512 => 64,
    }
}

/// Compute the HMAC value with the given `mode` and `key` on `data` with an
/// output tag length of `tag_length`.
/// Returns a vector of length `tag_length`.
pub fn hmac(mode: Mode, key: &[u8], data: &[u8], tag_length: Option<usize>) -> Vec<u8> {
    let native_tag_length = tag_size(mode);
    let tag_length = match tag_length {
        Some(v) => v,
        None => native_tag_length,
    };
    let mut dst = vec![0u8; native_tag_length];
    unsafe {
        EverCrypt_HMAC_compute(
            mode as u8,
            dst.as_mut_ptr(),
            key.as_ptr() as _,
            key.len() as u32,
            data.as_ptr() as _,
            data.len() as u32,
        );
    }
    dst.truncate(tag_length);
    dst
}

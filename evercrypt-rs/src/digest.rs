//! Hashing
//!
//! This module implements the SHA 1 and SHA 2 hash functions.
//!
//! # Usage
//! This module provides two APIs
//!
//! ## Stateful Hashing
//! ```rust
//! use evercrypt::digest::{Digest, Mode};
//!
//! let expected_digest_256 = [
//!     0xa5, 0x35, 0xf2, 0x6a, 0xff, 0xbc, 0x1f, 0x08, 0x73, 0xdb, 0x15, 0x15, 0x9d, 0xce, 0xbf,
//!     0x25, 0x99, 0x64, 0xbe, 0x42, 0xde, 0xa8, 0x4d, 0x29, 0x00, 0x38, 0x4b, 0xee, 0x15, 0x09,
//!     0xe4, 0x00,
//! ];
//! let expected_digest_512 = [
//!     0x36, 0x97, 0x36, 0x7c, 0xc9, 0x1e, 0xda, 0xa7, 0x6d, 0xb8, 0x03, 0x39, 0x61, 0x5f, 0xc2,
//!     0x12, 0xe1, 0x5e, 0x64, 0x3e, 0x31, 0x30, 0xf7, 0x1f, 0x28, 0xd0, 0x3f, 0x34, 0x3d, 0xf4,
//!     0x88, 0x0a, 0xd3, 0x6c, 0x63, 0xe5, 0x35, 0x1f, 0x56, 0xe0, 0xf7, 0xe0, 0x4c, 0x24, 0x96,
//!     0xc0, 0xb3, 0x6b, 0xcf, 0x7c, 0x5d, 0xcb, 0xf3, 0x5e, 0x38, 0xe9, 0xbb, 0x44, 0xf8, 0xa0,
//!     0xc2, 0x83, 0x42, 0x4e,
//! ];
//!
//! let data = b"evercrypt-rust bindings";
//!
//! let mut digest_256 = Digest::new(Mode::Sha256).unwrap();
//! if digest_256.update(data).is_err() {
//!     panic!("Error hashing.");
//! }
//! let digest_256_result = match digest_256.finish() {
//!     Ok(d) => d,
//!     Err(e) => panic!("Finish digest failed.\n{:?}", e),
//! };
//!
//! let mut digest_512 = Digest::new(Mode::Sha512).unwrap();
//! if digest_512.update(data).is_err() {
//!     panic!("Error hashing.");
//! }
//! let digest_512_result = match digest_512.finish() {
//!     Ok(d) => d,
//!     Err(e) => panic!("Finish digest failed.\n{:?}", e),
//! };
//!
//! assert_eq!(&digest_256_result[..], &expected_digest_256[..]);
//! assert_eq!(&digest_512_result[..], &expected_digest_512[..]);
//! ```
//!
//! ## Single-shot API
//! ```rust
//! use evercrypt::digest::{self, Mode};
//!
//! let expected_digest_256 = [
//!     0xa5, 0x35, 0xf2, 0x6a, 0xff, 0xbc, 0x1f, 0x08, 0x73, 0xdb, 0x15, 0x15, 0x9d, 0xce, 0xbf,
//!     0x25, 0x99, 0x64, 0xbe, 0x42, 0xde, 0xa8, 0x4d, 0x29, 0x00, 0x38, 0x4b, 0xee, 0x15, 0x09,
//!     0xe4, 0x00,
//! ];
//! let expected_digest_512 = [
//!     0x36, 0x97, 0x36, 0x7c, 0xc9, 0x1e, 0xda, 0xa7, 0x6d, 0xb8, 0x03, 0x39, 0x61, 0x5f, 0xc2,
//!     0x12, 0xe1, 0x5e, 0x64, 0x3e, 0x31, 0x30, 0xf7, 0x1f, 0x28, 0xd0, 0x3f, 0x34, 0x3d, 0xf4,
//!     0x88, 0x0a, 0xd3, 0x6c, 0x63, 0xe5, 0x35, 0x1f, 0x56, 0xe0, 0xf7, 0xe0, 0x4c, 0x24, 0x96,
//!     0xc0, 0xb3, 0x6b, 0xcf, 0x7c, 0x5d, 0xcb, 0xf3, 0x5e, 0x38, 0xe9, 0xbb, 0x44, 0xf8, 0xa0,
//!     0xc2, 0x83, 0x42, 0x4e,
//! ];
//!
//! let data = b"evercrypt-rust bindings";
//!
//! let digest_256 = digest::hash(Mode::Sha256, data);
//! let digest_512 = digest::hash(Mode::Sha512, data);
//!
//! assert_eq!(&digest_256[..], &expected_digest_256[..]);
//! assert_eq!(&digest_512[..], &expected_digest_512[..]);
//!
//! let digest_256 = digest::sha256(data);
//! let digest_512 = digest::sha512(data);
//!
//! assert_eq!(&digest_256[..], &expected_digest_256[..]);
//! assert_eq!(&digest_512[..], &expected_digest_512[..]);
//! ```
//!
//! ## SHA 3
//! ```rust
//! use evercrypt::digest::{self, Mode};
//!
//! let data = b"evercrypt-rust bindings";
//! let expected_digest_3_256 = [
//!     0x49, 0x4b, 0xc2, 0xea, 0x73, 0x43, 0x4f, 0x88, 0x62, 0x56, 0x13, 0x39, 0xda, 0x1a, 0x6d,
//!     0x58, 0x05, 0xee, 0x34, 0x4b, 0x67, 0x5d, 0x18, 0xfb, 0x9a, 0x81, 0xca, 0x65, 0xa7, 0x8f,
//!     0xeb, 0x6e,
//! ];
//! let expected_digest_3_512 = [
//!     0x7a, 0xaa, 0x97, 0x5c, 0x6b, 0x15, 0x5b, 0x55, 0xd3, 0x7b, 0xa6, 0x99, 0x3f, 0x7e, 0x14,
//!     0xd9, 0x8c, 0x28, 0x0d, 0x2b, 0x2f, 0xc2, 0x4a, 0xa7, 0x84, 0x07, 0xcf, 0x15, 0x2d, 0x0a,
//!     0xca, 0xbc, 0x32, 0xf2, 0x11, 0xf4, 0x64, 0x30, 0x19, 0x0a, 0x35, 0x26, 0x94, 0x76, 0x84,
//!     0x2a, 0x1f, 0x17, 0x41, 0xad, 0x46, 0x06, 0xf6, 0xc8, 0xc6, 0xad, 0x8d, 0x02, 0x2e, 0x85,
//!     0xb4, 0x9d, 0x6b, 0xd7,
//! ];
//!
//! assert_eq!(digest::hash(Mode::Sha3_256, data), expected_digest_3_256);
//! assert_eq!(
//!     digest::hash(Mode::Sha3_512, data)[..],
//!     expected_digest_3_512[..]
//! );
//! ```
//!
//! ## SHAKE
//! ```rust
//! use evercrypt::digest::{self, Mode};
//!
//! let data = b"evercrypt-rust bindings";
//! let expected_digest_128 = [
//!     0xfd, 0x3b, 0x31, 0x35, 0x35, 0x05, 0x87, 0xd5, 0x36, 0x2a, 0xae, 0x4d, 0x1c, 0x8a, 0x25,
//!     0xba, 0xa4, 0xec, 0x82, 0xef, 0xff, 0xb8, 0x27, 0x1c, 0x91, 0x20, 0xa2, 0xed, 0x53, 0x17,
//!     0x2a, 0xcc, 0x97, 0x97, 0x34, 0x65, 0x1e, 0x69, 0xb3, 0xb3, 0x27, 0x09, 0x4c, 0xc0, 0x5e,
//!     0xde, 0x3b, 0x5d, 0xf9, 0x98, 0xe6, 0x37, 0xce, 0x06, 0xb3, 0xa0, 0x53, 0xdf, 0x81, 0x80,
//!     0x99, 0x8c, 0xfc, 0x95,
//! ];
//! let expected_digest_256 = [
//!     0xf0, 0x85, 0x60, 0x6b, 0xed, 0xca, 0x25, 0xe4, 0x3c, 0x97, 0x05, 0x0f, 0xf2, 0x3e, 0xe0,
//!     0xd9, 0xe5, 0x89, 0x14, 0xff, 0xbb, 0x30, 0x5a, 0x00, 0x26, 0x30, 0x1c, 0x25, 0x7a, 0x5a,
//!     0xeb, 0x50, 0x7e, 0x4b, 0x21, 0x19, 0x53, 0x3f, 0xf7, 0x23, 0xc7, 0xe1, 0xad, 0xc5, 0xdf,
//!     0x2a, 0x62, 0x1d, 0xad, 0x18, 0xa4, 0x46, 0xaf, 0xeb, 0x2a, 0x54, 0xb3, 0xad, 0xfe, 0xc7,
//!     0x8e, 0x08, 0x6a, 0x6f,
//! ];
//!
//! assert_eq!(digest::shake128(data, 64)[..], expected_digest_128[..]);
//! assert_eq!(digest::shake256(data, 64)[..], expected_digest_256[..]);
//! ```
//!
//! ## Blake2b
//! ```rust
//! use evercrypt::digest::{self, Mode};
//!
//! let data = [
//!     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
//!     0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
//!     0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
//!     0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
//!     0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a,
//!     0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
//!     0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
//!     0x69, 0x6a,
//! ];
//! let expected_digest = [
//!     0x22, 0xef, 0xf8, 0xe6, 0xdd, 0x52, 0x36, 0xf5, 0xf5, 0x7d, 0x94, 0xed, 0xe8, 0x74, 0xd6,
//!     0xc9, 0x42, 0x8e, 0x8f, 0x5d, 0x56, 0x6f, 0x17, 0xcd, 0x6d, 0x18, 0x48, 0xcd, 0x75, 0x2f,
//!     0xe1, 0x3c, 0x65, 0x5c, 0xb1, 0x0f, 0xba, 0xaf, 0xf7, 0x68, 0x72, 0xf2, 0xbf, 0x2d, 0xa9,
//!     0x9e, 0x15, 0xdc, 0x62, 0x40, 0x75, 0xe1, 0xec, 0x2f, 0x58, 0xa3, 0xf6, 0x40, 0x72, 0x12,
//!     0x18, 0x38, 0x56, 0x9e,
//! ];
//!
//! assert_eq!(digest::hash(Mode::Blake2b, &data)[..], expected_digest[..]);
//! ```
//!
//! ## Blake2s
//! ```rust
//! use evercrypt::digest::{self, Mode};
//!
//! let data = [
//!     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
//!     0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
//!     0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
//!     0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
//! ];
//! let expected_digest = [
//!     0xe2, 0x90, 0xdd, 0x27, 0x0b, 0x46, 0x7f, 0x34, 0xab, 0x1c, 0x00, 0x2d, 0x34, 0x0f, 0xa0,
//!     0x16, 0x25, 0x7f, 0xf1, 0x9e, 0x58, 0x33, 0xfd, 0xbb, 0xf2, 0xcb, 0x40, 0x1c, 0x3b, 0x28,
//!     0x17, 0xde,
//! ];
//!
//! assert_eq!(digest::hash(Mode::Blake2s, &data), expected_digest);
//! ```

#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

use evercrypt_sys::evercrypt_bindings::*;

#[derive(Debug)]
pub enum Error {
    InvalidStateFinished,
    ModeUnsupportedForStreaming,
}

/// The Digest Mode.
#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
pub enum Mode {
    Sha1 = Spec_Hash_Definitions_SHA1 as isize,
    Sha224 = Spec_Hash_Definitions_SHA2_224 as isize,
    Sha256 = Spec_Hash_Definitions_SHA2_256 as isize,
    Sha384 = Spec_Hash_Definitions_SHA2_384 as isize,
    Sha512 = Spec_Hash_Definitions_SHA2_512 as isize,
    Blake2s = Spec_Hash_Definitions_Blake2S as isize,
    Blake2b = Spec_Hash_Definitions_Blake2B as isize,
    // XXX: The following is not in evercrypt (agile API) so we define something here.
    Sha3_224 = 8,
    Sha3_256 = 9,
    Sha3_384 = 10,
    Sha3_512 = 11,
}

#[allow(non_upper_case_globals)]
impl From<u32> for Mode {
    fn from(v: u32) -> Mode {
        match v {
            Spec_Hash_Definitions_SHA1 => Mode::Sha1,
            Spec_Hash_Definitions_SHA2_224 => Mode::Sha224,
            Spec_Hash_Definitions_SHA2_256 => Mode::Sha256,
            Spec_Hash_Definitions_SHA2_384 => Mode::Sha384,
            Spec_Hash_Definitions_SHA2_512 => Mode::Sha512,
            Spec_Hash_Definitions_Blake2S => Mode::Blake2s,
            Spec_Hash_Definitions_Blake2B => Mode::Blake2b,
            8 => Mode::Sha3_224,
            9 => Mode::Sha3_256,
            10 => Mode::Sha3_384,
            11 => Mode::Sha3_512,
            _ => panic!("Unknown Digest mode {}", v),
        }
    }
}

impl From<Mode> for Spec_Hash_Definitions_hash_alg {
    fn from(v: Mode) -> Spec_Hash_Definitions_hash_alg {
        match v {
            Mode::Sha1 => Spec_Hash_Definitions_SHA1 as Spec_Hash_Definitions_hash_alg,
            Mode::Sha224 => Spec_Hash_Definitions_SHA2_224 as Spec_Hash_Definitions_hash_alg,
            Mode::Sha256 => Spec_Hash_Definitions_SHA2_256 as Spec_Hash_Definitions_hash_alg,
            Mode::Sha384 => Spec_Hash_Definitions_SHA2_384 as Spec_Hash_Definitions_hash_alg,
            Mode::Sha512 => Spec_Hash_Definitions_SHA2_512 as Spec_Hash_Definitions_hash_alg,
            Mode::Blake2s => Spec_Hash_Definitions_Blake2S as Spec_Hash_Definitions_hash_alg,
            Mode::Blake2b => Spec_Hash_Definitions_Blake2B as Spec_Hash_Definitions_hash_alg,
            Mode::Sha3_224 => 8,
            Mode::Sha3_256 => 9,
            Mode::Sha3_384 => 10,
            Mode::Sha3_512 => 11,
        }
    }
}

#[deprecated(
    since = "0.0.10",
    note = "Please use digest_size instead. This alias will be removed with the first stable 0.1 release."
)]
pub fn get_digest_size(mode: Mode) -> usize {
    digest_size(mode)
}

/// Returns the output size of a digest.
pub const fn digest_size(mode: Mode) -> usize {
    match mode {
        Mode::Sha1 => 20,
        Mode::Sha224 => 28,
        Mode::Sha256 => 32,
        Mode::Sha384 => 48,
        Mode::Sha512 => 64,
        Mode::Blake2s => 32,
        Mode::Blake2b => 64,
        Mode::Sha3_224 => 28,
        Mode::Sha3_256 => 32,
        Mode::Sha3_384 => 48,
        Mode::Sha3_512 => 64,
    }
}

/// Check if we do SHA3, which is not in the agile API and hence has to be
/// handled differently.
const fn is_sha3(alg: Mode) -> bool {
    matches!(
        alg,
        Mode::Sha3_224 | Mode::Sha3_256 | Mode::Sha3_384 | Mode::Sha3_512
    )
}

/// The digest struct for stateful hashing.
pub struct Digest {
    mode: Mode,
    finished: bool,
    c_state: *mut Hacl_Streaming_Functor_state_s___EverCrypt_Hash_state_s____,
}

impl Digest {
    /// Create a new digest for the given mode `alg`.
    pub fn new(alg: Mode) -> Result<Self, Error> {
        if is_sha3(alg) {
            return Err(Error::ModeUnsupportedForStreaming);
        }

        let c_state: *mut Hacl_Streaming_Functor_state_s___EverCrypt_Hash_state_s____ =
            unsafe { EverCrypt_Hash_Incremental_create_in(alg.into()) };
        Ok(Self {
            mode: alg,
            finished: false,
            c_state,
        })
    }

    /// Update the hash state.
    /// Modifies `self` and doesn't return anything but an `Error` in case the
    /// update fails.
    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.finished {
            return Err(Error::InvalidStateFinished);
        }
        unsafe {
            EverCrypt_Hash_Incremental_update(self.c_state, data.as_ptr() as _, data.len() as u32);
        }
        Ok(())
    }

    /// Finish the hash computation.
    /// Returns the digest or an `Error`.
    ///
    /// **The struct can not be re-used after this!**
    pub fn finish(&mut self) -> Result<Vec<u8>, Error> {
        if self.finished {
            return Err(Error::InvalidStateFinished);
        }
        let mut out = vec![0u8; digest_size(self.mode)];
        unsafe {
            EverCrypt_Hash_Incremental_finish(self.c_state, out.as_mut_ptr());
            EverCrypt_Hash_Incremental_free(self.c_state);
        }
        self.finished = true;
        Ok(out)
    }
}

// Single-shot API with array returns.

macro_rules! define_plain_digest {
    ($name:ident, $version:expr, $l:literal) => {
        /// Single-shot API with a fixed length output.
        pub fn $name(data: &[u8]) -> [u8; $l] {
            let mut out = [0u8; $l];

            match $version {
                Mode::Sha3_224 => unsafe {
                    Hacl_SHA3_sha3_224(data.len() as u32, data.as_ptr() as _, out.as_mut_ptr())
                },
                Mode::Sha3_256 => unsafe {
                    Hacl_SHA3_sha3_256(data.len() as u32, data.as_ptr() as _, out.as_mut_ptr())
                },
                Mode::Sha3_384 => unsafe {
                    Hacl_SHA3_sha3_384(data.len() as u32, data.as_ptr() as _, out.as_mut_ptr())
                },
                Mode::Sha3_512 => unsafe {
                    Hacl_SHA3_sha3_512(data.len() as u32, data.as_ptr() as _, out.as_mut_ptr())
                },
                _ => unsafe {
                    EverCrypt_Hash_hash(
                        $version.into(),
                        out.as_mut_ptr(),
                        data.as_ptr() as _,
                        data.len() as u32,
                    );
                },
            }

            out
        }
    };
}

define_plain_digest!(sha1, Mode::Sha1, 20);
define_plain_digest!(sha224, Mode::Sha224, 28);
define_plain_digest!(sha256, Mode::Sha256, 32);
define_plain_digest!(sha384, Mode::Sha384, 48);
define_plain_digest!(sha512, Mode::Sha512, 64);
define_plain_digest!(sha3_224, Mode::Sha3_224, 28);
define_plain_digest!(sha3_256, Mode::Sha3_256, 32);
define_plain_digest!(sha3_384, Mode::Sha3_384, 48);
define_plain_digest!(sha3_512, Mode::Sha3_512, 64);
define_plain_digest!(blake2s, Mode::Blake2s, 32);
define_plain_digest!(blake2b, Mode::Blake2b, 64);

// Single-shot API

/// Create the digest for the given `data` and mode `alg`.
/// The output has length `get_digest_size(alg)`.
pub fn hash(alg: Mode, data: &[u8]) -> Vec<u8> {
    match alg {
        Mode::Sha1 => sha1(data).to_vec(),
        Mode::Sha224 => sha224(data).to_vec(),
        Mode::Sha256 => sha256(data).to_vec(),
        Mode::Sha384 => sha384(data).to_vec(),
        Mode::Sha512 => sha512(data).to_vec(),
        Mode::Sha3_224 => sha3_224(data).to_vec(),
        Mode::Sha3_256 => sha3_256(data).to_vec(),
        Mode::Sha3_384 => sha3_384(data).to_vec(),
        Mode::Sha3_512 => sha3_512(data).to_vec(),
        Mode::Blake2s => blake2s(data).to_vec(),
        Mode::Blake2b => blake2b(data).to_vec(),
    }
}

// SHAKE messages from SHA 3

/// SHAKE 128
pub fn shake128(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    unsafe {
        Hacl_SHA3_shake128_hacl(
            data.len() as u32,
            data.as_ptr() as _,
            out_len as u32,
            out.as_mut_ptr(),
        );
    }
    out
}

/// SHAKE 256
pub fn shake256(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    unsafe {
        Hacl_SHA3_shake256_hacl(
            data.len() as u32,
            data.as_ptr() as _,
            out_len as u32,
            out.as_mut_ptr(),
        );
    }
    out
}

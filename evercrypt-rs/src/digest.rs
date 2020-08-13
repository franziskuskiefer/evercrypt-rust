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
//! let mut digest_256 = Digest::new(Mode::Sha256);
//! if digest_256.update(data).is_err() {
//!     panic!("Error hashing.");
//! }
//! let digest_256_result = match digest_256.finish() {
//!     Ok(d) => d,
//!     Err(e) => panic!("Finish digest failed.\n{:?}", e),
//! };
//!
//! let mut digest_512 = Digest::new(Mode::Sha512);
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

use evercrypt_sys::evercrypt_bindings::*;

#[derive(Debug)]
pub enum Error {
    InvalidStateFinished,
}

/// The Digest Mode.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Mode {
    Sha1 = Spec_Hash_Definitions_SHA1 as isize,
    Sha224 = Spec_Hash_Definitions_SHA2_224 as isize,
    Sha256 = Spec_Hash_Definitions_SHA2_256 as isize,
    Sha384 = Spec_Hash_Definitions_SHA2_384 as isize,
    Sha512 = Spec_Hash_Definitions_SHA2_512 as isize,
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
        }
    }
}

/// Returns the output size of a digest.
pub fn get_digest_size(mode: Mode) -> usize {
    match mode {
        Mode::Sha1 => 20,
        Mode::Sha224 => 28,
        Mode::Sha256 => 32,
        Mode::Sha384 => 48,
        Mode::Sha512 => 64,
    }
}

/// The digest struct for stateful hashing.
pub struct Digest {
    mode: Mode,
    finished: bool,
    c_state: *mut Hacl_Streaming_Functor_state_s___EverCrypt_Hash_state_s____,
}

impl Digest {
    /// Create a new digest for the given mode `alg`.
    pub fn new(alg: Mode) -> Self {
        let c_state: *mut Hacl_Streaming_Functor_state_s___EverCrypt_Hash_state_s____ =
            unsafe { EverCrypt_Hash_Incremental_create_in(alg.into()) };
        Self {
            mode: alg,
            finished: false,
            c_state,
        }
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
        let mut out = vec![0u8; get_digest_size(self.mode)];
        unsafe {
            EverCrypt_Hash_Incremental_finish(self.c_state, out.as_mut_ptr());
            EverCrypt_Hash_Incremental_free(self.c_state);
        }
        self.finished = true;
        Ok(out)
    }
}

// Single-shot API

/// Create the digest for the given `data` and mode `alg`.
/// The output has length `get_digest_size(alg)`.
pub fn hash(alg: Mode, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; get_digest_size(alg)];
    unsafe {
        EverCrypt_Hash_hash(
            alg.into(),
            out.as_mut_ptr(),
            data.as_ptr() as _,
            data.len() as u32,
        );
    }
    out
}

// Single-shot API with array returns.

macro_rules! define_plain_digest {
    ($name:ident, $version:expr, $l:literal) => {
        /// Single-shot API with a fixed length output.
        pub fn $name(data: &[u8]) -> [u8; $l] {
            let mut out = [0u8; $l];
            unsafe {
                EverCrypt_Hash_hash(
                    $version.into(),
                    out.as_mut_ptr(),
                    data.as_ptr() as _,
                    data.len() as u32,
                );
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

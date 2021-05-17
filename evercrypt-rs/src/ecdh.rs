//! ECDH
//!
//! This module implements an agile API for ECDH on P256 and x25519.
//!
//! # Usage
//! ```rust
//! use evercrypt::ecdh::{self, Mode};
//!
//! // P256
//! let public = [0x04, 0x62, 0xd5, 0xbd, 0x33, 0x72, 0xaf, 0x75, 0xfe, 0x85, 0xa0, 0x40, 0x71, 0x5d, 0x0f, 0x50, 0x24, 0x28, 0xe0, 0x70, 0x46, 0x86, 0x8b, 0x0b, 0xfd, 0xfa, 0x61, 0xd7, 0x31, 0xaf, 0xe4, 0x4f, 0x26, 0xac, 0x33, 0x3a, 0x93, 0xa9, 0xe7, 0x0a, 0x81, 0xcd, 0x5a, 0x95, 0xb5, 0xbf, 0x8d, 0x13, 0x99, 0x0e, 0xb7, 0x41, 0xc8, 0xc3, 0x88, 0x72, 0xb4, 0xa0, 0x7d, 0x27, 0x5a, 0x01, 0x4e, 0x30, 0xcf];
//! let private = [0x06, 0x12, 0x46, 0x5c, 0x89, 0xa0, 0x23, 0xab, 0x17, 0x85, 0x5b, 0x0a, 0x6b, 0xce, 0xbf, 0xd3, 0xfe, 0xbb, 0x53, 0xae, 0xf8, 0x41, 0x38, 0x64, 0x7b, 0x53, 0x52, 0xe0, 0x2c, 0x10, 0xc3, 0x46];
//! let expected_result = [0x53, 0x02, 0x0d, 0x90, 0x8b, 0x02, 0x19, 0x32, 0x8b, 0x65, 0x8b, 0x52, 0x5f, 0x26, 0x78, 0x0e, 0x3a, 0xe1, 0x2b, 0xcd, 0x95, 0x2b, 0xb2, 0x5a, 0x93, 0xbc, 0x08, 0x95, 0xe1, 0x71, 0x42, 0x85];
//!
//! let result = match ecdh::derive(Mode::P256, &public, &private) {
//!     Ok(r) => r,
//!     Err(e) => panic!("P256 derive failed.\n{:?}", e),
//! };
//! assert_eq!(expected_result[..], result[..32]);
//!
//! let _result = match ecdh::derive_base(Mode::P256, &private) {
//!     Ok(r) => r,
//!     Err(e) => panic!("P256 derive failed.\n{:?}", e),
//! };
//!
//! // x25519
//! let public = [0x50, 0x4a, 0x36, 0x99, 0x9f, 0x48, 0x9c, 0xd2, 0xfd, 0xbc, 0x08, 0xba, 0xff, 0x3d, 0x88, 0xfa, 0x00, 0x56, 0x9b, 0xa9, 0x86, 0xcb, 0xa2, 0x25, 0x48, 0xff, 0xde, 0x80, 0xf9, 0x80, 0x68, 0x29];
//! let private = [0xc8, 0xa9, 0xd5, 0xa9, 0x10, 0x91, 0xad, 0x85, 0x1c, 0x66, 0x8b, 0x07, 0x36, 0xc1, 0xc9, 0xa0, 0x29, 0x36, 0xc0, 0xd3, 0xad, 0x62, 0x67, 0x08, 0x58, 0x08, 0x80, 0x47, 0xba, 0x05, 0x74, 0x75];
//! let expected_result = [0x43, 0x6a, 0x2c, 0x04, 0x0c, 0xf4, 0x5f, 0xea, 0x9b, 0x29, 0xa0, 0xcb, 0x81, 0xb1, 0xf4, 0x14, 0x58, 0xf8, 0x63, 0xd0, 0xd6, 0x1b, 0x45, 0x3d, 0x0a, 0x98, 0x27, 0x20, 0xd6, 0xd6, 0x13, 0x20];
//!
//! let result = match ecdh::derive(Mode::X25519, &public, &private) {
//!     Ok(r) => r,
//!     Err(e) => panic!("x25519 derive failed.\n{:?}", e),
//! };
//! assert_eq!(expected_result[..], result[..]);
//!
//! let _result = match ecdh::derive_base(Mode::X25519, &private) {
//!     Ok(r) => r,
//!     Err(e) => panic!("x25519 derive failed.\n{:?}", e),
//! };
//! ```

#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

use crate::p256;
use crate::x25519;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidPoint,
    InvalidScalar,
    UnknownAlgorithm,
    KeyGenError,
}

/// ECDH algorithm.
#[derive(Debug, PartialEq, Clone, Copy)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
pub enum Mode {
    X25519,
    P256,
}

/// Derive the ECDH shared secret.
/// Returns `Ok(p * s)` on the provided curve (`mode`) or an error.
pub fn derive(mode: Mode, p: &[u8], s: &[u8]) -> Result<Vec<u8>, Error> {
    match mode {
        Mode::X25519 => {
            if p.len() != 32 {
                return Err(Error::InvalidPoint);
            }
            if s.len() != 32 {
                return Err(Error::InvalidScalar);
            }
            let mut point = [0u8; 32];
            point.clone_from_slice(p);
            let mut scalar = [0u8; 32];
            scalar.clone_from_slice(s);

            match x25519::dh(&point, &scalar) {
                Ok(r) => Ok(r.to_vec()),
                Err(_) => Err(Error::InvalidPoint),
            }
        }
        Mode::P256 => match p256::dh(p, s) {
            Ok(r) => Ok(r.to_vec()),
            Err(_) => Err(Error::InvalidPoint),
        },
    }
}

/// Returns `Ok(base_point * s)` on the provided curve (`mode`) or an error.
pub fn derive_base(mode: Mode, s: &[u8]) -> Result<Vec<u8>, Error> {
    match mode {
        Mode::X25519 => {
            if s.len() != 32 {
                return Err(Error::InvalidScalar);
            }
            let mut scalar = [0u8; 32];
            scalar.clone_from_slice(s);

            Ok(x25519::dh_base(&scalar).to_vec())
        }
        Mode::P256 => match p256::dh_base(s) {
            Ok(r) => Ok(r.to_vec()),
            Err(_) => Err(Error::InvalidPoint),
        },
    }
}

/// Generate a random `Scalar` on the given curve.
///
/// Returns the scalar key bytes as `u8` vector.
#[cfg(feature = "random")]
pub fn key_gen(mode: Mode) -> Result<Vec<u8>, Error> {
    match mode {
        Mode::X25519 => Ok(x25519::key_gen().to_vec()),
        Mode::P256 => p256::key_gen()
            .map_err(|_| Error::KeyGenError)
            .map(|v| v.to_vec()),
    }
}

//! x25519
//!
//! This module implements ECDH on curve25519.
//!
//! # Usage
//! ```rust
//! use evercrypt::prelude::*;
//!
//! let public = [0x50, 0x4a, 0x36, 0x99, 0x9f, 0x48, 0x9c, 0xd2, 0xfd, 0xbc, 0x08, 0xba, 0xff, 0x3d, 0x88, 0xfa, 0x00, 0x56, 0x9b, 0xa9, 0x86, 0xcb, 0xa2, 0x25, 0x48, 0xff, 0xde, 0x80, 0xf9, 0x80, 0x68, 0x29];
//! let private = [0xc8, 0xa9, 0xd5, 0xa9, 0x10, 0x91, 0xad, 0x85, 0x1c, 0x66, 0x8b, 0x07, 0x36, 0xc1, 0xc9, 0xa0, 0x29, 0x36, 0xc0, 0xd3, 0xad, 0x62, 0x67, 0x08, 0x58, 0x08, 0x80, 0x47, 0xba, 0x05, 0x74, 0x75];
//! let expected_result = [0x43, 0x6a, 0x2c, 0x04, 0x0c, 0xf4, 0x5f, 0xea, 0x9b, 0x29, 0xa0, 0xcb, 0x81, 0xb1, 0xf4, 0x14, 0x58, 0xf8, 0x63, 0xd0, 0xd6, 0x1b, 0x45, 0x3d, 0x0a, 0x98, 0x27, 0x20, 0xd6, 0xd6, 0x13, 0x20];
//!
//! let my_pk = match x25519(&public, &private) {
//!     Ok(k) => k,
//!     Err(e) => panic!("Error x25519 {:?}", e),
//! };
//! assert_eq!(&expected_result[..], &my_pk[..]);
//!
//! let sk_a = x25519::key_gen();
//! let pk_a = x25519::dh_base(&sk_a);
//!
//! let sk_b = x25519::key_gen();
//! let pk_b = x25519::dh_base(&sk_b);
//!
//! let shared_a = x25519::dh(&pk_b, &sk_a);
//! let shared_b = x25519::dh(&pk_a, &sk_b);
//! assert_eq!(shared_a, shared_b);
//! ```

use evercrypt_sys::evercrypt_bindings::*;

#[derive(Debug, PartialEq)]
/// Curve 25519 errors
pub enum Error {
    /// The computed or provided point is not on the curve.
    InvalidPoint,
}

/// Points are 32 byte arrays.
pub type Point = [u8; 32];
/// Scalars are 32 byte arrays.
pub type Scalar = [u8; 32];

/// Return base * s
pub fn dh_base(s: &Scalar) -> Point {
    let mut out = [0u8; 32];
    unsafe {
        EverCrypt_Curve25519_secret_to_public(out.as_mut_ptr(), s.as_ptr() as _);
    }
    out
}

/// Return p * s
pub fn dh(p: &Point, s: &Scalar) -> Result<Point, Error> {
    let mut out = [0u8; 32];
    let r =
        unsafe { EverCrypt_Curve25519_ecdh(out.as_mut_ptr(), s.as_ptr() as _, p.as_ptr() as _) };
    if !r {
        Err(Error::InvalidPoint)
    } else {
        Ok(out)
    }
}

/// Generate a random `Scalar`.
#[cfg(feature = "random")]
pub fn key_gen() -> Scalar {
    crate::rand_util::random_array()
}

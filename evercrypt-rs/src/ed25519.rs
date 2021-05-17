//! Ed25519
//!
//! This module implements EdDSA on edwards25519.
//!
//! # Usage
//! ```rust
//! use evercrypt::ed25519;
//!
//! let public = [0x7d, 0x4d, 0x0e, 0x7f, 0x61, 0x53, 0xa6, 0x9b, 0x62, 0x42, 0xb5, 0x22, 0xab, 0xbe, 0xe6, 0x85, 0xfd, 0xa4, 0x42, 0x0f, 0x88, 0x34, 0xb1, 0x08, 0xc3, 0xbd, 0xae, 0x36, 0x9e, 0xf5, 0x49, 0xfa];
//! let private = [0xad, 0xd4, 0xbb, 0x81, 0x03, 0x78, 0x5b, 0xaf, 0x9a, 0xc5, 0x34, 0x25, 0x8e, 0x8a, 0xaf, 0x65, 0xf5, 0xf1, 0xad, 0xb5, 0xef, 0x5f, 0x3d, 0xf1, 0x9b, 0xb8, 0x0a, 0xb9, 0x89, 0xc4, 0xd6, 0x4b];
//! let msg = [0x78];
//! let expected_result = [0xd8, 0x07, 0x37, 0x35, 0x8e, 0xde, 0x54, 0x8a, 0xcb, 0x17, 0x3e, 0xf7, 0xe0, 0x39, 0x9f, 0x83, 0x39, 0x2f, 0xe8, 0x12, 0x5b, 0x2c, 0xe8, 0x77, 0xde, 0x79, 0x75, 0xd8, 0xb7, 0x26, 0xef, 0x5b, 0x1e, 0x76, 0x63, 0x22, 0x80, 0xee, 0x38, 0xaf, 0xad, 0x12, 0x12, 0x5e, 0xa4, 0x4b, 0x96, 0x1b, 0xf9, 0x2f, 0x11, 0x78, 0xc9, 0xfa, 0x81, 0x9d, 0x02, 0x08, 0x69, 0x97, 0x5b, 0xcb, 0xe1, 0x09];
//!
//! let my_pk = ed25519::sk2pk(&private);
//! assert_eq!(&public[..], &my_pk[..]);
//!
//! let signature = ed25519::eddsa_sign(&private, &msg);
//! assert_eq!(expected_result[..], signature[..]);
//!
//! let result = ed25519::eddsa_verify(&public, &signature, &msg);
//! assert!(result);
//!
//! let sk = ed25519::key_gen();
//! let pk = ed25519::sk2pk(&sk);
//! let signature = ed25519::eddsa_sign(&sk, &msg);
//! assert!(ed25519::eddsa_verify(&pk, &signature, &msg));
//! ```

use evercrypt_sys::evercrypt_bindings::*;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidPoint,
}

/// Points are 32 byte arrays.
pub type Point = [u8; 32];
/// Scalars are 32 byte arrays.
pub type Scalar = [u8; 32];
/// Signatures are 64 byte arrays.
pub type Signature = [u8; 64];

/// Sign message `msg` with secret key `sk`.
/// Returns a `Signature`.
pub fn eddsa_sign(sk: &Scalar, msg: &[u8]) -> Signature {
    let mut out = [0u8; 64];
    unsafe {
        EverCrypt_Ed25519_sign(
            out.as_mut_ptr(),
            sk.as_ptr() as _,
            msg.len() as u32,
            msg.as_ptr() as _,
        );
    }
    out
}

/// Verify signature `signature` on message `msg` with public key `pk`.
/// Returns `true` if the signature is valid and `false` otherwise.
pub fn eddsa_verify(pk: &Point, signature: &Signature, msg: &[u8]) -> bool {
    unsafe {
        EverCrypt_Ed25519_verify(
            pk.as_ptr() as _,
            msg.len() as u32,
            msg.as_ptr() as _,
            signature.as_ptr() as _,
        )
    }
}

/// Compute the public `Point` for the given secret key `sk`.
pub fn sk2pk(sk: &Scalar) -> Point {
    let mut out = [0u8; 32];
    unsafe {
        EverCrypt_Ed25519_secret_to_public(out.as_mut_ptr(), sk.as_ptr() as _);
    }
    out
}

/// Generate a random `Scalar`.
#[cfg(feature = "random")]
pub fn key_gen() -> Scalar {
    crate::rand_util::random_array()
}

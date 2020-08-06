//! Prelude for Evercrypt.
//! Include this to get access to all the public functions of Evercrypt.

pub use crate::aead::{Aead, Error as AeadError, Mode as AeadMode};
pub use crate::digest::{hash, Digest, Error as DigestError, Mode as DigestMode};
pub use crate::ecdh::{
    self, derive as ecdh_derive, derive_base as ecdh_derive_base, Error as EcdhError,
    Mode as EcdhMode,
};
pub use crate::ed25519::{
    self, eddsa_sign as ed25519_sign, eddsa_verify as ed25519_verify, sk2pk as ed25519_sk2pk,
    Error as Ed25519Error, Point as Ed25519Point, Scalar as Ed25519Scalar,
    Signature as Ed25519Signature,
};
pub use crate::hkdf::{self, expand as hkdf_expand, extract as hkdf_extract, hkdf};
pub use crate::hmac::{get_tag_size, hmac, Mode as HmacMode};
pub use crate::p256::{
    self, dh as p256, dh_base as p256_base, ecdsa_sign as p256_sign, ecdsa_verify as p256_verify,
    Error as P256Error, Nonce as P256Nonce, Scalar as P256Scalar, Signature as EcdsaSignature,
};
pub use crate::rand_util::{get_random_array, get_random_vec};
pub use crate::signature::{self, sign, verify, Error as SignatureError, Mode as SignatureMode};
pub use crate::x25519::{
    self, dh as x25519, dh_base as x25519_base, Error as X25519Error, Point as X25519Point,
    Scalar as X25519Scalar,
};

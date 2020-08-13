//! Prelude for Evercrypt.
//! Include this to get access to all the public functions of Evercrypt.

pub use crate::aead::{
    decrypt as aead_decrypt, encrypt as aead_encrypt, key_gen as aead_key_gen,
    key_size as aead_key_size, nonce_gen as aead_nonce_gen, Aead, Error as AeadError,
    Mode as AeadMode,
};
pub use crate::digest::{get_digest_size, hash, Digest, Error as DigestError, Mode as DigestMode};
pub use crate::ecdh::{
    self, derive as ecdh_derive, derive_base as ecdh_derive_base, key_gen as ecdh_key_gen,
    Error as EcdhError, Mode as EcdhMode,
};
pub use crate::ed25519::{
    self, eddsa_sign as ed25519_sign, eddsa_verify as ed25519_verify, key_gen as ed25519_key_gen,
    sk2pk as ed25519_sk2pk, Error as Ed25519Error, Point as Ed25519Point, Scalar as Ed25519Scalar,
    Signature as Ed25519Signature,
};
pub use crate::hkdf::{self, expand as hkdf_expand, extract as hkdf_extract, hkdf};
pub use crate::hmac::{get_tag_size, hmac, Mode as HmacMode};
pub use crate::p256::{
    self, dh as p256, dh_base as p256_base, ecdsa_sign as p256_sign, ecdsa_verify as p256_verify,
    random_nonce as p256_ecdsa_random_nonce, Error as P256Error, Nonce as P256Nonce,
    Scalar as P256Scalar, Signature as EcdsaSignature,
};
pub use crate::rand_util::{get_random_array, get_random_vec};
pub use crate::signature::{
    self, key_gen as signature_key_gen, sign, verify, Error as SignatureError,
    Mode as SignatureMode,
};
pub use crate::x25519::{
    self, dh as x25519, dh_base as x25519_base, key_gen as x25519_key_gen, Error as X25519Error,
    Point as X25519Point, Scalar as X25519Scalar,
};

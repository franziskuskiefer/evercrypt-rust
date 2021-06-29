//! Prelude for Evercrypt.
//! Include this to get access to all the public functions of Evercrypt.

pub use crate::aead::{
    self, decrypt as aead_decrypt, decrypt_combined as aead_decrypt_combined,
    encrypt as aead_encrypt, encrypt_combined as aead_encrypt_combined, key_size as aead_key_size,
    nonce_size as aead_nonce_size, tag_size as aead_tag_size, Aead, Error as AeadError,
    Mode as AeadMode, Nonce as AeadNonce, Tag as AeadTag,
};
pub use crate::digest::{
    self, digest_size, hash, Digest, Error as DigestError, Mode as DigestMode,
};
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
pub use crate::hmac::{self, hmac, tag_size, Mode as HmacMode};
pub use crate::p256::{
    self, dh as p256, dh_base as p256_base, ecdsa_sign as p256_sign, ecdsa_verify as p256_verify,
    validate_pk as p256_validate_pk, validate_sk as p256_validate_sk, Error as P256Error,
    Nonce as P256Nonce, Scalar as P256Scalar, Signature as EcdsaSignature,
};
pub use crate::signature::{self, sign, verify, Error as SignatureError, Mode as SignatureMode};
pub use crate::x25519::{
    self, dh as x25519, dh_base as x25519_base, Error as X25519Error, Point as X25519Point,
    Scalar as X25519Scalar,
};
#[cfg(feature = "random")]
pub use crate::{
    aead::{key_gen as aead_key_gen, nonce_gen as aead_nonce_gen},
    ecdh::key_gen as ecdh_key_gen,
    ed25519::key_gen as ed25519_key_gen,
    p256::random_nonce as p256_ecdsa_random_nonce,
    rand_util::{random_array, random_vec},
    signature::key_gen as signature_key_gen,
    x25519::key_gen as x25519_key_gen,
};

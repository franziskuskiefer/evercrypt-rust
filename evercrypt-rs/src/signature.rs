#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

use crate::digest;
use crate::ed25519;
use crate::p256;

#[derive(Debug, PartialEq)]
/// Signature errors.
pub enum Error {
    InvalidPoint,
    UnknownAlgorithm,
    NonceMissing,
    HashAlgorithmMissing,
    InvalidSignature,
    KeyGenError,
}

#[derive(Debug, PartialEq, Clone, Copy)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
/// Supported signature schemes.
pub enum Mode {
    /// EdDSA on curve 25519
    Ed25519,

    /// EcDSA on P256
    P256,
}

#[cfg(feature = "random")]
/// Generate a new key pair for the given `mode`.
/// The function throws an error for P256 keys if no valid key can be generated
/// in a reasonable time.
pub fn key_gen(mode: Mode) -> Result<(Vec<u8>, Vec<u8>), Error> {
    match mode {
        Mode::Ed25519 => {
            let sk = ed25519::key_gen();
            let pk = ed25519::sk2pk(&sk);
            Ok((sk.to_vec(), pk.to_vec()))
        }
        Mode::P256 => {
            let sk = p256::key_gen().map_err(|_| Error::KeyGenError)?;
            let pk = match p256::dh_base(&sk) {
                Ok(k) => {
                    let mut pk = vec![0x04];
                    pk.extend_from_slice(&k);
                    pk
                }
                Err(_) => return Err(Error::InvalidPoint),
            };
            Ok((sk.to_vec(), pk))
        }
    }
}

/// Sign a message `msg` with the secret key `sk` and the given signature scheme (`mode`).
/// For ECDSA the `hash` algorithm and a `nonce` have to be passed in as well.
pub fn sign<'a>(
    mode: Mode,
    hash: impl Into<Option<digest::Mode>>,
    sk: &[u8],
    msg: &[u8],
    nonce: impl Into<Option<&'a p256::Nonce>>,
) -> Result<Vec<u8>, Error> {
    match mode {
        Mode::Ed25519 => {
            let mut key = [0u8; 32];
            key.clone_from_slice(sk);

            Ok(ed25519::eddsa_sign(&key, msg).to_vec())
        }
        Mode::P256 => {
            let nonce = match nonce.into() {
                Some(n) => n,
                None => return Err(Error::NonceMissing),
            };
            let hash = match hash.into() {
                Some(h) => h,
                None => return Err(Error::HashAlgorithmMissing),
            };
            let mut key = [0u8; 32];
            key.clone_from_slice(sk);
            match p256::ecdsa_sign(hash, msg, &key, nonce) {
                Ok(r) => Ok(r.raw().to_vec()),
                Err(_) => Err(Error::InvalidPoint),
            }
        }
    }
}

/// Verify a signature.
/// Depending on the `Mode`, a `hash` mode has to be passed in.
/// The public key `pk`, `signature`, and message `msg` are passed in as byte
/// slices.
pub fn verify(
    mode: Mode,
    hash: impl Into<Option<digest::Mode>>,
    pk: &[u8],
    signature: &[u8],
    msg: &[u8],
) -> Result<bool, Error> {
    match mode {
        Mode::Ed25519 => {
            if signature.len() != 64 {
                return Err(Error::InvalidSignature);
            }
            if pk.len() != 32 {
                return Err(Error::InvalidPoint);
            }
            let mut key = [0u8; 32];
            key.clone_from_slice(pk);
            let mut sig = [0u8; 64];
            sig.clone_from_slice(signature);

            Ok(ed25519::eddsa_verify(&key, &sig, msg))
        }
        Mode::P256 => {
            let hash = match hash.into() {
                Some(h) => h,
                None => return Err(Error::HashAlgorithmMissing),
            };
            let sig = match p256::Signature::from_byte_slice(signature) {
                Ok(s) => s,
                Err(_) => return Err(Error::InvalidSignature),
            };
            match p256::ecdsa_verify(hash, msg, pk, &sig) {
                Ok(r) => Ok(r),
                Err(_) => Err(Error::InvalidPoint),
            }
        }
    }
}

use crate::digest;
use crate::ed25519;
use crate::p256;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidPoint,
    UnkownAlgorithm,
    NonceMissing,
    HashAlgorithmMissing,
    InvalidSignature,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Mode {
    Ed25519,
    P256,
}

pub struct Signature {}

// TODO: unnecessary conversions for P256
pub fn sign(
    mode: Mode,
    hash: Option<digest::Mode>,
    sk: &[u8],
    msg: &[u8],
    nonce: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    match mode {
        Mode::Ed25519 => {
            let mut key = [0u8; 32];
            key.clone_from_slice(sk);

            Ok(ed25519::eddsa_sign(&key, msg).to_vec())
        }
        Mode::P256 => {
            let nonce = match nonce {
                Some(n) => n,
                None => return Err(Error::NonceMissing),
            };
            let hash = match hash {
                Some(h) => h,
                None => return Err(Error::HashAlgorithmMissing),
            };
            let mut key = [0u8; 32];
            key.clone_from_slice(sk);
            let mut n = [0u8; 32];
            n.clone_from_slice(nonce);
            match p256::ecdsa_sign(hash, msg, &key, &n) {
                Ok(r) => Ok(r.raw().to_vec()),
                Err(_) => Err(Error::InvalidPoint),
            }
        }
    }
}

pub fn verify(
    mode: Mode,
    hash: Option<digest::Mode>,
    pk: &[u8],
    signature: &[u8],
    msg: &[u8],
) -> Result<bool, Error> {
    match mode {
        Mode::Ed25519 => {
            let mut key = [0u8; 32];
            key.clone_from_slice(pk);
            let mut sig = [0u8; 64];
            sig.clone_from_slice(signature);

            Ok(ed25519::eddsa_verify(&key, &sig, msg))
        }
        Mode::P256 => {
            let hash = match hash {
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

use crate::digest;
use crate::ed25519::{ed25519_sign, ed25519_verify};
use crate::p256::{p256_ecdsa_sign, p256_ecdsa_verify, EcdsaSignature};

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
impl Signature {
    pub fn sign(
        mode: Mode,
        hash: Option<digest::Mode>,
        sk: &[u8],
        msg: &[u8],
        nonce: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        match mode {
            Mode::Ed25519 => Ok(ed25519_sign(sk, msg).to_vec()),
            Mode::P256 => {
                let nonce = match nonce {
                    Some(n) => n,
                    None => return Err(Error::NonceMissing),
                };
                let hash = match hash {
                    Some(h) => h,
                    None => return Err(Error::HashAlgorithmMissing),
                };
                match p256_ecdsa_sign(hash, msg, sk, nonce) {
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
            Mode::Ed25519 => Ok(ed25519_verify(pk, signature, msg)),
            Mode::P256 => {
                let hash = match hash {
                    Some(h) => h,
                    None => return Err(Error::HashAlgorithmMissing),
                };
                let sig = match EcdsaSignature::from_bytes(signature) {
                    Ok(s) => s,
                    Err(_) => return Err(Error::InvalidSignature),
                };
                match p256_ecdsa_verify(hash, msg, pk, &sig) {
                    Ok(r) => Ok(r),
                    Err(_) => Err(Error::InvalidPoint),
                }
            }
        }
    }
}

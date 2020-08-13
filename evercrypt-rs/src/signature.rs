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

/// Generate a new key pair for the given `mode`.
pub fn key_gen(mode: Mode) -> Result<(Vec<u8>, Vec<u8>), Error> {
    match mode {
        Mode::Ed25519 => {
            let sk = ed25519::key_gen();
            let pk = ed25519::sk2pk(&sk);
            Ok((sk.to_vec(), pk.to_vec()))
        }
        Mode::P256 => {
            let sk = p256::key_gen();
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

// TODO: unnecessary conversions for P256
pub fn sign(
    mode: Mode,
    hash: Option<digest::Mode>,
    sk: &[u8],
    msg: &[u8],
    nonce: Option<&p256::Nonce>,
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
            match p256::ecdsa_sign(hash, msg, &key, nonce) {
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

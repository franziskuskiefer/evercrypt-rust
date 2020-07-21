use crate::p256;
use crate::x25519;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidPoint,
    UnkownAlgorithm,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Mode {
    X25519,
    P256,
}

pub struct Ecdh {}

impl Ecdh {
    pub fn derive(mode: Mode, p: &[u8], s: &[u8]) -> Result<Vec<u8>, Error> {
        match mode {
            Mode::X25519 => match x25519::x25519(p, s) {
                Ok(r) => Ok(r.to_vec()),
                Err(_) => Err(Error::InvalidPoint),
            },
            Mode::P256 => match p256::p256_dh(p, s) {
                Ok(r) => Ok(r.to_vec()),
                Err(_) => Err(Error::InvalidPoint),
            },
        }
    }
    pub fn derive_base(mode: Mode, s: &[u8]) -> Result<Vec<u8>, Error> {
        match mode {
            Mode::X25519 => Ok(x25519::x25519_base(s).to_vec()),
            Mode::P256 => match p256::p256_dh_base(s) {
                Ok(r) => Ok(r.to_vec()),
                Err(_) => Err(Error::InvalidPoint),
            },
        }
    }
}

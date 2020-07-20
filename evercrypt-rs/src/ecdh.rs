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

pub trait EcdhTrait {
    fn derive(&self, p: &[u8], s: &[u8]) -> Result<Vec<u8>, Error>;
    fn derive_base(&self, s: &[u8]) -> Result<Vec<u8>, Error>;
}

pub struct Ecdh {}

impl Ecdh {
    pub fn derive(mode: Mode, p: &[u8], s: &[u8]) -> Result<Vec<u8>, Error> {
        let alg: Box<dyn EcdhTrait> = match mode {
            Mode::X25519 => Box::new(X25519::default()),
            Mode::P256 => Box::new(P256::default()),
        };
        alg.derive(p, s)
    }
    pub fn derive_base(mode: Mode, s: &[u8]) -> Result<Vec<u8>, Error> {
        let alg: Box<dyn EcdhTrait> = match mode {
            Mode::X25519 => Box::new(X25519::default()),
            Mode::P256 => Box::new(P256::default()),
        };
        alg.derive_base(s)
    }
}

#[derive(Default)]
struct X25519 {}

#[derive(Default)]
struct P256 {}

impl EcdhTrait for X25519 {
    fn derive(&self, p: &[u8], s: &[u8]) -> Result<Vec<u8>, Error> {
        match x25519::x25519(p, s) {
            Ok(r) => Ok(r.to_vec()),
            Err(_) => Err(Error::InvalidPoint),
        }
    }
    fn derive_base(&self, s: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(x25519::x25519_base(s).to_vec())
    }
}

impl EcdhTrait for P256 {
    fn derive(&self, p: &[u8], s: &[u8]) -> Result<Vec<u8>, Error> {
        match p256::p256_dh(p, s) {
            Ok(r) => Ok(r.to_vec()),
            Err(_) => Err(Error::InvalidPoint),
        }
    }
    fn derive_base(&self, s: &[u8]) -> Result<Vec<u8>, Error> {
        match p256::p256_dh_base(s) {
            Ok(r) => Ok(r.to_vec()),
            Err(_) => Err(Error::InvalidPoint),
        }
    }
}

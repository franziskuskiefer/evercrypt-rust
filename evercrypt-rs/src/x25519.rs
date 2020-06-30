use evercrypt_sys::x25519;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidPoint,
}

impl From<x25519::Error> for Error {
    fn from(e: x25519::Error) -> Error {
        match e {
            x25519::Error::InvalidPoint => Error::InvalidPoint,
        }
    }
}

/// Return base * s
pub fn x25519_base(s: &[u8]) -> [u8; 32] {
    x25519::x25519_base(s)
}

/// Return p * s
pub fn x25519(p: &[u8], s: &[u8]) -> Result<[u8; 32], Error> {
    match x25519::x25519(p, s) {
        Ok(r) => Ok(r),
        Err(e) => Err(e.into()),
    }
}

use evercrypt_sys::evercrypt_bindings::*;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidPoint,
}

/// Points are 32 byte arrays.
pub type Point = [u8; 32];
/// Scalars are 32 byte arrays.
pub type Scalar = [u8; 32];
/// Signatures are 64 byte arrays.
pub type Signature = [u8; 64];

pub fn ed25519_sign(sk: &Scalar, msg: &[u8]) -> Signature {
    let mut out = [0u8; 64];
    unsafe {
        EverCrypt_Ed25519_sign(
            out.as_mut_ptr(),
            sk.as_ptr() as _,
            msg.len() as u32,
            msg.as_ptr() as _,
        );
    }
    out
}

pub fn ed25519_verify(pk: &Point, signature: &Signature, msg: &[u8]) -> bool {
    unsafe {
        EverCrypt_Ed25519_verify(
            pk.as_ptr() as _,
            msg.len() as u32,
            msg.as_ptr() as _,
            signature.as_ptr() as _,
        )
    }
}

pub fn ed25519_sk2pk(sk: &Scalar) -> Point {
    let mut out = [0u8; 32];
    unsafe {
        EverCrypt_Ed25519_secret_to_public(out.as_mut_ptr(), sk.as_ptr() as _);
    }
    out
}

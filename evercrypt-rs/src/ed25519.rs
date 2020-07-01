use evercrypt_sys::evercrypt_bindings::*;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidPoint,
}

pub fn ed25519_sign(sk: &[u8], msg: &[u8]) -> [u8; 64] {
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

pub fn ed25519_verify(pk: &[u8], signature: &[u8], msg: &[u8]) -> bool {
    if signature.len() == 0 || pk.len() != 32 {
        return false;
    }
    unsafe {
        EverCrypt_Ed25519_verify(
            pk.as_ptr() as _,
            msg.len() as u32,
            msg.as_ptr() as _,
            signature.as_ptr() as _,
        )
    }
}

pub fn ed25519_sk2pk(sk: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe {
        EverCrypt_Ed25519_secret_to_public(out.as_mut_ptr(), sk.as_ptr() as _);
    }
    out
}

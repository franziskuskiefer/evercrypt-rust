use evercrypt_sys::evercrypt_bindings::*;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidPoint,
}

/// Return base * s
pub fn x25519_base(s: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe {
        EverCrypt_Curve25519_secret_to_public(out.as_mut_ptr(), s.as_ptr() as _);
    }
    out
}

/// Return p * s
pub fn x25519(p: &[u8], s: &[u8]) -> Result<[u8; 32], Error> {
    let mut out = [0u8; 32];
    let r =
        unsafe { EverCrypt_Curve25519_ecdh(out.as_mut_ptr(), s.as_ptr() as _, p.as_ptr() as _) };
    if !r {
        Err(Error::InvalidPoint)
    } else {
        Ok(out)
    }
}

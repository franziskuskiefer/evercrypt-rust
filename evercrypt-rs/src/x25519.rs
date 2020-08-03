use evercrypt_sys::evercrypt_bindings::*;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidPoint,
}

/// Points are 32 byte arrays.
pub type Point = [u8; 32];
/// Scalars are 32 byte arrays.
pub type Scalar = [u8; 32];

/// Return base * s
pub fn dh_base(s: &Scalar) -> Point {
    let mut out = [0u8; 32];
    unsafe {
        EverCrypt_Curve25519_secret_to_public(out.as_mut_ptr(), s.as_ptr() as _);
    }
    out
}

/// Return p * s
pub fn dh(p: &Point, s: &Scalar) -> Result<Point, Error> {
    let mut out = [0u8; 32];
    let r =
        unsafe { EverCrypt_Curve25519_ecdh(out.as_mut_ptr(), s.as_ptr() as _, p.as_ptr() as _) };
    if !r {
        Err(Error::InvalidPoint)
    } else {
        Ok(out)
    }
}

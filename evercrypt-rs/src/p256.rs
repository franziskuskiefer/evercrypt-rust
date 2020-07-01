use evercrypt_sys::evercrypt_bindings::*;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidPoint,
    InvalidScalar,
}

/// Return base * s
pub fn p256_dh_base(s: &[u8]) -> Result<[u8; 64], Error> {
    let mut out = [0u8; 64];
    let r = unsafe { Hacl_P256_ecp256dh_i(out.as_mut_ptr(), s.as_ptr() as _) };
    if r != 0 {
        Err(Error::InvalidPoint)
    } else {
        Ok(out)
    }
}

/// Return p * s
pub fn p256_dh(p: &[u8], s: &[u8]) -> Result<[u8; 64], Error> {
    if p.len() == 0 {
        return Err(Error::InvalidPoint);
    }
    if s.len() == 0 {
        return Err(Error::InvalidScalar);
    }
    let mut out = [0u8; 64];
    let r = unsafe { Hacl_P256_ecp256dh_r(out.as_mut_ptr(), p.as_ptr() as _, s.as_ptr() as _) };
    if r != 0 {
        Err(Error::InvalidPoint)
    } else {
        Ok(out)
    }
}

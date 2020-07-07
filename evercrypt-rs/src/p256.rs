use evercrypt_sys::evercrypt_bindings::*;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidPoint,
    InvalidScalar,
    CompressedPoint,
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

    // Parse the public uncompressed key.
    let mut public = vec![0u8; 64];
    let success = unsafe {
        Hacl_P256_decompression_not_compressed_form(p.as_ptr() as _, public.as_mut_ptr())
    };
    if !success {
        return Err(Error::CompressedPoint);
    }

    // Cut the scalar to 32 byte and prepend with 0s if necessary.
    let mut private = [0u8; 32];
    let s_len = if s.len() >= 32 { 32 } else { s.len() };
    for i in 0..s_len {
        private[31 - i] = s[s.len() - 1 - i];
    }
    let mut out = [0u8; 64];
    let r = unsafe {
        Hacl_P256_ecp256dh_r(
            out.as_mut_ptr(),
            public.as_ptr() as _,
            private.as_ptr() as _,
        )
    };
    if r != 0 {
        Err(Error::InvalidPoint)
    } else {
        Ok(out)
    }
}

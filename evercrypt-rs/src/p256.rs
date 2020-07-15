use evercrypt_sys::evercrypt_bindings::*;

use crate::digest::Mode;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidPoint,
    InvalidScalar,
    CompressedPoint,
    InvalidConfig,
    SigningFailed,
    InvalidSignature,
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

    // Parse the public key.
    let mut public = vec![0u8; 64];
    let uncompressed_point = unsafe {
        Hacl_P256_decompression_not_compressed_form(p.as_ptr() as _, public.as_mut_ptr())
    };
    let compressed_point = if !uncompressed_point {
        unsafe { Hacl_P256_decompression_compressed_form(p.as_ptr() as _, public.as_mut_ptr()) }
    } else {
        false
    };
    if !uncompressed_point && !compressed_point {
        return Err(Error::InvalidPoint);
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

/// An ECDSA signature holding `r` and `s`.
#[derive(Clone, Copy, Debug)]
pub struct EcdsaSignature {
    r: [u8; 32],
    s: [u8; 32],
}

impl EcdsaSignature {
    pub fn new(r: &[u8], s: &[u8]) -> Result<Self, Error> {
        if r.len() != 32 || s.len() != 32 {
            return Err(Error::InvalidSignature);
        }

        let mut r_array = [0u8; 32];
        r_array.clone_from_slice(r);
        let mut s_array = [0u8; 32];
        s_array.clone_from_slice(s);

        Ok(Self { r: r_array, s: s_array })
    }
    pub fn from_bytes(combined: &[u8]) -> Result<Self, Error> {
        if combined.len() != 64 {
            return Err(Error::InvalidSignature);
        }

        let mut r = [0u8; 32];
        r.clone_from_slice(&combined[..32]);
        let mut s = [0u8; 32];
        s.clone_from_slice(&combined[32..]);

        Ok(Self { r: r, s: s })
    }
    pub fn from_arrays(r: [u8; 32], s: [u8; 32]) -> Self {
        Self { r: r, s: s }
    }
}

/// Sign `msg` with `sk` and `nonce` using `hash`.
pub fn p256_ecdsa_sign(
    hash: Mode,
    msg: &[u8],
    sk: &[u8],
    nonce: &[u8],
) -> Result<EcdsaSignature, Error> {
    let mut signature = [0u8; 64];
    let result = match hash {
        Mode::Sha256 => unsafe {
            Hacl_P256_ecdsa_sign_p256_sha2(
                signature.as_mut_ptr(),
                msg.len() as u32,
                msg.as_ptr() as _,
                sk.as_ptr() as _,
                nonce.as_ptr() as _,
            )
        },
        Mode::Sha384 => unsafe {
            Hacl_P256_ecdsa_sign_p256_sha384(
                signature.as_mut_ptr(),
                msg.len() as u32,
                msg.as_ptr() as _,
                sk.as_ptr() as _,
                nonce.as_ptr() as _,
            )
        },
        Mode::Sha512 => unsafe {
            Hacl_P256_ecdsa_sign_p256_sha512(
                signature.as_mut_ptr(),
                msg.len() as u32,
                msg.as_ptr() as _,
                sk.as_ptr() as _,
                nonce.as_ptr() as _,
            )
        },
        _ => return Err(Error::InvalidConfig),
    };

    if result != 0 {
        return Err(Error::SigningFailed);
    }

    let mut r = [0u8; 32];
    r.clone_from_slice(&signature[..32]);
    let mut s = [0u8; 32];
    s.clone_from_slice(&signature[32..]);
    Ok(EcdsaSignature { r: r, s: s })
}

/// Verify `signature` on `msg` with `pk` using `hash`.
pub fn p256_ecdsa_verify(
    hash: Mode,
    msg: &[u8],
    pk: &[u8],
    signature: &EcdsaSignature,
) -> Result<bool, Error> {
    match hash {
        Mode::Sha256 => unsafe {
            Ok(Hacl_P256_ecdsa_verif_p256_sha2(
                msg.len() as u32,
                msg.as_ptr() as _,
                pk.as_ptr() as _,
                signature.r.as_ptr() as _,
                signature.s.as_ptr() as _,
            ))
        },
        Mode::Sha384 => unsafe {
            Ok(Hacl_P256_ecdsa_verif_p256_sha2(
                msg.len() as u32,
                msg.as_ptr() as _,
                pk.as_ptr() as _,
                signature.r.as_ptr() as _,
                signature.s.as_ptr() as _,
            ))
        },
        Mode::Sha512 => unsafe {
            Ok(Hacl_P256_ecdsa_verif_p256_sha2(
                msg.len() as u32,
                msg.as_ptr() as _,
                pk.as_ptr() as _,
                signature.r.as_ptr() as _,
                signature.s.as_ptr() as _,
            ))
        },
        _ => Err(Error::InvalidConfig),
    }
}

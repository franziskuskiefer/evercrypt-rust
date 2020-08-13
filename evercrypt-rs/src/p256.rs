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

fn validate_pk(pk: &[u8]) -> Result<[u8; 64], Error> {
    if pk.is_empty() {
        return Err(Error::InvalidPoint);
    }

    // Parse the public key.
    let mut public = [0u8; 64];
    let uncompressed_point = unsafe {
        Hacl_P256_decompression_not_compressed_form(pk.as_ptr() as _, public.as_mut_ptr())
    };
    let compressed_point = if !uncompressed_point {
        unsafe { Hacl_P256_decompression_compressed_form(pk.as_ptr() as _, public.as_mut_ptr()) }
    } else {
        false
    };
    let valid = unsafe { Hacl_P256_verify_q(public.as_ptr() as _) };
    if (!uncompressed_point && !compressed_point) || !valid {
        return Err(Error::InvalidPoint);
    }

    Ok(public)
}

fn validate_sk(sk: &[u8]) -> Result<[u8; 32], Error> {
    if sk.is_empty() {
        return Err(Error::InvalidScalar);
    }

    let mut private = [0u8; 32];
    let sk_len = if sk.len() >= 32 { 32 } else { sk.len() };
    for i in 0..sk_len {
        private[31 - i] = sk[sk.len() - 1 - i];
    }

    Ok(private)
}

/// Return base * s
pub fn dh_base(s: &[u8]) -> Result<[u8; 64], Error> {
    let private = validate_sk(s)?;

    let mut out = [0u8; 64];
    let r = unsafe { Hacl_P256_ecp256dh_i(out.as_mut_ptr(), private.as_ptr() as _) };
    if r != 0 {
        Err(Error::InvalidPoint)
    } else {
        Ok(out)
    }
}

/// Return p * s
pub fn dh(p: &[u8], s: &[u8]) -> Result<[u8; 64], Error> {
    let public = validate_pk(p)?;
    let private = validate_sk(s)?;

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

/// Nonces are 32 byte arrays.
pub type Nonce = [u8; 32];
/// Scalars are 32 byte arrays.
pub type Scalar = [u8; 32];

/// An ECDSA signature holding `r` and `s`.
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    r: [u8; 32],
    s: [u8; 32],
}

/// Convert bytes to signatures and vice versa.
impl Signature {
    /// Build a new signature from `r` and `s`.
    pub fn new(r: &[u8; 32], s: &[u8; 32]) -> Self {
        Self { r: *r, s: *s }
    }

    /// Generate a new signature from a byte array holding `r||s`.
    pub fn from_bytes(combined: &[u8; 64]) -> Self {
        let mut r = [0u8; 32];
        r.clone_from_slice(&combined[..32]);
        let mut s = [0u8; 32];
        s.clone_from_slice(&combined[32..]);

        Self { r, s }
    }

    /// Unsafe version of `from_bytes` taking a slice.
    /// This function can fail when the slice has the wrong length.
    pub(crate) fn from_byte_slice(combined: &[u8]) -> Result<Self, Error> {
        if combined.len() != 64 {
            return Err(Error::InvalidSignature);
        }

        let mut r = [0u8; 32];
        r.clone_from_slice(&combined[..32]);
        let mut s = [0u8; 32];
        s.clone_from_slice(&combined[32..]);

        Ok(Self { r, s })
    }

    /// Get the raw signature bytes.
    /// Returns a 64 byte array containing `r||s`.
    pub fn raw(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        for (i, &b) in self.r.iter().enumerate() {
            out[i] = b;
        }
        for (i, &b) in self.s.iter().enumerate() {
            out[i + 32] = b;
        }
        out
    }
}

/// Sign `msg` with `sk` and `nonce` using `hash` with EcDSA on P256.
pub fn ecdsa_sign(hash: Mode, msg: &[u8], sk: &Scalar, nonce: &Nonce) -> Result<Signature, Error> {
    let private = validate_sk(sk)?;

    let mut signature = [0u8; 64];
    let result = match hash {
        Mode::Sha256 => unsafe {
            Hacl_P256_ecdsa_sign_p256_sha2(
                signature.as_mut_ptr(),
                msg.len() as u32,
                msg.as_ptr() as _,
                private.as_ptr() as _,
                nonce.as_ptr() as _,
            )
        },
        Mode::Sha384 => unsafe {
            Hacl_P256_ecdsa_sign_p256_sha384(
                signature.as_mut_ptr(),
                msg.len() as u32,
                msg.as_ptr() as _,
                private.as_ptr() as _,
                nonce.as_ptr() as _,
            )
        },
        Mode::Sha512 => unsafe {
            Hacl_P256_ecdsa_sign_p256_sha512(
                signature.as_mut_ptr(),
                msg.len() as u32,
                msg.as_ptr() as _,
                private.as_ptr() as _,
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
    Ok(Signature { r, s })
}

/// Verify EcDSA `signature` over P256 on `msg` with `pk` using `hash`.
/// Note that the public key `pk` must be a compressed or uncompressed point.
pub fn ecdsa_verify(
    hash: Mode,
    msg: &[u8],
    pk: &[u8],
    signature: &Signature,
) -> Result<bool, Error> {
    let public = validate_pk(pk)?;
    match hash {
        Mode::Sha256 => unsafe {
            Ok(Hacl_P256_ecdsa_verif_p256_sha2(
                msg.len() as u32,
                msg.as_ptr() as _,
                public.as_ptr() as _,
                signature.r.as_ptr() as _,
                signature.s.as_ptr() as _,
            ))
        },
        Mode::Sha384 => unsafe {
            Ok(Hacl_P256_ecdsa_verif_p256_sha384(
                msg.len() as u32,
                msg.as_ptr() as _,
                public.as_ptr() as _,
                signature.r.as_ptr() as _,
                signature.s.as_ptr() as _,
            ))
        },
        Mode::Sha512 => unsafe {
            Ok(Hacl_P256_ecdsa_verif_p256_sha512(
                msg.len() as u32,
                msg.as_ptr() as _,
                public.as_ptr() as _,
                signature.r.as_ptr() as _,
                signature.s.as_ptr() as _,
            ))
        },
        _ => Err(Error::InvalidConfig),
    }
}

pub fn random_nonce() -> Nonce {
    crate::rand_util::get_random_array()
}

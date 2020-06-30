use evercrypt_sys::evercrypt_bindings::*;

use crate::hmac::{get_tag_size, Mode};

pub fn hkdf_extract(mode: Mode, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let mut prk = vec![0u8; get_tag_size(mode)];
    unsafe {
        EverCrypt_HKDF_extract(
            mode as u8,
            prk.as_mut_ptr(),
            salt.as_ptr() as _,
            salt.len() as u32,
            ikm.as_ptr() as _,
            ikm.len() as u32,
        );
    }
    prk
}

pub fn hkdf_expand(mode: Mode, prk: &[u8], info: &[u8], okm_len: usize) -> Vec<u8> {
    if okm_len > 255 * get_tag_size(mode) {
        // Output size is too large. HACL doesn't catch this.
        return Vec::new();
    }
    let mut okm = vec![0u8; okm_len];
    unsafe {
        EverCrypt_HKDF_expand(
            mode as u8,
            okm.as_mut_ptr(),
            prk.as_ptr() as _,
            prk.len() as u32,
            info.as_ptr() as _,
            info.len() as u32,
            okm_len as u32,
        );
    }
    okm
}

pub fn hkdf(mode: Mode, salt: &[u8], ikm: &[u8], info: &[u8], okm_len: usize) -> Vec<u8> {
    let prk = hkdf_extract(mode, salt, ikm);
    hkdf_expand(mode, &prk, info, okm_len)
}

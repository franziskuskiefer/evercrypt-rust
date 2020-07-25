use evercrypt_sys::evercrypt_bindings::*;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Mode {
    Sha1 = Spec_Hash_Definitions_SHA1 as isize,
    // Not implemented
    // Sha224 = Spec_Hash_Definitions_SHA2_224 as isize,
    Sha256 = Spec_Hash_Definitions_SHA2_256 as isize,
    Sha384 = Spec_Hash_Definitions_SHA2_384 as isize,
    Sha512 = Spec_Hash_Definitions_SHA2_512 as isize,
}

pub fn get_tag_size(mode: Mode) -> usize {
    match mode {
        Mode::Sha1 => 20,
        Mode::Sha256 => 32,
        Mode::Sha384 => 48,
        Mode::Sha512 => 64,
    }
}

pub fn hmac(mode: Mode, key: &[u8], data: &[u8], tag_length: Option<usize>) -> Vec<u8> {
    let native_tag_length = get_tag_size(mode);
    let tag_length = match tag_length {
        Some(v) => v,
        None => native_tag_length,
    };
    let mut dst = vec![0u8; native_tag_length];
    unsafe {
        EverCrypt_HMAC_compute(
            mode as u8,
            dst.as_mut_ptr(),
            key.as_ptr() as _,
            key.len() as u32,
            data.as_ptr() as _,
            data.len() as u32,
        );
    }
    dst.truncate(tag_length);
    dst
}

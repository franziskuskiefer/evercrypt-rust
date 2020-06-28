#![allow(dead_code)]

// Include bindgen output
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct EverCrypt_AEAD_state_s {
    r#impl: Spec_Cipher_Expansion_impl,
    ek: *mut u8,
}

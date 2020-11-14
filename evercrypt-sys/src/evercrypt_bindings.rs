#![allow(dead_code)]

// Include bindgen output
// The bindings are freshly generated on Linux and MacOS builds.
// For Windows the prebuilt bindings.rs from the repository are used.
include!("bindings/bindings.rs");

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct EverCrypt_AEAD_state_s {
    r#impl: Spec_Cipher_Expansion_impl,
    ek: *mut u8,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Hacl_Streaming_Functor_state_s___EverCrypt_Hash_state_s____ {
    block_state: *mut EverCrypt_Hash_state_s,
    buf: *mut u8,
    total_len: u64,
}

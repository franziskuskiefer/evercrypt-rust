#![allow(dead_code)]

// Include bindgen output
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

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

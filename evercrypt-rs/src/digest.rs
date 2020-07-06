use evercrypt_sys::evercrypt_bindings::*;

#[derive(Copy, Clone, Debug)]
pub enum Mode {
    Sha1 = Spec_Hash_Definitions_SHA1 as isize,
    Sha224 = Spec_Hash_Definitions_SHA2_224 as isize,
    Sha256 = Spec_Hash_Definitions_SHA2_256 as isize,
    Sha384 = Spec_Hash_Definitions_SHA2_384 as isize,
    Sha512 = Spec_Hash_Definitions_SHA2_512 as isize,
}

pub(crate) fn get_digest_size(mode: Mode) -> usize {
    match mode {
        Mode::Sha1 => 20,
        Mode::Sha224 => 28,
        Mode::Sha256 => 32,
        Mode::Sha384 => 48,
        Mode::Sha512 => 64,
    }
}

pub fn hash(mode: Mode, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; get_digest_size(mode)];
    unsafe {
        EverCrypt_Hash_hash(
            mode as Spec_Hash_Definitions_hash_alg,
            out.as_mut_ptr(),
            data.as_ptr() as _,
            data.len() as u32,
        );
    }
    out
}

// TODO: add proper tests
#[test]
fn test_sha256() {
    let d = hash(Mode::Sha256, b"evercrypt-rust bindings");
    assert_eq!(
        d,
        [
            0xa5, 0x35, 0xf2, 0x6a, 0xff, 0xbc, 0x1f, 0x08, 0x73, 0xdb, 0x15, 0x15, 0x9d, 0xce,
            0xbf, 0x25, 0x99, 0x64, 0xbe, 0x42, 0xde, 0xa8, 0x4d, 0x29, 0x00, 0x38, 0x4b, 0xee,
            0x15, 0x09, 0xe4, 0x00
        ]
    );
}

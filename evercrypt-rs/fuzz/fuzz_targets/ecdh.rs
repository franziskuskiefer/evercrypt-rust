#![no_main]
use libfuzzer_sys::fuzz_target;

use evercrypt::prelude::*;

fuzz_target!(|data: &[u8]| {
    let _ = ecdh_derive(EcdhMode::X25519, data, data);
    let _ = ecdh_derive_base(EcdhMode::X25519, data);
    if data.len() >= 32 {
        let mut data32 = [0u8; 32];
        data32.clone_from_slice(&data[0..32]);
        let _ = x25519(&data32, &data32);
        let _ = x25519_base(&data32);
    }

    let _ = ecdh_derive(EcdhMode::P256, data, data);
    let _ = ecdh_derive_base(EcdhMode::P256, data);
    let _ = p256(data, data);
    let _ = p256_base(data);
});

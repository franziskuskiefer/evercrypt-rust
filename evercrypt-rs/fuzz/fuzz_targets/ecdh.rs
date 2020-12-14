#![no_main]
use libfuzzer_sys::fuzz_target;

use evercrypt::prelude::*;

fuzz_target!(|data: &[u8]| {
    let _ = ecdh_derive(EcdhMode::X25519, data, data);
    let _ = ecdh_derive_base(EcdhMode::X25519, data);
});

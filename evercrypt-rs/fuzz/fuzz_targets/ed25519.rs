#![no_main]
use libfuzzer_sys::fuzz_target;

use evercrypt::prelude::*;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 32 {
        let mut data32 = [0u8; 32];
        data32.clone_from_slice(&data[0..32]);
        let _pk = ed25519::sk2pk(&data32);
    }

    let sk = ed25519::key_gen();
    let pk = ed25519::sk2pk(&sk);
    let sig = ed25519::eddsa_sign(&sk, &data);
    let _sig_verified = ed25519::eddsa_verify(&pk, &sig, data);
    if data.len() >= 64 {
        let mut data32 = [0u8; 32];
        data32.clone_from_slice(&data[0..32]);
        let mut data64 = [0u8; 64];
        data64.clone_from_slice(&data[0..64]);
        let _sig_verified = ed25519::eddsa_verify(&data32, &sig, data);
        let _sig_verified = ed25519::eddsa_verify(&pk, &data64, data);
    }
    let sig = signature::sign(SignatureMode::Ed25519, None, &sk, &data, None);
    if let Ok(sig) = sig {
        let _sig_verified = signature::verify(SignatureMode::Ed25519, None, &pk, &sig, data);
        let _sig_verified = signature::verify(SignatureMode::Ed25519, None, data, &sig, data);
        let _sig_verified = signature::verify(SignatureMode::Ed25519, None, &pk, data, data);
    }
});

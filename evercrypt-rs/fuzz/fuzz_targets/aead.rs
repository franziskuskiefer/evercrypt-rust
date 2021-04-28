#![no_main]
use libfuzzer_sys::fuzz_target;

use evercrypt::prelude::*;

fuzz_target!(|data: &[u8]| {
    let modes = [
        AeadMode::Aes128Gcm,
        AeadMode::Aes256Gcm,
        AeadMode::Chacha20Poly1305,
    ];
    for &mode in modes.iter() {
        let k = if data.len() >= aead_key_size(mode) {
            data[0..aead_key_size(mode)].to_vec()
        } else {
            aead_key_gen(mode)
        };
        let nonce = if data.len() >= aead_key_size(mode) + aead_nonce_size(mode) {
            let mut nonce = AeadNonce::default();
            nonce.clone_from_slice(
                &data[aead_key_size(mode)..aead_key_size(mode) + aead_nonce_size(mode)],
            );
            nonce
        } else {
            aead_nonce_gen(mode)
        };
        let (c, t) = aead_encrypt(mode, &k, data, &nonce, &[]).expect("Error encrypting");
        let dec_result = aead_decrypt(mode, data, &c, &t, &nonce, &[]);
        if let Ok(ptxt) = dec_result {
            assert_eq!(ptxt, data);
        }
    }
});

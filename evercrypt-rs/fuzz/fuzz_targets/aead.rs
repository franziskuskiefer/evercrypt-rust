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
        let nonce = aead_nonce_gen(mode);
        let enc_result = aead_encrypt(mode, data, data, &nonce, &[]);
        let (c, t) = if let Ok((c, t)) = enc_result {
            (c, t)
        } else {
            if data.len() != 16 {
                return;
            }
            let mut tag = [0u8; 16];
            tag.clone_from_slice(data);
            (data.to_vec(), tag)
        };
        let dec_result = aead_decrypt(mode, data, &c, &t, &nonce, &[]);
        if let Ok(ptxt) = dec_result {
            assert_eq!(ptxt, data);
        }
    }
});

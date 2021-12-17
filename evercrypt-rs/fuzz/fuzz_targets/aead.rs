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
        let aead = match Aead::init(mode) {
            Ok(aead) => aead,
            Err(_) => {
                println!("{:?} is not available.", mode);
                continue;
            }
        };
        let k = if data.len() >= aead.key_size() {
            data[0..aead.key_size()].to_vec()
        } else {
            aead.key_gen()
        };
        let nonce = if data.len() >= aead.key_size() + aead.nonce_size() {
            data[aead.key_size()..aead.key_size() + aead.nonce_size()].to_vec()
        } else {
            aead.nonce_gen()
        };
        let aead = aead.set_key(&k).unwrap();
        let (c, t) = aead.encrypt(data, &nonce, &[]).expect("Error encrypting");
        let dec_result = aead.decrypt(&c, &t, &nonce, &[]);
        if let Ok(ptxt) = dec_result {
            assert_eq!(ptxt, data);
        }
    }

    // Check keys
    for &mode in modes.iter() {
        let aead = match Aead::init(mode) {
            Ok(aead) => aead,
            Err(_) => {
                println!("{:?} is not available.", mode);
                continue;
            }
        };
        let _aead = aead.set_key(data);
    }

    // Check nonce
    for &mode in modes.iter() {
        let mut aead = match Aead::init(mode) {
            Ok(aead) => aead,
            Err(_) => {
                println!("{:?} is not available.", mode);
                continue;
            }
        };
        aead.set_random_key().unwrap();
        let _enc = aead.encrypt(data, data, &[]);
    }
});

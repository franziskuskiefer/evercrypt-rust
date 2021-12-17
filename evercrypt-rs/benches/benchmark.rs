#[macro_use]
extern crate criterion;
extern crate evercrypt;
extern crate rand;

use criterion::{BatchSize, Criterion};

// 1 MB
const PAYLOAD_SIZE: usize = 0x100000;

fn clone_into_array<A, T>(slice: &[T]) -> A
where
    A: Default + AsMut<[T]>,
    T: Clone,
{
    let mut a = Default::default();
    A::as_mut(&mut a).clone_from_slice(slice);
    a
}

fn randombytes(n: usize) -> Vec<u8> {
    use rand::rngs::OsRng;
    use rand::RngCore;

    let mut bytes = vec![0u8; n];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for i in 0..(hex.len() / 2) {
        let b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        bytes.push(b);
    }
    bytes
}

fn criterion_digest(c: &mut Criterion) {
    use evercrypt::digest::{self, Mode};
    c.bench_function("SHA1", |b| {
        b.iter_batched(
            || randombytes(PAYLOAD_SIZE),
            |data| {
                let _d = digest::hash(Mode::Sha1, &data);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("SHA224", |b| {
        b.iter_batched(
            || randombytes(PAYLOAD_SIZE),
            |data| {
                let _d = digest::hash(Mode::Sha224, &data);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("SHA256", |b| {
        b.iter_batched(
            || randombytes(PAYLOAD_SIZE),
            |data| {
                let _d = digest::hash(Mode::Sha256, &data);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("SHA384", |b| {
        b.iter_batched(
            || randombytes(PAYLOAD_SIZE),
            |data| {
                let _d = digest::hash(Mode::Sha384, &data);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("SHA512", |b| {
        b.iter_batched(
            || randombytes(PAYLOAD_SIZE),
            |data| {
                let _d = digest::hash(Mode::Sha512, &data);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("SHA3 224", |b| {
        b.iter_batched(
            || randombytes(PAYLOAD_SIZE),
            |data| {
                let _d = digest::hash(Mode::Sha3_224, &data);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("SHA3 256", |b| {
        b.iter_batched(
            || randombytes(PAYLOAD_SIZE),
            |data| {
                let _d = digest::hash(Mode::Sha3_256, &data);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("SHA3 384", |b| {
        b.iter_batched(
            || randombytes(PAYLOAD_SIZE),
            |data| {
                let _d = digest::hash(Mode::Sha3_384, &data);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("SHA3 512", |b| {
        b.iter_batched(
            || randombytes(PAYLOAD_SIZE),
            |data| {
                let _d = digest::hash(Mode::Sha3_512, &data);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("SHAKE 128", |b| {
        b.iter_batched(
            || randombytes(PAYLOAD_SIZE),
            |data| {
                let _d = digest::shake128(&data, 64);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("SHAKE 256", |b| {
        b.iter_batched(
            || randombytes(PAYLOAD_SIZE),
            |data| {
                let _d = digest::shake256(&data, 64);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("Blake2s", |b| {
        b.iter_batched(
            || randombytes(PAYLOAD_SIZE),
            |data| {
                let _d = digest::hash(Mode::Blake2s, &data);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("Blake2b", |b| {
        b.iter_batched(
            || randombytes(PAYLOAD_SIZE),
            |data| {
                let _d = digest::hash(Mode::Blake2b, &data);
            },
            BatchSize::SmallInput,
        )
    });
}

fn criterion_aead(c: &mut Criterion) {
    use evercrypt::aead::{Aead, Mode};

    fn bench_encrypt<F>(c: &mut Criterion, id: &str, mode: Mode, mut fun: F)
    where
        F: FnMut(&[u8], &[u8], &[u8], Aead),
    {
        if Aead::init(mode).is_err() {
            println!("{:?} is not available.", mode);
            return;
        }
        c.bench_function(id, |b| {
            b.iter_batched(
                || {
                    let mut aead = Aead::init(mode).unwrap();
                    aead.set_random_key().unwrap();
                    let nonce = aead.nonce_gen();
                    let data = randombytes(PAYLOAD_SIZE);
                    let aad = randombytes(1_000);
                    (data, nonce, aad, aead)
                },
                |(data, nonce, aad, aead)| {
                    fun(&data, &nonce, &aad, aead);
                },
                BatchSize::SmallInput,
            )
        });
    }

    fn bench_decrypt<F>(c: &mut Criterion, id: &str, mode: Mode, mut fun: F)
    where
        F: FnMut(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
    {
        if Aead::init(mode).is_err() {
            println!("{:?} is not available.", mode);
            return;
        }
        c.bench_function(id, |b| {
            b.iter_batched(
                || {
                    let aead = Aead::init(mode).unwrap();
                    let key = aead.key_gen();
                    let aead = aead.set_key(&key).unwrap();
                    let nonce = aead.nonce_gen();
                    let data = randombytes(PAYLOAD_SIZE);
                    let aad = randombytes(1_000);
                    let (ct, tag) = aead.encrypt(&data, &nonce, &aad).unwrap();
                    let mut ct_tag = ct.clone();
                    ct_tag.extend(tag.clone());
                    (key, nonce, ct, tag, ct_tag, aad)
                },
                |(key, nonce, ct, tag, ct_tag, aad)| {
                    fun(key, nonce, ct, tag, ct_tag, aad);
                },
                BatchSize::SmallInput,
            )
        });
    }

    let payload_mb = PAYLOAD_SIZE / 1024 / 1024;
    bench_encrypt(
        c,
        &format!("AES128 GCM encrypt {}MB", payload_mb),
        Mode::Aes128Gcm,
        |data, nonce, aad, aead| {
            let (_ct, _tag) = aead.encrypt(&data, &nonce, &aad).unwrap();
        },
    );
    bench_encrypt(
        c,
        &format!("AES128 GCM encrypt (combine ctxt || tag) {}MB", payload_mb),
        Mode::Aes128Gcm,
        |data, nonce, aad, aead| {
            let (mut ct, mut tag) = aead.encrypt(&data, &nonce, &aad).unwrap();
            ct.append(&mut tag);
        },
    );
    bench_encrypt(
        c,
        &format!("AES128 GCM encrypt (combined ctxt || tag) {}MB", payload_mb),
        Mode::Aes128Gcm,
        |data, nonce, aad, aead| {
            let _ct = aead.encrypt_combined(&data, &nonce, &aad).unwrap();
        },
    );

    bench_decrypt(
        c,
        &format!("AES128 GCM decrypt {}MB", payload_mb),
        Mode::Aes128Gcm,
        |key, nonce, ct, tag, _ct_tag, aad| {
            let aead = Aead::new(Mode::Aes128Gcm, &key).unwrap();
            let _decrypted = aead.decrypt(&ct, &tag, &nonce, &aad).unwrap();
        },
    );
    bench_decrypt(
        c,
        &format!("AES128 GCM decrypt (combined ctxt || tag) {}MB", payload_mb),
        Mode::Aes128Gcm,
        |key, nonce, _ct, _tag, ct_tag, aad| {
            let aead = Aead::new(Mode::Aes128Gcm, &key).unwrap();
            let _decrypted = aead.decrypt_combined(&ct_tag, &nonce, &aad).unwrap();
        },
    );

    bench_encrypt(
        c,
        &format!("AES256 GCM encrypt {}MB", payload_mb),
        Mode::Aes256Gcm,
        |data, nonce, aad, aead| {
            let (_ct, _tag) = aead.encrypt(&data, &nonce, &aad).unwrap();
        },
    );
    bench_encrypt(
        c,
        &format!("AES256 GCM encrypt (combine ctxt || tag) {}MB", payload_mb),
        Mode::Aes256Gcm,
        |data, nonce, aad, aead| {
            let (mut ct, mut tag) = aead.encrypt(&data, &nonce, &aad).unwrap();
            ct.append(&mut tag);
        },
    );
    bench_encrypt(
        c,
        &format!("AES256 GCM encrypt (combined ctxt || tag) {}MB", payload_mb),
        Mode::Aes256Gcm,
        |data, nonce, aad, aead| {
            let _ct = aead.encrypt_combined(&data, &nonce, &aad).unwrap();
        },
    );

    bench_decrypt(
        c,
        &format!("AES256 GCM decrypt {}MB", payload_mb),
        Mode::Aes128Gcm,
        |key, nonce, ct, tag, _ct_tag, aad| {
            let aead = Aead::new(Mode::Aes128Gcm, &key).unwrap();
            let _decrypted = aead.decrypt(&ct, &tag, &nonce, &aad).unwrap();
        },
    );
    bench_decrypt(
        c,
        &format!("AES256 GCM decrypt (combined ctxt || tag) {}MB", payload_mb),
        Mode::Aes256Gcm,
        |key, nonce, _ct, _tag, ct_tag, aad| {
            let aead = Aead::new(Mode::Aes256Gcm, &key).unwrap();
            let _decrypted = aead.decrypt_combined(&ct_tag, &nonce, &aad).unwrap();
        },
    );

    bench_encrypt(
        c,
        &format!("ChaCha20Poly1305 encrypt {}MB", payload_mb),
        Mode::Chacha20Poly1305,
        |data, nonce, aad, aead| {
            let (_ct, _tag) = aead.encrypt(&data, &nonce, &aad).unwrap();
        },
    );
    bench_encrypt(
        c,
        &format!(
            "ChaCha20Poly1305 encrypt (combine ctxt || tag) {}MB",
            payload_mb
        ),
        Mode::Chacha20Poly1305,
        |data, nonce, aad, aead| {
            let (mut ct, mut tag) = aead.encrypt(&data, &nonce, &aad).unwrap();
            ct.append(&mut tag);
        },
    );
    bench_encrypt(
        c,
        &format!(
            "ChaCha20Poly1305 encrypt (combined ctxt || tag) {}MB",
            payload_mb
        ),
        Mode::Chacha20Poly1305,
        |data, nonce, aad, aead| {
            let _ct = aead.encrypt_combined(&data, &nonce, &aad).unwrap();
        },
    );

    bench_decrypt(
        c,
        &format!("ChaCha20Poly1305 decrypt {}MB", payload_mb),
        Mode::Chacha20Poly1305,
        |key, nonce, ct, tag, _ct_tag, aad| {
            let aead = Aead::new(Mode::Chacha20Poly1305, &key).unwrap();
            let _decrypted = aead.decrypt(&ct, &tag, &nonce, &aad).unwrap();
        },
    );
    bench_decrypt(
        c,
        &format!(
            "ChaCha20Poly1305 decrypt (combined ctxt || tag) {}MB",
            payload_mb
        ),
        Mode::Chacha20Poly1305,
        |key, nonce, _ct, _tag, ct_tag, aad| {
            let aead = Aead::new(Mode::Chacha20Poly1305, &key).unwrap();
            let _decrypted = aead.decrypt_combined(&ct_tag, &nonce, &aad).unwrap();
        },
    );
}

fn criterion_aead_keys(c: &mut Criterion) {
    use evercrypt::aead::{self, Aead, Mode};

    const PAYLOAD_MB: usize = PAYLOAD_SIZE / 1024 / 1024;
    const CHUNKS: usize = 100;

    if Aead::init(Mode::Aes128Gcm).is_err() {
        println!("{:?} is not available.", Mode::Aes128Gcm);
        return;
    }

    c.bench_function(
        &format!("AES128 GCM encrypt stateful {}x{}MB", CHUNKS, PAYLOAD_MB),
        |b| {
            b.iter_batched(
                || {
                    let mut aead = Aead::init(Mode::Aes128Gcm).unwrap();
                    aead.set_random_key().unwrap();
                    let mut nonce = Vec::new();
                    let mut data = Vec::new();
                    for _ in 0..CHUNKS {
                        data.push(randombytes(PAYLOAD_SIZE));
                        nonce.push(aead.nonce_gen());
                    }
                    let aad = randombytes(1_000);
                    (data, nonce, aad, aead)
                },
                |(data, nonce, aad, aead)| {
                    let mut ct = Vec::with_capacity(CHUNKS * PAYLOAD_SIZE);
                    for (chunk, chunk_nonce) in data.iter().zip(nonce.iter()) {
                        ct.push(aead.encrypt_combined(chunk, chunk_nonce, &aad).unwrap());
                    }
                },
                BatchSize::SmallInput,
            )
        },
    );
    c.bench_function(
        &format!("AES128 GCM encrypt single-shot {}x{}MB", CHUNKS, PAYLOAD_MB),
        |b| {
            b.iter_batched(
                || {
                    let key = aead::key_gen(Mode::Aes128Gcm);
                    let mut nonce = Vec::new();
                    let mut data = Vec::new();
                    for _ in 0..CHUNKS {
                        data.push(randombytes(PAYLOAD_SIZE));
                        nonce.push(aead::nonce_gen(Mode::Aes128Gcm));
                    }
                    let aad = randombytes(1_000);
                    (data, nonce, aad, key)
                },
                |(data, nonce, aad, key)| {
                    let mut ct = Vec::with_capacity(CHUNKS * PAYLOAD_SIZE);
                    for (chunk, chunk_nonce) in data.iter().zip(nonce.iter()) {
                        ct.push(
                            aead::encrypt_combined(Mode::Aes128Gcm, &key, chunk, chunk_nonce, &aad)
                                .unwrap(),
                        );
                    }
                },
                BatchSize::SmallInput,
            )
        },
    );
}

fn criterion_x25519(c: &mut Criterion) {
    use evercrypt::prelude::*;
    c.bench_function("X25519 base", |b| {
        b.iter_batched(
            || clone_into_array(&randombytes(32)),
            |sk| {
                let _pk = x25519_base(&sk);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("X25519 DH", |b| {
        b.iter_batched(
            || {
                let sk1 = clone_into_array(&randombytes(32));
                let pk1 = x25519_base(&sk1);
                let sk2 = clone_into_array(&randombytes(32));
                (pk1, sk2)
            },
            |(pk1, sk2)| {
                let _zz = x25519(&pk1, &sk2).unwrap();
            },
            BatchSize::SmallInput,
        )
    });
}

macro_rules! p256_signature_bench {
    ($c:expr, $name_sign:literal, $name_verify:literal, $name_sign_gen:literal,
        $name_verify_gen:literal, $sm:expr, $m:expr) => {
        $c.bench_function($name_sign, |b| {
            let sk1 = clone_into_array(&hex_to_bytes(SK1_HEX));
            let nonce = clone_into_array(&hex_to_bytes(NONCE));
            b.iter_batched(
                || randombytes(PAYLOAD_SIZE),
                |data| {
                    let _sig = p256::ecdsa_sign($m, &data, &sk1, &nonce).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
        $c.bench_function($name_verify, |b| {
            let pk1 = hex_to_bytes(PK1_HEX);
            let sk1 = clone_into_array(&hex_to_bytes(SK1_HEX));
            let nonce = clone_into_array(&hex_to_bytes(NONCE));
            b.iter_batched(
                || {
                    let data = randombytes(PAYLOAD_SIZE);
                    let sig = p256::ecdsa_sign($m, &data, &sk1, &nonce).unwrap();
                    (data, sig)
                },
                |(data, sig)| {
                    let _valid = p256::ecdsa_verify($m, &data, &pk1, &sig).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
        $c.bench_function($name_sign_gen, |b| {
            let sk1 = hex_to_bytes(SK1_HEX);
            let nonce = clone_into_array(&hex_to_bytes(NONCE));
            b.iter_batched(
                || randombytes(PAYLOAD_SIZE),
                |data| {
                    let _sig = signature::sign($sm, Some($m), &sk1, &data, Some(&nonce)).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
        $c.bench_function($name_verify_gen, |b| {
            let pk1 = hex_to_bytes(PK1_HEX);
            let sk1 = hex_to_bytes(SK1_HEX);
            let nonce = clone_into_array(&hex_to_bytes(NONCE));
            b.iter_batched(
                || {
                    let data = randombytes(PAYLOAD_SIZE);
                    let sig = signature::sign($sm, Some($m), &sk1, &data, Some(&nonce)).unwrap();
                    (data, sig)
                },
                |(data, sig)| {
                    let _valid = signature::verify($sm, Some($m), &pk1, &sig, &data).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
    };
}

fn criterion_p256(c: &mut Criterion) {
    use evercrypt::prelude::*;

    const PK1_HEX: &str = "0462d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26ac333a93a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30cf";
    const SK1_HEX: &str = "0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346";
    const _PK2_HEX: &str = "04bd07bd4326cdcabf42905efa4559a30e68cb215d40c9afb60ce02d4fda617579b927b5cba02d24fb9aafe1d429351e48bae9dd92d7bc7be15e5b8a30a86be13d";
    const SK2_HEX: &str = "00809c461d8b39163537ff8f5ef5b977e4cdb980e70e38a7ee0b37cc876729e9ff";
    const NONCE: &str = "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60";

    c.bench_function("P256 base", |b| {
        let sk1 = hex_to_bytes(SK1_HEX);
        b.iter(|| {
            let _pk = p256::dh_base(&sk1).unwrap();
        });
    });
    c.bench_function("P256 DH", |b| {
        let pk1 = hex_to_bytes(PK1_HEX);
        let sk2 = hex_to_bytes(SK2_HEX);
        b.iter(|| {
            let _zz = p256::dh(&pk1, &sk2).unwrap();
        });
    });
    c.bench_function("P256 base Agile", |b| {
        let sk1 = hex_to_bytes(SK1_HEX);
        b.iter(|| {
            let _pk = ecdh::derive_base(EcdhMode::P256, &sk1).unwrap();
        });
    });
    c.bench_function("P256 DH Agile", |b| {
        let pk1 = hex_to_bytes(PK1_HEX);
        let sk2 = hex_to_bytes(SK2_HEX);
        b.iter(|| {
            let _zz = ecdh::derive(EcdhMode::P256, &pk1, &sk2).unwrap();
        });
    });

    p256_signature_bench!(
        c,
        "P256 ECDSA Sign SHA-256",
        "P256 ECDSA Verify SHA-256",
        "P256 ECDSA Sign Agile SHA-256",
        "P256 ECDSA Verify Agile SHA-256",
        SignatureMode::P256,
        DigestMode::Sha256
    );

    p256_signature_bench!(
        c,
        "P256 ECDSA Sign SHA-384",
        "P256 ECDSA Verify SHA-384",
        "P256 ECDSA Sign Agile SHA-384",
        "P256 ECDSA Verify Agile SHA-384",
        SignatureMode::P256,
        DigestMode::Sha384
    );

    p256_signature_bench!(
        c,
        "P256 ECDSA Sign SHA-512",
        "P256 ECDSA Verify SHA-512",
        "P256 ECDSA Sign Agile SHA-512",
        "P256 ECDSA Verify Agile SHA-512",
        SignatureMode::P256,
        DigestMode::Sha512
    );
}

fn criterion_ed25519(c: &mut Criterion) {
    use evercrypt::ed25519;
    c.bench_function("ed25519 key gen", |b| {
        b.iter_batched(
            || clone_into_array(&randombytes(32)),
            |sk| {
                let _pk = ed25519::sk2pk(&sk);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("ed25519 sign", |b| {
        b.iter_batched(
            || {
                let sk = clone_into_array(&randombytes(32));
                let data = randombytes(0x10000);
                (sk, data)
            },
            |(sk, data)| {
                let _sig = ed25519::eddsa_sign(&sk, &data);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("ed25519 verify", |b| {
        b.iter_batched(
            || {
                let sk = clone_into_array(&randombytes(32));
                let pk = ed25519::sk2pk(&sk);
                let data = randombytes(0x10000);
                let sig = ed25519::eddsa_sign(&pk, &data);
                (pk, data, sig)
            },
            |(pk, data, sig)| {
                let _valid = ed25519::eddsa_verify(&pk, &sig, &data);
            },
            BatchSize::SmallInput,
        )
    });
}

fn criterion_hmac(c: &mut Criterion) {
    use evercrypt::hmac::{hmac, Mode};
    const KEY: [u8; 10] = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    c.bench_function("HMAC SHA1", |b| {
        b.iter_batched(
            || randombytes(PAYLOAD_SIZE),
            |data| {
                let _hmac = hmac(Mode::Sha1, &KEY, &data, None);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("HMAC SHA256", |b| {
        b.iter_batched(
            || randombytes(PAYLOAD_SIZE),
            |data| {
                let _hmac = hmac(Mode::Sha256, &KEY, &data, None);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("HMAC SHA384", |b| {
        b.iter_batched(
            || randombytes(PAYLOAD_SIZE),
            |data| {
                let _hmac = hmac(Mode::Sha384, &KEY, &data, None);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("HMAC SHA512", |b| {
        b.iter_batched(
            || randombytes(PAYLOAD_SIZE),
            |data| {
                let _hmac = hmac(Mode::Sha512, &KEY, &data, None);
            },
            BatchSize::SmallInput,
        )
    });
}

fn criterion_hkdf(c: &mut Criterion) {
    use evercrypt::prelude::*;

    macro_rules! hkdf_expand_bench {
        ($c:expr, $name_expand:literal, $name_extract:literal, $m:expr) => {
            c.bench_function($name_expand, |b| {
                b.iter_batched(
                    || {
                        let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
                        let salt = hex_to_bytes("000102030405060708090a0b0c");
                        let len = 32;
                        let prk = hkdf_extract(HmacMode::Sha1, &salt, &ikm);
                        let data = randombytes(0x10000);
                        (len, prk, data)
                    },
                    |(len, prk, data)| {
                        let _okm = hkdf_expand($m, &prk, &data, len);
                    },
                    BatchSize::SmallInput,
                )
            });
            c.bench_function($name_extract, |b| {
                let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
                let salt = hex_to_bytes("000102030405060708090a0b0c");
                b.iter(|| {
                    let _prk = hkdf_extract($m, &salt, &ikm);
                });
            });
        };
    }
    hkdf_expand_bench!(c, "HKDF Expand SHA1", "HKDF Extract SHA1", HmacMode::Sha1);
    hkdf_expand_bench!(
        c,
        "HKDF Expand SHA256",
        "HKDF Extract SHA256",
        HmacMode::Sha256
    );
    hkdf_expand_bench!(
        c,
        "HKDF Expand SHA384",
        "HKDF Extract SHA384",
        HmacMode::Sha384
    );
    hkdf_expand_bench!(
        c,
        "HKDF Expand SHA512",
        "HKDF Extract SHA512",
        HmacMode::Sha512
    );

    macro_rules! hkdf_bench {
        ($c:expr, $name:literal, $m:expr) => {
            c.bench_function($name, |b| {
                b.iter_batched(
                    || {
                        let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
                        let salt = hex_to_bytes("000102030405060708090a0b0c");
                        let len = 32;
                        let data = randombytes(0x10000);
                        (ikm, salt, len, data)
                    },
                    |(ikm, salt, len, data)| {
                        let _hkdf = hkdf($m, &salt, &ikm, &data, len);
                    },
                    BatchSize::SmallInput,
                )
            });
        };
    }
    hkdf_bench!(c, "HKDF SHA1", HmacMode::Sha1);
    hkdf_bench!(c, "HKDF SHA256", HmacMode::Sha256);
    hkdf_bench!(c, "HKDF SHA384", HmacMode::Sha384);
    hkdf_bench!(c, "HKDF SHA512", HmacMode::Sha512);
}

fn criterion_benchmark(c: &mut Criterion) {
    criterion_digest(c);
    criterion_aead(c);
    criterion_aead_keys(c);
    criterion_x25519(c);
    criterion_p256(c);
    criterion_ed25519(c);
    criterion_hmac(c);
    criterion_hkdf(c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

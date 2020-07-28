#[macro_use]
extern crate criterion;
extern crate evercrypt;
extern crate rand;

use criterion::{BatchSize, Criterion};

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

fn random_nonce<A: Default + AsMut<[u8]>>(n: usize) -> A {
    let b = randombytes(n);
    clone_into_array(&b)
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
            || randombytes(1_000),
            |data| {
                let _d = digest::hash(Mode::Sha1, &data);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("SHA224", |b| {
        b.iter_batched(
            || randombytes(1_000),
            |data| {
                let _d = digest::hash(Mode::Sha224, &data);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("SHA256", |b| {
        b.iter_batched(
            || randombytes(1_000),
            |data| {
                let _d = digest::hash(Mode::Sha256, &data);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("SHA384", |b| {
        b.iter_batched(
            || randombytes(1_000),
            |data| {
                let _d = digest::hash(Mode::Sha384, &data);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("SHA512", |b| {
        b.iter_batched(
            || randombytes(1_000),
            |data| {
                let _d = digest::hash(Mode::Sha512, &data);
            },
            BatchSize::SmallInput,
        )
    });
}

fn criterion_aead(c: &mut Criterion) {
    use evercrypt::aead::{Aead, Mode};

    c.bench_function("AES128 encrypt", |b| {
        let key = &randombytes(16);
        b.iter_batched(
            || {
                let nonce = random_nonce(12);
                let data = randombytes(1_000);
                let aad = randombytes(1_000);
                let aead = Aead::new(Mode::Aes128Gcm, key).unwrap();
                (data, nonce, aad, aead)
            },
            |(data, nonce, aad, aead)| {
                let (_ct, _tag) = aead.encrypt(&data, &nonce, &aad).unwrap();
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("AES128 decrypt", |b| {
        b.iter_batched(
            || {
                let key = randombytes(16);
                let nonce = random_nonce(12);
                let data = randombytes(1_000);
                let aad = randombytes(1_000);
                let aead = Aead::new(Mode::Aes128Gcm, &key).unwrap();
                let (ct, tag) = aead.encrypt(&data, &nonce, &aad).unwrap();
                (key, nonce, ct, tag, aad)
            },
            |(key, nonce, ct, tag, aad)| {
                let aead = Aead::new(Mode::Aes128Gcm, &key).unwrap();
                let _decrypted = aead.decrypt(&ct, &tag, &nonce, &aad).unwrap();
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("AES256 encrypt", |b| {
        let key = &randombytes(32);
        b.iter_batched(
            || {
                let nonce = random_nonce(12);
                let data = randombytes(1_000);
                let aad = randombytes(1_000);
                let aead = Aead::new(Mode::Aes256Gcm, key).unwrap();
                (data, nonce, aad, aead)
            },
            |(data, nonce, aad, aead)| {
                let (_ct, _tag) = aead.encrypt(&data, &nonce, &aad).unwrap();
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("AES256 decrypt", |b| {
        b.iter_batched(
            || {
                let key = randombytes(32);
                let nonce = random_nonce(12);
                let data = randombytes(1_000);
                let aad = randombytes(1_000);
                let aead = Aead::new(Mode::Aes256Gcm, &key).unwrap();
                let (ct, tag) = aead.encrypt(&data, &nonce, &aad).unwrap();
                (key, nonce, ct, tag, aad)
            },
            |(key, nonce, ct, tag, aad)| {
                let aead = Aead::new(Mode::Aes256Gcm, &key).unwrap();
                let _decrypted = aead.decrypt(&ct, &tag, &nonce, &aad).unwrap();
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("ChaCha20Poly1305 encrypt", |b| {
        let key = &randombytes(32);
        b.iter_batched(
            || {
                let nonce = random_nonce(12);
                let data = randombytes(1_000);
                let aad = randombytes(1_000);
                let aead = Aead::new(Mode::Chacha20Poly1305, key).unwrap();
                (data, nonce, aad, aead)
            },
            |(data, nonce, aad, aead)| {
                let (_ct, _tag) = aead.encrypt(&data, &nonce, &aad).unwrap();
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("ChaCha20Poly1305 decrypt", |b| {
        b.iter_batched(
            || {
                let key = randombytes(32);
                let nonce = random_nonce(12);
                let data = randombytes(1_000);
                let aad = randombytes(1_000);
                let aead = Aead::new(Mode::Chacha20Poly1305, &key).unwrap();
                let (ct, tag) = aead.encrypt(&data, &nonce, &aad).unwrap();
                (key, nonce, ct, tag, aad)
            },
            |(key, nonce, ct, tag, aad)| {
                let aead = Aead::new(Mode::Chacha20Poly1305, &key).unwrap();
                let _decrypted = aead.decrypt(&ct, &tag, &nonce, &aad).unwrap();
            },
            BatchSize::SmallInput,
        )
    });
}

fn criterion_x25519(c: &mut Criterion) {
    use evercrypt::x25519::{x25519, x25519_base};
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

fn criterion_p256(c: &mut Criterion) {
    use evercrypt::digest::Mode;
    use evercrypt::p256::{p256_dh, p256_dh_base, p256_ecdsa_sign, p256_ecdsa_verify};

    const PK1_HEX: &str = "0462d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26ac333a93a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30cf";
    const SK1_HEX: &str = "0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346";
    const _PK2_HEX: &str = "04bd07bd4326cdcabf42905efa4559a30e68cb215d40c9afb60ce02d4fda617579b927b5cba02d24fb9aafe1d429351e48bae9dd92d7bc7be15e5b8a30a86be13d";
    const SK2_HEX: &str = "00809c461d8b39163537ff8f5ef5b977e4cdb980e70e38a7ee0b37cc876729e9ff";
    const NONCE: &str = "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60";

    c.bench_function("P256 base", |b| {
        let sk1 = hex_to_bytes(SK1_HEX);
        b.iter(|| {
            let _pk = p256_dh_base(&sk1).unwrap();
        });
    });
    c.bench_function("P256 DH", |b| {
        let pk1 = hex_to_bytes(PK1_HEX);
        let sk2 = hex_to_bytes(SK2_HEX);
        b.iter(|| {
            let _zz = p256_dh(&pk1, &sk2).unwrap();
        });
    });

    c.bench_function("P256 ECDSA Sign SHA-256", |b| {
        let sk1 = hex_to_bytes(SK1_HEX);
        let nonce = hex_to_bytes(NONCE);
        b.iter_batched(
            || {
                let data = randombytes(1_000);
                data
            },
            |data| {
                let _sig = p256_ecdsa_sign(Mode::Sha256, &data, &sk1, &nonce).unwrap();
            },
            BatchSize::SmallInput,
        );
    });
    c.bench_function("P256 ECDSA Verify SHA-256", |b| {
        let pk1 = hex_to_bytes(PK1_HEX);
        let sk1 = hex_to_bytes(SK1_HEX);
        let nonce = hex_to_bytes(NONCE);
        b.iter_batched(
            || {
                let data = randombytes(1_000);
                let sig = p256_ecdsa_sign(Mode::Sha256, &data, &sk1, &nonce).unwrap();
                (data, sig)
            },
            |(data, sig)| {
                let _valid = p256_ecdsa_verify(Mode::Sha256, &data, &pk1, &sig).unwrap();
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("P256 ECDSA Sign SHA-384", |b| {
        let sk1 = hex_to_bytes(SK1_HEX);
        let nonce = hex_to_bytes(NONCE);
        b.iter_batched(
            || {
                let data = randombytes(1_000);
                data
            },
            |data| {
                let _sig = p256_ecdsa_sign(Mode::Sha384, &data, &sk1, &nonce).unwrap();
            },
            BatchSize::SmallInput,
        );
    });
    c.bench_function("P256 ECDSA Verify SHA-384", |b| {
        let pk1 = hex_to_bytes(PK1_HEX);
        let sk1 = hex_to_bytes(SK1_HEX);
        let nonce = hex_to_bytes(NONCE);
        b.iter_batched(
            || {
                let data = randombytes(1_000);
                let sig = p256_ecdsa_sign(Mode::Sha384, &data, &sk1, &nonce).unwrap();
                (data, sig)
            },
            |(data, sig)| {
                let _valid = p256_ecdsa_verify(Mode::Sha384, &data, &pk1, &sig).unwrap();
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("P256 ECDSA Sign SHA-512", |b| {
        let sk1 = hex_to_bytes(SK1_HEX);
        let nonce = hex_to_bytes(NONCE);
        b.iter_batched(
            || {
                let data = randombytes(1_000);
                data
            },
            |data| {
                let _sig = p256_ecdsa_sign(Mode::Sha512, &data, &sk1, &nonce).unwrap();
            },
            BatchSize::SmallInput,
        );
    });
    c.bench_function("P256 ECDSA Verify SHA-512", |b| {
        let pk1 = hex_to_bytes(PK1_HEX);
        let sk1 = hex_to_bytes(SK1_HEX);
        let nonce = hex_to_bytes(NONCE);
        b.iter_batched(
            || {
                let data = randombytes(1_000);
                let sig = p256_ecdsa_sign(Mode::Sha512, &data, &sk1, &nonce).unwrap();
                (data, sig)
            },
            |(data, sig)| {
                let _valid = p256_ecdsa_verify(Mode::Sha512, &data, &pk1, &sig).unwrap();
            },
            BatchSize::SmallInput,
        );
    });
}

fn criterion_ed25519(c: &mut Criterion) {
    use evercrypt::ed25519::{ed25519_sign, ed25519_sk2pk, ed25519_verify};
    c.bench_function("ed25519 key gen", |b| {
        b.iter_batched(
            || clone_into_array(&randombytes(32)),
            |sk| {
                let _pk = ed25519_sk2pk(&sk);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("ed25519 sign", |b| {
        b.iter_batched(
            || {
                let sk = clone_into_array(&randombytes(32));
                let data = randombytes(1_000);
                (sk, data)
            },
            |(sk, data)| {
                let _sig = ed25519_sign(&sk, &data);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("ed25519 verify", |b| {
        b.iter_batched(
            || {
                let sk = clone_into_array(&randombytes(32));
                let pk = ed25519_sk2pk(&sk);
                let data = randombytes(1_000);
                let sig = ed25519_sign(&pk, &data);
                (pk, data, sig)
            },
            |(pk, data, sig)| {
                let _valid = ed25519_verify(&pk, &sig, &data);
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
            || randombytes(1_000),
            |data| {
                let _hmac = hmac(Mode::Sha1, &KEY, &data, None);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("HMAC SHA256", |b| {
        b.iter_batched(
            || randombytes(1_000),
            |data| {
                let _hmac = hmac(Mode::Sha256, &KEY, &data, None);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("HMAC SHA384", |b| {
        b.iter_batched(
            || randombytes(1_000),
            |data| {
                let _hmac = hmac(Mode::Sha384, &KEY, &data, None);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("HMAC SHA512", |b| {
        b.iter_batched(
            || randombytes(1_000),
            |data| {
                let _hmac = hmac(Mode::Sha512, &KEY, &data, None);
            },
            BatchSize::SmallInput,
        )
    });
}

fn criterion_hkdf(c: &mut Criterion) {
    use evercrypt::hkdf::{hkdf, hkdf_expand, hkdf_extract};
    use evercrypt::hmac::Mode;

    c.bench_function("HKDF extract SHA1", |b| {
        let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_to_bytes("000102030405060708090a0b0c");
        b.iter(|| {
            let _prk = hkdf_extract(Mode::Sha1, &salt, &ikm);
        });
    });
    c.bench_function("HKDF extract SHA256", |b| {
        let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_to_bytes("000102030405060708090a0b0c");
        b.iter(|| {
            let _prk = hkdf_extract(Mode::Sha256, &salt, &ikm);
        });
    });
    c.bench_function("HKDF extract SHA384", |b| {
        let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_to_bytes("000102030405060708090a0b0c");
        b.iter(|| {
            let _prk = hkdf_extract(Mode::Sha384, &salt, &ikm);
        });
    });
    c.bench_function("HKDF extract SHA512", |b| {
        let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_to_bytes("000102030405060708090a0b0c");
        b.iter(|| {
            let _prk = hkdf_extract(Mode::Sha512, &salt, &ikm);
        });
    });

    c.bench_function("HKDF expand SHA1", |b| {
        b.iter_batched(
            || {
                let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
                let salt = hex_to_bytes("000102030405060708090a0b0c");
                let len = 32;
                let prk = hkdf_extract(Mode::Sha1, &salt, &ikm);
                let data = randombytes(1_000);
                (len, prk, data)
            },
            |(len, prk, data)| {
                let _okm = hkdf_expand(Mode::Sha1, &prk, &data, len);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("HKDF expand SHA256", |b| {
        b.iter_batched(
            || {
                let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
                let salt = hex_to_bytes("000102030405060708090a0b0c");
                let len = 32;
                let prk = hkdf_extract(Mode::Sha1, &salt, &ikm);
                let data = randombytes(1_000);
                (len, prk, data)
            },
            |(len, prk, data)| {
                let _okm = hkdf_expand(Mode::Sha256, &prk, &data, len);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("HKDF expand SHA384", |b| {
        b.iter_batched(
            || {
                let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
                let salt = hex_to_bytes("000102030405060708090a0b0c");
                let len = 32;
                let prk = hkdf_extract(Mode::Sha1, &salt, &ikm);
                let data = randombytes(1_000);
                (len, prk, data)
            },
            |(len, prk, data)| {
                let _okm = hkdf_expand(Mode::Sha384, &prk, &data, len);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("HKDF expand SHA512", |b| {
        b.iter_batched(
            || {
                let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
                let salt = hex_to_bytes("000102030405060708090a0b0c");
                let len = 32;
                let prk = hkdf_extract(Mode::Sha1, &salt, &ikm);
                let data = randombytes(1_000);
                (len, prk, data)
            },
            |(len, prk, data)| {
                let _okm = hkdf_expand(Mode::Sha512, &prk, &data, len);
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("HKDF SHA1", |b| {
        b.iter_batched(
            || {
                let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
                let salt = hex_to_bytes("000102030405060708090a0b0c");
                let len = 32;
                let data = randombytes(1_000);
                (ikm, salt, len, data)
            },
            |(ikm, salt, len, data)| {
                let _hkdf = hkdf(Mode::Sha1, &salt, &ikm, &data, len);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("HKDF SHA256", |b| {
        b.iter_batched(
            || {
                let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
                let salt = hex_to_bytes("000102030405060708090a0b0c");
                let len = 32;
                let data = randombytes(1_000);
                (ikm, salt, len, data)
            },
            |(ikm, salt, len, data)| {
                let _hkdf = hkdf(Mode::Sha256, &salt, &ikm, &data, len);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("HKDF SHA384", |b| {
        b.iter_batched(
            || {
                let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
                let salt = hex_to_bytes("000102030405060708090a0b0c");
                let len = 32;
                let data = randombytes(1_000);
                (ikm, salt, len, data)
            },
            |(ikm, salt, len, data)| {
                let _hkdf = hkdf(Mode::Sha384, &salt, &ikm, &data, len);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("HKDF SHA512", |b| {
        b.iter_batched(
            || {
                let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
                let salt = hex_to_bytes("000102030405060708090a0b0c");
                let len = 32;
                let data = randombytes(1_000);
                (ikm, salt, len, data)
            },
            |(ikm, salt, len, data)| {
                let _hkdf = hkdf(Mode::Sha512, &salt, &ikm, &data, len);
            },
            BatchSize::SmallInput,
        )
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    criterion_digest(c);
    criterion_aead(c);
    criterion_x25519(c);
    criterion_p256(c);
    criterion_ed25519(c);
    criterion_hmac(c);
    criterion_hkdf(c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

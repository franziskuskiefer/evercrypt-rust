use std::time::{Duration, Instant};

fn randombytes(n: usize) -> Vec<u8> {
    use rand::rngs::OsRng;
    use rand::RngCore;

    let mut bytes = vec![0u8; n];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn duration(d: Duration) -> f64 {
    (d.as_secs() as f64) + (d.subsec_nanos() as f64 * 1e-9)
}

fn aead_keys() {
    use evercrypt::aead::{self, Aead, Mode};
    const ONE_MB: usize = 0x100000;

    fn run(chunks: usize, payload_size: usize) {
        let payload_mb: f64 = (payload_size as f64) / 1024. / 1024.;
        let total_mb: f64 = payload_mb * chunks as f64;
        let aead = Aead::init(Mode::Aes128Gcm).unwrap();
        let key = aead::key_gen(Mode::Aes128Gcm);
        let mut nonce = Vec::new();
        let mut data = Vec::new();
        for _ in 0..chunks {
            data.push(randombytes(payload_size));
            nonce.push(aead.nonce_gen());
        }
        let aad = randombytes(1_000);

        println!("Warmup ...");
        for (chunk, chunk_nonce) in data.iter().zip(nonce.iter()) {
            aead::encrypt_combined(Mode::Aes128Gcm, &key, chunk, chunk_nonce, &aad).unwrap();
        }

        // Stateful
        let name = format!("AES128 GCM encrypt stateful {}x{}MB", chunks, payload_mb);
        println!("{}", name);

        let start = Instant::now();
        let aead = aead.set_key(&key).unwrap();
        let end = Instant::now();
        let time = duration(end.duration_since(start));
        println!("\t{}s key expansion", time);

        let mut ct1 = vec![];
        let start = Instant::now();
        for (chunk, chunk_nonce) in data.iter().zip(nonce.iter()) {
            ct1 = aead.encrypt_combined(chunk, chunk_nonce, &aad).unwrap();
        }
        let end = Instant::now();
        let time = duration(end.duration_since(start));
        println!("\t{} MB/s", total_mb / time);

        // Stateless
        let name = format!("AES128 GCM encrypt single-shot {}x{}MB", chunks, payload_mb);
        println!("{}", name);
        let mut ct2 = vec![];
        let start = Instant::now();
        for (chunk, chunk_nonce) in data.iter().zip(nonce.iter()) {
            ct2 = aead::encrypt_combined(Mode::Aes128Gcm, &key, chunk, chunk_nonce, &aad).unwrap();
        }
        let end = Instant::now();
        assert_eq!(&ct1, &ct2);
        let time = duration(end.duration_since(start));
        println!("\t{} MB/s", total_mb / time);
    }

    for num_mb in 1..2 {
        for chunks in 1..2 {
            let payload_size = num_mb * ONE_MB;
            run(chunks, payload_size);
        }
    }

    // 64 x 16KB
    let chunks = 64;
    let payload_size = 1024 * 16;
    run(chunks, payload_size);
}

fn main() {
    aead_keys();
}

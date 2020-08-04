# Evercrypt & HACL Rust bindings

This workspace holds the [evercrypt-sys](evercrypt-sys/) and high-level [evercrypt](evercrypt-rs/) crates.

## Features
By default the Evercrypt crate includes the `random` feature that allows generating random values (keys, nonces, etc.).
But this is not verified code and uses the [rand](https://crates.io/crates/rand) crate. It can be disabled with `--no-default-features`.
Please bring your own randomness if you want to be safe.

### RustCrypto AES
Evecrypt currently implements AES only for x64 CPUs with a certain set of CPU instructions.
To provide AES for other platforms the Evercrypt crate uses the [RustCrypto](https://github.com/RustCrypto/) AES implementation when using `--features rust-crypto-aes`.

## Benchmarks
To run benchmarks use `cargo bench`.

## Tests
All primitives are tested against the [Wycheproof](https://github.com/google/wycheproof) test vectors.
They can be run with `cargo test`.
This will also run automatically generated binding tests from bindgen.

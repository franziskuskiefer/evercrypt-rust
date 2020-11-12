# Evercrypt & HACL Rust bindings

![Build & Test](https://github.com/franziskuskiefer/evercrypt-rust/workflows/Build%20&%20Test/badge.svg)
[![codecov](https://codecov.io/gh/franziskuskiefer/evercrypt-rust/branch/master/graph/badge.svg?token=RO2Q0YTSNY)](https://codecov.io/gh/franziskuskiefer/evercrypt-rust/)
![Maturity Level](https://img.shields.io/badge/maturity-beta-orange.svg)

High-level [evercrypt](https://github.com/project-everest/hacl-star) bindings crates.

**⚠️ Note:** This crate is still work in progress. Don't use in production.

## Features
By default the Evercrypt crate includes the `random` feature that allows generating random values (keys, nonces, etc.).
But this is not verified code and uses the [rand](https://crates.io/crates/rand) crate. It can be disabled with `--no-default-features`.
Please bring your own randomness if you want to be safe.

### RustCrypto AES
Evecrypt currently implements AES only for x64 CPUs with a certain set of CPU instructions.
To provide AES for other platforms the Evercrypt crate uses the [RustCrypto](https://github.com/RustCrypto/) AES implementation when using `--features rust-crypto-aes`.

## Platforms
Currently only Linux x64 and MacOS are supported.
Windows builds are on the To Do list and should be supported in future.

| Platform      |                              Supported                              |
| :------------ | :-----------------------------------------------------------------: |
| MacOS         |                                  ✅                                  |
| Linux x86/x64 |                                  ✅                                  |
| Windows       | ❌ [#3](https://github.com/franziskuskiefer/evercrypt-rust/issues/3) |
| Arm64 Linux   |                                  ✅                                  |
| Arm32 Linux   |                                  ✅                                  |


## Benchmarks
To run benchmarks use `cargo bench`.

## Tests
All primitives are tested against the [Wycheproof](https://github.com/google/wycheproof) test vectors.
They can be run with `cargo test`.
This will also run automatically generated binding tests from bindgen.

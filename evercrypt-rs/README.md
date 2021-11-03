# Evercrypt & HACL Rust bindings

![Maturity Level][maturity-badge]
[![Build & Test][github-actions-badge]][github-actions-link]
[![ARM Build][drone-badge]][drone-link]
[![codecov][codecov-badge]][codecov-link]
![Rust Version][rustc-image]

High-level [evercrypt](https://github.com/project-everest/hacl-star) bindings crates.

**⚠️ Note:** This crate is still work in progress.
Don't use in production just yet.

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

| Platform             | Supported |
| :------------------- | :-------: |
| MacOS                |    ✅     |
| MacOS Arm64          |    ✅     |
| iOS                  |    ✅     |
| iOS Simulator x86_64 |    ❌     |
| Linux x64            |    ✅     |
| Linux x86            |    ✅     |
| Windows x64          |    ✅     |
| Arm64 Linux          |    ✅     |
| Arm32 Linux          |    ✅     |

## Benchmarks

To run benchmarks use `cargo bench`.

## Tests

All primitives are tested against the [Wycheproof](https://github.com/google/wycheproof) test vectors.
They can be run with `cargo test`.
This will also run automatically generated binding tests from bindgen.

[maturity-badge]: https://img.shields.io/badge/maturity-beta-orange.svg?style=for-the-badge
[github-actions-badge]: https://img.shields.io/github/workflow/status/franziskuskiefer/evercrypt-rust/Build%20&%20Test?label=build%20%26%20tests&logo=github&style=for-the-badge
[github-actions-link]: https://github.com/franziskuskiefer/evercrypt-rust/actions/workflows/evercrypt-rs.yml?query=branch%3Amain
[drone-badge]: https://img.shields.io/drone/build/franziskuskiefer/evercrypt-rust?label=ARM%20BUILD&style=for-the-badge
[drone-link]: https://cloud.drone.io/franziskuskiefer/evercrypt-rust
[codecov-badge]: https://img.shields.io/codecov/c/github/franziskuskiefer/evercrypt-rust?style=for-the-badge&token=RO2Q0YTSNY
[codecov-link]: https://codecov.io/gh/franziskuskiefer/evercrypt-rust/
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg?style=for-the-badge

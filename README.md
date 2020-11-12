# Evercrypt & HACL Rust bindings

![Maturity Level](https://img.shields.io/badge/maturity-beta-orange.svg)

This workspace holds the [evercrypt-sys](evercrypt-sys/) and high-level [evercrypt](evercrypt-rs/) crates.

| Platform    |                              Supported                              |                                                                                                            Status                                                                                                            |
| :---------- | :-----------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: |
| MacOS       |                                  ✅                                  | [![Build & Test](https://github.com/franziskuskiefer/evercrypt-rust/workflows/Build%20&%20Test/badge.svg)](https://github.com/franziskuskiefer/evercrypt-rust/actions?query=workflow%3A%22Build+%26+Test%22+branch%3Amaster) |
| Linux  x64  |                                  ✅                                  | [![Build & Test](https://github.com/franziskuskiefer/evercrypt-rust/workflows/Build%20&%20Test/badge.svg)](https://github.com/franziskuskiefer/evercrypt-rust/actions?query=workflow%3A%22Build+%26+Test%22+branch%3Amaster) |
| Windows     | ❌ [#3](https://github.com/franziskuskiefer/evercrypt-rust/issues/3) |                                                                                                                                                                                                                              |
| Arm64 Linux |                                  ✅                                  |                                   [![Build Status](https://cloud.drone.io/api/badges/franziskuskiefer/evercrypt-rust/status.svg)](https://cloud.drone.io/franziskuskiefer/evercrypt-rust)                                    |
| Arm32 Linux |                                  ✅                                  |                                   [![Build Status](https://cloud.drone.io/api/badges/franziskuskiefer/evercrypt-rust/status.svg)](https://cloud.drone.io/franziskuskiefer/evercrypt-rust)                                    |

## Crates

| Name          | Crates.io                                                                                                  | Docs  |
| :------------ | :-------------------------------------------------------------------------------------------------------- | :---: |
| evercrypt-sys | [![crates.io](https://img.shields.io/crates/v/evercrypt-sys.svg)](https://crates.io/crates/evercrypt-sys) |       |
| evercrypt     | [![crates.io](https://img.shields.io/crates/v/evercrypt.svg)](https://crates.io/crates/evercrypt)         |       |

## Features
By default the Evercrypt crate includes the `random` feature that allows generating random values (keys, nonces, etc.).
But this is not verified code and uses the [rand](https://crates.io/crates/rand) crate. It can be disabled with `--no-default-features`.
Please bring your own randomness if you want to be safe.

### RustCrypto AES
Evecrypt currently implements AES only for x64 CPUs with a certain set of CPU instructions.
To provide AES for other platforms the Evercrypt crate uses the [RustCrypto](https://github.com/RustCrypto/) AES implementation when using `--features rust-crypto-aes`.

## Platforms
Currently only Linux x64 and MacOS are supported.
Windows and ARM builds are on the To Do list and should be supported in future.

## Benchmarks
To run benchmarks use `cargo bench`.

## Tests
All primitives are tested against the [Wycheproof](https://github.com/google/wycheproof) test vectors.
They can be run with `cargo test`.
This will also run automatically generated binding tests from bindgen.

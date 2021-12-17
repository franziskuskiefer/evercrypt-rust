# Evercrypt & HACL Rust bindings

![Maturity Level][maturity-badge]
[![Build & Test][github-actions-badge]][github-actions-link]
[![ARM Build][drone-badge]][drone-link]

This workspace holds the [evercrypt-sys](evercrypt-sys/) and high-level [evercrypt](evercrypt-rs/) crates.

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

## Crates

| Name          | Crates.io                                                                     |                                                Docs                                                 |
| :------------ | :---------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------: |
| evercrypt-sys | [![crates.io][evercrypt-crate-badge]](https://crates.io/crates/evercrypt-sys) | [![Docs][docs-main-badge]](https://www.franziskuskiefer.de/evercrypt-rust/evercrypt_sys/index.html) |
| evercrypt     | [![crates.io][evercrypt-sys-crate-badge]](https://crates.io/crates/evercrypt) |   [![Docs][docs-main-badge]](https://www.franziskuskiefer.de/evercrypt-rust/evercrypt/index.html)   |

## Features

By default the Evercrypt crate includes the `random` feature that allows generating random values (keys, nonces, etc.).
But this is not verified code and uses the [rand](https://crates.io/crates/rand) crate. It can be disabled with `--no-default-features`.
Please bring your own randomness if you want to be safe.

## Platforms

See above for a list of supported platforms.

### Building

You will need to:

```
git clone --recurse-submodules path_of_repo
cargo build
```

### Building on Windows

To build `evercrypt` and `evercrypt-sys` on Windows ensure path for the `VsDevCmd.bat`
called in in `evercrypt-sys/hacl-build.bat` is correct on your system.
The build has only been tested with VisualStudio 2019.

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
[evercrypt-crate-badge]: https://img.shields.io/crates/v/evercrypt-sys.svg?style=for-the-badge
[evercrypt-sys-crate-badge]: https://img.shields.io/crates/v/evercrypt.svg?style=for-the-badge
[docs-main-badge]: https://img.shields.io/badge/docs-main-blue.svg?style=for-the-badge

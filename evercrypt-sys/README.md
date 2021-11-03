# evercrypt-sys

![Maturity Level][maturity-badge]
[![Build & Test][github-actions-badge]][github-actions-link]
[![ARM Build][drone-badge]][drone-link]
![Rust Version][rustc-image]

Rust wrapper for [hacl-star and evercrypt](https://github.com/project-everest/hacl-star/).

## Build

When building this `*-sys` crate make sure to get the hacl-star git submodule (`git submodule update --init --recursive`).
The hacl/evercrypt build is currently not part of the `cargo build`.
Run `build-evercrypt.sh` in order to build the `gcc-compatible` dist (this requires OCAML to be set up.).

### Platforms

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

#### Building on Windows

To build `evercrypt` and `evercrypt-sys` on Windows ensure path for the `VsDevCmd.bat`
called in in `hacl-build.bat` is correct on your system.
The build has only been tested with VisualStudio 2019.

[maturity-badge]: https://img.shields.io/badge/maturity-beta-orange.svg?style=for-the-badge
[github-actions-badge]: https://img.shields.io/github/workflow/status/franziskuskiefer/evercrypt-rust/Build%20&%20Test?label=build%20%26%20tests&logo=github&style=for-the-badge
[github-actions-link]: https://github.com/franziskuskiefer/evercrypt-rust/actions/workflows/evercrypt-rs.yml?query=branch%3Amain
[drone-badge]: https://img.shields.io/drone/build/franziskuskiefer/evercrypt-rust?label=ARM%20BUILD&style=for-the-badge
[drone-link]: https://cloud.drone.io/franziskuskiefer/evercrypt-rust
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg?style=for-the-badge

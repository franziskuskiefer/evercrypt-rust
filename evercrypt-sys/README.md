# evercrypt-sys

![Build & Test](https://github.com/franziskuskiefer/evercrypt-rust/workflows/Build%20&%20Test/badge.svg)
![Maturity Level](https://img.shields.io/badge/maturity-beta-orange.svg)

Rust wrapper for [hacl-star and evercrypt](https://github.com/project-everest/hacl-star/).

## Build
When building this `*-sys` crate make sure to get the hacl-star git submodule (`git submodule update --init --recursive`).
The hacl/evercrypt build is currently not part of the `cargo build`.
Run `build-evercrypt.sh` in order to build the `gcc-compatible` dist (this requires OCAML to be set up.).

### Platforms

| Platform    | Supported |                                                                                                            Status                                                                                                            |
| :---------- | :-------: | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: |
| MacOS       |     ✅     | [![Build & Test](https://github.com/franziskuskiefer/evercrypt-rust/workflows/Build%20&%20Test/badge.svg)](https://github.com/franziskuskiefer/evercrypt-rust/actions?query=workflow%3A%22Build+%26+Test%22+branch%3Amain) |
| Linux x64   |     ✅     | [![Build & Test](https://github.com/franziskuskiefer/evercrypt-rust/workflows/Build%20&%20Test/badge.svg)](https://github.com/franziskuskiefer/evercrypt-rust/actions?query=workflow%3A%22Build+%26+Test%22+branch%3Amain) |
| Linux x86   |     ✅     | [![Build & Test](https://github.com/franziskuskiefer/evercrypt-rust/workflows/Build%20&%20Test/badge.svg)](https://github.com/franziskuskiefer/evercrypt-rust/actions?query=workflow%3A%22Build+%26+Test%22+branch%3Amain) |
| Windows x64 |     ✅     | [![Build & Test](https://github.com/franziskuskiefer/evercrypt-rust/workflows/Build%20&%20Test/badge.svg)](https://github.com/franziskuskiefer/evercrypt-rust/actions?query=workflow%3A%22Build+%26+Test%22+branch%3Amain) |
| Arm64 Linux |     ✅     |                                   [![Build Status](https://cloud.drone.io/api/badges/franziskuskiefer/evercrypt-rust/status.svg)](https://cloud.drone.io/franziskuskiefer/evercrypt-rust)                                    |
| Arm32 Linux |     ✅     |                                   [![Build Status](https://cloud.drone.io/api/badges/franziskuskiefer/evercrypt-rust/status.svg)](https://cloud.drone.io/franziskuskiefer/evercrypt-rust)                                    |

#### Building on Windows
To build `evercrypt` and `evercrypt-sys` on Windows ensure path for the `VsDevCmd.bat`
called in in `hacl-build.bat` is correct on your system.
The build has only been tested with VisualStudio 2019.

# evercrypt-sys

![Build & Test](https://github.com/franziskuskiefer/evercrypt-rust/workflows/Build%20&%20Test/badge.svg)
![Maturity Level](https://img.shields.io/badge/maturity-beta-orange.svg)

Rust wrapper for [hacl-star and evercrypt](https://github.com/project-everest/hacl-star/).

## Build
When building this `*-sys` crate make sure to get the hacl-star git submodule (`git submodule update --init --recursive`).
The hacl/evercrypt build is currently not part of the `cargo build`.
Run `build-evercrypt.sh` in order to build the `gcc-compatible` dist (this requires OCAML to be set up.).

### Platforms
Windows support is on the To Do list.

| Platform |                              Supported                              |
| :------- | :-----------------------------------------------------------------: |
| MacOS    |                                  ✅                                  |
| Linux    |                                  ✅                                  |
| Windows  | ❌ [#3](https://github.com/franziskuskiefer/evercrypt-rust/issues/3) |
| Arm64    |                                  ✅                                  |
| Arm32    |                                  ✅                                  |

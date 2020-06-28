# evercrypt-sys

Rust wrapper for [hacl-star and evercrypt](https://github.com/project-everest/hacl-star/).

## Build
When building this `*-sys` crate make sure to get the hacl-star git submodule (`git submodule update --init --recursive`).
The hacl/evercrypt build is currently not part of the `cargo build`.
Run `build-evercrypt.sh` in order to build the `gcc-compatible` dist (this requires OCAML to be set up.).

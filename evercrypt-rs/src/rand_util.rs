//! Utilities that provide randomness.
//! Note that this currently uses the rand crate and should be moved to a more
//! secure alternative.
//!

use rand::{self, AsByteSliceMut};
use rand_core::{OsRng, RngCore};

/// Generate a random byte vector of length `len`.
pub fn get_random_vec(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    OsRng.fill_bytes(out.as_byte_slice_mut());
    out
}

/// Generate a random array.
pub fn get_random_array<A: Default + AsByteSliceMut>() -> A {
    let mut out = A::default();
    OsRng.fill_bytes(out.as_byte_slice_mut());
    out
}

//! Utilities that provide randomness.
//! Note that this currently uses the rand crate and should be moved to a more
//! secure alternative.
//! 

use rand::{self, Rng, AsByteSliceMut};

/// Generate a random byte vector of length `len`.
pub(crate) fn get_random_vec(len: usize) -> Vec<u8> {
    (0..len).map(|_| rand::random::<u8>()).collect()
}

/// Generate a random array.
pub(crate) fn get_random_array<A: Default + AsByteSliceMut>() -> A {
    let mut out = A::default();
    rand::thread_rng().fill(&mut out);
    out
}

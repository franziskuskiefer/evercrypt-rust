//! Authenticated Encryption with Associated Data (AEAD)
//!
//! This module implements AES-GCM 128 and 256, and Chacha20Poly1305.
//!
//! # Usage
//! This module provides two APIs
//!
//! ## Aead with key state
//! ```rust
//! use evercrypt::aead::{Aead, Mode, Error};
//!
//! let key = [0x5b, 0x96, 0x04, 0xfe, 0x14, 0xea, 0xdb, 0xa9, 0x31, 0xb0, 0xcc,
//!            0xf3, 0x48, 0x43, 0xda, 0xb9, 0x5b, 0x96, 0x04, 0xfe, 0x14, 0xea,
//!            0xdb, 0xa9, 0x31, 0xb0, 0xcc, 0xf3, 0x48, 0x43, 0xda, 0xb9];
//! let cipher = match Aead::new(Mode::Chacha20Poly1305, &key) {
//!    Ok(c) => c,
//!    Err(e) => panic!("Error instantiating AEAD.\n{:?}", e),
//! };
//!
//! let iv = [0x02, 0x83, 0x18, 0xab, 0xc1, 0x82, 0x40, 0x29, 0x13, 0x81, 0x41, 0xa2];
//! let msg = [0x00, 0x1d, 0x0c, 0x23, 0x12, 0x87, 0xc1, 0x18, 0x27, 0x84, 0x55, 0x4c, 0xa3, 0xa2, 0x19, 0x08];
//! let aad = [];
//!
//! let (ciphertext, tag) = match cipher.encrypt(&msg, &iv, &aad) {
//!     Ok(r) => r,
//!     Err(e) => panic!("Error encrypting.\n{:?}", e),
//! };
//!
//! let msg_ = match cipher.decrypt(&ciphertext, &tag, &iv, &aad) {
//!     Ok(r) => r,
//!     Err(e) => panic!("Error decrypting.\n{:?}", e),
//! };
//!
//! assert_eq!(&msg[..], &msg_[..]);
//! ```
//!
//! ## Single-shot API
//! ```rust
//! use evercrypt::aead::{self, Mode};
//!
//! let key = [0x5b, 0x96, 0x04, 0xfe, 0x14, 0xea, 0xdb, 0xa9, 0x31, 0xb0, 0xcc,
//!            0xf3, 0x48, 0x43, 0xda, 0xb9, 0x5b, 0x96, 0x04, 0xfe, 0x14, 0xea,
//!            0xdb, 0xa9, 0x31, 0xb0, 0xcc, 0xf3, 0x48, 0x43, 0xda, 0xb9];
//! let iv = [0x02, 0x83, 0x18, 0xab, 0xc1, 0x82, 0x40, 0x29, 0x13, 0x81, 0x41, 0xa2];
//! let msg = [0x00, 0x1d, 0x0c, 0x23, 0x12, 0x87, 0xc1, 0x18, 0x27, 0x84, 0x55, 0x4c, 0xa3, 0xa2, 0x19, 0x08];
//! let aad = [];
//!
//! let (ciphertext, tag) = match aead::encrypt(Mode::Chacha20Poly1305, &key, &msg, &iv, &aad) {
//!    Ok(r) => r,
//!    Err(e) => panic!("Error encrypting.\n{:?}", e),
//! };
//!
//! let msg_ = match aead::decrypt(Mode::Chacha20Poly1305, &key, &ciphertext, &tag, &iv, &aad) {
//!     Ok(r) => r,
//!     Err(e) => panic!("Error decrypting.\n{:?}", e),
//! };
//!
//! assert_eq!(&msg[..], &msg_[..]);
//! ```
//!

use std::convert::TryInto;

#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

use evercrypt_sys::evercrypt_bindings::*;

/// The AEAD Mode.
#[derive(Clone, Copy, PartialEq, Debug)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
pub enum Mode {
    Aes128Gcm = Spec_Agile_AEAD_AES128_GCM as isize,
    Aes256Gcm = Spec_Agile_AEAD_AES256_GCM as isize,
    Chacha20Poly1305 = Spec_Agile_AEAD_CHACHA20_POLY1305 as isize,
}

impl From<u8> for Mode {
    fn from(v: u8) -> Mode {
        match v {
            0 => Mode::Aes128Gcm,
            1 => Mode::Aes256Gcm,
            2 => Mode::Chacha20Poly1305,
            _ => panic!("Unknown AEAD mode {}", v),
        }
    }
}

impl From<Mode> for Spec_Agile_AEAD_alg {
    fn from(v: Mode) -> Spec_Agile_AEAD_alg {
        match v {
            Mode::Aes128Gcm => Spec_Agile_AEAD_AES128_GCM as Spec_Agile_AEAD_alg,
            Mode::Aes256Gcm => Spec_Agile_AEAD_AES256_GCM as Spec_Agile_AEAD_alg,
            Mode::Chacha20Poly1305 => Spec_Agile_AEAD_CHACHA20_POLY1305 as Spec_Agile_AEAD_alg,
        }
    }
}

/// Get the key size of the `Mode` in bytes.
#[inline]
pub const fn key_size(mode: Mode) -> usize {
    match mode {
        Mode::Aes128Gcm => 16,
        Mode::Aes256Gcm => 32,
        Mode::Chacha20Poly1305 => 32,
    }
}

/// Get the tag size of the `Mode` in bytes.
#[inline]
pub const fn tag_size(mode: Mode) -> usize {
    match mode {
        Mode::Aes128Gcm => 16,
        Mode::Aes256Gcm => 16,
        Mode::Chacha20Poly1305 => 16,
    }
}

/// Get the nonce size of the `Mode` in bytes.
#[inline]
pub const fn nonce_size(mode: Mode) -> usize {
    match mode {
        Mode::Aes128Gcm => 12,
        Mode::Aes256Gcm => 12,
        Mode::Chacha20Poly1305 => 12,
    }
}

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidInit = 0,
    InvalidAlgorithm = 1,
    InvalidCiphertext = 2,
    InvalidNonce = 3,
    UnsupportedConfig = 4,
    Encrypting = 5,
    Decrypting = 6,
    InvalidKeySize = 7,
    InvalidTagSize = 8,
}

/// The Aead struct allows to re-use a key without having to initialize it
/// every time.
pub struct Aead {
    mode: Mode,
    c_state: Option<*mut EverCrypt_AEAD_state_s>,
}

/// Ciphertexts are byte vectors.
pub type Ciphertext = Vec<u8>;

/// Aead keys are byte vectors.
pub type Key = Vec<u8>;

/// Aead tags are byte vectors.
pub type Tag = Vec<u8>;

/// Nonces are byte vectors.
pub type Nonce = Vec<u8>;

/// Associated data are byte arrays.
pub type Aad = [u8];

// Check hardware support for HACL* AES implementation.
unsafe fn hacl_aes_available() -> bool {
    EverCrypt_AutoConfig2_has_pclmulqdq()
        && EverCrypt_AutoConfig2_has_avx()
        && EverCrypt_AutoConfig2_has_sse()
        && EverCrypt_AutoConfig2_has_movbe()
        && EverCrypt_AutoConfig2_has_aesni()
}

impl Aead {
    fn set_key_(&mut self, mut k: Vec<u8>) -> Result<(), Error> {
        let state = unsafe {
            let mut state_ptr: *mut EverCrypt_AEAD_state_s = std::ptr::null_mut();
            let e = EverCrypt_AEAD_create_in(self.mode.into(), &mut state_ptr, k.as_mut_ptr());
            if e != 0 {
                return Err(Error::InvalidInit);
            }
            state_ptr
        };
        self.c_state = Some(state);
        Ok(())
    }

    /// Create a new Aead cipher with the given Mode `alg` and key `k`.
    /// If the algorithm is not supported or the state generation fails, this
    /// function returns an `Error`.
    ///
    /// To get an Aead instance without setting a key immediately see `init`.
    pub fn new(mode: Mode, k: &[u8]) -> Result<Self, Error> {
        // Check key lengths. Evercrypt is not doing this.
        if k.len() != key_size(mode) {
            return Err(Error::InvalidKeySize);
        }

        unsafe {
            // Make sure this happened.
            EverCrypt_AutoConfig2_init();
        }
        let mut out = Self::init(mode)?;
        out.set_key_(k.to_vec())?;
        Ok(out)
    }

    /// Initialize a new Aead object without a key.
    /// Use `set_key` to do so later.
    pub fn init(mode: Mode) -> Result<Self, Error> {
        if unsafe {
            // Make sure this happened.
            EverCrypt_AutoConfig2_init();

            // Make sure the algorithm is supported
            (mode == Mode::Aes128Gcm || mode == Mode::Aes256Gcm) && !hacl_aes_available()
        } {
            return Err(Error::UnsupportedConfig);
        }
        Ok(Self {
            mode,
            c_state: None,
        })
    }

    /// Set the key for this instance.
    /// This consumes the Aead and returns a new instance with the key.
    pub fn set_key(self, k: &[u8]) -> Result<Self, Error> {
        Self::new(self.mode, k)
    }

    /// Generate a new random key for this instance.
    /// This consumes the Aead and returns a new instance with the key.
    #[cfg(feature = "random")]
    pub fn set_random_key(&mut self) -> Result<(), Error> {
        let k = self.key_gen();
        self.set_key_(k)
    }

    /// Generate a random key.
    #[cfg(feature = "random")]
    pub fn key_gen(&self) -> Key {
        key_gen(self.mode)
    }

    /// Generate a nonce.
    #[cfg(feature = "random")]
    pub fn nonce_gen(&self) -> Nonce {
        // debug_assert!(LEN == nonce_size(self.mode));
        nonce_gen(self.mode)
    }

    /// Get the nonce size of this Aead in bytes.
    pub const fn nonce_size(&self) -> usize {
        nonce_size(self.mode)
    }

    /// Get the key size of this Aead in bytes.
    pub const fn key_size(&self) -> usize {
        key_size(self.mode)
    }

    /// Get the tag size of this Aead in bytes.
    pub const fn tag_size(&self) -> usize {
        tag_size(self.mode)
    }

    /// Encrypt with the algorithm and key of this Aead.
    /// Returns `(ctxt, tag)` or an `Error`.
    pub fn encrypt(&self, msg: &[u8], iv: &[u8], aad: &Aad) -> Result<(Ciphertext, Tag), Error> {
        if iv.len() != self.nonce_size() {
            return Err(Error::InvalidNonce);
        }

        let mut ctxt = vec![0u8; msg.len()];
        let mut tag = vec![0u8; self.tag_size()];
        unsafe {
            EverCrypt_AEAD_encrypt(
                self.c_state.unwrap(),
                iv.as_ptr() as _,
                self.nonce_size().try_into().unwrap(),
                aad.as_ptr() as _,
                aad.len() as u32,
                msg.as_ptr() as _,
                msg.len() as u32,
                ctxt.as_mut_ptr(),
                tag.as_mut_ptr(),
            );
        }
        Ok((ctxt, tag))
    }

    /// Encrypt with the algorithm and key of this Aead.
    /// Returns `(ctxt || tag)` or an `Error`.
    /// This is more efficient if the tag needs to be appended to the cipher text.
    pub fn encrypt_combined(&self, msg: &[u8], iv: &[u8], aad: &Aad) -> Result<Ciphertext, Error> {
        if iv.len() != self.nonce_size() {
            return Err(Error::InvalidNonce);
        }

        // combined cipher text and tag
        let mut ctxt = vec![0u8; msg.len() + self.tag_size()];
        unsafe {
            EverCrypt_AEAD_encrypt(
                self.c_state.unwrap(),
                iv.as_ptr() as _,
                self.nonce_size().try_into().unwrap(),
                aad.as_ptr() as _,
                aad.len() as u32,
                msg.as_ptr() as _,
                msg.len() as u32,
                ctxt.as_mut_ptr(),
                ctxt.as_mut_ptr().offset(msg.len().try_into().unwrap()),
            );
        }
        Ok(ctxt)
    }

    /// Encrypt with the algorithm and key of this Aead.
    /// Returns the cipher text in the `payload` and a `tag` or an `Error`.
    pub fn encrypt_in_place(&self, payload: &mut [u8], iv: &[u8], aad: &Aad) -> Result<Tag, Error> {
        if iv.len() != self.nonce_size() {
            return Err(Error::InvalidNonce);
        }

        // The tag
        let mut tag = vec![0u8; self.tag_size()];
        unsafe {
            EverCrypt_AEAD_encrypt(
                self.c_state.unwrap(),
                iv.as_ptr() as _,
                self.nonce_size().try_into().unwrap(),
                aad.as_ptr() as _,
                aad.len() as u32,
                payload.as_ptr() as _,
                payload.len() as u32,
                payload.as_ptr() as _,
                tag.as_mut_ptr(),
            );
        }
        Ok(tag)
    }

    #[inline]
    fn _decrypt_checks(&self, tag: &[u8], iv: &[u8]) -> Result<(), Error> {
        if iv.len() != 12 {
            return Err(Error::InvalidNonce);
        }
        if tag.len() != self.tag_size() {
            return Err(Error::InvalidTagSize);
        }
        Ok(())
    }

    #[inline]
    fn _decrypt(&self, ctxt: &[u8], tag: &[u8], iv: &[u8], aad: &Aad) -> Result<Vec<u8>, Error> {
        self._decrypt_checks(tag, iv)?;

        let mut msg = vec![0u8; ctxt.len()];
        let r = unsafe {
            EverCrypt_AEAD_decrypt(
                self.c_state.unwrap(),
                iv.as_ptr() as _,
                self.nonce_size().try_into().unwrap(),
                aad.as_ptr() as _,
                aad.len() as u32,
                ctxt.as_ptr() as _,
                ctxt.len() as u32,
                tag.as_ptr() as _,
                msg.as_mut_ptr(),
            )
        };
        if r as u32 != EverCrypt_Error_Success {
            Err(Error::InvalidCiphertext)
        } else {
            Ok(msg)
        }
    }

    /// Decrypt with the algorithm and key of this Aead.
    /// Returns `msg` or an `Error`.
    pub fn decrypt(&self, ctxt: &[u8], tag: &[u8], iv: &[u8], aad: &Aad) -> Result<Vec<u8>, Error> {
        self._decrypt(ctxt, tag, iv, aad)
    }

    /// Decrypt with the algorithm and key of this Aead.
    /// Returns `msg` or an `Error`.
    /// This takes the combined ctxt || tag as input and might be more efficient
    /// than `decrypt`.
    pub fn decrypt_combined(&self, ctxt: &[u8], iv: &[u8], aad: &Aad) -> Result<Vec<u8>, Error> {
        if ctxt.len() < self.tag_size() {
            return Err(Error::InvalidTagSize);
        }
        let msg_len = ctxt.len() - self.tag_size();
        let tag = &ctxt[msg_len..];
        let ctxt = &ctxt[..msg_len];
        self._decrypt(ctxt, tag, iv, aad)
    }

    /// Decrypt with the algorithm and key of this Aead.
    ///
    /// Returns an `Error` if decryption failed. The decrypted `payload` is written
    /// into `payload`.
    pub fn decrypt_in_place(
        &self,
        payload: &mut [u8],
        tag: &[u8],
        iv: &[u8],
        aad: &Aad,
    ) -> Result<(), Error> {
        self._decrypt_checks(tag, iv)?;

        let r = unsafe {
            EverCrypt_AEAD_decrypt(
                self.c_state.unwrap(),
                iv.as_ptr() as _,
                self.nonce_size().try_into().unwrap(),
                aad.as_ptr() as _,
                aad.len() as u32,
                payload.as_ptr() as _,
                payload.len() as u32,
                tag.as_ptr() as _,
                payload.as_mut_ptr(),
            )
        };
        if r as u32 != EverCrypt_Error_Success {
            Err(Error::InvalidCiphertext)
        } else {
            Ok(())
        }
    }
}

impl Drop for Aead {
    fn drop(&mut self) {
        if let Some(c_state) = self.c_state {
            unsafe { EverCrypt_AEAD_free(c_state) }
        }
    }
}

// Single-shot APIs

/// Single-shot API for AEAD encryption.
pub fn encrypt(
    alg: Mode,
    k: &[u8],
    msg: &[u8],
    iv: &[u8],
    aad: &Aad,
) -> Result<(Ciphertext, Tag), Error> {
    let cipher = Aead::new(alg, k)?;
    cipher.encrypt(msg, iv, aad)
}

/// Single-shot API for combined AEAD encryption.
pub fn encrypt_combined(
    alg: Mode,
    k: &[u8],
    msg: &[u8],
    iv: &[u8],
    aad: &Aad,
) -> Result<Ciphertext, Error> {
    let cipher = Aead::new(alg, k)?;
    cipher.encrypt_combined(msg, iv, aad)
}

/// Single-shot API for in place AEAD encryption.
pub fn encrypt_in_place(
    alg: Mode,
    k: &[u8],
    payload: &mut [u8],
    iv: &[u8],
    aad: &Aad,
) -> Result<Tag, Error> {
    let cipher = Aead::new(alg, k)?;
    cipher.encrypt_in_place(payload, iv, aad)
}

/// Single-shot API for AEAD decryption.
pub fn decrypt(
    alg: Mode,
    k: &[u8],
    ctxt: &[u8],
    tag: &[u8],
    iv: &[u8],
    aad: &Aad,
) -> Result<Vec<u8>, Error> {
    let cipher = Aead::new(alg, k)?;
    cipher.decrypt(ctxt, tag, iv, aad)
}

/// Single-shot API for combined AEAD decryption.
pub fn decrypt_combined(
    alg: Mode,
    k: &[u8],
    ctxt: &[u8],
    iv: &[u8],
    aad: &Aad,
) -> Result<Vec<u8>, Error> {
    let cipher = Aead::new(alg, k)?;
    cipher.decrypt_combined(ctxt, iv, aad)
}

/// Single-shot API for AEAD decryption in place.
pub fn decrypt_in_place(
    alg: Mode,
    k: &[u8],
    payload: &mut [u8],
    tag: &[u8],
    iv: &[u8],
    aad: &Aad,
) -> Result<(), Error> {
    let cipher = Aead::new(alg, k)?;
    cipher.decrypt_in_place(payload, tag, iv, aad)
}

/// Generate a random key.
#[cfg(feature = "random")]
pub fn key_gen(mode: Mode) -> Key {
    crate::rand_util::random_vec(key_size(mode))
}

/// Generate a nonce.
#[cfg(feature = "random")]
pub fn nonce_gen(mode: Mode) -> Nonce {
    crate::rand_util::random_vec(nonce_size(mode))
}

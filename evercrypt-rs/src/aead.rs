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
//! let key = [0x5b, 0x96, 0x04, 0xfe, 0x14, 0xea, 0xdb, 0xa9, 0x31, 0xb0, 0xcc, 0xf3, 0x48, 0x43, 0xda, 0xb9];
//! let cipher = match Aead::new(Mode::Aes128Gcm, &key) {
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
//! let key = [0x5b, 0x96, 0x04, 0xfe, 0x14, 0xea, 0xdb, 0xa9, 0x31, 0xb0, 0xcc, 0xf3, 0x48, 0x43, 0xda, 0xb9];
//! let iv = [0x02, 0x83, 0x18, 0xab, 0xc1, 0x82, 0x40, 0x29, 0x13, 0x81, 0x41, 0xa2];
//! let msg = [0x00, 0x1d, 0x0c, 0x23, 0x12, 0x87, 0xc1, 0x18, 0x27, 0x84, 0x55, 0x4c, 0xa3, 0xa2, 0x19, 0x08];
//! let aad = [];
//!
//! let (ciphertext, tag) = match aead::encrypt(Mode::Aes128Gcm, &key, &msg, &iv, &aad) {
//!    Ok(r) => r,
//!    Err(e) => panic!("Error encrypting.\n{:?}", e),
//! };
//!
//! let msg_ = match aead::decrypt(Mode::Aes128Gcm, &key, &ciphertext, &tag, &iv, &aad) {
//!     Ok(r) => r,
//!     Err(e) => panic!("Error decrypting.\n{:?}", e),
//! };
//!
//! assert_eq!(&msg[..], &msg_[..]);
//! ```
//!

use evercrypt_sys::evercrypt_bindings::*;

#[cfg(feature = "rust-crypto-aes")]
use aes_gcm::aead::{Aead as RcAead, NewAead, Payload};
#[cfg(feature = "rust-crypto-aes")]
use aes_gcm::{Aes128Gcm, Aes256Gcm};

/// Operating mode for AEAD.
/// This allows enabling enabling RustCrypto AES as a fallback mode.
#[derive(Clone, Copy, PartialEq)]
enum OpMode {
    Hacl = 0,
    RustCryptoAes128 = 1,
    RustCryptoAes256 = 2,
}

/// The AEAD Mode.
#[derive(Clone, Copy, PartialEq, Debug)]
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

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidInit = 0,
    InvalidAlgorithm = 1,
    InvalidCiphertext = 2,
    InvalidNonce = 3,
    UnsupportedConfig = 4,
    Encrypting = 5,
    Decrypting = 6,
}

/// The Aead struct allows to re-use a key without having to initialize it
/// every time.
pub struct Aead<'a> {
    c_state: Option<*mut EverCrypt_AEAD_state_s>,
    op_mode: OpMode,
    #[allow(dead_code)] // key is only used when using rust-crypto
    key: &'a [u8],
}

type Ciphertext = Vec<u8>;
type Tag = Vec<u8>;
type Nonce = [u8]; // TODO: fix to length 12
type Aad = [u8];

// Check hardware support for HACL* AES implementation.
fn hacl_aes_available() -> bool {
    unsafe {
        EverCrypt_AutoConfig2_has_pclmulqdq()
            && EverCrypt_AutoConfig2_has_avx()
            && EverCrypt_AutoConfig2_has_sse()
            && EverCrypt_AutoConfig2_has_movbe()
            && EverCrypt_AutoConfig2_has_aesni()
    }
}

fn alg_is_aes(alg: Mode) -> bool {
    match alg {
        Mode::Aes128Gcm | Mode::Aes256Gcm => true,
        _ => false,
    }
}

impl<'a> Aead<'a> {
    /// Create a new Aead cipher with the given Mode `alg` and key `k`.
    /// If the algorithm is not supported or the state generation fails, this
    /// function returns an `Error`.
    pub fn new(alg: Mode, k: &'a [u8]) -> Result<Self, Error> {
        unsafe {
            // Make sure this happened.
            EverCrypt_AutoConfig2_init();
        }
        if hacl_aes_available() || !alg_is_aes(alg) {
            let state = unsafe {
                let mut state_ptr: *mut EverCrypt_AEAD_state_s = std::ptr::null_mut();
                let e =
                    EverCrypt_AEAD_create_in(alg.into(), &mut state_ptr, k.to_vec().as_mut_ptr());
                if e != 0 {
                    return Err(Error::InvalidInit);
                }
                state_ptr
            };
            Ok(Self {
                c_state: Some(state),
                op_mode: OpMode::Hacl,
                key: k,
            })
        } else if cfg!(feature = "rust-crypto-aes") {
            // Fall back to software AES GCM implemented in RustCrypto
            debug_assert!(alg_is_aes(alg));
            match alg {
                Mode::Aes128Gcm => Ok(Self {
                    c_state: None,
                    op_mode: OpMode::RustCryptoAes128,
                    key: k,
                }),
                Mode::Aes256Gcm => Ok(Self {
                    c_state: None,
                    op_mode: OpMode::RustCryptoAes256,
                    key: k,
                }),
                _ => panic!("This can't happen. We must only get in here if you want AES."),
            }
        } else {
            Err(Error::UnsupportedConfig)
        }
    }

    // Encryption using RustCrytpo AES.
    // Only available if the feature is enabled.
    #[cfg(feature = "rust-crypto-aes")]
    fn encrypt_rs(&self, msg: &[u8], iv: &Nonce, aad: &Aad) -> Result<(Ciphertext, Tag), Error> {
        let ctxt_tag =
            match self.op_mode {
                OpMode::RustCryptoAes128 => Aes128Gcm::new(self.key.into())
                    .encrypt(iv.into(), Payload { msg: msg, aad: aad }),
                OpMode::RustCryptoAes256 => Aes256Gcm::new(self.key.into())
                    .encrypt(iv.into(), Payload { msg: msg, aad: aad }),
                _ => return Err(Error::UnsupportedConfig),
            };
        match ctxt_tag {
            Ok(c) => {
                let (ctxt, tag) = c.split_at(c.len() - 16);
                Ok((ctxt.to_owned(), tag.to_owned()))
            }
            Err(_) => Err(Error::Encrypting),
        }
    }

    // Decryption using RustCrytpo AES.
    // Only available if the feature is enabled.
    #[cfg(feature = "rust-crypto-aes")]
    fn decrypt_rs(&self, ctxt: &[u8], tag: &[u8], iv: &Nonce, aad: &Aad) -> Result<Vec<u8>, Error> {
        let mut p_in: Vec<u8> = vec![];
        p_in.extend(ctxt);
        p_in.extend(tag);
        let msg = match self.op_mode {
            OpMode::RustCryptoAes128 => Aes128Gcm::new(self.key.into()).decrypt(
                iv.into(),
                Payload {
                    msg: &p_in[..],
                    aad: aad,
                },
            ),
            OpMode::RustCryptoAes256 => Aes256Gcm::new(self.key.into()).decrypt(
                iv.into(),
                Payload {
                    msg: &p_in[..],
                    aad: aad,
                },
            ),
            _ => return Err(Error::UnsupportedConfig),
        };
        match msg {
            Ok(c) => Ok(c),
            Err(_) => Err(Error::InvalidCiphertext),
        }
    }

    // Stub function for the default mode when RustCrypto support is not enabled.
    #[cfg(not(feature = "rust-crypto-aes"))]
    fn encrypt_rs(&self, _msg: &[u8], _iv: &Nonce, _aad: &Aad) -> Result<(Ciphertext, Tag), Error> {
        Err(Error::UnsupportedConfig)
    }

    // Stub function for the default mode when RustCrypto support is not enabled.
    #[cfg(not(feature = "rust-crypto-aes"))]
    fn decrypt_rs(
        &self,
        _ctxt: &[u8],
        _tag: &[u8],
        _iv: &Nonce,
        _aad: &Aad,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::UnsupportedConfig)
    }

    /// Encrypt with the algorithm and key of this Aead.
    /// Returns `(ctxt, tag)` or an `Error`.
    pub fn encrypt(&self, msg: &[u8], iv: &Nonce, aad: &Aad) -> Result<(Ciphertext, Tag), Error> {
        if iv.len() != 12 {
            return Err(Error::InvalidNonce);
        }

        match self.op_mode {
            OpMode::Hacl => {
                let mut ctxt = vec![0u8; msg.len()];
                let mut tag = vec![0u8; 16];
                unsafe {
                    EverCrypt_AEAD_encrypt(
                        self.c_state.unwrap(),
                        iv.as_ptr() as _,
                        12,
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
            OpMode::RustCryptoAes128 => self.encrypt_rs(msg, iv, aad),
            OpMode::RustCryptoAes256 => self.encrypt_rs(msg, iv, aad),
        }
    }

    /// Decrypt with the algorithm and key of this Aead.
    /// Returns `msg` or an `Error`.
    pub fn decrypt(
        &self,
        ctxt: &[u8],
        tag: &[u8],
        iv: &Nonce,
        aad: &Aad,
    ) -> Result<Vec<u8>, Error> {
        if iv.len() != 12 {
            return Err(Error::InvalidNonce);
        }

        match self.op_mode {
            OpMode::Hacl => {
                let mut msg = vec![0u8; ctxt.len()];
                let r = unsafe {
                    EverCrypt_AEAD_decrypt(
                        self.c_state.unwrap(),
                        iv.as_ptr() as _,
                        12,
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
            OpMode::RustCryptoAes128 => self.decrypt_rs(ctxt, tag, iv, aad),
            OpMode::RustCryptoAes256 => self.decrypt_rs(ctxt, tag, iv, aad),
        }
    }
}

// Single-shot APIs

/// Single-shot API for AEAD encryption.
pub fn encrypt(
    alg: Mode,
    k: &[u8],
    msg: &[u8],
    iv: &Nonce,
    aad: &Aad,
) -> Result<(Ciphertext, Tag), Error> {
    let cipher = Aead::new(alg, k)?;
    cipher.encrypt(msg, iv, aad)
}

/// Single-shot API for AEAD decryption.
pub fn decrypt(
    alg: Mode,
    k: &[u8],
    ctxt: &[u8],
    tag: &[u8],
    iv: &Nonce,
    aad: &Aad,
) -> Result<Vec<u8>, Error> {
    let cipher = Aead::new(alg, k)?;
    cipher.decrypt(ctxt, tag, iv, aad)
}

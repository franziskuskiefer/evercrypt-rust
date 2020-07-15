use evercrypt_sys::evercrypt_bindings::*;

#[cfg(feature = "rust-crypto-aes")]
use aes_gcm::aead::{Aead as RcAead, NewAead, Payload};
#[cfg(feature = "rust-crypto-aes")]
use aes_gcm::{Aes128Gcm, Aes256Gcm};

#[derive(Clone, Copy, PartialEq)]
enum OpMode {
    Hacl = 0,
    RustCryptoAes128 = 1,
    RustCryptoAes256 = 2,
}

#[derive(Clone, Copy, PartialEq)]
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
    pub fn new(alg: Mode, k: &'a [u8]) -> Result<Self, Error> {
        unsafe {
            // Make sure this happened.
            EverCrypt_AutoConfig2_init();
        }
        if hacl_aes_available() || !alg_is_aes(alg) {
            let state = unsafe {
                let mut state_ptr: *mut EverCrypt_AEAD_state_s = std::ptr::null_mut();
                let e =
                    EverCrypt_AEAD_create_in(alg as u8, &mut state_ptr, k.to_vec().as_mut_ptr());
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

    #[cfg(not(feature = "rust-crypto-aes"))]
    fn encrypt_rs(&self, _msg: &[u8], _iv: &Nonce, _aad: &Aad) -> Result<(Ciphertext, Tag), Error> {
        Err(Error::UnsupportedConfig)
    }

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

    /// Returns `(ctxt, tag)`.
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

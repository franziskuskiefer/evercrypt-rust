use evercrypt_sys::evercrypt_bindings::*;

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
}

pub struct Aead {
    c_state: *mut EverCrypt_AEAD_state_s,
}

type Ciphertext = Vec<u8>;
type Tag = Vec<u8>;
type Nonce = [u8]; // TODO: fix to length 12
type Aad = [u8];

impl Aead {
    pub fn new(alg: Mode, k: &[u8]) -> Result<Self, Error> {
        unsafe {
            // Make sure this happened.
            EverCrypt_AutoConfig2_init();
        }
        let state = unsafe {
            let mut state_ptr: *mut EverCrypt_AEAD_state_s = std::ptr::null_mut();
            let e = EverCrypt_AEAD_create_in(alg as u8, &mut state_ptr, k.to_vec().as_mut_ptr());
            if e != 0 {
                return Err(Error::InvalidInit);
            }
            state_ptr
        };
        Ok(Self { c_state: state })
    }

    /// Returns `(ctxt, tag)`.
    pub fn encrypt(&self, msg: &[u8], iv: &Nonce, aad: &Aad) -> Result<(Ciphertext, Tag), Error> {
        if iv.len() != 12 {
            return Err(Error::InvalidNonce);
        }
        let mut ctxt = vec![0u8; msg.len()];
        let mut tag = vec![0u8; 16];
        unsafe {
            EverCrypt_AEAD_encrypt(
                self.c_state,
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
        let mut msg = vec![0u8; ctxt.len()];
        let r = unsafe {
            EverCrypt_AEAD_decrypt(
                self.c_state,
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
}

// impl Aead {
//     pub fn new(algorithm: Mode, key: &[u8]) -> Result<Self, Error> {
//         let aead_sys = match aead::Aead::init(algorithm as u8, key) {
//             Ok(s) => s,
//             Err(e) => match e {
//                 aead::Error::InvalidAlgorithm => return Err(Error::UnknownAlgorithm),
//                 aead::Error::InvalidInit => return Err(Error::InvalidKey),
//                 _ => panic!("Unknown error occured in sys init {:?}", e),
//             },
//         };
//         Ok(Self { sys: aead_sys })
//     }
//     pub fn encrypt(&self, ptxt: &[u8], iv: &Nonce, aad: &[u8]) -> Result<(Ciphertext, Tag), Error> {
//         // The only error that can occur is a wrong IV size, which can't happen through this interface.
//         match self.sys.encrypt(ptxt, &iv, aad) {
//             Ok(r) => Ok(r),
//             // The only error we expect here is an invalid nonce. Everything else should panic.
//             Err(_) => Err(Error::InvalidNonce),
//         }
//     }
//     pub fn decrypt(
//         &self,
//         ctxt: &[u8],
//         tag: &[u8],
//         iv: &Nonce,
//         aad: &[u8],
//     ) -> Result<Ciphertext, Error> {
//         // The only error that can occur is a wrong IV size, which can't happen through this interface.
//         match self.sys.decrypt(ctxt, tag, &iv, aad) {
//             Err(aead::Error::InvalidCiphertext) => Err(Error::InvalidCiphertext),
//             Ok(ptxt) => Ok(ptxt),
//             Err(e) => panic!("Unknown Error occured when decrypting {:?}", e),
//         }
//     }
// }

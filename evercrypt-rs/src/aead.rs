use evercrypt_sys::aead;

#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    AesGcm128 = 0,
    AesGcm256 = 1,
    Chacha20Poly1305 = 2,
}

impl From<u8> for Mode {
    fn from(v: u8) -> Mode {
        match v {
            0 => Mode::AesGcm128,
            1 => Mode::AesGcm256,
            2 => Mode::Chacha20Poly1305,
            _ => panic!("Unknown AEAD mode {}", v),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidKey = 0,
    UnknownAlgorithm = 1,
    InvalidCiphertext = 2,
    InvalidNonce = 3,
}

pub struct Aead {
    sys: aead::AEAD,
}

type Ciphertext = Vec<u8>;
type Tag = Vec<u8>;
type Nonce = [u8]; // TODO: fix to length 12

impl Aead {
    pub fn new(algorithm: Mode, key: &[u8]) -> Result<Self, Error> {
        let aead_sys = match aead::AEAD::init(algorithm as u8, key) {
            Ok(s) => s,
            Err(e) => match e {
                aead::AEADError::InvalidAlgorithm => return Err(Error::UnknownAlgorithm),
                aead::AEADError::InvalidInit => return Err(Error::InvalidKey),
                _ => panic!("Unknown error occured in sys init {:?}", e),
            },
        };
        Ok(Self { sys: aead_sys })
    }
    pub fn encrypt(&self, ptxt: &[u8], iv: &Nonce, aad: &[u8]) -> Result<(Ciphertext, Tag), Error> {
        // The only error that can occur is a wrong IV size, which can't happen through this interface.
        match self.sys.encrypt(ptxt, &iv, aad) {
            Ok(r) => Ok(r),
            // The only error we expect here is an invalid nonce. Everything else should panic.
            Err(_) => Err(Error::InvalidNonce),
        }
    }
    pub fn decrypt(
        &self,
        ctxt: &[u8],
        tag: &[u8],
        iv: &Nonce,
        aad: &[u8],
    ) -> Result<Ciphertext, Error> {
        // The only error that can occur is a wrong IV size, which can't happen through this interface.
        match self.sys.decrypt(ctxt, tag, &iv, aad) {
            Err(aead::AEADError::InvalidCiphertext) => Err(Error::InvalidCiphertext),
            Ok(ptxt) => Ok(ptxt),
            Err(e) => panic!("Unknown Error occured when decrypting {:?}", e),
        }
    }
}

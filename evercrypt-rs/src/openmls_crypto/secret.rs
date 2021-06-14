use std::fmt::Debug;

use crypto_algorithms::{AeadType, SymmetricKeyType};
use rand::{CryptoRng, RngCore};
use tls_codec::{Deserialize, SecretTlsVecU16, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize};
use zeroize::Zeroize;

use key_store::traits::KeyStoreValue;

use crate::sqlite_key_store::util::{bytes_to_hex, equal_ct};

use super::errors::SymmetricKeyError;

#[derive(Eq, Zeroize, TlsDeserialize, TlsSerialize)]
#[zeroize(drop)]
pub struct Secret {
    value: SecretTlsVecU16<u8>,
    key_type: SymmetricKeyType,
    label: SecretTlsVecU16<u8>,
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        if self.key_type != other.key_type {
            log::error!("The two secrets have different key types.");
            return false;
        }
        if self.label != other.label {
            log::error!("The two secrets have different labels.");
            return false;
        }
        if self.value.len() != other.value.len() {
            log::error!("The two secrets have different lengths.");
            return false;
        }
        equal_ct(self.value.as_slice(), other.value.as_slice())
    }
}

#[cfg(not(feature = "hazmat"))]
impl Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Secret {{\n  value: {}\n  key_type: {:?}\n label: {}\n}}",
            &"***",
            self.key_type,
            bytes_to_hex(self.label.as_slice())
        )
    }
}

#[cfg(feature = "hazmat")]
impl Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Secret {{\n  value: {}\n  key_type: {:?}\n label: {}\n}}",
            bytes_to_hex(self.value.as_slice()),
            self.key_type,
            bytes_to_hex(self.label.as_slice())
        )
    }
}

impl Secret {
    #[cfg(feature = "random")]
    pub fn random(key_type: SymmetricKeyType, label: &[u8]) -> Self {
        let mut value = vec![0u8; key_type.len()];
        rand::rngs::OsRng.fill_bytes(&mut value);
        Self {
            value: value.into(),
            key_type,
            label: label.into(),
        }
    }

    pub fn random_bor<T: CryptoRng + RngCore>(
        randomness: &mut T,
        key_type: SymmetricKeyType,
        label: &[u8],
    ) -> Self {
        let mut value = vec![0u8; key_type.len()];
        randomness.fill_bytes(&mut value);
        Self {
            value: value.into(),
            key_type,
            label: label.into(),
        }
    }

    pub fn try_from(
        b: Vec<u8>,
        key_type: SymmetricKeyType,
        label: &[u8],
    ) -> Result<Self, SymmetricKeyError> {
        if b.len() != key_type.len() {
            return Err(SymmetricKeyError::InvalidLength(b.len(), key_type.len()));
        }
        Ok(Self {
            value: b.into(),
            key_type,
            label: label.into(),
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }

    /// Get the type of this secret.
    pub fn key_type(&self) -> SymmetricKeyType {
        self.key_type
    }

    /// Check secret compatibility with AEAD algorithm.
    pub fn compatible(&self, aead: AeadType) -> bool {
        match self.key_type {
            SymmetricKeyType::Aes128 => aead == AeadType::Aes128Gcm,
            SymmetricKeyType::Aes256 => aead == AeadType::Aes256Gcm,
            SymmetricKeyType::ChaCha20 => aead == AeadType::ChaCha20Poly1305,
            SymmetricKeyType::Any(_) => false,
        }
    }
}

impl KeyStoreValue for Secret {
    type Error = SymmetricKeyError;
    type SerializedValue = Vec<u8>;

    fn serialize(&self) -> Result<Vec<u8>, SymmetricKeyError> {
        Ok(self.tls_serialize_detached().unwrap())
    }

    fn deserialize(raw: &mut [u8]) -> Result<Self, SymmetricKeyError> {
        // XXX: can we do this without copy please?
        Ok(Self::tls_deserialize(&mut raw.as_ref()).unwrap())
    }
}

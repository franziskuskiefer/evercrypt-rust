use std::array::TryFromSliceError;

use crypto_algorithms::{AsymmetricKeyType, SymmetricKeyType};

use crate::sqlite_key_store;

/// # AsymmetricKeyError
///
/// This error is thrown when an asymmetric key operation fails.
#[derive(Debug, PartialEq, Eq)]
pub enum AsymmetricKeyError {
    /// The key type is not supported.
    InvalidKeyType(usize),

    /// The key serialization is not valid.
    InvalidSerialization,

    /// An error in the underlying crypto library occurred.
    CryptoLibError(String),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SymmetricKeyError {
    InvalidLength(usize, usize),
    InvalidArrayConversion(String),
    InvalidKeyType(usize),
    InvalidKey(String),
    InvalidSerialization,
}

/// Error types
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    SerializationError(String),
    DigestError(String),
    UnsupportedKeyType(AsymmetricKeyType),
    UnsupportedSecretType(SymmetricKeyType),
    SymmetricKeyError(SymmetricKeyError),
    AsymmetricKeyError(AsymmetricKeyError),
    UnsupportedAlgorithm(String),
    InvalidLength(String),
    EncryptionError(String),
    DecryptionError(String),
    KeyStoreError(String),
    CryptoLibError(String),
    InvalidSignature(String),
}

impl From<sqlite_key_store::KeyStoreError> for Error {
    fn from(e: sqlite_key_store::KeyStoreError) -> Self {
        Self::KeyStoreError(format!("Key store error {:?}", e))
    }
}

impl From<tls_codec::Error> for Error {
    fn from(e: tls_codec::Error) -> Self {
        Self::SerializationError(format!("TLS codec error {:?}", e))
    }
}

// impl From<Error> for key_store::Error {
//     fn from(e: Error) -> Self {
//         Self::CryptoLibError(format!("TLS codec error {:?}", e))
//     }
// }

impl From<TryFromSliceError> for SymmetricKeyError {
    fn from(e: TryFromSliceError) -> Self {
        Self::InvalidArrayConversion(format!("{}", e))
    }
}

impl Into<String> for SymmetricKeyError {
    fn into(self) -> String {
        format!("SymmetricKeyError {:?}", self)
    }
}

use std::array::TryFromSliceError;

use crypto_algorithms::{AsymmetricKeyType, SymmetricKeyType};

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

#[derive(Debug, PartialEq, Eq)]
pub enum SymmetricKeyError {
    InvalidLength(usize, usize),
    InvalidArrayConversion(String),
    InvalidKeyType(usize),
    InvalidKey(String),
    InvalidSerialization,
}

/// Error types
/// XXX: Maybe these should go into the traits as types.
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

impl From<key_store::Error> for Error {
    fn from(e: key_store::Error) -> Self {
        Self::KeyStoreError(format!("Key store error {:?}", e))
    }
}

impl From<tls_codec::Error> for Error {
    fn from(e: tls_codec::Error) -> Self {
        Self::SerializationError(format!("TLS codec error {:?}", e))
    }
}

impl From<Error> for key_store::Error {
    fn from(e: Error) -> Self {
        Self::CryptoLibError(format!("TLS codec error {:?}", e))
    }
}

impl From<TryFromSliceError> for SymmetricKeyError {
    fn from(e: TryFromSliceError) -> Self {
        Self::InvalidArrayConversion(format!("{}", e))
    }
}

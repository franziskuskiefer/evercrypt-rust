use std::sync::PoisonError;

use tls_codec::Error;

/// Errors that can occur in the everest sqlite key store.
/// XXX: Maybe the error should be a trait type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStoreError {
    /// Error writing a value to the key store.
    WriteError(String),

    /// Error reading a value from the key store.
    ReadError(String),

    /// Error updating a value in the key store.
    UpdateError(String),

    /// Error deleting a value from the key store.
    DeleteError(String),

    /// Error trying to read a value from the key store that is not extractable.
    ForbiddenExtraction(String),

    /// An error from a crypto library.
    CryptoLibError(String),

    /// An invalid [`Status`](`crate::types::Status`) value.
    InvalidStatus(String),

    /// Mutex poison error.
    MutexError(String),

    /// An error in the [TLS codec](tls_codec::Error).
    TlsCodecError(String),
}

impl<Guard> From<PoisonError<Guard>> for KeyStoreError {
    fn from(e: PoisonError<Guard>) -> Self {
        Self::MutexError(format!("Sync poison error {}", e))
    }
}

impl From<Error> for KeyStoreError {
    fn from(e: Error) -> Self {
        Self::TlsCodecError(format!("TLS codec error {:?}", e))
    }
}

impl Into<String> for KeyStoreError {
    fn into(self) -> String {
        format!("KeyStoreError {:?}", self)
    }
}


/// Key store error values
/// XXX: Maybe the error should be a trait type.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
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

    /// An error from a key store implementation.
    KeyStoreError(String),

    /// An error from a crypto library.
    CryptoLibError(String),

    /// An invalid [`Status`](`crate::types::Status`) value.
    InvalidStatus(String),
}

use std::{
    convert::TryFrom,
    path::Path,
    sync::{Mutex, PoisonError},
};

use key_store::{
    traits::{KeyStore as KeyStoreTrait, KeyStoreValue},
    types::Status,
    Error, KeyStoreResult,
};
use rusqlite::{
    params,
    types::{FromSql, FromSqlError, ToSqlOutput},
    Connection, OpenFlags, ToSql,
};

mod types;
pub use types::PrivateKey;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Errors that can occur in the everest sqlite key store.
pub enum EverestSqlKeyStoreError {
    /// Mutex poison error.
    MutexError(String),
}

impl<Guard> From<PoisonError<Guard>> for EverestSqlKeyStoreError {
    fn from(e: PoisonError<Guard>) -> Self {
        Self::MutexError(format!("Sync poison error {}", e))
    }
}

impl From<EverestSqlKeyStoreError> for Error {
    fn from(e: EverestSqlKeyStoreError) -> Self {
        Self::KeyStoreError(format!("EverestSqlKeyStoreError {:?}", e))
    }
}

pub struct KeyStore {
    sql: Mutex<Connection>,
}

fn init_key_store(connection: &Connection) -> KeyStoreResult<()> {
    let _ = connection
        .execute(
            "CREATE TABLE secrets (
              id              INTEGER PRIMARY KEY,
              label           BLOB,
              value           BLOB,
              status          INTEGER,
              UNIQUE(label)
              )",
            [],
        )
        .map_err(|e| {
            log::error!("SQL ERROR: {:?}", e);
            Error::WriteError(format!("SQLite create table error {:?}", e))
        })?;
    Ok(())
}

impl Default for KeyStore {
    fn default() -> Self {
        let connection = Connection::open_in_memory().unwrap();
        init_key_store(&connection).unwrap();
        Self {
            sql: Mutex::new(connection),
        }
    }
}

/// Public proprietary API.
impl KeyStore {
    pub fn new(path: &Path) -> Self {
        let connection = Connection::open(path).unwrap();
        init_key_store(&connection).unwrap();
        Self {
            sql: Mutex::new(connection),
        }
    }

    pub fn open(path: &Path) -> Self {
        let connection =
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE).unwrap();
        Self {
            sql: Mutex::new(connection),
        }
    }
}

struct SqlKeyStoreId<'a>(&'a KeyStoreId);

impl<'a> ToSql for SqlKeyStoreId<'a> {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.0.to_vec()))
    }
}

struct SqlStatus(Status);

impl FromSql for SqlStatus {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let raw = u8::column_result(value)?;
        Ok(Self(
            Status::try_from(raw).map_err(|_| FromSqlError::OutOfRange(raw.into()))?,
        ))
    }
}

/// Private functions.
impl KeyStore {
    fn _store(
        &self,
        k: &<KeyStore as KeyStoreTrait>::KeyStoreId,
        v: &impl KeyStoreValue,
        status: Status,
    ) -> KeyStoreResult<()> {
        let connection = self
            .sql
            .lock()
            .map_err(|e| EverestSqlKeyStoreError::from(e))?;
        connection
            .execute(
                "INSERT INTO secrets (label, value, status) VALUES (?1, ?2, ?3)",
                params![SqlKeyStoreId(k), v.serialize()?, status as u8],
            )
            .map_err(|e| {
                log::error!("SQL ERROR: {:?}", e);
                Error::WriteError(format!("SQLite write error {:?}", e))
            })?;
        Ok(())
    }

    pub(crate) fn internal_read<V: KeyStoreValue>(
        &self,
        k: &<KeyStore as KeyStoreTrait>::KeyStoreId,
    ) -> KeyStoreResult<(V, Status)> {
        let connection = self
            .sql
            .lock()
            .map_err(|e| EverestSqlKeyStoreError::from(e))?;
        let mut result: (Vec<u8>, SqlStatus) = connection
            .query_row(
                "SELECT value, status FROM secrets WHERE label = ?1",
                params![SqlKeyStoreId(k)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|e| {
                log::error!("SQL ERROR: {:?}", e);
                Error::ReadError(format!("SQLite read error {:?}", e))
            })?;
        Ok((V::deserialize(&mut result.0)?, result.1 .0))
    }

    fn _read<V: KeyStoreValue>(
        &self,
        k: &<KeyStore as KeyStoreTrait>::KeyStoreId,
    ) -> KeyStoreResult<V> {
        let (v, status) = self.internal_read(k)?;
        match status {
            Status::Extractable | Status::UnconfirmedExtractable => Ok(v),
            Status::Hidden | Status::UnconfirmedHidden => Err(Error::ForbiddenExtraction(format!(
                "The value is {:?}",
                status
            ))),
        }
    }

    fn _update(
        &self,
        k: &<KeyStore as KeyStoreTrait>::KeyStoreId,
        v: &impl KeyStoreValue,
    ) -> KeyStoreResult<()> {
        let connection = self
            .sql
            .lock()
            .map_err(|e| EverestSqlKeyStoreError::from(e))?;
        let updated_rows = connection
            .execute(
                "UPDATE secrets SET value = ?1 WHERE label = ?2",
                params![v.serialize()?, SqlKeyStoreId(k)],
            )
            .map_err(|e| {
                log::error!("SQL ERROR: {:?}", e);
                Error::UpdateError(format!("SQLite update error {:?}", e))
            })?;
        if updated_rows == 1 {
            Ok(())
        } else {
            Err(Error::UpdateError(format!("No row was updated")))
        }
    }

    fn _delete(&self, k: &<KeyStore as KeyStoreTrait>::KeyStoreId) -> KeyStoreResult<()> {
        let connection = self
            .sql
            .lock()
            .map_err(|e| EverestSqlKeyStoreError::from(e))?;
        connection
            .execute(
                "DELETE FROM secrets WHERE label = ?1",
                params![SqlKeyStoreId(k)],
            )
            .map_err(|e| {
                log::error!("SQL ERROR: {:?}", e);
                Error::DeleteError(format!("SQLite delete error {:?}", e))
            })?;
        Ok(())
    }
}

pub(crate) type KeyStoreId = [u8; 32];

impl KeyStoreTrait for KeyStore {
    type KeyStoreId = KeyStoreId;

    fn store(&self, k: &Self::KeyStoreId, v: &impl KeyStoreValue) -> KeyStoreResult<()> {
        self._store(k, v, Status::Extractable)
    }

    fn read<V: KeyStoreValue>(&self, k: &Self::KeyStoreId) -> KeyStoreResult<V> {
        self._read(k)
    }

    fn update(&self, k: &Self::KeyStoreId, v: &impl KeyStoreValue) -> KeyStoreResult<()> {
        self._update(k, v)
    }

    fn delete(&self, k: &Self::KeyStoreId) -> KeyStoreResult<()> {
        self._delete(k)
    }

    fn store_with_status(
        &self,
        k: &Self::KeyStoreId,
        v: &impl KeyStoreValue,
        s: Status,
    ) -> KeyStoreResult<()> {
        self._store(k, v, s)
    }
}

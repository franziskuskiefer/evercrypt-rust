use std::{convert::TryFrom, path::Path, sync::Mutex};

use key_store::traits::KeyStoreValue;
use rusqlite::{
    params,
    types::{FromSql, FromSqlError, ToSqlOutput},
    Connection, OpenFlags, ToSql,
};

mod errors;
mod types;
pub(crate) mod util;
pub use errors::*;
pub use key_store::{traits::KeyStore as KeyStoreTrait, types::Status};
pub use types::{PrivateKey, PublicKey};

pub struct KeyStore {
    sql: Mutex<Connection>,
}

fn init_key_store(connection: &Connection) -> Result<(), KeyStoreError> {
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
            KeyStoreError::WriteError(format!("SQLite create table error {:?}", e))
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
        Ok(ToSqlOutput::from(&self.0[..]))
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
    ) -> Result<(), KeyStoreError> {
        let connection = self.sql.lock().map_err(|e| KeyStoreError::from(e))?;
        let v = v
            .serialize()
            .map_err(|e| KeyStoreError::TlsCodecError(format!("Error serializing value {:?}", e)))?
            .into();
        connection
            .execute(
                "INSERT INTO secrets (label, value, status) VALUES (?1, ?2, ?3)",
                params![SqlKeyStoreId(k), v, status as u8],
            )
            .map_err(|e| {
                log::error!("SQL ERROR: {:?}", e);
                KeyStoreError::WriteError(format!("SQLite write error {:?}", e))
            })?;
        Ok(())
    }

    /// Retrieve a value from the key store.
    ///
    /// ☣️ Note that his ignores the [`Status`] of the value and just returns it.
    pub fn unsafe_read<V: KeyStoreValue>(
        &self,
        k: &<KeyStore as KeyStoreTrait>::KeyStoreId,
    ) -> Result<(V, Status), KeyStoreError> {
        let connection = self.sql.lock().map_err(|e| KeyStoreError::from(e))?;
        let mut result: (Vec<u8>, SqlStatus) = connection
            .query_row(
                "SELECT value, status FROM secrets WHERE label = ?1",
                params![SqlKeyStoreId(k)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|e| {
                log::error!("SQL ERROR: {:?}", e);
                KeyStoreError::ReadError(format!("SQLite read error {:?}", e))
            })?;
        let out = V::deserialize(&mut result.0).map_err(|e| {
            KeyStoreError::TlsCodecError(format!("Error deserializing value {:?}", e))
        })?;
        Ok((out, result.1 .0))
    }

    fn _read<V: KeyStoreValue>(
        &self,
        k: &<KeyStore as KeyStoreTrait>::KeyStoreId,
    ) -> Result<V, KeyStoreError> {
        let (v, status) = self.unsafe_read(k)?;
        match status {
            Status::Extractable | Status::UnconfirmedExtractable => Ok(v),
            Status::Hidden | Status::UnconfirmedHidden => Err(KeyStoreError::ForbiddenExtraction(
                format!("The value is {:?}", status),
            )),
        }
    }

    fn _update(
        &self,
        k: &<KeyStore as KeyStoreTrait>::KeyStoreId,
        v: &impl KeyStoreValue,
    ) -> Result<(), KeyStoreError> {
        let connection = self.sql.lock().map_err(|e| KeyStoreError::from(e))?;
        let v = v
            .serialize()
            .map_err(|e| KeyStoreError::TlsCodecError(format!("Error serializing value {:?}", e)))?
            .into();
        let updated_rows = connection
            .execute(
                "UPDATE secrets SET value = ?1 WHERE label = ?2",
                params![v, SqlKeyStoreId(k)],
            )
            .map_err(|e| {
                log::error!("SQL ERROR: {:?}", e);
                KeyStoreError::UpdateError(format!("SQLite update error {:?}", e))
            })?;
        if updated_rows == 1 {
            Ok(())
        } else {
            Err(KeyStoreError::UpdateError(format!("No row was updated")))
        }
    }

    fn _delete(&self, k: &<KeyStore as KeyStoreTrait>::KeyStoreId) -> Result<(), KeyStoreError> {
        let connection = self.sql.lock().map_err(|e| KeyStoreError::from(e))?;
        connection
            .execute(
                "DELETE FROM secrets WHERE label = ?1",
                params![SqlKeyStoreId(k)],
            )
            .map_err(|e| {
                log::error!("SQL ERROR: {:?}", e);
                KeyStoreError::DeleteError(format!("SQLite delete error {:?}", e))
            })?;
        Ok(())
    }
}

pub type KeyStoreId = [u8; 32];

impl KeyStoreTrait for KeyStore {
    type KeyStoreId = KeyStoreId;
    type Error = KeyStoreError;

    fn store_with_status(
        &self,
        k: &Self::KeyStoreId,
        v: &impl KeyStoreValue,
        s: Status,
    ) -> Result<(), KeyStoreError> {
        self._store(k, v, s)
    }

    fn store(&self, k: &Self::KeyStoreId, v: &impl KeyStoreValue) -> Result<(), KeyStoreError> {
        self._store(k, v, Status::Extractable)
    }

    fn read<V: KeyStoreValue>(&self, k: &Self::KeyStoreId) -> Result<V, KeyStoreError> {
        self._read(k)
    }

    fn update(&self, k: &Self::KeyStoreId, v: &impl KeyStoreValue) -> Result<(), KeyStoreError> {
        self._update(k, v)
    }

    fn delete(&self, k: &Self::KeyStoreId) -> Result<(), KeyStoreError> {
        self._delete(k)
    }
}

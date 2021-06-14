#[cfg(feature = "sqlite-key-store")]
mod sqlite_keystore_tests {

    use crypto_algorithms::{AeadType, SymmetricKeyType};
    use evercrypt::{
        openmls_crypto::{secret::Secret, Aead},
        sqlite_key_store::{KeyStore, KeyStoreError},
    };
    use key_store::traits::KeyStore as KeyStoreTrait;
    use openmls_crypto::aead::{Open, Seal};

    #[test]
    fn basic_key_store() {
        // let _ = pretty_env_logger::try_init();
        // let ks = KeyStore::new(Path::new("test-db.sqlite"));
        // let ks = KeyStore::open(Path::new("test-db.sqlite"));
        let ks = KeyStore::default();
        let secret = Secret::try_from(vec![3u8; 32], SymmetricKeyType::Aes256, &[]).unwrap();
        let id = evercrypt::digest::sha256(b"Key Id 1");

        ks.store(&id, &secret).unwrap();
        let secret_again = ks.read(&id).unwrap();
        assert_eq!(secret, secret_again);

        let secret2 = Secret::try_from(vec![4u8; 32], SymmetricKeyType::Aes256, &[]).unwrap();
        let id2 = evercrypt::digest::sha256(b"Key Id 2");

        ks.store(&id2, &secret2).unwrap();
        let secret_again = ks.read(&id2).unwrap();
        assert_eq!(secret2, secret_again);
        let secret_again = ks.read(&id).unwrap();
        assert_eq!(secret, secret_again);

        ks.delete(&id2).unwrap();
        let secret_again: Result<Secret, KeyStoreError> = ks.read(&id2);
        assert_eq!(
            KeyStoreError::ReadError("SQLite read error QueryReturnedNoRows".to_owned()),
            secret_again.err().unwrap()
        );

        let secret_again = ks.read(&id).unwrap();
        assert_eq!(secret, secret_again);

        ks.update(&id, &secret2).unwrap();
        let secret_again = ks.read(&id).unwrap();
        assert_eq!(secret2, secret_again);

        // AEAD
        let ctxt_tag = Aead::seal(
            &ks,
            &id,
            AeadType::Aes256Gcm,
            b"This is trying to use a wrong key type",
            b"AAD",
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        )
        .unwrap();

        let msg = Aead::open(
            &ks,
            &id,
            AeadType::Aes256Gcm,
            &ctxt_tag,
            b"AAD",
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        )
        .unwrap();

        assert_eq!(&msg, b"This is trying to use a wrong key type");
    }
}

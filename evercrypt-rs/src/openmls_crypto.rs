use std::convert::TryInto;

use crate::{
    aead, digest as evercrypt_digest, ed25519, hkdf, hmac, p256,
    prelude::{p256_ecdsa_random_nonce, DigestMode},
    signature,
    sqlite_key_store::{self, KeyStore, PrivateKey},
    x25519,
};
use crypto_algorithms::{
    AeadType, AsymmetricKeyType, HashType, KemKeyType, SignatureKeyType, SymmetricKeyType,
};
use key_store::{traits::KeyStore as KeyStoreTrait, types::Status};
use openmls_crypto::{
    aead::{CiphertextTag, Open, Plaintext, Seal},
    errors::SymmetricKeyError,
    errors::{AsymmetricKeyError, Error},
    hash::{Hash, Hasher},
    hkdf::HkdfDerive,
    key_generation::GenerateKeys,
    keys::PublicKey,
    secret::Secret,
    signature::{Sign, Signature, Verify},
    Supports,
};
use sqlite_key_store::KeyStoreId;

pub struct Evercrypt {}

impl Supports for Evercrypt {
    fn symmetric_key_types() -> Vec<SymmetricKeyType> {
        vec![
            SymmetricKeyType::Aes128,
            SymmetricKeyType::Aes256,
            SymmetricKeyType::ChaCha20,
        ]
    }

    fn asymmetric_key_types() -> Vec<AsymmetricKeyType> {
        vec![
            AsymmetricKeyType::KemKey(KemKeyType::X25519),
            AsymmetricKeyType::SignatureKey(SignatureKeyType::Ed25519),
            AsymmetricKeyType::KemKey(KemKeyType::P256),
            AsymmetricKeyType::SignatureKey(SignatureKeyType::EcdsaP256Sha256),
        ]
    }
}

#[inline]
fn hash_type_to_evercrypt(hash: HashType) -> Result<DigestMode, openmls_crypto::errors::Error> {
    Ok(match hash {
        HashType::Sha1 => DigestMode::Sha1,
        HashType::Sha2_224 => DigestMode::Sha224,
        HashType::Sha2_256 => DigestMode::Sha256,
        HashType::Sha2_384 => DigestMode::Sha256,
        HashType::Sha2_512 => DigestMode::Sha512,
        HashType::Sha3_224 => DigestMode::Sha3_224,
        HashType::Sha3_256 => DigestMode::Sha3_256,
        HashType::Sha3_384 => DigestMode::Sha3_384,
        HashType::Sha3_512 => DigestMode::Sha3_512,
        _ => {
            return Err(openmls_crypto::errors::Error::UnsupportedAlgorithm(
                format!("{:?} is not supported by evercrypt", hash),
            ))
        }
    })
}

impl From<crate::digest::Error> for Error {
    fn from(e: crate::digest::Error) -> Self {
        Self::DigestError(format!("Evercrypt digest error: {:?}", e))
    }
}

impl Hash for Evercrypt {
    type StatefulHasher = crate::digest::Digest;

    fn hash(hash: HashType, data: &[u8]) -> Result<Vec<u8>, openmls_crypto::errors::Error> {
        Ok(crate::digest::hash(hash_type_to_evercrypt(hash)?, data))
    }

    fn hasher(hash: HashType) -> Result<Self::StatefulHasher, openmls_crypto::errors::Error> {
        crate::digest::Digest::new(hash_type_to_evercrypt(hash)?).map_err(|e| e.into())
    }
}

impl Hasher for crate::digest::Digest {
    fn update(&mut self, data: &[u8]) -> Result<(), openmls_crypto::errors::Error> {
        self.update(data).map_err(|e| e.into())
    }

    fn finish(&mut self) -> Result<Vec<u8>, openmls_crypto::errors::Error> {
        self.finish().map_err(|e| e.into())
    }
}

impl From<p256::Error> for openmls_crypto::errors::Error {
    fn from(e: p256::Error) -> Self {
        Self::AsymmetricKeyError(AsymmetricKeyError::CryptoLibError(format!(
            "Hashing error {:?}",
            e
        )))
    }
}

impl GenerateKeys for Evercrypt {
    type KeyStoreType = KeyStore;
    type KeyStoreIndex = KeyStoreId;

    fn new_secret(
        key_store: &Self::KeyStoreType,
        key_type: SymmetricKeyType,
        status: Status,
        k: &Self::KeyStoreIndex,
        label: &[u8],
    ) -> Result<(), openmls_crypto::errors::Error> {
        if !Self::symmetric_key_types().contains(&key_type) {
            return Err(openmls_crypto::errors::Error::UnsupportedSecretType(
                key_type,
            ));
        }
        let mut randomness = rand::thread_rng();
        let secret = Secret::random_bor(&mut randomness, key_type, label);
        key_store
            .store_with_status(k, &secret, status)
            .map_err(|e| {
                openmls_crypto::errors::Error::KeyStoreError(format!(
                    "Key store write error {:?}",
                    e
                ))
            })
    }

    fn new_key_pair(
        key_store: &Self::KeyStoreType,
        key_type: AsymmetricKeyType,
        status: Status,
        label: &[u8],
    ) -> Result<(PublicKey, Self::KeyStoreIndex), openmls_crypto::errors::Error> {
        let (public_key, private_key) = match key_type {
            AsymmetricKeyType::KemKey(KemKeyType::X25519) => {
                let private_key = x25519::key_gen();
                let public_key = x25519::dh_base(&private_key);
                let public_key = PublicKey::from(key_type, &public_key, label);
                let private_key = PrivateKey::from(key_type, &private_key, label, &public_key);
                (public_key, private_key)
            }
            AsymmetricKeyType::SignatureKey(SignatureKeyType::Ed25519) => {
                let private_key = ed25519::key_gen();
                let public_key = ed25519::sk2pk(&private_key);
                let public_key = PublicKey::from(key_type, &public_key, label);
                let private_key = PrivateKey::from(key_type, &private_key, label, &public_key);
                (public_key, private_key)
            }
            AsymmetricKeyType::SignatureKey(SignatureKeyType::EcdsaP256Sha256)
            | AsymmetricKeyType::KemKey(KemKeyType::P256) => {
                let private_key = p256::key_gen()?;
                let public_key = p256::dh_base(&private_key)?;
                let public_key = PublicKey::from(key_type, &public_key, label);
                let private_key = PrivateKey::from(key_type, &private_key, label, &public_key);
                (public_key, private_key)
            }
            _ => return Err(openmls_crypto::errors::Error::UnsupportedKeyType(key_type)),
        };
        let mut sha256 = Self::hasher(HashType::Sha2_256)?;
        sha256.update(label)?;
        sha256.update(public_key.as_slice())?;
        let mut id = [0u8; 32];
        id.clone_from_slice(&sha256.finish()?);
        key_store
            .store_with_status(&id, &private_key, status)
            .map_err(|e| {
                openmls_crypto::errors::Error::KeyStoreError(format!("Key store error {:?}", e))
            })?;
        Ok((public_key, id))
    }
}

fn hmac_type(hash: HashType) -> Result<hmac::Mode, openmls_crypto::errors::Error> {
    match hash {
        HashType::Sha1 => Ok(hmac::Mode::Sha1),
        HashType::Sha2_256 => Ok(hmac::Mode::Sha256),
        HashType::Sha2_384 => Ok(hmac::Mode::Sha384),
        HashType::Sha2_512 => Ok(hmac::Mode::Sha512),
        _ => Err(openmls_crypto::errors::Error::UnsupportedAlgorithm(
            format!("{:?}", hash),
        )),
    }
}

fn extract_unsafe(
    ks: &KeyStore,
    hash: HashType,
    ikm: &KeyStoreId,
    salt: &[u8],
) -> Result<Secret, openmls_crypto::errors::Error> {
    let mode = hmac_type(hash)?;
    let (ikm_secret, _status): (Secret, Status) = ks.internal_read(ikm).map_err(|e| {
        openmls_crypto::errors::Error::KeyStoreError(format!("Key store error {:?}", e))
    })?;
    let prk = hkdf::extract(mode, salt, ikm_secret.as_slice());
    let prk_len = prk.len();
    Secret::try_from(
        prk,
        SymmetricKeyType::Any(prk_len.try_into().map_err(|_| {
            openmls_crypto::errors::Error::InvalidLength(format!(
                "HKDF PRK is too long ({}) for a secret (u16)",
                prk_len
            ))
        })?),
        b"HKDF-PRK",
    )
    .map_err(|e| openmls_crypto::errors::Error::KeyStoreError(format!("Key store error {:?}", e)))
}

fn expand_unsafe(
    hash: HashType,
    prk: Secret,
    info: &[u8],
    out_len: usize,
) -> Result<Secret, openmls_crypto::errors::Error> {
    let mode = hmac_type(hash)?;
    let key = hkdf::expand(mode, prk.as_slice(), info, out_len);
    if key.is_empty() {
        return Err(openmls_crypto::errors::Error::InvalidLength(format!(
            "Invalid HKDF output length {}",
            out_len
        )));
    }
    let key_len = key.len();
    Secret::try_from(
        key,
        SymmetricKeyType::Any(key_len.try_into().map_err(|_| {
            openmls_crypto::errors::Error::InvalidLength(format!(
                "HKDF key is too long ({}) for a secret (u16)",
                key_len
            ))
        })?),
        b"HKDF-KEY",
    )
    .map_err(|e| openmls_crypto::errors::Error::KeyStoreError(format!("Key store error {:?}", e)))
}

impl HkdfDerive for Evercrypt {
    type KeyStoreType = KeyStore;
    type KeyStoreIndex = KeyStoreId;

    fn hkdf(
        key_store: &Self::KeyStoreType,
        ikm: &Self::KeyStoreIndex,
        hash: HashType,
        salt: &[u8],
        info: &[u8],
        out_len: usize,
        okm: &Self::KeyStoreIndex,
    ) -> Result<(), openmls_crypto::errors::Error> {
        let prk = extract_unsafe(key_store, hash, ikm, salt)?;
        let key = expand_unsafe(hash, prk, info, out_len)?;
        key_store
            .store(okm, &key)
            .map_err(|e| openmls_crypto::errors::Error::from(e))
    }
}

fn aead_type(aead: AeadType) -> Result<aead::Mode, openmls_crypto::errors::Error> {
    match aead {
        AeadType::Aes128Gcm => Ok(aead::Mode::Aes128Gcm),
        AeadType::Aes256Gcm => Ok(aead::Mode::Aes256Gcm),
        AeadType::ChaCha20Poly1305 => Ok(aead::Mode::Chacha20Poly1305),
        AeadType::HpkeExport => Err(openmls_crypto::errors::Error::UnsupportedAlgorithm(
            format!("HPKE Export AEAD"),
        )),
    }
}

pub struct Aead {}

impl Seal for Aead {
    type KeyStoreType = KeyStore;
    type KeyStoreIndex = KeyStoreId;

    fn seal(
        ks: &Self::KeyStoreType,
        key_id: &Self::KeyStoreIndex,
        aead: AeadType,
        msg: &[u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<openmls_crypto::aead::CiphertextTag, openmls_crypto::errors::Error> {
        let (key, _status): (Secret, Status) = ks.internal_read(key_id)?;
        if !key.compatible(aead) {
            return Err(openmls_crypto::errors::Error::SymmetricKeyError(
                SymmetricKeyError::InvalidKey(format!(
                    "Key is not compatible with the requested AEAD."
                )),
            ));
        }
        let mode = aead_type(aead)?;
        let (ct, tag) = aead::encrypt(mode, key.as_slice(), msg, nonce, aad)
            .map_err(|e| Error::EncryptionError(format!("Error encrypting: {:?}", e)))?;
        Ok((ct, tag))
    }

    fn seal_combined(
        ks: &Self::KeyStoreType,
        key_id: &Self::KeyStoreIndex,
        aead: AeadType,
        msg: &[u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, openmls_crypto::errors::Error> {
        let (key, _status): (Secret, Status) = ks.internal_read(key_id)?;
        if !key.compatible(aead) {
            return Err(openmls_crypto::errors::Error::SymmetricKeyError(
                SymmetricKeyError::InvalidKey(format!(
                    "Key is not compatible with the requested AEAD."
                )),
            ));
        }
        let mode = aead_type(aead)?;
        let ct = aead::encrypt_combined(mode, key.as_slice(), msg, nonce, aad)
            .map_err(|e| Error::EncryptionError(format!("Error encrypting: {:?}", e)))?;
        Ok(ct)
    }

    fn seal_in_place(
        ks: &Self::KeyStoreType,
        key_id: &Self::KeyStoreIndex,
        aead: AeadType,
        msg: &mut [u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, openmls_crypto::errors::Error> {
        // We can't do this in evercrypt.
        let ct = Self::seal(ks, key_id, aead, msg, aad, nonce)?;
        let (ct, tag) = ct.into();
        if ct.len() != msg.len() {
            return Err(openmls_crypto::errors::Error::InvalidLength(format!(
                "Cipher text has length {}. Message was {}.",
                ct.len(),
                msg.len()
            )));
        }
        msg.clone_from_slice(&ct);
        Ok(tag)
    }

    fn seal_in_place_combined(
        ks: &Self::KeyStoreType,
        key_id: &Self::KeyStoreIndex,
        aead: AeadType,
        msg: &mut [u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<(), openmls_crypto::errors::Error> {
        // We can't do this in evercrypt.
        let ct = Self::seal(ks, key_id, aead, msg, aad, nonce)?;
        let (mut ct, mut tag) = ct.into();
        ct.append(&mut tag);
        if ct.len() != msg.len() {
            return Err(openmls_crypto::errors::Error::InvalidLength(format!(
                "Cipher text has length {}. Message was {}.",
                ct.len(),
                msg.len()
            )));
        }
        msg.clone_from_slice(&ct);
        Ok(())
    }
}

impl Open for Aead {
    type KeyStoreType = KeyStore;
    type KeyStoreIndex = KeyStoreId;

    fn open(
        key_store: &Self::KeyStoreType,
        key_id: &Self::KeyStoreIndex,
        aead: AeadType,
        cipher_text: &CiphertextTag,
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<Plaintext, openmls_crypto::errors::Error> {
        let (key, _status): (Secret, Status) = key_store.internal_read(key_id)?;
        let mode = aead_type(aead)?;
        let pt = aead::decrypt(
            mode,
            key.as_slice(),
            &cipher_text.0,
            &cipher_text.1,
            nonce,
            aad,
        )
        .map_err(|e| Error::DecryptionError(format!("Decryption encrypting: {:?}", e)))?;
        Ok(pt)
    }

    fn open_combined(
        key_store: &Self::KeyStoreType,
        key_id: &Self::KeyStoreIndex,
        aead: AeadType,
        cipher_text: &[u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<Plaintext, openmls_crypto::errors::Error> {
        let (key, _status): (Secret, Status) = key_store.internal_read(key_id)?;
        let mode = aead_type(aead)?;
        let pt = aead::decrypt_combined(mode, key.as_slice(), cipher_text, nonce, aad)
            .map_err(|e| Error::DecryptionError(format!("Decryption encrypting: {:?}", e)))?;
        Ok(pt)
    }
}

fn evercrypt_signature_type(
    key_type: AsymmetricKeyType,
) -> Result<signature::Mode, openmls_crypto::errors::Error> {
    match key_type {
        AsymmetricKeyType::SignatureKey(SignatureKeyType::Ed25519) => Ok(signature::Mode::Ed25519),
        AsymmetricKeyType::SignatureKey(SignatureKeyType::EcdsaP256Sha256)
        | AsymmetricKeyType::SignatureKey(SignatureKeyType::EcdsaP521Sha512) => {
            Ok(signature::Mode::P256)
        }
        _ => return Err(Error::UnsupportedAlgorithm(format!("{:?}", key_type))),
    }
}

fn evercrypt_hash_type(hash: impl Into<Option<HashType>>) -> Option<crate::prelude::DigestMode> {
    if let Some(hash) = hash.into() {
        Some(match hash {
            HashType::Sha1 => evercrypt_digest::Mode::Sha1,
            HashType::Sha2_224 => evercrypt_digest::Mode::Sha224,
            HashType::Sha2_256 => evercrypt_digest::Mode::Sha256,
            HashType::Sha2_384 => evercrypt_digest::Mode::Sha384,
            HashType::Sha2_512 => evercrypt_digest::Mode::Sha512,
            HashType::Sha3_224 => evercrypt_digest::Mode::Sha3_224,
            HashType::Sha3_256 => evercrypt_digest::Mode::Sha3_256,
            HashType::Sha3_384 => evercrypt_digest::Mode::Sha3_384,
            HashType::Sha3_512 => evercrypt_digest::Mode::Sha3_512,
            HashType::Shake_128 | HashType::Shake_256 => return None,
        })
    } else {
        None
    }
}

impl Sign for Evercrypt {
    type KeyStoreType = KeyStore;
    type KeyStoreIndex = KeyStoreId;

    fn sign(
        key_store: &Self::KeyStoreType,
        key_id: &Self::KeyStoreIndex,
        payload: &[u8],
        hash: impl Into<Option<HashType>>,
    ) -> Result<Signature, openmls_crypto::errors::Error> {
        let (sk, _status): (PrivateKey, Status) = key_store.internal_read(key_id)?;
        let hash = hash.into();
        let evercrypt_hash = evercrypt_hash_type(hash);
        let signature_mode = evercrypt_signature_type(sk.key_type())?;
        let nonce = if signature_mode == signature::Mode::P256 {
            Some(p256_ecdsa_random_nonce().map_err(|e| {
                Error::CryptoLibError(format!("P256 nonce generation error: {:?}", e))
            })?)
        } else {
            None
        };
        let signature = signature::sign(
            signature_mode,
            evercrypt_hash,
            &sk.as_slice(),
            payload,
            nonce.as_ref(),
        )
        .map_err(|e| Error::CryptoLibError(format!("P256 nonce generation error: {:?}", e)))?;
        Ok(signature)
    }
}

impl Verify for Evercrypt {
    type KeyStoreType = KeyStore;
    type KeyStoreIndex = KeyStoreId;

    fn verify(
        key_store: &Self::KeyStoreType,
        key_id: &Self::KeyStoreIndex,
        signature: &[u8],
        payload: &[u8],
        hash: impl Into<Option<HashType>>,
    ) -> Result<(), openmls_crypto::errors::Error> {
        let (pk, _status): (PublicKey, Status) = key_store.internal_read(key_id)?;
        Self::verify_with_pk(&pk, signature, payload, hash)
    }

    fn verify_with_pk(
        key: &PublicKey,
        signature: &[u8],
        payload: &[u8],
        hash: impl Into<Option<HashType>>,
    ) -> Result<(), openmls_crypto::errors::Error> {
        let mode = evercrypt_signature_type(key.key_type())?;
        let hash = evercrypt_hash_type(hash);
        let valid = signature::verify(mode, hash, key.as_slice(), signature, payload)
            .map_err(|e| Error::InvalidSignature(format!("Error verifying signature: {:?}", e)))?;
        if valid {
            Ok(())
        } else {
            Err(Error::InvalidSignature(format!("Invalid signature")))
        }
    }
}

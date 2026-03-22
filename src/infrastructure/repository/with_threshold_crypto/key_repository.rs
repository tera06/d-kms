use std::{fs, path::Path};

use aes_gcm::{
    AeadCore, Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, OsRng},
    aes::cipher::Unsigned,
};
use base64::{Engine, engine::general_purpose};
use thiserror::Error;
use threshold_crypto::serde_impl::SerdeSecret;

use crate::core::{
    model::key::{PublicKey, SecretKeyShare},
    repository::key_repository::{PublicKeyStore, SecretKeyShareStore},
};
pub struct PublicKeyRepository {
    file_path: String,
    crypter: Crypter,
}

impl PublicKeyRepository {
    pub fn new(file_path: String, crypter: Crypter) -> Self {
        Self { file_path, crypter }
    }
}

impl PublicKeyStore for PublicKeyRepository {
    type TPublicKey = threshold_crypto::PublicKeySet;

    type TError = PublicKeyRepositoryError;

    async fn save(
        &self,
        public_key: &crate::core::model::key::PublicKey<Self::TPublicKey>,
    ) -> Result<(), Self::TError> {
        let public_key_bytes = bincode::serialize(&public_key.public_key)
            .map_err(|_| PublicKeyRepositoryError::FailedSerialize)?;

        let encrypted_public_key_bytes = self
            .crypter
            .encrypt_bytes(&public_key_bytes)
            .map_err(|_| PublicKeyRepositoryError::FailedEncryptPublicKey)?;

        let file_path = Path::new(&self.file_path);
        fs::write(file_path, encrypted_public_key_bytes)
            .map_err(|_| PublicKeyRepositoryError::FailedWriteRepoFile)?;
        Ok(())
    }

    async fn load(
        &self,
    ) -> Result<crate::core::model::key::PublicKey<Self::TPublicKey>, Self::TError> {
        let file_path = Path::new(&self.file_path);
        let encrypted_pub_key_bytes =
            fs::read(file_path).map_err(|_| PublicKeyRepositoryError::FailedReadRepoFile)?;
        let pub_key_bytes = self
            .crypter
            .decrypt_bytes(&encrypted_pub_key_bytes)
            .map_err(|_| PublicKeyRepositoryError::FailedDecryptPublicKey)?;

        let pub_key: Self::TPublicKey = bincode::deserialize(&pub_key_bytes)
            .map_err(|_| PublicKeyRepositoryError::FailedDeserialize)?;

        let pub_key = PublicKey::new(pub_key);

        Ok(pub_key)
    }
}

#[derive(Error, Debug)]
enum PublicKeyRepositoryError {
    #[error("Failed to serialize")]
    FailedSerialize,
    #[error("Failed to encrypt public key")]
    FailedEncryptPublicKey,
    #[error("Failed to write public key into repository file")]
    FailedWriteRepoFile,
    #[error("Faile to read public key from repository file")]
    FailedReadRepoFile,
    #[error("Failed to decrypt public key")]
    FailedDecryptPublicKey,
    #[error("Failed to deserialize")]
    FailedDeserialize,
}

#[derive(Clone)]
pub struct SecretKeyShareRepository {
    file_path: String,
    crypter: Crypter,
}

impl SecretKeyShareRepository {
    pub fn new(file_path: String, crypter: Crypter) -> Self {
        Self { file_path, crypter }
    }
    fn get_file_path_with_index(&self, index: usize) -> String {
        format!("{}-{}", self.file_path, index)
    }
}
impl SecretKeyShareStore for SecretKeyShareRepository {
    type TSecretKeyShare = threshold_crypto::SecretKeyShare;

    type TError = SecretKeyShareRepositoryError;

    async fn save(
        &self,
        secret_key_share: &crate::core::model::key::SecretKeyShare<Self::TSecretKeyShare>,
    ) -> Result<(), Self::TError> {
        let serde_secret_key_share = SerdeSecret(&secret_key_share.secret_key_share);
        let secret_key_share_bytes = bincode::serialize(&serde_secret_key_share)
            .map_err(|_| SecretKeyShareRepositoryError::FailedSerialize)?;
        let encrypted_secret_key_share_bytes = self
            .crypter
            .encrypt_bytes(&secret_key_share_bytes)
            .map_err(|_| SecretKeyShareRepositoryError::FailedEncryptSecretKeyShare)?;

        let file_path = self.get_file_path_with_index(secret_key_share.index);
        let file_path = Path::new(&file_path);
        fs::write(file_path, encrypted_secret_key_share_bytes)
            .map_err(|_| SecretKeyShareRepositoryError::FailedWriteRepoFile)?;
        Ok(())
    }

    async fn load(
        &self,
        index: usize,
    ) -> Result<crate::core::model::key::SecretKeyShare<Self::TSecretKeyShare>, Self::TError> {
        let file_path = self.get_file_path_with_index(index);
        let file_path = Path::new(&file_path);
        let encrypted_serde_secret_key_share_bytes =
            fs::read(file_path).map_err(|_| SecretKeyShareRepositoryError::FailedReadRepoFile)?;
        let serde_secret_key_share_bytes = self
            .crypter
            .decrypt_bytes(&encrypted_serde_secret_key_share_bytes)
            .map_err(|_| SecretKeyShareRepositoryError::FailedDecryptSecretKeyShare)?;
        let serde_secret_key_share: SerdeSecret<Self::TSecretKeyShare> =
            bincode::deserialize(&serde_secret_key_share_bytes)
                .map_err(|_| SecretKeyShareRepositoryError::FailedDeserialize)?;

        let secret_key_share = serde_secret_key_share.into_inner();
        let secret_key_share = SecretKeyShare::new(index, secret_key_share);

        Ok(secret_key_share)
    }
}

#[derive(Error, Debug)]
enum SecretKeyShareRepositoryError {
    #[error("Failed to serialize")]
    FailedSerialize,
    #[error("Failed to encrypt secret key share")]
    FailedEncryptSecretKeyShare,
    #[error("Failed to write secret key share into repository file")]
    FailedWriteRepoFile,
    #[error("Faile to read secret key share from repository file")]
    FailedReadRepoFile,
    #[error("Failed to decrypt secret key share")]
    FailedDecryptSecretKeyShare,
    #[error("Failed to deserialize")]
    FailedDeserialize,
}

#[derive(Clone)]
pub struct Crypter;

impl Crypter {
    fn load_master_key(&self) -> Result<Vec<u8>, CrypterError> {
        let base64_key =
            std::env::var("DKMS_MASTER_KEY").map_err(|_| CrypterError::FailedGetEnvVar)?;
        let key = general_purpose::STANDARD
            .decode(base64_key)
            .map_err(|_| CrypterError::FailedBase64Decode)?;

        if key.len() != 32 {
            return Err(CrypterError::InvalidKeyLength);
        }
        Ok(key)
    }

    pub fn encrypt_bytes(&self, plain_data: &[u8]) -> Result<Vec<u8>, CrypterError> {
        let master_key = self.load_master_key()?;

        let key = Key::<Aes256Gcm>::from_slice(&master_key);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let enc_data = cipher
            .encrypt(&nonce, plain_data)
            .map_err(|_| CrypterError::FailedEncrypt)?;

        let mut final_bytes = Vec::new();
        final_bytes.extend_from_slice(nonce.as_slice());
        final_bytes.extend_from_slice(&enc_data);

        Ok(final_bytes)
    }

    pub fn decrypt_bytes(&self, encrypted_bytes: &[u8]) -> Result<Vec<u8>, CrypterError> {
        let master_key = self.load_master_key()?;
        type NonceSize = <Aes256Gcm as AeadCore>::NonceSize;
        let nonce_size = NonceSize::to_usize();
        let (nonce_bytes, encrypted_bytes) = encrypted_bytes.split_at(nonce_size);

        let nonce = Nonce::from_slice(nonce_bytes);

        let key = Key::<Aes256Gcm>::from_slice(&master_key);
        let cipher = Aes256Gcm::new(&key);

        let plain_data = cipher
            .decrypt(nonce, encrypted_bytes)
            .map_err(|_| CrypterError::FailedDecrypt)?;

        Ok(plain_data)
    }
}

#[derive(Error, Debug)]
enum CrypterError {
    #[error("Faile to get eivironment variable")]
    FailedGetEnvVar,
    #[error("Failed to base64 decode")]
    FailedBase64Decode,
    #[error("Key length is invalid")]
    InvalidKeyLength,
    #[error("Failed to encrypt")]
    FailedEncrypt,
    #[error("Failed to decrypt")]
    FailedDecrypt,
}

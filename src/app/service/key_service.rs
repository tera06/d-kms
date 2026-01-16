use thiserror::Error;

use crate::domain::{
    model::{
        key::{CombineSignatureShares, Divisible, PublicKey, SecretKey, Signable, Verifiable},
        signature::{Digest, SignatureShare},
    },
    repository::key_repository::{PublicKeyRepository, SecretKeyShareRepository},
};

struct KeyService<T, U, V, W> {
    public_key_repo: T,
    secret_key_share_repo: U,
    key_generator: V,
    digest_generator: W,
}

impl<T, U, V, W> KeyService<T, U, V, W>
where
    T: PublicKeyRepository<TPublicKey = V::TPublicKey>,
    U: SecretKeyShareRepository<SecretKeyShare = <V::TSecretKey as Divisible>::TSecretKeyShare>,
    V: GenerateKey,
    W: GenerateDigest<TDigest = <V::TPublicKey as Verifiable>::TDigest>,
    V::TSecretKey: Divisible,
    V::TPublicKey:
        CombineSignatureShares<TSignature = <V::TPublicKey as Verifiable>::TSignature> + Verifiable,
    <V::TSecretKey as Divisible>::TSecretKeyShare:
        Signable<TDigest = <V::TPublicKey as Verifiable>::TDigest>,
{
    async fn init_keys(&self, threshold: usize, num_divide: usize) -> Result<(), KeyServiceError> {
        let (public_key, secret_key) = self
            .key_generator
            .generate_keys(threshold, num_divide)
            .map_err(|_| KeyServiceError::FailedGenerateKeys)?;

        let secret_key_shares = secret_key
            .divide()
            .map_err(|_| KeyServiceError::FailedCreateSecretKeyShares)?;

        self.public_key_repo
            .save(&public_key)
            .await
            .map_err(|_| KeyServiceError::FailedSavePublicKey)?;
        for share in &secret_key_shares {
            self.secret_key_share_repo
                .save(share)
                .await
                .map_err(|_| KeyServiceError::FailedSaveSecretKeyShare)?;
        }

        Ok(())
    }

    async fn sign_message(
        &self,
        message: &str,
        index: usize,
    ) -> Result<
        SignatureShare<
            <<V::TSecretKey as Divisible>::TSecretKeyShare as Signable>::TSignatureShare,
        >,
        KeyServiceError,
    > {
        let secret_key_share = self
            .secret_key_share_repo
            .load(index)
            .await
            .map_err(|_| KeyServiceError::FailedLoadSecretKeyShare)?;

        let digest = self
            .digest_generator
            .generate_digest(message)
            .map_err(|_| KeyServiceError::FailedGenarateDigest)?;

        let signature_share = secret_key_share
            .sign(&digest)
            .map_err(|_| KeyServiceError::FailedSignDigest)?;

        Ok(signature_share)
    }

    async fn verify_signature(
        &self,
        signature_shares: &Vec<
            SignatureShare<<V::TPublicKey as CombineSignatureShares>::TSignatureShare>,
        >,
        message: &str,
    ) -> Result<bool, KeyServiceError> {
        let public_key = self
            .public_key_repo
            .load()
            .await
            .map_err(|_| KeyServiceError::FailedLoadPublicKey)?;

        let signature = public_key
            .combine_signature_shares(signature_shares)
            .map_err(|_| KeyServiceError::FailedCombineSignatureShares)?;

        let digest = self
            .digest_generator
            .generate_digest(message)
            .map_err(|_| KeyServiceError::FailedGenarateDigest)?;

        let is_verify = public_key
            .verify(&signature, &digest)
            .map_err(|_| KeyServiceError::FailedVerifySignature)?;

        Ok(is_verify)
    }
}

#[derive(Error, Debug)]
enum KeyServiceError {
    #[error("Failed to generate keys")]
    FailedGenerateKeys,

    #[error("Failed to create secret key shares")]
    FailedCreateSecretKeyShares,

    #[error("Failed to save public key")]
    FailedSavePublicKey,

    #[error("Failed to load public key")]
    FailedLoadPublicKey,

    #[error("Failed to save secret key share")]
    FailedSaveSecretKeyShare,

    #[error("Failed to load secret key share")]
    FailedLoadSecretKeyShare,

    #[error("Failed to generate digest")]
    FailedGenarateDigest,

    #[error("Failed to sign digest")]
    FailedSignDigest,

    #[error("Failed to combine signature shares")]
    FailedCombineSignatureShares,

    #[error("Failed to verify signature")]
    FailedVerifySignature,
}
pub trait GenerateKey {
    type TError: std::error::Error;
    type TPublicKey;
    type TSecretKey;
    fn generate_keys(
        &self,
        threshold: usize,
        num_divide: usize,
    ) -> Result<(PublicKey<Self::TPublicKey>, SecretKey<Self::TSecretKey>), Self::TError>;
}

pub trait GenerateDigest {
    type TError: std::error::Error;
    type TDigest;

    fn generate_digest(&self, message: &str) -> Result<Digest<Self::TDigest>, Self::TError>;
}

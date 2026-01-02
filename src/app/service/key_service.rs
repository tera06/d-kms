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
    T: PublicKeyRepository<PublicKey = V::PublicKey>,
    U: SecretKeyShareRepository<SecretKeyShare = <V::SecretKey as Divisible>::SecretKeyShare>,
    V: GenerateKey,
    W: GenerateDigest<Digest = <V::PublicKey as Verifiable>::Digest>,
    V::SecretKey: Divisible,
    V::PublicKey:
        CombineSignatureShares<Signature = <V::PublicKey as Verifiable>::Signature> + Verifiable,
    <V::SecretKey as Divisible>::SecretKeyShare:
        Signable<Digest = <V::PublicKey as Verifiable>::Digest>,
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
        SignatureShare<<<V::SecretKey as Divisible>::SecretKeyShare as Signable>::SignatureShare>,
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
            SignatureShare<<V::PublicKey as CombineSignatureShares>::SignatureShare>,
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
trait GenerateKey {
    type Error: std::error::Error;
    type PublicKey;
    type SecretKey;
    fn generate_keys(
        &self,
        threshold: usize,
        num_divide: usize,
    ) -> Result<(PublicKey<Self::PublicKey>, SecretKey<Self::SecretKey>), Self::Error>;
}

trait GenerateDigest {
    type Error: std::error::Error;
    type Digest;

    fn generate_digest(&self, message: &str) -> Result<Digest<Self::Digest>, Self::Error>;
}

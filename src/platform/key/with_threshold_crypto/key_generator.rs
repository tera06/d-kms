use rand::thread_rng;
use thiserror::Error;
use threshold_crypto::SecretKeySet;

use crate::{
    core::model::key::{PublicKey, SecretKey},
    logic::service::key_service::GenerateKey,
};

pub struct KeyGenerator;

impl GenerateKey for KeyGenerator {
    type TError = KeyGeneratorError;

    type TPublicKey = threshold_crypto::PublicKeySet;

    type TSecretKey = threshold_crypto::SecretKeySet;

    fn generate_keys(
        &self,
        threshold: usize,
        num_divide: usize,
    ) -> Result<
        (
            crate::core::model::key::PublicKey<Self::TPublicKey>,
            crate::core::model::key::SecretKey<Self::TSecretKey>,
        ),
        Self::TError,
    > {
        let mut rng = thread_rng();
        let secret_key_set = SecretKeySet::random(threshold - 1, &mut rng);
        let public_key_set = secret_key_set.public_keys();

        let public_key = PublicKey::new(public_key_set);
        let secret_key = SecretKey::new(threshold, num_divide, secret_key_set)
            .ok_or(KeyGeneratorError::FailedGenerateSecretKey)?;

        Ok((public_key, secret_key))
    }
}

#[derive(Error, Debug)]
enum KeyGeneratorError {
    #[error("Failed to generate secret key")]
    FailedGenerateSecretKey,
}

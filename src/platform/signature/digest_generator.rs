use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::app::service::key_service::GenerateDigest;

pub struct DigestGenarator;

impl GenerateDigest for DigestGenarator {
    type TError = DigestGenaratorError;

    type TDigest = Vec<u8>;

    fn generate_digest(
        &self,
        message: &str,
    ) -> Result<crate::core::model::signature::Digest<Self::TDigest>, Self::TError> {
        let mut hasher = Sha256::new();
        hasher.update(&message);
        let digest = hasher.finalize();

        let digest = crate::core::model::signature::Digest::new(digest.to_vec());

        Ok(digest)
    }
}

#[derive(Error, Debug)]
enum DigestGenaratorError {}

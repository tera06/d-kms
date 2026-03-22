use thiserror::Error;

use crate::core::model::{key::Signable, signature::SignatureShare};

impl Signable for threshold_crypto::SecretKeyShare {
    type TDigest = Vec<u8>;

    type TSignatureShare = threshold_crypto::SignatureShare;

    type TError = SecretKeyShareError;

    fn sign(
        &self,
        index: usize,
        digest: &crate::core::model::signature::Digest<Self::TDigest>,
    ) -> Result<crate::core::model::signature::SignatureShare<Self::TSignatureShare>, Self::TError>
    {
        let signature_share = self.sign(&digest.digest);
        let signature_share = SignatureShare::new(index, signature_share);
        Ok(signature_share)
    }
}

#[derive(Error, Debug)]
enum SecretKeyShareError {}

use thiserror::Error;

use crate::domain::model::{key::Signable, signature::SignatureShare};

impl Signable for threshold_crypto::SecretKeyShare {
    type TDigest = Vec<u8>;

    type TSignatureShare = threshold_crypto::SignatureShare;

    type TError = SecretKeyShareError;

    fn sign(
        &self,
        index: usize,
        digest: &crate::domain::model::signature::Digest<Self::TDigest>,
    ) -> Result<crate::domain::model::signature::SignatureShare<Self::TSignatureShare>, Self::TError>
    {
        let signature_share = self.sign(&digest.digest);
        let signature_share = SignatureShare::new(index, signature_share);
        Ok(signature_share)
    }
}

#[derive(Error, Debug)]
enum SecretKeyShareError {}

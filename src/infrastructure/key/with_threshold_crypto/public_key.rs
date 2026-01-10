use thiserror::Error;

use crate::domain::model::{
    key::{CombineSignatureShares, Verifiable},
    signature::Signature,
};

impl Verifiable for threshold_crypto::PublicKeySet {
    type TSignature = threshold_crypto::Signature;

    type TDigest = Vec<u8>;

    type TError = PublicKeySetError;

    fn verify(
        &self,
        signature: &crate::domain::model::signature::Signature<Self::TSignature>,
        digest: &crate::domain::model::signature::Digest<Self::TDigest>,
    ) -> Result<bool, Self::TError> {
        let public_key = self.public_key();
        let is_valid = public_key.verify(&signature.signature, &digest.digest);
        Ok(is_valid)
    }
}

impl CombineSignatureShares for threshold_crypto::PublicKeySet {
    type TSignatureShare = threshold_crypto::SignatureShare;

    type TSignature = threshold_crypto::Signature;

    type TError = PublicKeySetError;

    fn combine_signature_shares(
        &self,
        signature_shares: &Vec<
            crate::domain::model::signature::SignatureShare<Self::TSignatureShare>,
        >,
    ) -> Result<crate::domain::model::signature::Signature<Self::TSignature>, Self::TError> {
        let shares_for_combine = signature_shares
            .iter()
            .map(|s| (s.index, &s.signature_share));

        let signature = self
            .combine_signatures(shares_for_combine)
            .map_err(|_| PublicKeySetError::FailedCombineSignature)?;
        let signature = Signature::new(signature);
        Ok(signature)
    }
}

#[derive(Error, Debug)]
enum PublicKeySetError {
    #[error("Failed to combine signature")]
    FailedCombineSignature,
}

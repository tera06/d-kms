use futures::future::Shared;

use crate::domain::model::signature::{Digest, Signature, SignatureShare};
pub struct PublicKey<T> {
    public_key: T,
}

pub struct SecretKey<T> {
    threshold: usize,
    num_key_shares: usize,
    secret_key: T,
}
pub struct SecretKeyShare<T> {
    index: usize,
    secret_key_share: T,
}
pub trait Verifiable {
    type TSignature;
    type TDigest;
    type TError: std::error::Error;

    fn verify(
        &self,
        signature: &Signature<Self::TSignature>,
        digest: &Digest<Self::TDigest>,
    ) -> Result<bool, Self::TError>;
}

pub trait Divisible {
    type TSecretKeyShare;
    type TError: std::error::Error;
    fn divide(
        &self,
        num_divide: usize,
    ) -> Result<Vec<SecretKeyShare<Self::TSecretKeyShare>>, Self::TError>;
}
pub trait Signable {
    type TDigest;
    type TSignatureShare;
    type TError: std::error::Error;

    fn sign(
        &self,
        digest: &Digest<Self::TDigest>,
    ) -> Result<SignatureShare<Self::TSignatureShare>, Self::TError>;
}

pub trait CombineSignatureShares {
    type TSignatureShare;
    type TSignature;
    type TError: std::error::Error;

    fn combine_signature_shares(
        &self,
        signature_shares: &Vec<SignatureShare<Self::TSignatureShare>>,
    ) -> Result<Signature<Self::TSignature>, Self::TError>;
}

impl<T> PublicKey<T>
where
    T: Verifiable + CombineSignatureShares,
{
    pub fn new(public_key: T) -> Self {
        Self { public_key }
    }

    pub fn verify(
        &self,
        signature: &Signature<<T as Verifiable>::TSignature>,
        digest: &Digest<T::TDigest>,
    ) -> Result<bool, <T as Verifiable>::TError> {
        self.public_key.verify(signature, digest)
    }

    pub fn combine_signature_shares(
        &self,
        signature_shares: &Vec<SignatureShare<<T as CombineSignatureShares>::TSignatureShare>>,
    ) -> Result<
        Signature<<T as CombineSignatureShares>::TSignature>,
        <T as CombineSignatureShares>::TError,
    > {
        self.public_key.combine_signature_shares(signature_shares)
    }
}

impl<T> SecretKey<T>
where
    T: Divisible,
{
    pub fn new(threshold: usize, num_key_shares: usize, secret_key: T) -> Option<Self> {
        if threshold > num_key_shares {
            return None;
        }

        Some(Self {
            threshold,
            num_key_shares,
            secret_key,
        })
    }
    pub fn divide(&self) -> Result<Vec<SecretKeyShare<T::TSecretKeyShare>>, T::TError> {
        self.secret_key.divide(self.num_key_shares)
    }
}

impl<T> SecretKeyShare<T>
where
    T: Signable,
{
    pub fn new(index: usize, secret_key_share: T) -> Self {
        Self {
            index,
            secret_key_share,
        }
    }

    pub fn sign(
        &self,
        digest: &Digest<T::TDigest>,
    ) -> Result<SignatureShare<T::TSignatureShare>, T::TError> {
        self.secret_key_share.sign(&digest)
    }
}

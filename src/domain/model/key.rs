use futures::future::Shared;

use crate::domain::model::signature::{Digest, Signature, SignatureShare};
pub struct PublicKey<T> {
    public_key: T,
}

struct SecretKey<T> {
    threshold: usize,
    num_key_shares: usize,
    secret_key: T,
}
pub struct SecretKeyShare<T> {
    index: usize,
    secret_key_share: T,
}
trait Verifiable {
    type Signature;
    type Digest;
    type Error: std::error::Error;

    fn verify(
        &self,
        signature: &Signature<Self::Signature>,
        digest: &Digest<Self::Digest>,
    ) -> Result<bool, Self::Error>;
}

trait Divisible {
    type SecretKeyShare;
    type Error: std::error::Error;
    fn divide(
        &self,
        num_divide: usize,
    ) -> Result<Vec<SecretKeyShare<Self::SecretKeyShare>>, Self::Error>;
}
trait Signable {
    type Digest;
    type SignatureShare;
    type Error: std::error::Error;

    fn sign(
        &self,
        digest: &Digest<Self::Digest>,
    ) -> Result<SignatureShare<Self::SignatureShare>, Self::Error>;
}

pub trait CombineSignatureShares {
    type SignatureShare;
    type Signature;
    type Error: std::error::Error;

    fn combine_signature_shares(
        &self,
        signature_shares: Vec<SignatureShare<Self::SignatureShare>>,
    ) -> Result<Signature<Self::Signature>, Self::Error>;
}

impl<T> PublicKey<T>
where
    T: Verifiable + CombineSignatureShares,
{
    fn new(public_key: T) -> Self {
        Self { public_key }
    }

    fn verify(
        &self,
        signature: &Signature<<T as Verifiable>::Signature>,
        digest: &Digest<T::Digest>,
    ) -> Result<bool, <T as Verifiable>::Error> {
        self.public_key.verify(signature, digest)
    }

    pub fn combine_signature_shares(
        &self,
        signature_shares: Vec<SignatureShare<<T as CombineSignatureShares>::SignatureShare>>,
    ) -> Result<
        Signature<<T as CombineSignatureShares>::Signature>,
        <T as CombineSignatureShares>::Error,
    > {
        self.public_key.combine_signature_shares(signature_shares)
    }
}

impl<T> SecretKey<T>
where
    T: Divisible,
{
    fn new(threshold: usize, num_key_shares: usize, secret_key: T) -> Option<Self> {
        if threshold > num_key_shares {
            return None;
        }

        Some(Self {
            threshold,
            num_key_shares,
            secret_key,
        })
    }
    fn divide(&self) -> Result<Vec<SecretKeyShare<T::SecretKeyShare>>, T::Error> {
        self.secret_key.divide(self.num_key_shares)
    }
}

impl<T> SecretKeyShare<T>
where
    T: Signable,
{
    fn new(index: usize, secret_key_share: T) -> Self {
        Self {
            index,
            secret_key_share,
        }
    }

    fn sign(
        &self,
        digest: &Digest<T::Digest>,
    ) -> Result<SignatureShare<T::SignatureShare>, T::Error> {
        self.secret_key_share.sign(&digest)
    }
}

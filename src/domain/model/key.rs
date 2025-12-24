use crate::domain::model::signature::{Digest, Signature, SignatureShare};
struct PublicKey<T> {
    public_key: T,
}

struct SecretKey<T> {
    threshold: usize,
    num_key_shares: usize,
    secret_key: T,
}
struct SecretKeyShare<T> {
    index: usize,
    secret_key_share: T,
}
trait Verifiable<T, U> {
    type Error: std::error::Error;

    fn verify(&self, signature: &Signature<T>, digest: &Digest<U>) -> Result<bool, Self::Error>;
}

trait Divisible<T> {
    type Error: std::error::Error;
    fn divide(&self, num_divide: usize) -> Result<Vec<SecretKeyShare<T>>, Self::Error>;
}
trait Signable<T, U> {
    type Error: std::error::Error;

    fn sign(&self, digest: &Digest<T>) -> Result<SignatureShare<U>, Self::Error>;
}

impl<T> PublicKey<T> {
    fn new(public_key: T) -> Self {
        Self { public_key }
    }

    fn verify<U, V>(&self, signature: &Signature<U>, digest: &Digest<V>) -> Result<bool, T::Error>
    where
        T: Verifiable<U, V>,
    {
        self.public_key.verify(signature, digest)
    }
}

impl<T> SecretKey<T> {
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
    fn divide<U>(&self) -> Result<Vec<SecretKeyShare<U>>, T::Error>
    where
        T: Divisible<U>,
    {
        self.secret_key.divide(self.num_key_shares)
    }
}

impl<T> SecretKeyShare<T> {
    fn new(index: usize, secret_key_share: T) -> Self {
        Self {
            index,
            secret_key_share,
        }
    }

    fn sign<U, V>(&self, digest: &Digest<U>) -> Result<SignatureShare<V>, T::Error>
    where
        T: Signable<U, V>,
    {
        self.secret_key_share.sign(&digest)
    }
}

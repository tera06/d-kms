use crate::domain::model::error::{PublicKeyError, SecretKeyShareError};

struct PublicKey<T> {
    public_key: T,
}

struct SecretKeyShare<T> {
    index: usize,
    secret_key_share: T,
}
struct SignedData<T> {
    data: T,
}
struct SignatureShare<T> {
    signature_share: T,
}

trait Signable<T, U> {
    fn sign(&self, data: &SignedData<T>) -> Result<SignatureShare<U>, SecretKeyShareError>;
}

trait Verifiable<T> {
    fn verify(&self, signature_share: &SignatureShare<T>) -> Result<bool, PublicKeyError>;
}

impl<T> PublicKey<T> {
    fn new(public_key: T) -> Self {
        Self { public_key }
    }

    fn verify<U>(&self, signature_share: &SignatureShare<U>) -> Result<bool, PublicKeyError>
    where
        T: Verifiable<U>,
    {
        self.public_key.verify(signature_share)
    }
}

impl<T> SecretKeyShare<T> {
    fn new(index: usize, secret_key_share: T) -> Self {
        Self {
            index,
            secret_key_share,
        }
    }

    fn sign<U, V>(&self, data: &SignedData<U>) -> Result<SignatureShare<V>, SecretKeyShareError>
    where
        T: Signable<U, V>,
    {
        self.secret_key_share.sign(&data)
    }
}

impl<T> SignedData<T> {
    fn new(data: T) -> Self {
        Self { data }
    }
}

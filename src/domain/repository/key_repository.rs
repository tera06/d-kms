use crate::domain::model::key::{PublicKey, SecretKeyShare};

pub trait PublicKeyRepository<T> {
    type PublicKey;
    type Error: std::error::Error + Send + Sync + 'static;
    async fn save(&self, public_key: &PublicKey<Self::PublicKey>) -> Result<(), Self::Error>;
    async fn load(&self) -> Result<PublicKey<Self::PublicKey>, Self::Error>;
}

pub trait SecretKeyShareRepository {
    type SecretKeyShare;
    type Error: std::error::Error + Send + Sync + 'static;
    async fn save(
        &self,
        secret_key_share: &SecretKeyShare<Self::SecretKeyShare>,
    ) -> Result<(), Self::Error>;
    async fn load(&self) -> Result<SecretKeyShare<Self::SecretKeyShare>, Self::Error>;
}

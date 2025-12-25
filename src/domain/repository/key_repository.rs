use crate::domain::model::key::{PublicKey, SecretKeyShare};

trait PublicKeyRepository<T> {
    type Error: std::error::Error + Send + Sync + 'static;
    async fn save(&self, public_key: &PublicKey<T>) -> Result<(), Self::Error>;
    async fn load(&self) -> Result<PublicKey<T>, Self::Error>;
}

trait SecretKeyShareRepository<T> {
    type Error: std::error::Error + Send + Sync + 'static;
    async fn save(&self, secret_key_share: &SecretKeyShare<T>) -> Result<(), Self::Error>;
    async fn load(&self) -> Result<SecretKeyShare<T>, Self::Error>;
}

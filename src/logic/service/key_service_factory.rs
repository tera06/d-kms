use crate::logic::service::key_service::KeyService;

pub trait BuildKeyService<T, U, V, W> {
    type TError;
    fn build(&self) -> Result<KeyService<T, U, V, W>, Self::TError>;
}

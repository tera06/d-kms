use thiserror::Error;

#[derive(Error, Debug)]
pub(super) enum SecretKeyShareError {
    #[error("failed to sign")]
    SignFailed,
}

#[derive(Error, Debug)]
pub(super) enum PublicKeyError {
    #[error("Failed to verify")]
    VerifyFailed,
}

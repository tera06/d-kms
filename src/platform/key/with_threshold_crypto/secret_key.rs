use thiserror::Error;

use crate::core::model::key::{Divisible, SecretKeyShare};

impl Divisible for threshold_crypto::SecretKeySet {
    type TSecretKeyShare = threshold_crypto::SecretKeyShare;

    type TError = SecretKeySetErrror;

    fn divide(
        &self,
        num_divide: usize,
    ) -> Result<Vec<crate::core::model::key::SecretKeyShare<Self::TSecretKeyShare>>, Self::TError>
    {
        let mut secret_key_shares = Vec::new();

        for i in 0..num_divide {
            let share = self.secret_key_share(i);
            let share = SecretKeyShare::new(i, share);
            secret_key_shares.push(share);
        }

        Ok(secret_key_shares)
    }
}

#[derive(Debug, Error)]
pub enum SecretKeySetErrror {}

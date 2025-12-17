use std::{fs, path::Path};

use anyhow::{Ok, Result, anyhow};
use base64::{Engine, engine::general_purpose};
use rand::thread_rng;
use threshold_crypto::{
    PublicKeySet, SecretKeySet, SecretKeyShare, SignatureShare, serde_impl::SerdeSecret,
};

use crate::encryption::{decrypt_bytes, encrypt_bytes};

const PUBLIC_KEY_FILENAME: &str = "public.key.enc";
fn get_secret_key_filename(index: usize) -> String {
    format!("secret_key_share-{}.key.enc", index)
}

pub async fn create_keys(threshold: usize, n: usize) -> Result<()> {
    if threshold == 0 || threshold > n {
        return Err(anyhow!(
            "Invalid threashold or n (threshold={}, n={})",
            threshold,
            n
        ));
    }

    let mut rng = thread_rng();
    let secret_key_set = SecretKeySet::random(threshold - 1, &mut rng);

    let public_key_set = secret_key_set.public_keys();
    let path = Path::new(PUBLIC_KEY_FILENAME);
    sava_public_key_as_encrypted(&path, &public_key_set).await?;

    let shares = create_secret_key_shares(&secret_key_set, n)?;
    for (i, share) in shares.iter().enumerate() {
        let filename = get_secret_key_filename(i);
        let path = Path::new(&filename);
        save_secret_key_share_as_encrypted(path, share).await?;
    }

    Ok(())
}

async fn sava_public_key_as_encrypted(path: &Path, public_key_set: &PublicKeySet) -> Result<()> {
    let pub_key_set_bytes = bincode::serialize(public_key_set)?;

    let encrypted_pub_key_set_bytes = encrypt_bytes(&pub_key_set_bytes)?;
    fs::write(path, encrypted_pub_key_set_bytes)?;

    Ok(())
}

pub async fn load_public_key() -> Result<PublicKeySet> {
    let enc_pub_key_set_bytes = fs::read(PUBLIC_KEY_FILENAME)?;
    let pub_key_set_bytes = crate::encryption::decrypt_bytes(&enc_pub_key_set_bytes)?;
    let pub_key_set: PublicKeySet = bincode::deserialize(&pub_key_set_bytes)?;
    Ok(pub_key_set)
}

fn create_secret_key_shares(
    secret_key_set: &SecretKeySet,
    n: usize,
) -> Result<Vec<SecretKeyShare>> {
    let mut shares = Vec::new();
    for i in 0..n {
        let share = secret_key_set.secret_key_share(i);
        shares.push(share);
    }

    Ok(shares)
}

async fn save_secret_key_share_as_encrypted(path: &Path, share: &SecretKeyShare) -> Result<()> {
    let serde_share = SerdeSecret(share);
    let serde_share_bytes = bincode::serialize(&serde_share)?;

    let encrypted_serde_share_bytes = encrypt_bytes(&serde_share_bytes)?;
    fs::write(path, encrypted_serde_share_bytes)?;

    Ok(())
}

pub async fn load_secret_key_share(index: usize) -> Result<SecretKeyShare> {
    let filename = get_secret_key_filename(index);
    let encrypted_secret_key_share_bytes = fs::read(filename)?;
    let secret_key_share_bytes = decrypt_bytes(&encrypted_secret_key_share_bytes)?;
    let serde_secret_key_share: SerdeSecret<SecretKeyShare> =
        bincode::deserialize(&secret_key_share_bytes)?;
    let secret_key_share = serde_secret_key_share.into_inner();
    Ok(secret_key_share)
}

pub fn decode_signature_secret_key_share(
    b64_signature_share_bytes: &str,
) -> Result<SignatureShare> {
    let signature_share_bytes = general_purpose::STANDARD.decode(b64_signature_share_bytes)?;
    let signature_secret_key_share: SignatureShare = bincode::deserialize(&signature_share_bytes)?;

    Ok(signature_secret_key_share)
}

pub fn encode_signature_secret_key_share(signature_share: &SignatureShare) -> Result<String> {
    let signature_share_bytes = bincode::serialize(&signature_share)?;
    let b64_signature_share_bytes = general_purpose::STANDARD.encode(signature_share_bytes);
    Ok(b64_signature_share_bytes)
}

use aes_gcm::{
    AeadCore, Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, OsRng},
    aes::cipher::Unsigned,
};

use anyhow::{Result, anyhow};
use base64::{Engine, engine::general_purpose};

pub fn load_master_key() -> Result<[u8; 32]> {
    let base64_key = std::env::var("DKMS_MASTER_KEY")?;
    let key = general_purpose::STANDARD.decode(base64_key)?;

    if key.len() != 32 {
        anyhow::bail!("DKMS_MASTER_KEY must decode to exactly 32 bytes");
    }

    let key = key.as_slice().try_into()?;
    Ok(key)
}

pub fn encrypt_bytes(plain_data: &[u8]) -> Result<Vec<u8>> {
    let master_key = load_master_key()?;

    let key = Key::<Aes256Gcm>::from_slice(&master_key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let enc_data = cipher.encrypt(&nonce, plain_data).map_err(|e| anyhow!(e))?;

    let mut final_bytes = Vec::new();
    final_bytes.extend_from_slice(nonce.as_slice());
    final_bytes.extend_from_slice(&enc_data);

    Ok(final_bytes)
}

pub fn decrypt_bytes(encrypted_bytes: &[u8]) -> Result<Vec<u8>> {
    let master_key = load_master_key()?;
    type NonceSize = <Aes256Gcm as AeadCore>::NonceSize;
    let nonce_size = NonceSize::to_usize();
    let (nonce_bytes, enc_data) = encrypted_bytes.split_at(nonce_size);

    let nonce = Nonce::from_slice(nonce_bytes);

    let key = Key::<Aes256Gcm>::from_slice(&master_key);
    let cipher = Aes256Gcm::new(&key);

    let plain_data = cipher.decrypt(nonce, enc_data).map_err(|e| anyhow!(e))?;

    Ok(plain_data)
}

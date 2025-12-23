// src/crypto/aes_gcm.rs

use crate::error::{AppError, AppResult};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;

pub fn encrypt_aes_gcm(key: &[u8; 32], plaintext: &[u8]) -> AppResult<(Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new(key.into());

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| AppError::Crypto("AES-GCM encrypt error".into()))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

pub fn decrypt_aes_gcm(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> AppResult<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| AppError::Crypto("AES-GCM decrypt error".into()))?;

    Ok(plaintext)
}

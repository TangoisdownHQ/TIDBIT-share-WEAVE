// src/pqc/dilithium.rs

use crate::error::AppError;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};

#[derive(Debug, Clone)]
pub struct DilithiumKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

pub fn generate_keypair() -> DilithiumKeypair {
    let (pk, sk) = dilithium3::keypair();
    DilithiumKeypair {
        public_key: pk.as_bytes().to_vec(),
        secret_key: sk.as_bytes().to_vec(),
    }
}

/// Sign message; returns serialized SignedMessage blob
pub fn sign(secret_key_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, AppError> {
    let sk = dilithium3::SecretKey::from_bytes(secret_key_bytes)
        .map_err(|_| AppError::Internal("Dilithium secret key decode failed".into()))?;
    let sm = dilithium3::sign(msg, &sk);
    Ok(sm.as_bytes().to_vec())
}

/// Verify: re-open the SignedMessage and compare inner message
pub fn verify(public_key_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<bool, AppError> {
    let pk = dilithium3::PublicKey::from_bytes(public_key_bytes)
        .map_err(|_| AppError::Internal("Dilithium public key decode failed".into()))?;
    let sm = dilithium3::SignedMessage::from_bytes(sig_bytes)
        .map_err(|_| AppError::Internal("Dilithium signed message decode failed".into()))?;

    match dilithium3::open(&sm, &pk) {
        Ok(opened) => Ok(opened == msg),
        Err(_) => Ok(false),
    }
}

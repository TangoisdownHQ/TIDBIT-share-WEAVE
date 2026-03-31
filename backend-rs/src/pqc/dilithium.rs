// src/pqc/dilithium.rs

use crate::error::AppError;
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};

#[derive(Debug, Clone)]
pub struct DilithiumKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

pub fn generate_keypair() -> DilithiumKeypair {
    let (pk, sk) = ml_dsa_65::try_keygen()
        .expect("ML-DSA key generation should succeed with the default RNG");
    DilithiumKeypair {
        public_key: pk.into_bytes().to_vec(),
        secret_key: sk.into_bytes().to_vec(),
    }
}

fn public_key_from_bytes(bytes: &[u8]) -> Result<ml_dsa_65::PublicKey, AppError> {
    let array: [u8; ml_dsa_65::PK_LEN] = bytes
        .try_into()
        .map_err(|_| AppError::Internal("ML-DSA public key length mismatch".into()))?;
    ml_dsa_65::PublicKey::try_from_bytes(array)
        .map_err(|_| AppError::Internal("ML-DSA public key decode failed".into()))
}

fn secret_key_from_bytes(bytes: &[u8]) -> Result<ml_dsa_65::PrivateKey, AppError> {
    let array: [u8; ml_dsa_65::SK_LEN] = bytes
        .try_into()
        .map_err(|_| AppError::Internal("ML-DSA secret key length mismatch".into()))?;
    ml_dsa_65::PrivateKey::try_from_bytes(array)
        .map_err(|_| AppError::Internal("ML-DSA secret key decode failed".into()))
}

fn signature_from_bytes(bytes: &[u8]) -> Result<[u8; ml_dsa_65::SIG_LEN], AppError> {
    bytes
        .try_into()
        .map_err(|_| AppError::Internal("ML-DSA signature length mismatch".into()))
}

/// Sign message; returns serialized signature blob
pub fn sign(secret_key_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, AppError> {
    let sk = secret_key_from_bytes(secret_key_bytes)?;
    let sig = sk
        .try_sign(msg, &[])
        .map_err(|_| AppError::Internal("ML-DSA signing failed".into()))?;
    Ok(sig.to_vec())
}

pub fn verify(public_key_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<bool, AppError> {
    let pk = public_key_from_bytes(public_key_bytes)?;
    let sig = signature_from_bytes(sig_bytes)?;
    Ok(pk.verify(msg, &sig, &[]))
}

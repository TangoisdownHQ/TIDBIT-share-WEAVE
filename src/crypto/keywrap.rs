// src/crypto/keywrap.rs
use crate::error::AppError;

pub fn wrap_key_for_recipient(
    _recipient_kyber_public_key: &[u8],
    _aes_key: &[u8],
) -> Result<Vec<u8>, AppError> {
    Err(AppError::Crypto("Key wrapping not implemented yet".into()))
}

pub fn unwrap_key_for_recipient(
    _recipient_kyber_secret_key: &[u8],
    _wrapped_key: &[u8],
) -> Result<Vec<u8>, AppError> {
    Err(AppError::Crypto(
        "Key unwrapping not implemented yet".into(),
    ))
}

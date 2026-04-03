use axum::{extract::State, Json};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::AppError;

use super::state::AuthState;

#[derive(Serialize)]
pub struct SolNonceResponse {
    pub session_id: String,
    pub nonce: String,
    pub message: String,
}

pub async fn sol_nonce_handler(State(st): State<AuthState>) -> Json<SolNonceResponse> {
    let (session_id, nonce) = st.create_nonce();
    let message = sol_login_message(&nonce);
    Json(SolNonceResponse {
        session_id,
        nonce,
        message,
    })
}

#[derive(Deserialize)]
pub struct SolVerifyRequest {
    pub session_id: String,
    pub address: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct AuthSuccess {
    pub address: String,
    pub session_id: String,
}

pub async fn sol_verify_handler(
    State(st): State<AuthState>,
    Json(req): Json<SolVerifyRequest>,
) -> Result<Json<AuthSuccess>, AppError> {
    let session_id = req.session_id.trim();
    let address = req.address.trim();
    let signature = req.signature.trim();

    if session_id.is_empty() {
        return Err(AppError::Auth("Missing session_id".into()));
    }
    if address.is_empty() {
        return Err(AppError::Auth("Empty address".into()));
    }
    if signature.is_empty() {
        return Err(AppError::Auth("Empty signature".into()));
    }

    let nonce = st
        .take_nonce(session_id)
        .ok_or_else(|| AppError::Auth("Unknown or expired session".into()))?;
    let message = sol_login_message(&nonce);

    verify_solana_signature(&message, address, signature)
        .map_err(|_| AppError::Auth("Invalid Solana signature".into()))?;

    st.bind_wallet(session_id.to_string(), address.to_string(), "sol");

    Ok(Json(AuthSuccess {
        address: address.to_string(),
        session_id: session_id.to_string(),
    }))
}

pub fn sol_login_message(nonce: &str) -> String {
    format!(
        "TIDBIT Authentication\n\
Nonce: {}\n\
Purpose: Login\n\
Version: 1",
        nonce
    )
}

pub fn verify_solana_signature(
    message: &str,
    wallet_address: &str,
    signature: &str,
) -> Result<(), AppError> {
    let public_key_bytes = bs58::decode(wallet_address.trim())
        .into_vec()
        .map_err(|_| AppError::BadRequest("Invalid Solana wallet address".into()))?;
    let public_key_array: [u8; 32] = public_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AppError::BadRequest("Invalid Solana wallet address length".into()))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_array)
        .map_err(|_| AppError::BadRequest("Invalid Solana public key".into()))?;

    let signature_bytes = decode_signature_blob(signature)?;
    let signature_array: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AppError::BadRequest("Invalid Solana signature length".into()))?;
    let parsed_signature = Ed25519Signature::from_bytes(&signature_array);

    verifying_key
        .verify(message.as_bytes(), &parsed_signature)
        .map_err(|_| AppError::BadRequest("Invalid Solana signature".into()))
}

fn decode_signature_blob(signature: &str) -> Result<Vec<u8>, AppError> {
    let trimmed = signature.trim();

    if trimmed.len() % 2 == 0 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        if let Ok(bytes) = hex::decode(trimmed) {
            return Ok(bytes);
        }
    }

    BASE64_STANDARD
        .decode(trimmed)
        .or_else(|_| bs58::decode(trimmed).into_vec())
        .map_err(|_| AppError::BadRequest("Invalid signature encoding".into()))
}

#[cfg(test)]
mod tests {
    use super::{sol_login_message, verify_solana_signature};
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn verifies_hex_encoded_solana_signature() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let wallet = bs58::encode(signing_key.verifying_key().to_bytes()).into_string();
        let message = sol_login_message("nonce-123");
        let signature = signing_key.sign(message.as_bytes());
        let signature_hex = hex::encode(signature.to_bytes());

        let verified = verify_solana_signature(&message, &wallet, &signature_hex);

        assert!(verified.is_ok());
    }

    #[test]
    fn verifies_base64_encoded_solana_signature() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let wallet = bs58::encode(signing_key.verifying_key().to_bytes()).into_string();
        let message = sol_login_message("nonce-456");
        let signature = signing_key.sign(message.as_bytes());
        let signature_b64 = BASE64_STANDARD.encode(signature.to_bytes());

        let verified = verify_solana_signature(&message, &wallet, &signature_b64);

        assert!(verified.is_ok());
    }
}

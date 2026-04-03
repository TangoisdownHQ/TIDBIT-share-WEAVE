// src/identity_web/evm.rs

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::identity_web::state::AuthState;

use ethers_core::types::Signature;
use ethers_core::utils::hash_message;

use crate::crypto::canonical::keystore::load_or_create_mlkem_keypair;

// ============================================================
// NONCE
// ============================================================

#[derive(Serialize)]
pub struct EvmNonceResponse {
    pub session_id: String,
    pub nonce: String,
    pub message: String,
}

pub async fn evm_nonce_handler(
    State(st): State<AuthState>,
) -> Result<Json<EvmNonceResponse>, AppError> {
    let (session_id, nonce) = st.create_nonce().await?;
    let message = evm_login_message(&nonce);

    Ok(Json(EvmNonceResponse {
        session_id,
        nonce,
        message,
    }))
}

// ============================================================
// VERIFY
// ============================================================

#[derive(Deserialize)]
pub struct EvmVerifyRequest {
    pub session_id: String,
    pub address: String,
    pub signature: String,
}

pub async fn evm_verify_handler(
    State(st): State<AuthState>,
    Json(req): Json<EvmVerifyRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let sid = req.session_id.trim();
    let address = req.address.trim().to_lowercase();
    let signature = req.signature.trim();

    if sid.is_empty() {
        return Err(AppError::Auth("Missing session_id".into()));
    }
    if address.is_empty() {
        return Err(AppError::Auth("Empty address".into()));
    }
    if signature.is_empty() {
        return Err(AppError::Auth("Empty signature".into()));
    }

    let nonce = st
        .take_nonce(sid)
        .await?
        .ok_or_else(|| AppError::Auth("Unknown or expired session".into()))?;

    let message = evm_login_message(&nonce);

    let recovered = verify_evm_signature(&message, signature)
        .map_err(|_| AppError::Auth("Invalid signature".into()))?
        .to_lowercase();

    if recovered != address {
        return Err(AppError::Auth("Signature does not match address".into()));
    }

    st.bind_wallet(sid.to_string(), address.clone(), "evm", None, None, None)
        .await?;

    let keys = load_or_create_mlkem_keypair(&address)
        .map_err(|e| AppError::Internal(format!("mlkem keystore: {e}")))?;

    Ok(Json(serde_json::json!({
        "ok": true,
        "wallet": address,
        "chain": "evm",
        "mlkem_pk_b64": keys.pk_b64
    })))
}

// ============================================================
// SIGNATURE VERIFICATION
// ============================================================

pub fn verify_evm_signature(message: &str, signature: &str) -> Result<String, ()> {
    let sig: Signature = signature.parse().map_err(|_| ())?;
    let msg_hash = hash_message(message);
    let recovered = sig.recover(msg_hash).map_err(|_| ())?;
    Ok(format!("{:?}", recovered))
}

pub fn evm_login_message(nonce: &str) -> String {
    format!(
        "TIDBIT Authentication\n\
Nonce: {}\n\
Purpose: Login\n\
Version: 1",
        nonce
    )
}

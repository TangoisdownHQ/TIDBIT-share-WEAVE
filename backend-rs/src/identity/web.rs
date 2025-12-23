// src/identity/web.rs

use axum::{
    extract::State,
    Json,
};
use serde::{Deserialize, Serialize};
use rand::Rng;
use std::sync::{Arc, Mutex};

use crate::error::{AppError, AppResult};
use crate::identity::local_wallet::LocalWallet;

// ---------------------------------------
// Memory nonce store (replace w/ redis later)
// ---------------------------------------
#[derive(Clone)]
pub struct AuthState {
    pub evm_nonces: Arc<Mutex<std::collections::HashMap<String, String>>>,
    pub sol_nonces: Arc<Mutex<std::collections::HashMap<String, String>>>,
}

impl AuthState {
    pub fn new() -> Self {
        Self {
            evm_nonces: Arc::new(Mutex::new(std::collections::HashMap::new())),
            sol_nonces: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }
}

// ---------------------------------------
// EVM FLOW: request nonce
// ---------------------------------------
#[derive(Serialize)]
pub struct NonceResponse {
    pub nonce: String,
}

pub async fn evm_nonce_handler(
    State(state): State<AuthState>,
    Json(req): Json<EvmAddressReq>,
) -> AppResult<Json<NonceResponse>> {
    let nonce = format!("tidbit-login-{}", rand::thread_rng().gen::<u64>());
    state.evm_nonces.lock().unwrap().insert(req.address.clone(), nonce.clone());

    Ok(Json(NonceResponse { nonce }))
}

#[derive(Deserialize)]
pub struct EvmAddressReq {
    pub address: String,
}

// ---------------------------------------
// EVM FLOW: verify signature
// ---------------------------------------
#[derive(Deserialize)]
pub struct EvmVerifyReq {
    pub address: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub identity: String,
}

pub async fn evm_verify_handler(
    State(state): State<AuthState>,
    Json(req): Json<EvmVerifyReq>,
) -> AppResult<Json<LoginResponse>> {

    let stored_nonce = {
        let map = state.evm_nonces.lock().unwrap();
        map.get(&req.address).cloned()
    }.ok_or(AppError::BadRequest("Nonce expired".into()))?;

    // TODO: real EVM signature verification
    // For now we accept anything for dev mode:
    println!("[auth] VERIFY EVM request from {} sig={}", req.address, req.signature);

    // Create or lookup identity
    let identity = format!("evm:{}", req.address.to_lowercase());
    let token = format!("token-{}", identity); // TODO: real JWT or HMAC

    Ok(Json(LoginResponse { token, identity }))
}


// ---------------------------------------
// Phantom SOLANA FLOW (placeholder similar to EVM)
// ---------------------------------------
pub async fn sol_nonce_handler(
    State(state): State<AuthState>,
) -> AppResult<Json<NonceResponse>> {
    let nonce = format!("tidbit-sol-{}", rand::thread_rng().gen::<u64>());
    Ok(Json(NonceResponse { nonce }))
}

pub async fn sol_verify_handler(
    Json(req): Json<EvmVerifyReq>,
) -> AppResult<Json<LoginResponse>> {
    // TODO real solana signature verification
    let identity = format!("sol:{}", req.address.to_lowercase());
    let token = format!("token-{}", identity);

    Ok(Json(LoginResponse { token, identity }))
}


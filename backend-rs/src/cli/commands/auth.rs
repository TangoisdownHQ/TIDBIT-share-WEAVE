// src/cli/commands/auth.rs

use anyhow::{anyhow, Result};
use ethers_core::types::Signature;
use ethers_signers::{LocalWallet, Signer};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::cli::parser::AuthCommands;

// ======================================================
// TYPES
// ======================================================

#[derive(Debug, Deserialize)]
struct NonceResponse {
    session_id: String,
    nonce: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct VerifyRequest {
    session_id: String,
    address: String,
    signature: String,
}

// ======================================================
// COMMANDS
// ======================================================

pub async fn auth_evm(api: &str, private_key_hex: &str) -> Result<()> {
    let client = Client::new();

    // --------------------------------------------------
    // 1. Request nonce
    // --------------------------------------------------
    let nonce_resp: NonceResponse = client
        .post(format!("{api}/api/identity/evm/nonce"))
        .send()
        .await?
        .json()
        .await?;

    // --------------------------------------------------
    // 2. Load Ethereum wallet (MetaMask-compatible)
    // --------------------------------------------------
    let wallet =
        LocalWallet::from_str(private_key_hex).map_err(|e| anyhow!("invalid private key: {e}"))?;

    let address = wallet.address().to_string();

    // --------------------------------------------------
    // 3. Sign EXACT message (same as MetaMask)
    // --------------------------------------------------
    let message = nonce_resp.message.clone();
    let signature: Signature = wallet.sign_message(message).await?;

    // --------------------------------------------------
    // 4. Verify with backend
    // --------------------------------------------------
    let verify = VerifyRequest {
        session_id: nonce_resp.session_id.clone(),
        address: address.clone(),
        signature: signature.to_string(),
    };

    let resp = client
        .post(format!("{api}/api/identity/evm/verify"))
        .json(&verify)
        .send()
        .await?;

    if !resp.status().is_success() {
        let body = resp.text().await?;
        return Err(anyhow!("verify failed: {body}"));
    }

    println!("✅ Logged in as {address}");
    println!("🆔 Session ID: {}", nonce_resp.session_id);
    println!("💡 Export it:");
    println!("export TIDBIT_SESSION_ID={}", nonce_resp.session_id);

    Ok(())
}

pub async fn handle_auth(cmd: AuthCommands) -> Result<()> {
    match cmd {
        AuthCommands::Evm { api, private_key } => auth_evm(&api, &private_key).await?,
        AuthCommands::Whoami { api } => {
            let session_id =
                std::env::var("TIDBIT_SESSION_ID").map_err(|_| anyhow!("TIDBIT_SESSION_ID not set"))?;
            auth_whoami(&api, &session_id).await?;
        }
        AuthCommands::Logout { api } => {
            let session_id =
                std::env::var("TIDBIT_SESSION_ID").map_err(|_| anyhow!("TIDBIT_SESSION_ID not set"))?;
            auth_logout(&api, &session_id).await?;
        }
    }

    Ok(())
}

pub async fn auth_whoami(api: &str, session_id: &str) -> Result<()> {
    let client = Client::new();

    let resp = client
        .get(format!("{api}/auth/session"))
        .header("x-session-id", session_id)
        .send()
        .await?;

    let body = resp.text().await?;
    println!("{body}");

    Ok(())
}

pub async fn auth_logout(api: &str, session_id: &str) -> Result<()> {
    let client = Client::new();

    client
        .post(format!("{api}/auth/logout"))
        .header("x-session-id", session_id)
        .send()
        .await?;

    println!("🚪 Logged out");
    Ok(())
}

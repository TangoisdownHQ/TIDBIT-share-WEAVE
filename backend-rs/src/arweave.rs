// src/arweave.rs
use serde::Serialize;

use crate::error::{AppError, AppResult};

/// What we send to Arweave (or Bundlr)
#[derive(Debug, Serialize)]
pub struct ArweaveAnchorPayload<'a> {
    pub kind: &'a str,
    pub hash_hex: &'a str,
    pub label: Option<&'a str>,
}

/// Minimal returned struct for anchors.
/// Your filetrail.rs expects this.
#[derive(Debug, Clone)]
pub struct ArweaveAnchor {
    pub tx_id: String,
}

/// Minimal Arweave client wrapper
pub struct ArweaveClient {
    endpoint: String,
    api_key: Option<String>,
}

impl ArweaveClient {
    pub fn from_env() -> Self {
        let endpoint = std::env::var("ARWEAVE_ENDPOINT")
            .unwrap_or_else(|_| "https://node2.bundlr.network".to_string());

        let api_key = std::env::var("ARWEAVE_API_KEY").ok();

        Self { endpoint, api_key }
    }

    /// Anchor a hash and return TXID
    pub async fn anchor_hash(&self, payload: &ArweaveAnchorPayload<'_>) -> AppResult<String> {
        if self.api_key.is_none() {
            // simulation mode, deterministic fake txid
            let fake = format!("simulated-{}", payload.hash_hex);
            println!(
                "[arweave] SIMULATED anchor kind={} hash={} label={:?} -> {}",
                payload.kind, payload.hash_hex, payload.label, fake
            );
            return Ok(fake);
        }

        let client = reqwest::Client::new();
        let url = format!("{}/tx", self.endpoint);

        let res = client
            .post(url)
            .bearer_auth(self.api_key.as_ref().unwrap())
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Arweave HTTP error: {e}")))?;

        let status = res.status();
        let body: serde_json::Value = res
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Arweave parse error: {e}")))?;

        if !status.is_success() {
            return Err(AppError::Internal(format!(
                "Arweave HTTP {}: {}",
                status, body
            )));
        }

        let txid = body["id"].as_str().unwrap_or("").to_string();
        if txid.is_empty() {
            return Err(AppError::Internal("Arweave response missing `id`".into()));
        }

        println!("[arweave] anchored {} -> txid={}", payload.hash_hex, txid);

        Ok(txid)
    }
}

/// The function filetrail.rs imports:
///
/// ```rust
/// use crate::arweave::anchor_hash_to_arweave;
/// ```
///
/// This is a convenience wrapper around ArweaveClient.
pub async fn anchor_hash_to_arweave(hash_hex: &str) -> AppResult<ArweaveAnchor> {
    let client = ArweaveClient::from_env();

    let payload = ArweaveAnchorPayload {
        kind: "file_version_hash",
        hash_hex,
        label: None,
    };

    let txid = client.anchor_hash(&payload).await?;

    Ok(ArweaveAnchor { tx_id: txid })
}

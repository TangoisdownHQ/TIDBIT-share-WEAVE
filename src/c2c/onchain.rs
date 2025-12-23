// src/c2c/onchain.rs

use crate::arweave::{ArweaveAnchorPayload, ArweaveClient};
use crate::error::AppResult;

/// Anchor the hash of a C2C event to Arweave and return the txid.
///
/// `hash` is the raw bytes (e.g. SHA3-256) of the serialized event-without-signature.
pub async fn anchor_event_hash(hash: &[u8]) -> AppResult<String> {
    let hash_hex = hex::encode(hash);

    let client = ArweaveClient::from_env();
    let payload = ArweaveAnchorPayload {
        kind: "c2c_event_hash",
        hash_hex: &hash_hex,
        label: None,
    };

    client.anchor_hash(&payload).await
}

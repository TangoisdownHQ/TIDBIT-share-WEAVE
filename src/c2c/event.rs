//src/c2c/event.rs

use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::c2c::types::{C2CEvent, C2CEventKind};

/// Build a new C2C event for a document hash + optional extras.
pub fn new_doc_event(
    actor_wallet: String,
    kind: C2CEventKind,
    doc_hash_hex: String,
    arweave_tx: Option<String>,
    metadata: Option<serde_json::Value>,
) -> C2CEvent {
    let payload = json!({
        "doc_hash": doc_hash_hex,
        "arweave_tx": arweave_tx,
        "metadata": metadata,
    });

    C2CEvent {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now().timestamp() as u64,
        actor_wallet,
        kind,
        payload,
        signature_b64: None, // for later when PQC/EVM signing is ready
    }
}

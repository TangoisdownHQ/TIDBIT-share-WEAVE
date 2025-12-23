// src/c2c/types.rs

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum C2CEventKind {
    DocumentUploaded,
    DocumentDownloaded,
    DocumentSigned,
    DocumentUpdated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2CEvent {
    pub id: String,
    pub timestamp: u64,
    pub actor_wallet: String,
    pub kind: C2CEventKind,
    pub payload: serde_json::Value,
    pub signature_b64: Option<String>,
}

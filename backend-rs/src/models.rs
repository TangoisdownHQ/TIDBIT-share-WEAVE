
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct DocEntry {
    pub doc_id: String,
    pub hash_hex: String,
    pub label: Option<String>,
    pub local_path: Option<String>,
    pub arweave_tx: Option<String>,
}


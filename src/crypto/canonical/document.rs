// src/crypto/canonical/document.rs

use crate::pqc::sha3;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalDocumentV1 {
    pub logical_id: String,
    pub filename: Option<String>,
    pub mime: Option<String>,
    pub plaintext_sha3_256_hex: String,
    pub size_bytes: u64,
}

impl CanonicalDocumentV1 {
    pub fn from_plaintext(
        logical_id: String,
        bytes: &[u8],
        filename: Option<String>,
        mime: Option<String>,
    ) -> Self {
        let hash = sha3::sha3_256_bytes(bytes);
        Self {
            logical_id,
            filename,
            mime,
            plaintext_sha3_256_hex: hex::encode(hash),
            size_bytes: bytes.len() as u64,
        }
    }
}

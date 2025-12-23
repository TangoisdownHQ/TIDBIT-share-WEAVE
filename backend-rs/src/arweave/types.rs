// src/arweave/types.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single file version on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileVersionRef {
    /// Where the file lives locally at the time of signing.
    pub local_path: String,

    /// SHA-256 hash of the file, hex-encoded.
    pub sha256_hex: String,

    /// File size in bytes.
    pub size_bytes: u64,

    /// Best-effort MIME type (optional).
    pub mime_type: Option<String>,
}

/// Where this version is stored on Arweave (or Bundlr → Arweave).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArweaveLocation {
    /// Arweave transaction ID (or pseudo ID in dev mode).
    pub tx_id: String,

    /// Gateway URL to fetch the content.
    pub gateway_url: String,
}

/// Immutable record describing a single document version + where it lives.
///
/// This is what all parties can use as a chain-of-custody anchor
/// (local hash, actor, arweave tx, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainOfCustodyRecord {
    /// Logical document identifier, e.g. "msa-1234" or a UUID.
    pub document_id: String,

    /// Monotonic version number for this document.
    pub version: u64,

    /// When this version was created/signed.
    pub created_at: DateTime<Utc>,

    /// Who signed / uploaded this version (your PQC wallet, base64).
    pub actor_wallet_b64: String,

    /// Where this version is pinned on Arweave (if any).
    pub arweave: Option<ArweaveLocation>,

    /// Local file metadata and content hash.
    pub file: FileVersionRef,

    /// Optional link to a C2C event id (if this came from a C2C share).
    pub c2c_event_id: Option<String>,
}


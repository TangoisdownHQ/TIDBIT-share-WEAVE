// src/arweave/client.rs

use std::{
    fs,
    path::{Path, PathBuf},
};

use chrono::Utc;
use dirs::home_dir;
use sha2::{Digest, Sha256};

use crate::error::AppResult;
use crate::identity::local_wallet::LocalWallet;

use super::types::{ArweaveLocation, ChainOfCustodyRecord, FileVersionRef};

/// Simple dev-mode Arweave client.
///
/// - No real Arweave network calls yet.
/// - Writes JSON chain-of-custody records to ~/.tidbit/arweave-dev
/// - Generates a pseudo tx_id from the SHA-256 hash of the file.
pub struct ArweaveClient {
    /// Base URL of the Arweave gateway (used for URLs only for now).
    pub gateway_base: String,

    /// Where we persist chain-of-custody JSON records locally.
    dev_store_root: PathBuf,
}

impl ArweaveClient {
    /// Create a dev/offline client.
    ///
    /// This is safe to call anywhere; it just ensures ~/.tidbit/arweave-dev exists.
    pub fn dev_default() -> AppResult<Self> {
        let home = home_dir().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "No home directory found")
        })?;

        let root = home.join(".tidbit").join("arweave-dev");
        fs::create_dir_all(&root)?;

        Ok(Self {
            gateway_base: "https://arweave.net".to_string(),
            dev_store_root: root,
        })
    }

    /// "Upload" a document version in dev mode:
    ///
    /// - calculates SHA-256 of `bytes`
    /// - fabricates a pseudo Arweave tx_id from the hash
    /// - writes a JSON `ChainOfCustodyRecord` to ~/.tidbit/arweave-dev
    ///
    /// This gives you:
    ///   - a stable ID that looks like an Arweave tx id
    ///   - a JSON record you can reference from C2C events and contracts
    pub async fn upload_bytes_dev(
        &self,
        document_id: &str,
        version: u64,
        bytes: &[u8],
        local_path: &Path,
        wallet: &LocalWallet,
        c2c_event_id: Option<String>,
        mime_type: Option<String>,
    ) -> AppResult<ChainOfCustodyRecord> {
        // 1. Hash the content
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let sha256_hex = hex::encode(hasher.finalize());

        // 2. In real Arweave this would be the real tx_id.
        //    For dev we just reuse the hash as a pseudo tx_id.
        let pseudo_tx_id = sha256_hex.clone();

        let arweave_loc = ArweaveLocation {
            tx_id: pseudo_tx_id.clone(),
            gateway_url: format!("{}/{}", self.gateway_base, pseudo_tx_id),
        };

        // 3. File metadata
        let file_meta = FileVersionRef {
            local_path: local_path.to_string_lossy().to_string(),
            sha256_hex,
            size_bytes: bytes.len() as u64,
            mime_type,
        };

        // LocalWallet already stores the public key as base64,
        // so we just copy it directly.
        let actor_wallet_b64 = wallet.dilithium_public_key_b64.clone();

        // 4. Full chain-of-custody record
        let record = ChainOfCustodyRecord {
            document_id: document_id.to_string(),
            version,
            created_at: Utc::now(),
            actor_wallet_b64,
            arweave: Some(arweave_loc),
            file: file_meta,
            c2c_event_id,
        };

        // 5. Persist JSON to ~/.tidbit/arweave-dev/<document_id>-v<version>.json
        let json_bytes = serde_json::to_vec_pretty(&record)?;
        let filename = format!("{}-v{}.json", document_id, version);
        let path = self.dev_store_root.join(filename);
        fs::write(path, json_bytes)?;

        Ok(record)
    }

    /// Load all chain-of-custody records from the dev store.
    ///
    /// This will be useful for:
    ///   - listing versions of a document
    ///   - verifying that parties see the same history
    pub fn load_all_records(&self) -> AppResult<Vec<ChainOfCustodyRecord>> {
        let mut out = Vec::new();

        if !self.dev_store_root.exists() {
            return Ok(out);
        }

        for entry in fs::read_dir(&self.dev_store_root)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }

            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            let bytes = fs::read(path)?;
            let record: ChainOfCustodyRecord = serde_json::from_slice(&bytes)?;
            out.push(record);
        }

        Ok(out)
    }
}


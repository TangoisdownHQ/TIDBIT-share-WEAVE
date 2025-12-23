// src/cli/commands/doc.rs

use anyhow::Result;
use std::{fs, path::PathBuf};

use crate::arweave::anchor_hash_to_arweave;
use crate::c2c::filetrail::{record_file_version, FileAction};
use crate::c2c::{record, store as c2c_store};
use crate::cli::parser::DocCommands;
use crate::error::AppError;
use crate::identity::local_wallet::LocalWallet;
use crate::pqc::sha3 as pqc_sha3;

// 🔐 Canonical envelope + keystore
use crate::crypto::canonical::{
    canonicalize::canonical_json,
    keystore::{load_envelope_json, load_or_create_mlkem_keypair, save_envelope_json},
    CanonicalDocumentV1, DocumentEnvelopeV1,
};

/// -----------------------------------------------------------
/// PUBLIC DocEntry
/// -----------------------------------------------------------
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct DocEntry {
    pub logical_id: String,
    pub hash_hex: String,
    pub label: Option<String>,
    pub local_path: Option<String>,
    pub arweave_tx: Option<String>,
    #[serde(default)]
    pub owner_wallet: Option<String>,
}

/// -----------------------------------------------------------
/// Paths
/// -----------------------------------------------------------

pub fn docs_root() -> PathBuf {
    let mut dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    dir.push(".tidbit/docs");
    dir
}

pub fn docs_data_dir() -> PathBuf {
    let mut d = docs_root();
    d.push("data");
    d
}

pub fn docs_index_path() -> PathBuf {
    let mut d = docs_root();
    d.push("index.json");
    d
}

/// -----------------------------------------------------------
/// Index helpers
/// -----------------------------------------------------------

pub fn load_index() -> Result<Vec<DocEntry>, AppError> {
    let path = docs_index_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&data)?)
}

pub fn save_index(entries: &[DocEntry]) -> Result<(), AppError> {
    let path = docs_index_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(entries)?)?;
    Ok(())
}

pub fn find_doc_mut<'a>(
    list: &'a mut [DocEntry],
    id: &Option<String>,
    hash: &Option<String>,
) -> Result<&'a mut DocEntry, AppError> {
    if let Some(id) = id {
        return list
            .iter_mut()
            .find(|e| e.logical_id == *id)
            .ok_or_else(|| AppError::BadRequest(format!("No doc with id={id}")));
    }
    if let Some(h) = hash {
        return list
            .iter_mut()
            .find(|e| e.hash_hex == *h)
            .ok_or_else(|| AppError::BadRequest(format!("No doc with hash={h}")));
    }
    Err(AppError::BadRequest("Must specify --id or --hash".into()))
}

/// -----------------------------------------------------------
/// CLI HANDLER
/// -----------------------------------------------------------

pub async fn handle_doc(cmd: DocCommands) -> Result<()> {
    match cmd {
        // ===================================================
        // UPLOAD
        // ===================================================
        DocCommands::Upload { path, label, store } => {
            let bytes = fs::read(&path)?;
            let hash = pqc_sha3::sha3_256_bytes(&bytes);
            let hash_hex = hex::encode(&hash);
            let logical_id = uuid::Uuid::new_v4().to_string();

            let owner_wallet = LocalWallet::load()
                .map(|w| w.actor_id())
                .unwrap_or_else(|_| "local-dev-wallet".into());

            let data_dir = docs_data_dir();
            fs::create_dir_all(&data_dir)?;
            let stored_path = data_dir.join(&hash_hex);
            fs::write(&stored_path, &bytes)?;

            let arweave_tx = match store.as_str() {
                "arweave" | "both" => Some(anchor_hash_to_arweave(&hash_hex).await?.tx_id),
                _ => None,
            };

            let mut idx = load_index()?;
            idx.push(DocEntry {
                logical_id: logical_id.clone(),
                hash_hex: hash_hex.clone(),
                label,
                local_path: Some(stored_path.to_string_lossy().into_owned()),
                arweave_tx: arweave_tx.clone(),
                owner_wallet: Some(owner_wallet.clone()),
            });
            save_index(&idx)?;

            let ev = record::record_upload_event(
                owner_wallet.clone(),
                hash_hex.clone(),
                arweave_tx.clone(),
            )?;

            record_file_version(
                &logical_id,
                FileAction::Uploaded,
                &stored_path,
                &hash_hex,
                &ev,
                None,
            )?;

            println!("Uploaded doc {}", logical_id);
        }

        // ===================================================
        // ENVELOPE CREATE
        // ===================================================
        DocCommands::EnvelopeCreate { input } => {
            let wallet = LocalWallet::load()
                .map(|w| w.actor_id())
                .unwrap_or_else(|_| "local-dev-wallet".into());

            let keys = load_or_create_mlkem_keypair(&wallet).map_err(|e| anyhow::anyhow!(e))?;

            let plaintext = fs::read(&input)?;

            let doc = CanonicalDocumentV1::from_plaintext(
                uuid::Uuid::new_v4().to_string(),
                &plaintext,
                Some(input.clone()),
                None,
            );

            let (env, eid) = DocumentEnvelopeV1::create_mlkem_owner(
                wallet.clone(),
                &keys.pk_b64,
                chrono::Utc::now().timestamp(),
                doc,
                &plaintext,
            )
            .map_err(|e| anyhow::anyhow!(e))?;

            let canon = canonical_json(&env);
            save_envelope_json(&eid, &canon).map_err(|e| anyhow::anyhow!(e))?;

            println!("🔐 Envelope created: {}", eid);
        }

        // ===================================================
        // ENVELOPE DECRYPT
        // ===================================================
        DocCommands::EnvelopeDecrypt { envelope_id, out } => {
            let wallet = LocalWallet::load()
                .map(|w| w.actor_id())
                .unwrap_or_else(|_| "local-dev-wallet".into());

            let keys = load_or_create_mlkem_keypair(&wallet).map_err(|e| anyhow::anyhow!(e))?;

            let bytes = load_envelope_json(&envelope_id).map_err(|e| anyhow::anyhow!(e))?;

            let env: DocumentEnvelopeV1 = serde_json::from_slice(&bytes)?;
            let recovered = env
                .decrypt_for_owner_mlkem(&keys.sk_b64)
                .map_err(|e| anyhow::anyhow!(e))?;

            fs::write(&out, &recovered)?;
            println!("🔓 Decrypted to {}", out);
        }

        _ => {
            println!("Command handled (legacy)");
        }
    }

    Ok(())
}

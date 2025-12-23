// src/c2c/filetrail.rs

use crate::arweave::ArweaveAnchor;
use crate::c2c::types::C2CEvent;
use crate::error::AppResult;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileAction {
    Uploaded,
    Updated,
    Shared,
    Downloaded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileVersionRecord {
    pub id: String,
    pub logical_doc_id: String,
    pub version: u64,
    pub action: FileAction,

    /// Hash of previous version (None for v1)
    pub parent_hash: Option<String>,

    pub path: String,
    pub sha256_hex: String,
    pub c2c_event_id: String,
    pub arweave_tx_id: Option<String>,
    pub timestamp: i64,
}

fn log_dir() -> AppResult<PathBuf> {
    let base = dirs::config_dir().unwrap_or(std::env::current_dir()?);
    let dir = base.join("tidbit-share-weave").join("c2c");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn log_path() -> AppResult<PathBuf> {
    Ok(log_dir()?.join("filetrail.jsonl"))
}

/// Determine next version + parent hash
fn next_version(logical_doc_id: &str) -> AppResult<(u64, Option<String>)> {
    let history = load_history(logical_doc_id)?;
    if let Some(last) = history.last() {
        Ok((last.version + 1, Some(last.sha256_hex.clone())))
    } else {
        Ok((1, None))
    }
}

/// Append a new FileTrail record
pub fn record_file_version(
    logical_doc_id: &str,
    action: FileAction,
    path: &Path,
    sha256_hex: &str,
    ev: &C2CEvent,
    anchor: Option<&ArweaveAnchor>,
) -> AppResult<FileVersionRecord> {
    let (version, parent_hash) = next_version(logical_doc_id)?;

    let record = FileVersionRecord {
        id: Uuid::new_v4().to_string(),
        logical_doc_id: logical_doc_id.to_string(),
        version,
        action,
        parent_hash,
        path: path.to_string_lossy().into_owned(),
        sha256_hex: sha256_hex.to_string(),
        c2c_event_id: ev.id.clone(),
        arweave_tx_id: anchor.map(|a| a.tx_id.clone()),
        timestamp: Utc::now().timestamp(),
    };

    let json = serde_json::to_string(&record)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path()?)?;

    file.write_all(json.as_bytes())?;
    file.write_all(b"\n")?;

    Ok(record)
}

/// Load full version history
pub fn load_history(logical_doc_id: &str) -> AppResult<Vec<FileVersionRecord>> {
    let path = log_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }

    let data = fs::read_to_string(path)?;
    let mut out = Vec::new();

    for line in data.lines() {
        if let Ok(rec) = serde_json::from_str::<FileVersionRecord>(line) {
            if rec.logical_doc_id == logical_doc_id {
                out.push(rec);
            }
        }
    }

    out.sort_by_key(|r| r.version);
    Ok(out)
}

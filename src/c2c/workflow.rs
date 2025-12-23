use crate::c2c::types::{C2CEvent, C2CEventKind};
use crate::c2c::event::record_c2c_event;
use crate::c2c::filetrail::{record_file_version, FileAction};
use crate::arweave::anchor_hash_to_arweave;
use crate::error::AppResult;

use sha2::{Sha256, Digest};
use std::path::Path;

/// Unified pipeline for document actions:
/// - Compute hash
/// - Generate C2C event
/// - Anchor to Arweave
/// - Save FileTrail version
pub async fn record_document_event(
    logical_doc_id: &str,
    version: u64,
    action: FileAction,
    file_path: &Path,
    actor_wallet: &str,
) -> AppResult<()> {

    //
    // 1 — Hash file
    //
    let data = std::fs::read(file_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let sha = hasher.finalize();
    let sha_hex = hex::encode(sha);

    //
    // 2 — Build and store a C2C event
    //
    let ev = C2CEvent::new(
        C2CEventKind::FileAction { action: format!("{:?}", action) },
        actor_wallet.to_string(),
        Some(sha_hex.clone()),
    );

    record_c2c_event(&ev)?;

    //
    // 3 — Anchor the hash into Arweave (optional but recommended)
    //
    let anchor = anchor_hash_to_arweave(&sha_hex).await?;

    //
    // 4 — Record chain-of-custody version (FileTrail)
    //
    let _rec = record_file_version(
        logical_doc_id,
        version,
        action,
        file_path,
        &sha_hex,
        &ev,
        Some(&anchor),
    )?;

    println!("📌 Document event recorded:");
    println!("• logical_id: {}", logical_doc_id);
    println!("• version: {}", version);
    println!("• action: {:?}", action);
    println!("• sha256: {}", sha_hex);
    println!("• c2c_event_id: {}", ev.id);
    println!("• arweave_tx: {}", anchor.tx_id);

    Ok(())
}


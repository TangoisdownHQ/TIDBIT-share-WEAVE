// src/cli/commands/doc.rs

use std::{fs, path::PathBuf};

use anyhow::Result;
use reqwest::Client;
use sqlx::Row;

use crate::arweave::anchor_hash_to_arweave;
use crate::c2c::{record, store as c2c_store};
use crate::cli::parser::DocCommands;
use crate::identity::local_wallet::LocalWallet;
use crate::pqc::sha3 as pqc_sha3;
use crate::storage::supabase::SupabaseStorage;

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct DocEntry {
    pub logical_id: String,
    pub hash_hex: String,
    pub label: Option<String>,
    pub local_path: Option<String>,
    pub arweave_tx: Option<String>,
    pub owner_wallet: Option<String>,
}

// ======================================================
// Paths
// ======================================================

fn docs_root() -> PathBuf {
    let mut dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    dir.push(".tidbit/docs");
    dir
}

fn docs_data_dir() -> PathBuf {
    let mut d = docs_root();
    d.push("data");
    d
}

fn docs_index_path() -> PathBuf {
    let mut d = docs_root();
    d.push("index.json");
    d
}

// ======================================================
// Index helpers
// ======================================================

pub fn load_index() -> Result<Vec<DocEntry>> {
    let path = docs_index_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn save_index(entries: &[DocEntry]) -> Result<()> {
    let path = docs_index_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(entries)?)?;
    Ok(())
}

// ======================================================
// Owner resolution
// ======================================================

async fn resolve_owner_wallet(use_session: bool, owner_wallet: Option<String>) -> Result<String> {
    if use_session && owner_wallet.is_some() {
        anyhow::bail!("Use either --use-session or --owner-wallet, not both");
    }

    if use_session {
        let sid = std::env::var("TIDBIT_SESSION_ID")
            .map_err(|_| anyhow::anyhow!("TIDBIT_SESSION_ID not set"))?;

        let api =
            std::env::var("TIDBIT_API").unwrap_or_else(|_| "http://localhost:4100".to_string());

        let resp = Client::new()
            .get(format!("{api}/auth/session"))
            .header("x-session-id", sid)
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Invalid or expired session");
        }

        let v: serde_json::Value = resp.json().await?;
        return v["wallet"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("Session missing wallet"));
    }

    if let Some(w) = owner_wallet {
        return Ok(w);
    }

    Ok(LocalWallet::load()
        .map(|w| w.actor_id())
        .unwrap_or_else(|_| "local-dev-wallet".into()))
}

#[derive(Debug)]
struct DocumentStorageRow {
    id: uuid::Uuid,
    owner_wallet: String,
    hash_hex: String,
    version: i32,
    storage_path: String,
}

async fn load_storage_rows(
    db: &sqlx::PgPool,
    id: Option<&str>,
    limit: Option<i64>,
) -> Result<Vec<DocumentStorageRow>> {
    let rows = if let Some(id) = id {
        let doc_id = uuid::Uuid::parse_str(id)?;
        sqlx::query(
            r#"
            select id, owner_wallet, hash_hex, version, storage_path
            from documents
            where id = $1 and is_deleted = false
            "#,
        )
        .bind(doc_id)
        .fetch_all(db)
        .await?
    } else if let Some(limit) = limit {
        sqlx::query(
            r#"
            select id, owner_wallet, hash_hex, version, storage_path
            from documents
            where is_deleted = false
            order by created_at desc
            limit $1
            "#,
        )
        .bind(limit)
        .fetch_all(db)
        .await?
    } else {
        sqlx::query(
            r#"
            select id, owner_wallet, hash_hex, version, storage_path
            from documents
            where is_deleted = false
            order by created_at desc
            "#,
        )
        .fetch_all(db)
        .await?
    };

    Ok(rows
        .into_iter()
        .map(|row| DocumentStorageRow {
            id: row.get("id"),
            owner_wallet: row.get("owner_wallet"),
            hash_hex: row.get("hash_hex"),
            version: row.get("version"),
            storage_path: row.get("storage_path"),
        })
        .collect())
}

async fn repair_storage_paths(apply: bool, id: Option<String>, limit: Option<i64>) -> Result<()> {
    let database_url = std::env::var("DATABASE_URL")?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    let storage = SupabaseStorage::new(
        std::env::var("SUPABASE_URL")?,
        std::env::var("SUPABASE_SERVICE_ROLE_KEY")?,
        std::env::var("SUPABASE_BUCKET")?,
    );

    let rows = load_storage_rows(&pool, id.as_deref(), limit).await?;

    let mut unchanged = 0usize;
    let mut planned = 0usize;
    let mut moved = 0usize;
    let mut db_only = 0usize;
    let mut skipped_missing = 0usize;
    let mut conflicts = 0usize;

    for row in rows {
        let expected_path = SupabaseStorage::expected_object_path(
            &row.owner_wallet,
            &row.id.to_string(),
            row.version,
            &row.hash_hex,
        );

        if row.storage_path == expected_path {
            unchanged += 1;
            continue;
        }

        planned += 1;
        println!("document {}", row.id);
        println!("  old: {}", row.storage_path);
        println!("  new: {}", expected_path);

        if !apply {
            continue;
        }

        let old_exists = storage.object_exists(&row.storage_path).await?;
        let new_exists = storage.object_exists(&expected_path).await?;

        match (old_exists, new_exists) {
            (true, false) => {
                storage.move_object(&row.storage_path, &expected_path).await?;
                sqlx::query("update documents set storage_path = $1 where id = $2")
                    .bind(&expected_path)
                    .bind(row.id)
                    .execute(&pool)
                    .await?;
                moved += 1;
                println!("  action: moved object and updated documents.storage_path");
            }
            (false, true) => {
                sqlx::query("update documents set storage_path = $1 where id = $2")
                    .bind(&expected_path)
                    .bind(row.id)
                    .execute(&pool)
                    .await?;
                db_only += 1;
                println!("  action: expected object already existed; updated documents.storage_path only");
            }
            (true, true) => {
                sqlx::query("update documents set storage_path = $1 where id = $2")
                    .bind(&expected_path)
                    .bind(row.id)
                    .execute(&pool)
                    .await?;
                conflicts += 1;
                println!("  action: both objects existed; updated DB to expected path and left legacy object in place");
            }
            (false, false) => {
                skipped_missing += 1;
                println!("  action: skipped, neither old nor expected object exists in Supabase");
            }
        }
    }

    println!();
    println!("repair summary");
    println!("  unchanged: {unchanged}");
    println!("  mismatches: {planned}");
    if apply {
        println!("  moved: {moved}");
        println!("  db_only: {db_only}");
        println!("  conflicts: {conflicts}");
        println!("  missing: {skipped_missing}");
    } else {
        println!("  dry_run: true");
        println!("  apply with: cargo run -- doc repair-storage-paths --apply");
    }

    Ok(())
}

// ======================================================
// CLI dispatcher
// ======================================================

pub async fn handle_doc(cmd: DocCommands) -> Result<()> {
    match cmd {
        // ---------------- Upload ----------------
        DocCommands::Upload {
            path,
            label,
            use_session,
            owner_wallet,
            store,
        } => {
            let bytes = fs::read(&path)?;
            let hash_hex = hex::encode(pqc_sha3::sha3_256_bytes(&bytes));
            let logical_id = uuid::Uuid::new_v4().to_string();

            let owner = resolve_owner_wallet(use_session, owner_wallet).await?;

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
                local_path: Some(stored_path.to_string_lossy().into()),
                arweave_tx: arweave_tx.clone(),
                owner_wallet: Some(owner.clone()),
            });
            save_index(&idx)?;

            record::record_upload_event(owner, hash_hex, arweave_tx)?;
            println!("Uploaded document {}", logical_id);
        }

        // ---------------- Sign (CLI stub) ----------------
        DocCommands::Sign {
            api,
            session_id,
            doc_id,
            wallet,
            private_key: _,
        } => {
            println!("CLI signing is intentionally disabled for security.");
            println!("Use frontend MetaMask signing instead.");
            println!("API: {api}");
            println!("Session: {session_id}");
            println!("Doc ID: {doc_id}");
            println!("Wallet: {wallet}");
        }

        // ---------------- History ----------------
        DocCommands::History { id, hash } => {
            let needle = id
                .or(hash)
                .ok_or_else(|| anyhow::anyhow!("--id or --hash required"))?;
            let events = c2c_store::load_all_events()?;

            for ev in events
                .into_iter()
                .filter(|e| e.payload.get("doc_hash").and_then(|v| v.as_str()) == Some(&needle))
            {
                println!("{} | {:?} | {}", ev.timestamp, ev.kind, ev.actor_wallet);
            }
        }

        DocCommands::RepairStoragePaths { apply, id, limit } => {
            repair_storage_paths(apply, id, limit).await?;
        }

        _ => {}
    }

    Ok(())
}

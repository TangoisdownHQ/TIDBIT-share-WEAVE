// src/c2c/store.rs

use std::{fs, path::PathBuf};

use serde_json::Value;
use sqlx::{PgPool, Row};

use crate::c2c::types::{C2CEvent, C2CEventKind};
use crate::error::{AppError, AppResult};

fn events_dir() -> PathBuf {
    let mut dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    dir.push(".tidbit");
    dir.push("c2c_events");
    dir
}

fn event_path(id: &str) -> PathBuf {
    let mut p = events_dir();
    p.push(format!("{id}.json"));
    p
}

// ================================================================
// LOCAL (JSON) STORE
// ================================================================

pub fn store_local_event(ev: &C2CEvent) -> AppResult<()> {
    let dir = events_dir();
    fs::create_dir_all(&dir)?;
    let json = serde_json::to_string_pretty(ev)?;
    fs::write(event_path(&ev.id), json)?;
    Ok(())
}

pub fn load_all_events() -> AppResult<Vec<C2CEvent>> {
    let dir = events_dir();
    let mut out = Vec::new();

    if !dir.exists() {
        return Ok(out);
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        let data = fs::read_to_string(&path)?;
        if let Ok(ev) = serde_json::from_str::<C2CEvent>(&data) {
            out.push(ev);
        }
    }

    out.sort_by_key(|e| e.timestamp);
    out.reverse();
    Ok(out)
}

pub fn load_event_by_id(id: &str) -> AppResult<Option<C2CEvent>> {
    let path = event_path(id);
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read_to_string(path)?;
    let ev = serde_json::from_str(&data)?;
    Ok(Some(ev))
}

// ================================================================
// DB STORE
// ================================================================

fn kind_to_string(kind: &C2CEventKind) -> &'static str {
    match kind {
        C2CEventKind::DocumentUploaded => "UPLOAD",
        C2CEventKind::DocumentDownloaded => "DOWNLOAD",
        C2CEventKind::DocumentSigned => "SIGN",
        C2CEventKind::DocumentUpdated => "UPDATE",
        C2CEventKind::DocumentShared => "SHARE",
    }
}

fn kind_from_string(s: &str) -> C2CEventKind {
    match s {
        "UPLOAD" => C2CEventKind::DocumentUploaded,
        "DOWNLOAD" => C2CEventKind::DocumentDownloaded,
        "SIGN" => C2CEventKind::DocumentSigned,
        "UPDATE" => C2CEventKind::DocumentUpdated,
        "SHARE" => C2CEventKind::DocumentShared,
        _ => C2CEventKind::DocumentUpdated, // safe fallback
    }
}

pub async fn store_db_event(db: &PgPool, ev: &C2CEvent, ip_address: Option<&str>) -> AppResult<()> {
    let document_id = ev.payload.get("document_id").and_then(Value::as_str);
    let version_id = ev.payload.get("version_id").and_then(Value::as_str);
    let hash_hex = ev.payload.get("hash_hex").and_then(Value::as_str);

    let document_id = document_id
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Internal("Missing document_id in C2C payload".into()))?;

    let version_id = version_id.and_then(|s| uuid::Uuid::parse_str(s).ok());

    sqlx::query(
        r#"
        insert into c2c_events (
            id,
            owner_wallet,
            document_id,
            version_id,
            action,
            hash_hex,
            signature,
            ip_address,
            created_at
        )
        values ($1,$2,$3,$4,$5,$6,$7,$8, to_timestamp($9 / 1000.0))
        "#,
    )
    .bind(&ev.id)
    .bind(&ev.actor_wallet)
    .bind(document_id)
    .bind(version_id)
    .bind(kind_to_string(&ev.kind))
    .bind(hash_hex)
    .bind(&ev.signature_b64)
    .bind(ip_address)
    .bind(ev.timestamp as i64)
    .execute(db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(())
}

pub async fn load_db_events_for_document(
    db: &PgPool,
    owner_wallet: &str,
    document_id: uuid::Uuid,
) -> AppResult<Vec<C2CEvent>> {
    let rows = sqlx::query(
        r#"
        select
          id,
          owner_wallet,
          action,
          hash_hex,
          signature,
          extract(epoch from created_at) * 1000 as ts
        from c2c_events
        where owner_wallet = $1 and document_id = $2
        order by created_at desc
        "#,
    )
    .bind(owner_wallet)
    .bind(document_id)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let mut out = Vec::new();

    for row in rows {
        let id: uuid::Uuid = row.get("id");
        let owner_wallet: String = row.get("owner_wallet");
        let action: String = row.get("action");
        let hash_hex: Option<String> = row.get("hash_hex");
        let signature: Option<String> = row.get("signature");
        let ts: f64 = row.get("ts");

        out.push(C2CEvent {
            id: id.to_string(),
            actor_wallet: owner_wallet,
            kind: kind_from_string(&action),
            payload: serde_json::json!({ "hash_hex": hash_hex }),
            signature_b64: signature,
            timestamp: ts as u64,
        });
    }

    Ok(out)
}

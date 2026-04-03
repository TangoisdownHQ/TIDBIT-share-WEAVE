use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

use crate::{error::AppError, identity_web::AuthState};

// ======================================================
// MODELS
// ======================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InboxItem {
    pub id: String,
    pub envelope_id: String,
    pub from_wallet: String,
    pub to_wallet: String,
    pub created_at: i64,
    pub status: String, // pending | accepted | rejected
    pub note: Option<String>,
    pub decided_at: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShareEnvelopeRequest {
    pub envelope_id: String,
    pub to_wallet: String,
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InboxListResponse {
    pub wallet: String,
    pub items: Vec<InboxItem>,
}

// ======================================================
// STORAGE
// ======================================================

fn inbox_root() -> PathBuf {
    let mut dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    dir.push(".tidbit");
    dir.push("inbox");
    dir
}

fn inbox_path_for(wallet: &str) -> PathBuf {
    let mut p = inbox_root();
    let safe = wallet.to_lowercase().replace(':', "_");
    p.push(format!("{safe}.json"));
    p
}

fn load_inbox(wallet: &str) -> Result<Vec<InboxItem>, AppError> {
    let path = inbox_path_for(wallet);
    if !path.exists() {
        return Ok(vec![]);
    }
    let s = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&s)?)
}

fn save_inbox(wallet: &str, items: &[InboxItem]) -> Result<(), AppError> {
    fs::create_dir_all(inbox_root())?;
    let path = inbox_path_for(wallet);
    fs::write(path, serde_json::to_string_pretty(items)?)?;
    Ok(())
}

// ======================================================
// HELPERS
// ======================================================

async fn wallet_from_headers(
    st: &AuthState,
    headers: &axum::http::HeaderMap,
) -> Result<String, AppError> {
    let sid = headers
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Auth("missing x-session-id".into()))?;

    let sess = st
        .get_session(sid, None)
        .await?
        .ok_or_else(|| AppError::Auth("invalid or expired session".into()))?;

    Ok(sess.wallet)
}

// ======================================================
// ROUTES
// ======================================================

/// POST /api/envelope/share
pub async fn share_envelope_v2(
    State(st): State<AuthState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ShareEnvelopeRequest>,
) -> Result<Json<InboxItem>, AppError> {
    let from_wallet = wallet_from_headers(&st, &headers).await?;
    let now = chrono::Utc::now().timestamp();

    let item = InboxItem {
        id: uuid::Uuid::new_v4().to_string(),
        envelope_id: req.envelope_id,
        from_wallet,
        to_wallet: req.to_wallet.to_lowercase(),
        created_at: now,
        status: "pending".into(),
        note: req.note,
        decided_at: None,
    };

    let mut items = load_inbox(&item.to_wallet)?;
    items.insert(0, item.clone());
    save_inbox(&item.to_wallet, &items)?;

    Ok(Json(item))
}

/// GET /api/inbox
pub async fn list_inbox(
    State(st): State<AuthState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<InboxListResponse>, AppError> {
    let wallet = wallet_from_headers(&st, &headers).await?;
    let items = load_inbox(&wallet)?;

    Ok(Json(InboxListResponse { wallet, items }))
}

/// POST /api/inbox/:id/accept
pub async fn accept_inbox_item(
    State(st): State<AuthState>,
    headers: axum::http::HeaderMap,
    Path(item_id): Path<String>,
) -> Result<Json<InboxItem>, AppError> {
    let wallet = wallet_from_headers(&st, &headers).await?;
    let mut items = load_inbox(&wallet)?;

    let now = chrono::Utc::now().timestamp();
    let mut updated: Option<InboxItem> = None;

    for i in items.iter_mut() {
        if i.id == item_id {
            i.status = "accepted".into();
            i.decided_at = Some(now);
            updated = Some(i.clone());
            break;
        }
    }

    let item = updated.ok_or_else(|| AppError::BadRequest("inbox item not found".into()))?;
    save_inbox(&wallet, &items)?;

    Ok(Json(item))
}

/// POST /api/inbox/:id/reject
pub async fn reject_inbox_item(
    State(st): State<AuthState>,
    headers: axum::http::HeaderMap,
    Path(item_id): Path<String>,
) -> Result<Json<InboxItem>, AppError> {
    let wallet = wallet_from_headers(&st, &headers).await?;
    let mut items = load_inbox(&wallet)?;

    let now = chrono::Utc::now().timestamp();
    let mut updated: Option<InboxItem> = None;

    for i in items.iter_mut() {
        if i.id == item_id {
            i.status = "rejected".into();
            i.decided_at = Some(now);
            updated = Some(i.clone());
            break;
        }
    }

    let item = updated.ok_or_else(|| AppError::BadRequest("inbox item not found".into()))?;
    save_inbox(&wallet, &items)?;

    Ok(Json(item))
}

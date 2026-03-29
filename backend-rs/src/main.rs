// src/main.rs

mod arweave;
mod c2c;
mod cli;
mod config;
mod crypto;
mod delivery;
mod error;
mod identity;
mod identity_web;
mod models;
mod pqc;
mod routes;
mod sanitizer;
mod storage;

use axum::extract::{Multipart, Path, Query, State};
use axum::http::HeaderMap;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use base64::Engine;
use clap::Parser;
use cli::commands::{auth, c2c as cli_c2c, doc, wallet};
use cli::parser::{Cli, Commands};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use std::collections::HashMap;

use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;

use crate::error::AppError;
use crate::identity_web::evm::{verify_evm_signature, EvmNonceResponse, EvmVerifyRequest};
use crate::identity_web::state::WalletSession;
use crate::delivery::{send_email_invite, send_sms_invite, DeliveryOutcome};
use crate::models::{
    AgentRegisterRequest, AgentSignRequest, AgentVersionRequest, DocumentPolicyUpdateRequest,
    PublicEnvelopeSignRequest, ShareRequest, SignRequest, SignerAnnotationField,
};
use crate::crypto::canonical::{
    canonicalize::canonical_json,
    keystore::load_or_create_mlkem_keypair,
    CanonicalDocumentV1,
    DocumentEnvelopeV1,
};
use crate::pqc::dilithium;
use crate::pqc::sha3 as pqc_sha3;
use storage::supabase::SupabaseStorage;

// ================================================================
// APP STATE
// ================================================================

#[derive(Clone)]
struct AppState {
    auth: identity_web::AuthState,
    db: PgPool,
    storage: SupabaseStorage,
}

struct DocumentAccessRecord {
    id: uuid::Uuid,
    storage_path: String,
    owner_wallet: String,
    label: Option<String>,
    hash_hex: String,
    version: i32,
    mime_type: String,
    parent_id: Option<uuid::Uuid>,
    arweave_tx: Option<String>,
    encryption_mode: String,
    ciphertext_hash_hex: Option<String>,
}

struct CreatedDocumentRecord {
    id: uuid::Uuid,
    hash_hex: String,
    label: Option<String>,
    storage_path: String,
    version: i32,
    mime_type: String,
    parent_id: Option<uuid::Uuid>,
    arweave_tx: Option<String>,
}

struct AgentIdentityRecord {
    id: uuid::Uuid,
    owner_wallet: String,
    label: String,
    provider: Option<String>,
    model: Option<String>,
    capabilities_json: serde_json::Value,
}

struct DocumentBytesResponse {
    bytes: Vec<u8>,
    mime_type: String,
    label: Option<String>,
    hash_hex: String,
    version: i32,
    parent_id: Option<uuid::Uuid>,
    arweave_tx: Option<String>,
    encryption_mode: String,
}

// ================================================================
// ENTRY
// ================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Server => start_server().await?,
        Commands::Auth { action } => auth::handle_auth(action).await?,
        Commands::Wallet { action } => wallet::handle_wallet(action).await?,
        Commands::Doc { action } => doc::handle_doc(action).await?,
        Commands::C2c { action } => cli_c2c::handle_c2c(action).await?,
    }

    Ok(())
}

// ================================================================
// SERVER
// ================================================================

async fn start_server() -> anyhow::Result<()> {
    let auth_state = identity_web::AuthState::new();

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&std::env::var("DATABASE_URL")?)
        .await?;

    println!("Connected to Supabase Postgres");

    let storage = SupabaseStorage::new(
        std::env::var("SUPABASE_URL")?,
        std::env::var("SUPABASE_SERVICE_ROLE_KEY")?,
        std::env::var("SUPABASE_BUCKET")?,
    );

    let state = AppState {
        auth: auth_state,
        db: pool,
        storage,
    };

    let static_files = ServeDir::new("web").append_index_html_on_directories(true);

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/api/identity/evm/nonce", post(evm_nonce_handler_app))
        .route("/api/identity/evm/verify", post(evm_verify_handler_app))
        .route("/api/identity/sol/nonce", post(sol_nonce_handler_app))
        .route("/api/identity/sol/verify", post(sol_verify_handler_app))
        .route("/api/public/verify", post(public_verify_handler))
        .route("/api/public/envelope/:token", get(public_envelope_handler))
        .route("/api/public/envelope/:token/blob", get(public_envelope_blob_handler))
        .route("/api/public/envelope/:token/sign", post(public_envelope_sign_handler))
        .route("/api/agent/register", post(register_agent_handler))
        .route("/api/overview", get(overview_handler))
        .route("/api/doc/list", get(list_docs_handler))
        .route("/api/doc/:id/events", get(list_doc_events_handler))
        .route("/api/doc/:id/evidence", get(export_doc_evidence_handler))
        .route("/api/doc/:id/evidence/anchor", post(anchor_evidence_bundle_handler))
        .route("/api/doc/:id/policy", get(get_document_policy_handler).post(set_document_policy_handler))
        .route("/api/doc/upload", post(upload_doc_handler))
        .route("/api/doc/:id/version", post(create_document_version_handler))
        .route("/api/doc/:id/review", get(review_doc_handler))
        .route("/api/doc/:id/blob", get(doc_blob_handler))
        .route("/api/doc/:id/download", get(download_doc_handler))
        .route("/api/doc/:id/sign", post(sign_doc_handler))
        .route("/api/doc/:id/delete", post(delete_doc_handler))
        .route("/api/doc/:id/share", post(share_doc_handler))
        .route("/api/agent/doc/:id/review", get(agent_review_doc_handler))
        .route("/api/agent/doc/:id/sign", post(agent_sign_doc_handler))
        .route("/api/agent/doc/:id/version", post(agent_version_doc_handler))
        .route("/api/inbox", get(list_inbox_handler))
        .route("/auth/session", get(session_info_handler))
        .route("/auth/logout", post(logout_handler))
        .nest_service("/", static_files)
        .with_state(state)
        .layer(CorsLayer::permissive());

    let addr: std::net::SocketAddr = "0.0.0.0:4100".parse().unwrap();

    println!("Server running at http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// ================================================================
// BASIC
// ================================================================

async fn health_handler() -> &'static str {
    "OK"
}

fn wallet_can_access_document(owner_wallet: &str, actor_wallet: &str, is_shared_with_actor: bool) -> bool {
    owner_wallet.eq_ignore_ascii_case(actor_wallet) || is_shared_with_actor
}

fn build_share_event_payload(
    recipient_wallet: Option<&str>,
    note: Option<&str>,
    envelope_id: uuid::Uuid,
    signature: Option<&str>,
    recipient_name: Option<&str>,
    recipient_email: Option<&str>,
    recipient_phone: Option<&str>,
    access_token: Option<&str>,
) -> serde_json::Value {
    json!({
        "recipient_wallet": recipient_wallet,
        "recipient_name": recipient_name,
        "note": note,
        "envelope_id": envelope_id,
        "signature": signature,
        "recipient_email": recipient_email,
        "recipient_phone": recipient_phone,
        "access_token": access_token
    })
}

fn require_wallet_from_headers(st: &AppState, headers: &HeaderMap) -> Result<String, AppError> {
    Ok(require_session_from_headers(st, headers)?.wallet)
}

fn require_session_from_headers(st: &AppState, headers: &HeaderMap) -> Result<WalletSession, AppError> {
    let sid = headers
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Auth("Missing x-session-id".into()))?;

    st
        .auth
        .get_session(sid)
        .ok_or_else(|| AppError::Auth("Invalid or expired session".into()))
}

fn token_hash_hex(token: &str) -> String {
    hex::encode(pqc_sha3::sha3_256_bytes(token.as_bytes()))
}

fn default_document_policy() -> serde_json::Value {
    json!({
        "allow_guest_sign": true,
        "allow_agent_review": true,
        "allow_agent_sign": false,
        "require_human_countersign": true,
        "allowed_agent_ids": [],
        "allowed_wallet_signers": []
    })
}

async fn load_document_policy(
    db: &PgPool,
    doc_id: uuid::Uuid,
    owner_wallet: &str,
) -> Result<serde_json::Value, AppError> {
    let row = sqlx::query(
        "select policy_json from document_policies where doc_id = $1 and owner_wallet = $2",
    )
    .bind(doc_id)
    .bind(owner_wallet)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(row.map(|row| row.get::<serde_json::Value, _>("policy_json")).unwrap_or_else(default_document_policy))
}

async fn require_agent_from_headers(
    st: &AppState,
    headers: &HeaderMap,
) -> Result<AgentIdentityRecord, AppError> {
    let token = headers
        .get("x-agent-token")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::Auth("Missing x-agent-token".into()))?;

    let row = sqlx::query(
        r#"
        select id, owner_wallet, label, provider, model, capabilities_json
        from agent_identities
        where api_token_hash = $1
          and is_active = true
        "#,
    )
    .bind(token_hash_hex(token))
    .fetch_optional(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let Some(row) = row else {
        return Err(AppError::Auth("Invalid or inactive agent token".into()));
    };

    Ok(AgentIdentityRecord {
        id: row.get("id"),
        owner_wallet: row.get("owner_wallet"),
        label: row.get("label"),
        provider: row.get("provider"),
        model: row.get("model"),
        capabilities_json: row.get("capabilities_json"),
    })
}

fn agent_allowed(policy: &serde_json::Value, key: &str, agent: &AgentIdentityRecord) -> bool {
    if !policy.get(key).and_then(|value| value.as_bool()).unwrap_or(false) {
        return false;
    }

    let allowed_ids = policy
        .get("allowed_agent_ids")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();

    if allowed_ids.is_empty() {
        return true;
    }

    allowed_ids
        .iter()
        .filter_map(|value| value.as_str())
        .any(|value| value.eq_ignore_ascii_case(&agent.id.to_string()))
}

async fn load_document_access_record(
    db: &PgPool,
    doc_id: uuid::Uuid,
    actor_wallet: &str,
) -> Result<DocumentAccessRecord, AppError> {
    let row = sqlx::query(
        r#"
        select
            d.id,
            d.storage_path,
            d.owner_wallet,
            d.label,
            d.hash_hex,
            d.version,
            d.mime_type,
            d.parent_id,
            d.arweave_tx,
            coalesce(d.encryption_mode, 'plaintext_server_managed') as encryption_mode,
            d.ciphertext_hash_hex,
            exists (
              select 1
              from document_shares s
              where s.doc_id = d.id and s.recipient_wallet = $2
            ) as shared_with_actor
        from documents d
        where d.id = $1
          and d.is_deleted = false
        "#,
    )
    .bind(doc_id)
    .bind(actor_wallet)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let Some(row) = row else {
        return Err(AppError::NotFound("Document not found".into()));
    };

    let owner_wallet: String = row.get("owner_wallet");
    let shared_with_actor: bool = row.get("shared_with_actor");

    if !wallet_can_access_document(&owner_wallet, actor_wallet, shared_with_actor) {
        return Err(AppError::NotFound("Document not found".into()));
    }

    Ok(DocumentAccessRecord {
        id: row.get("id"),
        storage_path: row.get("storage_path"),
        owner_wallet,
        label: row.get("label"),
        hash_hex: row.get("hash_hex"),
        version: row.get("version"),
        mime_type: row
            .get::<Option<String>, _>("mime_type")
            .unwrap_or_else(|| "application/octet-stream".to_string()),
        parent_id: row.get("parent_id"),
        arweave_tx: row.get("arweave_tx"),
        encryption_mode: row.get("encryption_mode"),
        ciphertext_hash_hex: row.get("ciphertext_hash_hex"),
    })
}

fn bool_from_form_text(value: &str) -> bool {
    matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

fn auto_anchor_enabled() -> bool {
    std::env::var("ARWEAVE_AUTO_ANCHOR")
        .map(|value| bool_from_form_text(&value))
        .unwrap_or(false)
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name).and_then(|value| value.to_str().ok()).map(ToOwned::to_owned)
}

fn multipart_error(context: &str, err: impl std::fmt::Display) -> AppError {
    AppError::BadRequest(format!("{context}: {err}"))
}

fn session_actor_json(session: &WalletSession) -> serde_json::Value {
    json!({
        "kind": "human_wallet",
        "wallet": session.wallet,
        "chain": session.chain
    })
}

fn public_actor_json(envelope_id: uuid::Uuid) -> serde_json::Value {
    json!({
        "kind": "public_envelope",
        "envelope_id": envelope_id
    })
}

fn agent_actor_json(agent: &AgentIdentityRecord) -> serde_json::Value {
    json!({
        "kind": "agent",
        "agent_id": agent.id,
        "owner_wallet": agent.owner_wallet,
        "label": agent.label,
        "provider": agent.provider,
        "model": agent.model,
        "capabilities": agent.capabilities_json
    })
}

fn custody_payload(base: serde_json::Value, session: &WalletSession, headers: &HeaderMap) -> serde_json::Value {
    let mut payload = match base {
        serde_json::Value::Object(map) => map,
        other => {
            let mut map = serde_json::Map::new();
            map.insert("data".into(), other);
            map
        }
    };

    payload.insert("recorded_at".into(), json!(chrono::Utc::now()));
    payload.insert("actor".into(), session_actor_json(session));
    payload.insert("actor_chain".into(), json!(session.chain));
    payload.insert("user_agent".into(), json!(header_value(headers, "user-agent")));
    payload.insert("origin".into(), json!(header_value(headers, "origin")));
    payload.insert("referer".into(), json!(header_value(headers, "referer")));
    payload.insert("x_forwarded_for".into(), json!(header_value(headers, "x-forwarded-for")));
    payload.insert("x_real_ip".into(), json!(header_value(headers, "x-real-ip")));

    serde_json::Value::Object(payload)
}

fn public_custody_payload(base: serde_json::Value, headers: &HeaderMap) -> serde_json::Value {
    let mut payload = match base {
        serde_json::Value::Object(map) => map,
        other => {
            let mut map = serde_json::Map::new();
            map.insert("data".into(), other);
            map
        }
    };

    payload.insert("recorded_at".into(), json!(chrono::Utc::now()));
    payload.insert("actor".into(), public_actor_json(uuid::Uuid::nil()));
    payload.insert("actor_chain".into(), json!("public-envelope"));
    payload.insert("user_agent".into(), json!(header_value(headers, "user-agent")));
    payload.insert("origin".into(), json!(header_value(headers, "origin")));
    payload.insert("referer".into(), json!(header_value(headers, "referer")));
    payload.insert("x_forwarded_for".into(), json!(header_value(headers, "x-forwarded-for")));
    payload.insert("x_real_ip".into(), json!(header_value(headers, "x-real-ip")));

    serde_json::Value::Object(payload)
}

fn public_custody_payload_for_envelope(
    base: serde_json::Value,
    envelope_id: uuid::Uuid,
    headers: &HeaderMap,
) -> serde_json::Value {
    let mut payload = match public_custody_payload(base, headers) {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    payload.insert("actor".into(), public_actor_json(envelope_id));
    serde_json::Value::Object(payload)
}

fn agent_custody_payload(
    base: serde_json::Value,
    agent: &AgentIdentityRecord,
    headers: &HeaderMap,
) -> serde_json::Value {
    let mut payload = match base {
        serde_json::Value::Object(map) => map,
        other => {
            let mut map = serde_json::Map::new();
            map.insert("data".into(), other);
            map
        }
    };

    payload.insert("recorded_at".into(), json!(chrono::Utc::now()));
    payload.insert("actor".into(), agent_actor_json(agent));
    payload.insert("actor_chain".into(), json!("agent-api"));
    payload.insert("user_agent".into(), json!(header_value(headers, "user-agent")));
    payload.insert("origin".into(), json!(header_value(headers, "origin")));
    payload.insert("referer".into(), json!(header_value(headers, "referer")));
    payload.insert("x_forwarded_for".into(), json!(header_value(headers, "x-forwarded-for")));
    payload.insert("x_real_ip".into(), json!(header_value(headers, "x-real-ip")));

    serde_json::Value::Object(payload)
}

fn internal_blob_url(doc_id: uuid::Uuid) -> String {
    format!("/api/doc/{doc_id}/blob")
}

fn public_blob_url(token: &str) -> String {
    format!("/api/public/envelope/{token}/blob")
}

fn is_office_mime_type(mime_type: &str) -> bool {
    matches!(
        mime_type,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            | "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            | "application/msword"
            | "application/vnd.ms-excel"
            | "application/vnd.ms-powerpoint"
    )
}

fn onlyoffice_editor_enabled() -> bool {
    std::env::var("ONLYOFFICE_DOCUMENT_SERVER_URL")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

fn base64_standard(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn build_document_envelope(
    owner_wallet: &str,
    document_id: uuid::Uuid,
    label: Option<&str>,
    mime_type: &str,
    plaintext: &[u8],
) -> Result<(Vec<u8>, String), AppError> {
    let keys = load_or_create_mlkem_keypair(owner_wallet)
        .map_err(|e| AppError::Crypto(format!("mlkem keystore: {e}")))?;
    let doc = CanonicalDocumentV1::from_plaintext(
        document_id.to_string(),
        plaintext,
        label.map(ToOwned::to_owned),
        Some(mime_type.to_string()),
    );
    let created_at = time::OffsetDateTime::now_utc().unix_timestamp();
    let (envelope, _) = DocumentEnvelopeV1::create_mlkem_owner(
        owner_wallet.to_string(),
        &keys.pk_b64,
        created_at,
        doc,
        plaintext,
    )
    .map_err(AppError::Crypto)?;
    let canonical = canonical_json(&envelope);
    let ciphertext_hash_hex = hex::encode(pqc_sha3::sha3_256_bytes(&canonical));
    Ok((canonical, ciphertext_hash_hex))
}

fn decrypt_document_envelope(owner_wallet: &str, encrypted_bytes: &[u8]) -> Result<Vec<u8>, AppError> {
    let keys = load_or_create_mlkem_keypair(owner_wallet)
        .map_err(|e| AppError::Crypto(format!("mlkem keystore: {e}")))?;
    let envelope: DocumentEnvelopeV1 = serde_json::from_slice(encrypted_bytes)
        .map_err(|e| AppError::Crypto(format!("envelope parse: {e}")))?;
    envelope
        .decrypt_for_owner_mlkem(&keys.sk_b64)
        .map_err(AppError::Crypto)
}

async fn load_document_bytes_for_access(
    st: &AppState,
    access: &DocumentAccessRecord,
) -> Result<DocumentBytesResponse, AppError> {
    let stored = st
        .storage
        .download_bytes(&access.storage_path)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let bytes = if access.encryption_mode == "pq_envelope_server_managed" {
        decrypt_document_envelope(&access.owner_wallet, &stored)?
    } else {
        stored
    };

    Ok(DocumentBytesResponse {
        bytes,
        mime_type: access.mime_type.clone(),
        label: access.label.clone(),
        hash_hex: access.hash_hex.clone(),
        version: access.version,
        parent_id: access.parent_id,
        arweave_tx: access.arweave_tx.clone(),
        encryption_mode: access.encryption_mode.clone(),
    })
}

fn document_sign_message(doc_id: uuid::Uuid, hash_hex: &str, wallet: &str, version: i32) -> String {
    format!(
        "TIDBIT Document Attestation\n\
Document ID: {doc_id}\n\
Hash: {hash_hex}\n\
Action: SIGN\n\
Wallet: {wallet}\n\
Version: {version}"
    )
}

fn public_envelope_sign_message(
    envelope_id: uuid::Uuid,
    doc_id: uuid::Uuid,
    hash_hex: &str,
    signer_identity: &str,
    version: i32,
) -> String {
    format!(
        "TIDBIT Public Envelope Signature\n\
Envelope ID: {envelope_id}\n\
Document ID: {doc_id}\n\
Hash: {hash_hex}\n\
Signer: {signer_identity}\n\
Version: {version}"
    )
}

fn public_app_url() -> String {
    std::env::var("PUBLIC_APP_URL").unwrap_or_else(|_| "http://127.0.0.1:4100".to_string())
}

fn envelope_signing_url(access_token: &str) -> String {
    format!("{}/public-sign.html?token={access_token}", public_app_url())
}

fn redact_token(token: Option<&str>) -> Option<String> {
    token.map(|value| {
        if value.len() <= 8 {
            value.to_string()
        } else {
            format!("{}...{}", &value[..4], &value[value.len() - 4..])
        }
    })
}

fn normalize_annotation_fields(fields: Option<Vec<SignerAnnotationField>>) -> Vec<SignerAnnotationField> {
    fields
        .unwrap_or_default()
        .into_iter()
        .map(|field| SignerAnnotationField {
            kind: field.kind.trim().to_string(),
            label: field.label.map(|value| value.trim().to_string()).filter(|value| !value.is_empty()),
            value: field.value.map(|value| value.trim().to_string()).filter(|value| !value.is_empty()),
            x_pct: field.x_pct.clamp(0.0, 100.0),
            y_pct: field.y_pct.clamp(0.0, 100.0),
        })
        .filter(|field| !field.kind.is_empty())
        .collect()
}

fn invite_email_subject(label: Option<&str>) -> String {
    match label {
        Some(value) if !value.trim().is_empty() => format!("Signature request for {}", value.trim()),
        _ => "Signature request from TIDBIT-share-WEAVE".to_string(),
    }
}

fn invite_message_text(
    label: Option<&str>,
    doc_id: uuid::Uuid,
    hash_hex: &str,
    envelope_id: uuid::Uuid,
    recipient_name: Option<&str>,
    signing_url: &str,
) -> String {
    format!(
        "TIDBIT-share-WEAVE signature request\n\nDocument: {}\nDocument ID: {doc_id}\nHash: {hash_hex}\nEnvelope ID: {envelope_id}\nRecipient: {}\nOpen secure signing link: {signing_url}",
        label.unwrap_or("Untitled document"),
        recipient_name.unwrap_or("signer"),
    )
}

fn invite_message_html(
    label: Option<&str>,
    doc_id: uuid::Uuid,
    hash_hex: &str,
    envelope_id: uuid::Uuid,
    recipient_name: Option<&str>,
    signing_url: &str,
) -> String {
    format!(
        "<div style=\"font-family:Arial,sans-serif;line-height:1.6\"><h2>TIDBIT-share-WEAVE signature request</h2><p><strong>Document:</strong> {}</p><p><strong>Document ID:</strong> {doc_id}<br><strong>Hash:</strong> {hash_hex}<br><strong>Envelope ID:</strong> {envelope_id}<br><strong>Recipient:</strong> {}</p><p><a href=\"{signing_url}\">Open secure signing link</a></p></div>",
        label.unwrap_or("Untitled document"),
        recipient_name.unwrap_or("signer"),
    )
}

async fn dispatch_share_deliveries(
    recipient_email: Option<&str>,
    recipient_phone: Option<&str>,
    label: Option<&str>,
    doc_id: uuid::Uuid,
    hash_hex: &str,
    envelope_id: uuid::Uuid,
    recipient_name: Option<&str>,
    signing_url: &str,
) -> (Vec<DeliveryOutcome>, Vec<String>) {
    let subject = invite_email_subject(label);
    let text_body = invite_message_text(label, doc_id, hash_hex, envelope_id, recipient_name, signing_url);
    let html_body = invite_message_html(label, doc_id, hash_hex, envelope_id, recipient_name, signing_url);
    let mut outcomes = Vec::new();
    let mut errors = Vec::new();

    if let Some(email) = recipient_email {
        match send_email_invite(email, &subject, &text_body, &html_body).await {
            Ok(Some(outcome)) => outcomes.push(outcome),
            Ok(None) => {}
            Err(err) => errors.push(err.to_string()),
        }
    }

    if let Some(phone) = recipient_phone {
        match send_sms_invite(phone, &text_body).await {
            Ok(Some(outcome)) => outcomes.push(outcome),
            Ok(None) => {}
            Err(err) => errors.push(err.to_string()),
        }
    }

    (outcomes, errors)
}

async fn create_document_record(
    st: &AppState,
    owner_wallet: &str,
    bytes: &[u8],
    label: Option<String>,
    mime_type: String,
    parent_id: Option<uuid::Uuid>,
    parent_version: Option<i32>,
    anchor_to_arweave: bool,
) -> Result<CreatedDocumentRecord, AppError> {
    let hash_hex = hex::encode(pqc_sha3::sha3_256_bytes(bytes));

    let existing = sqlx::query(
        "select id from documents where owner_wallet = $1 and hash_hex = $2 and is_deleted = false",
    )
    .bind(owner_wallet)
    .bind(&hash_hex)
    .fetch_optional(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    if let Some(row) = existing {
        let existing_id: uuid::Uuid = row.get("id");
        return Err(AppError::BadRequest(format!(
            "An active document with the same content already exists: {existing_id}"
        )));
    }

    let id = uuid::Uuid::new_v4();
    let version = parent_version.map(|value| value + 1).unwrap_or(1);
    let (stored_bytes, ciphertext_hash_hex) =
        build_document_envelope(owner_wallet, id, label.as_deref(), &mime_type, bytes)?;
    let storage_path = st
        .storage
        .upload_bytes(
            owner_wallet,
            &id.to_string(),
            version,
            &stored_bytes,
            "application/tidbit-envelope+json",
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let arweave_tx = if anchor_to_arweave {
        Some(
            crate::arweave::anchor_hash_to_arweave(&hash_hex)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?
                .tx_id,
        )
    } else {
        None
    };

    sqlx::query(
        r#"insert into documents
        (id, owner_wallet, hash_hex, label, file_size, mime_type, storage_path, version, parent_id, arweave_tx, is_deleted, encryption_mode, ciphertext_hash_hex)
        values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,false,$11,$12)"#,
    )
    .bind(id)
    .bind(owner_wallet)
    .bind(&hash_hex)
    .bind(&label)
    .bind(bytes.len() as i64)
    .bind(&mime_type)
    .bind(&storage_path)
    .bind(version)
    .bind(parent_id)
    .bind(&arweave_tx)
    .bind("pq_envelope_server_managed")
    .bind(&ciphertext_hash_hex)
    .execute(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(CreatedDocumentRecord {
        id,
        hash_hex,
        label,
        storage_path,
        version,
        mime_type,
        parent_id,
        arweave_tx,
    })
}

// ================================================================
// AUTH
// ================================================================

async fn evm_nonce_handler_app(State(st): State<AppState>) -> Json<EvmNonceResponse> {
    identity_web::evm_nonce_handler(State(st.auth.clone())).await
}

async fn evm_verify_handler_app(
    State(st): State<AppState>,
    Json(body): Json<EvmVerifyRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    identity_web::evm_verify_handler(State(st.auth.clone()), Json(body)).await
}

async fn sol_nonce_handler_app(
    State(st): State<AppState>,
) -> Json<identity_web::sol::SolNonceResponse> {
    identity_web::sol::sol_nonce_handler(State(st.auth.clone())).await
}

async fn sol_verify_handler_app(
    State(st): State<AppState>,
    Json(body): Json<identity_web::sol::SolVerifyRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let res = identity_web::sol::sol_verify_handler(State(st.auth.clone()), Json(body))
        .await
        .map_err(|(_, message)| AppError::Auth(message))?;

    Ok(Json(json!({
        "ok": true,
        "wallet": res.address,
        "chain": "sol"
    })))
}

// ================================================================
// DOCUMENT LIST
// ================================================================

async fn list_docs_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    let wallet = require_wallet_from_headers(&st, &headers)?;

    let rows = sqlx::query(
        r#"
        select id, owner_wallet, hash_hex, label, created_at, version, mime_type, parent_id, arweave_tx
        from documents
        where owner_wallet = $1 and is_deleted = false
        order by created_at desc
        "#,
    )
    .bind(wallet)
    .fetch_all(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| {
                json!({
                    "id": r.get::<uuid::Uuid,_>("id"),
                    "owner_wallet": r.get::<String,_>("owner_wallet"),
                    "hash_hex": r.get::<String,_>("hash_hex"),
                    "label": r.get::<Option<String>,_>("label"),
                    "created_at": r.get::<chrono::DateTime<chrono::Utc>,_>("created_at"),
                    "version": r.get::<i32,_>("version"),
                    "mime_type": r.get::<Option<String>,_>("mime_type"),
                    "parent_id": r.get::<Option<uuid::Uuid>,_>("parent_id"),
                    "arweave_tx": r.get::<Option<String>,_>("arweave_tx")
                })
            })
            .collect(),
    ))
}

async fn overview_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let wallet = require_wallet_from_headers(&st, &headers)?;

    let counts = sqlx::query(
        r#"
        select
            count(*) filter (where is_deleted = false) as total_docs,
            count(*) filter (where is_deleted = false and parent_id is not null) as total_versions,
            count(*) filter (where is_deleted = false and arweave_tx is not null) as anchored_docs
        from documents
        where owner_wallet = $1
        "#,
    )
    .bind(&wallet)
    .fetch_one(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let share_counts = sqlx::query(
        r#"
        select count(*) as total_shares
        from document_shares
        where sender_wallet = $1
        "#,
    )
    .bind(&wallet)
    .fetch_one(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let recent_docs = sqlx::query(
        r#"
        select id, label, hash_hex, version, mime_type, arweave_tx, created_at
        from documents
        where owner_wallet = $1
          and is_deleted = false
        order by created_at desc
        limit 8
        "#,
    )
    .bind(&wallet)
    .fetch_all(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let recent_events = sqlx::query(
        r#"
        select
            e.id,
            e.doc_id,
            e.event_type,
            e.actor_wallet,
            e.payload,
            e.created_at,
            d.label
        from document_events e
        join documents d on d.id = e.doc_id
        where d.owner_wallet = $1
        order by e.created_at desc
        limit 12
        "#,
    )
    .bind(&wallet)
    .fetch_all(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({
        "counts": {
            "total_docs": counts.get::<i64,_>("total_docs"),
            "total_versions": counts.get::<i64,_>("total_versions"),
            "anchored_docs": counts.get::<i64,_>("anchored_docs"),
            "total_shares": share_counts.get::<i64,_>("total_shares")
        },
        "recent_docs": recent_docs.into_iter().map(|row| json!({
            "id": row.get::<uuid::Uuid,_>("id"),
            "label": row.get::<Option<String>,_>("label"),
            "hash_hex": row.get::<String,_>("hash_hex"),
            "version": row.get::<i32,_>("version"),
            "mime_type": row.get::<String,_>("mime_type"),
            "arweave_tx": row.get::<Option<String>,_>("arweave_tx"),
            "created_at": row.get::<chrono::DateTime<chrono::Utc>,_>("created_at")
        })).collect::<Vec<_>>(),
        "recent_events": recent_events.into_iter().map(|row| json!({
            "id": row.get::<uuid::Uuid,_>("id"),
            "doc_id": row.get::<uuid::Uuid,_>("doc_id"),
            "event_type": row.get::<String,_>("event_type"),
            "actor_wallet": row.get::<String,_>("actor_wallet"),
            "payload": row.get::<serde_json::Value,_>("payload"),
            "created_at": row.get::<chrono::DateTime<chrono::Utc>,_>("created_at"),
            "label": row.get::<Option<String>,_>("label")
        })).collect::<Vec<_>>()
    })))
}

// ================================================================
// DOCUMENT EVENTS
// ================================================================

async fn list_doc_events_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    let wallet = require_wallet_from_headers(&st, &headers)?;

    let access_row = sqlx::query(
        r#"
        select
            d.owner_wallet,
            exists (
              select 1
              from document_shares s
              where s.doc_id = d.id and s.recipient_wallet = $2
            ) as shared_with_actor
        from documents d
        where d.id = $1
          and d.is_deleted = false
        "#,
    )
    .bind(id)
        .bind(&wallet)
        .fetch_optional(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let Some(access_row) = access_row else {
        return Err(AppError::NotFound("Document not found".into()));
    };

    let owner_wallet: String = access_row.get("owner_wallet");
    let shared_with_actor: bool = access_row.get("shared_with_actor");

    if !wallet_can_access_document(&owner_wallet, &wallet, shared_with_actor) {
        return Err(AppError::NotFound("Document not found".into()));
    }

    let rows = sqlx::query(
        r#"
        select id, event_type, actor_wallet, payload, created_at
        from document_events
        where doc_id = $1
        order by created_at desc
        "#,
    )
    .bind(id)
    .fetch_all(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| {
                json!({
                    "id": r.get::<uuid::Uuid,_>("id"),
                    "event_type": r.get::<String,_>("event_type"),
                    "actor_wallet": r.get::<String,_>("actor_wallet"),
                    "payload": r.get::<serde_json::Value,_>("payload"),
                    "created_at": r.get::<chrono::DateTime<chrono::Utc>,_>("created_at")
                })
            })
            .collect(),
    ))
}

async fn export_doc_evidence_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let wallet = require_wallet_from_headers(&st, &headers)?;
    let access = load_document_access_record(&st.db, id, &wallet).await?;

    let doc_row = sqlx::query(
        r#"
        select id, owner_wallet, hash_hex, label, file_size, mime_type, storage_path, version, parent_id, arweave_tx, created_at
        from documents
        where id = $1
          and is_deleted = false
        "#,
    )
    .bind(id)
    .fetch_one(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let mut lineage = Vec::new();
    let mut cursor: Option<uuid::Uuid> = Some(id);

    while let Some(current_id) = cursor {
        let Some(row) = sqlx::query(
            r#"
            select id, hash_hex, label, version, parent_id, arweave_tx, created_at
            from documents
            where id = $1
            "#,
        )
        .bind(current_id)
        .fetch_optional(&st.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        else {
            break;
        };

        cursor = row.get("parent_id");
        lineage.push(json!({
            "id": row.get::<uuid::Uuid,_>("id"),
            "hash_hex": row.get::<String,_>("hash_hex"),
            "label": row.get::<Option<String>,_>("label"),
            "version": row.get::<i32,_>("version"),
            "parent_id": row.get::<Option<uuid::Uuid>,_>("parent_id"),
            "arweave_tx": row.get::<Option<String>,_>("arweave_tx"),
            "created_at": row.get::<chrono::DateTime<chrono::Utc>,_>("created_at")
        }));
    }

    let events = sqlx::query(
        r#"
        select id, event_type, actor_wallet, payload, created_at
        from document_events
        where doc_id = $1
        order by created_at asc
        "#,
    )
    .bind(id)
    .fetch_all(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let shares = sqlx::query(
        r#"
        select
            id,
            sender_wallet,
            recipient_wallet,
            recipient_name,
            recipient_email,
            recipient_phone,
            envelope_id,
            note,
            status,
            viewed_at,
            signed_at,
            completed_at,
            signer_name,
            signer_email,
            signer_title,
            signer_org,
            signer_wallet,
            sign_reason,
            completion_signature_type,
            annotation_json,
            delivery_json,
            access_token,
            created_at
        from document_shares
        where doc_id = $1
        order by created_at asc
        "#,
    )
    .bind(id)
    .fetch_all(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({
        "exported_at": chrono::Utc::now(),
        "requested_by": wallet,
        "document": {
            "id": doc_row.get::<uuid::Uuid,_>("id"),
            "owner_wallet": doc_row.get::<String,_>("owner_wallet"),
            "hash_hex": doc_row.get::<String,_>("hash_hex"),
            "label": doc_row.get::<Option<String>,_>("label"),
            "file_size": doc_row.get::<i64,_>("file_size"),
            "mime_type": doc_row.get::<String,_>("mime_type"),
            "storage_path": doc_row.get::<String,_>("storage_path"),
            "version": doc_row.get::<i32,_>("version"),
            "parent_id": doc_row.get::<Option<uuid::Uuid>,_>("parent_id"),
            "arweave_tx": doc_row.get::<Option<String>,_>("arweave_tx"),
            "created_at": doc_row.get::<chrono::DateTime<chrono::Utc>,_>("created_at")
        },
        "access": {
            "owner_wallet": access.owner_wallet,
            "version": access.version,
            "mime_type": access.mime_type,
            "parent_id": access.parent_id,
            "arweave_tx": access.arweave_tx
        },
        "lineage": lineage,
        "shares": shares.into_iter().map(|row| json!({
            "id": row.get::<uuid::Uuid,_>("id"),
            "sender_wallet": row.get::<String,_>("sender_wallet"),
            "recipient_wallet": row.get::<Option<String>,_>("recipient_wallet"),
            "recipient_name": row.get::<Option<String>,_>("recipient_name"),
            "recipient_email": row.get::<Option<String>,_>("recipient_email"),
            "recipient_phone": row.get::<Option<String>,_>("recipient_phone"),
            "envelope_id": row.get::<uuid::Uuid,_>("envelope_id"),
            "note": row.get::<Option<String>,_>("note"),
            "status": row.get::<String,_>("status"),
            "viewed_at": row.get::<Option<chrono::DateTime<chrono::Utc>>,_>("viewed_at"),
            "signed_at": row.get::<Option<chrono::DateTime<chrono::Utc>>,_>("signed_at"),
            "completed_at": row.get::<Option<chrono::DateTime<chrono::Utc>>,_>("completed_at"),
            "signer_name": row.get::<Option<String>,_>("signer_name"),
            "signer_email": row.get::<Option<String>,_>("signer_email"),
            "signer_title": row.get::<Option<String>,_>("signer_title"),
            "signer_org": row.get::<Option<String>,_>("signer_org"),
            "signer_wallet": row.get::<Option<String>,_>("signer_wallet"),
            "sign_reason": row.get::<Option<String>,_>("sign_reason"),
            "completion_signature_type": row.get::<Option<String>,_>("completion_signature_type"),
            "annotation_json": row.get::<serde_json::Value,_>("annotation_json"),
            "delivery_json": row.get::<serde_json::Value,_>("delivery_json"),
            "access_token_redacted": redact_token(row.get::<Option<String>,_>("access_token").as_deref()),
            "created_at": row.get::<chrono::DateTime<chrono::Utc>,_>("created_at")
        })).collect::<Vec<_>>(),
        "events": events.into_iter().map(|row| json!({
            "id": row.get::<uuid::Uuid,_>("id"),
            "event_type": row.get::<String,_>("event_type"),
            "actor_wallet": row.get::<String,_>("actor_wallet"),
            "payload": row.get::<serde_json::Value,_>("payload"),
            "created_at": row.get::<chrono::DateTime<chrono::Utc>,_>("created_at")
        })).collect::<Vec<_>>()
    })))
}

async fn anchor_evidence_bundle_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let session = require_session_from_headers(&st, &headers)?;
    let wallet = session.wallet.clone();
    let doc = load_document_access_record(&st.db, id, &wallet).await?;

    if !doc.owner_wallet.eq_ignore_ascii_case(&wallet) {
        return Err(AppError::Forbidden("Only the owner can anchor evidence bundles".into()));
    }

    let evidence = export_doc_evidence_handler(State(st.clone()), headers.clone(), Path(id)).await?;
    let evidence_json = evidence.0;
    let evidence_bytes =
        serde_json::to_vec(&evidence_json).map_err(|e| AppError::Internal(e.to_string()))?;
    let evidence_hash_hex = hex::encode(pqc_sha3::sha3_256_bytes(&evidence_bytes));
    let tx_id = crate::arweave::anchor_hash_to_arweave(&evidence_hash_hex)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .tx_id;

    sqlx::query("update documents set evidence_bundle_arweave_tx = $2 where id = $1")
        .bind(id)
        .bind(&tx_id)
        .execute(&st.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    sqlx::query(
        "insert into document_events (doc_id, actor_wallet, event_type, payload) values ($1,$2,'EVIDENCE_ANCHORED',$3)",
    )
    .bind(id)
    .bind(&wallet)
    .bind(custody_payload(
        json!({
            "evidence_hash_hex": evidence_hash_hex,
            "arweave_tx": tx_id,
            "document_hash_hex": doc.hash_hex,
            "version": doc.version
        }),
        &session,
        &headers,
    ))
    .execute(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({
        "ok": true,
        "doc_id": id,
        "evidence_hash_hex": evidence_hash_hex,
        "arweave_tx": tx_id
    })))
}

async fn get_document_policy_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let wallet = require_wallet_from_headers(&st, &headers)?;
    let doc = load_document_access_record(&st.db, id, &wallet).await?;

    if !doc.owner_wallet.eq_ignore_ascii_case(&wallet) {
        return Err(AppError::Forbidden("Only the owner can view document policy".into()));
    }

    let policy = load_document_policy(&st.db, id, &wallet).await?;
    Ok(Json(json!({
        "doc_id": id,
        "owner_wallet": wallet,
        "policy_json": policy
    })))
}

async fn set_document_policy_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<DocumentPolicyUpdateRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let session = require_session_from_headers(&st, &headers)?;
    let wallet = session.wallet.clone();
    let doc = load_document_access_record(&st.db, id, &wallet).await?;

    if !doc.owner_wallet.eq_ignore_ascii_case(&wallet) {
        return Err(AppError::Forbidden("Only the owner can update document policy".into()));
    }

    sqlx::query(
        r#"
        insert into document_policies (doc_id, owner_wallet, policy_json)
        values ($1, $2, $3)
        on conflict (doc_id)
        do update set
            owner_wallet = excluded.owner_wallet,
            policy_json = excluded.policy_json,
            updated_at = now()
        "#,
    )
    .bind(id)
    .bind(&wallet)
    .bind(&body.policy_json)
    .execute(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    sqlx::query(
        "insert into document_events (doc_id, actor_wallet, event_type, payload) values ($1,$2,'POLICY_UPDATED',$3)",
    )
    .bind(id)
    .bind(&wallet)
    .bind(custody_payload(
        json!({
            "policy_json": body.policy_json
        }),
        &session,
        &headers,
    ))
    .execute(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({
        "ok": true,
        "doc_id": id,
        "policy_json": body.policy_json
    })))
}

async fn register_agent_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AgentRegisterRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let session = require_session_from_headers(&st, &headers)?;
    let wallet = session.wallet.clone();
    let token = format!("agt_{}", uuid::Uuid::new_v4().simple());
    let token_hash = token_hash_hex(&token);
    let capabilities = serde_json::to_value(body.capabilities.unwrap_or_default())
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let row = sqlx::query(
        r#"
        insert into agent_identities (owner_wallet, label, provider, model, capabilities_json, api_token_hash)
        values ($1,$2,$3,$4,$5,$6)
        returning id
        "#,
    )
    .bind(&wallet)
    .bind(body.label.trim())
    .bind(body.provider.as_deref())
    .bind(body.model.as_deref())
    .bind(&capabilities)
    .bind(&token_hash)
    .fetch_one(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({
        "ok": true,
        "agent_id": row.get::<uuid::Uuid,_>("id"),
        "owner_wallet": wallet,
        "token": token,
        "label": body.label.trim(),
        "provider": body.provider,
        "model": body.model,
        "capabilities": capabilities
    })))
}

async fn agent_review_doc_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let agent = require_agent_from_headers(&st, &headers).await?;
    let doc = load_document_access_record(&st.db, id, &agent.owner_wallet).await?;

    if !doc.owner_wallet.eq_ignore_ascii_case(&agent.owner_wallet) {
        return Err(AppError::Forbidden("Agent may only review owner-controlled documents".into()));
    }

    let policy = load_document_policy(&st.db, id, &doc.owner_wallet).await?;
    if !agent_allowed(&policy, "allow_agent_review", &agent) {
        return Err(AppError::Forbidden("Agent review is blocked by document policy".into()));
    }

    sqlx::query(
        "insert into document_events (doc_id, actor_wallet, event_type, payload) values ($1,$2,'AGENT_REVIEW',$3)",
    )
    .bind(id)
    .bind(format!("agent:{}", agent.id))
    .bind(agent_custody_payload(
        json!({
            "hash_hex": doc.hash_hex,
            "version": doc.version,
            "mime_type": doc.mime_type,
            "policy_json": policy
        }),
        &agent,
        &headers,
    ))
    .execute(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({
        "ok": true,
        "doc_id": id,
        "label": doc.label,
        "hash_hex": doc.hash_hex,
        "version": doc.version,
        "mime_type": doc.mime_type,
        "parent_id": doc.parent_id,
        "arweave_tx": doc.arweave_tx,
        "blob_url": internal_blob_url(id),
        "policy_json": policy
    })))
}

async fn agent_sign_doc_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<AgentSignRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let agent = require_agent_from_headers(&st, &headers).await?;
    let doc = load_document_access_record(&st.db, id, &agent.owner_wallet).await?;
    let policy = load_document_policy(&st.db, id, &doc.owner_wallet).await?;

    if !agent_allowed(&policy, "allow_agent_sign", &agent) {
        return Err(AppError::Forbidden("Agent signing is blocked by document policy".into()));
    }

    let require_human_countersign = policy
        .get("require_human_countersign")
        .and_then(|value| value.as_bool())
        .unwrap_or(true);
    let event_type = if require_human_countersign {
        "AGENT_SIGN_PROPOSED"
    } else {
        "AGENT_SIGN"
    };

    sqlx::query(
        "insert into document_events (doc_id, actor_wallet, event_type, payload) values ($1,$2,$3,$4)",
    )
    .bind(id)
    .bind(format!("agent:{}", agent.id))
    .bind(event_type)
    .bind(agent_custody_payload(
        json!({
            "hash_hex": doc.hash_hex,
            "version": doc.version,
            "sign_reason": body.sign_reason,
            "summary": body.summary,
            "require_human_countersign": require_human_countersign
        }),
        &agent,
        &headers,
    ))
    .execute(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({
        "ok": true,
        "doc_id": id,
        "event_type": event_type,
        "require_human_countersign": require_human_countersign
    })))
}

async fn agent_version_doc_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(parent_doc_id): Path<uuid::Uuid>,
    Json(body): Json<AgentVersionRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let agent = require_agent_from_headers(&st, &headers).await?;
    let parent = load_document_access_record(&st.db, parent_doc_id, &agent.owner_wallet).await?;
    let policy = load_document_policy(&st.db, parent_doc_id, &parent.owner_wallet).await?;

    if !agent_allowed(&policy, "allow_agent_review", &agent) {
        return Err(AppError::Forbidden("Agent version creation is blocked by document policy".into()));
    }

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(body.content_b64.trim())
        .map_err(|_| AppError::BadRequest("Invalid content_b64".into()))?;

    let record = create_document_record(
        &st,
        &agent.owner_wallet,
        &bytes,
        body.label.clone().filter(|value| !value.trim().is_empty()).or(parent.label.clone()),
        body.mime_type.clone().unwrap_or_else(|| parent.mime_type.clone()),
        Some(parent_doc_id),
        Some(parent.version),
        body.anchor_to_arweave.unwrap_or_else(auto_anchor_enabled),
    )
    .await?;

    sqlx::query(
        "insert into document_events (doc_id, actor_wallet, event_type, payload) values ($1,$2,'AGENT_VERSION_CREATED',$3)",
    )
    .bind(record.id)
    .bind(format!("agent:{}", agent.id))
    .bind(agent_custody_payload(
        json!({
            "hash_hex": record.hash_hex,
            "version": record.version,
            "mime_type": record.mime_type,
            "label": record.label,
            "parent_id": record.parent_id,
            "parent_hash_hex": parent.hash_hex,
            "parent_version": parent.version,
            "arweave_tx": record.arweave_tx,
            "change_summary": body.change_summary,
            "editor_mode": "agent_api",
            "before_snapshot_hash_hex": parent.hash_hex
        }),
        &agent,
        &headers,
    ))
    .execute(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({
        "ok": true,
        "id": record.id,
        "version": record.version,
        "parent_id": parent_doc_id,
        "arweave_tx": record.arweave_tx
    })))
}

// ================================================================
// UPLOAD
// ================================================================

async fn upload_doc_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, AppError> {
    let session = require_session_from_headers(&st, &headers)?;
    let wallet = session.wallet.clone();

    let mut file_bytes = None;
    let mut label = None;
    let mut mime_type = None;
    let mut original_name = None;
    let mut anchor_to_arweave = auto_anchor_enabled();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| multipart_error("Upload stream failed", e))?
    {
        match field.name().unwrap_or("") {
            "file" => {
                mime_type = field.content_type().map(ToOwned::to_owned);
                original_name = field.file_name().map(ToOwned::to_owned);
                file_bytes = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| multipart_error("Reading uploaded file failed", e))?
                        .to_vec(),
                );
            }
            "label" => {
                label = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| multipart_error("Reading upload label failed", e))?,
                )
            }
            "anchor_to_arweave" => {
                anchor_to_arweave = bool_from_form_text(
                    &field
                        .text()
                        .await
                        .map_err(|e| multipart_error("Reading Arweave flag failed", e))?,
                )
            }
            _ => {}
        }
    }

    let bytes = file_bytes.ok_or_else(|| AppError::BadRequest("No file uploaded".into()))?;
    let mime_type = mime_type.unwrap_or_else(|| "application/octet-stream".to_string());
    let label = label
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or(original_name);
    let record = create_document_record(
        &st,
        &wallet,
        &bytes,
        label.clone(),
        mime_type.clone(),
        None,
        None,
        anchor_to_arweave,
    )
    .await?;

    sqlx::query(
        "insert into document_events (doc_id, actor_wallet, event_type, payload) values ($1,$2,'UPLOAD',$3)",
    )
    .bind(record.id)
    .bind(&wallet)
    .bind(custody_payload(
        json!({
            "hash_hex": record.hash_hex,
            "storage_path": record.storage_path,
            "version": record.version,
            "mime_type": record.mime_type,
            "label": record.label,
            "parent_id": record.parent_id,
            "arweave_tx": record.arweave_tx,
            "encryption_mode": "pq_envelope_server_managed"
        }),
        &session,
        &headers,
    ))
    .execute(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({
        "ok": true,
        "id": record.id,
        "version": record.version,
        "arweave_tx": record.arweave_tx
    })))
}

async fn create_document_version_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(parent_doc_id): Path<uuid::Uuid>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, AppError> {
    let session = require_session_from_headers(&st, &headers)?;
    let wallet = session.wallet.clone();
    let parent = load_document_access_record(&st.db, parent_doc_id, &wallet).await?;

    if !parent.owner_wallet.eq_ignore_ascii_case(&wallet) {
        return Err(AppError::Forbidden("Only the document owner can create a new version".into()));
    }

    let mut file_bytes = None;
    let mut label = None;
    let mut mime_type = None;
    let mut original_name = None;
    let mut anchor_to_arweave = auto_anchor_enabled();
    let mut change_summary: Option<String> = None;
    let mut editor_mode: Option<String> = None;
    let mut before_hash_hex: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| multipart_error("Version upload stream failed", e))?
    {
        match field.name().unwrap_or("") {
            "file" => {
                mime_type = field.content_type().map(ToOwned::to_owned);
                original_name = field.file_name().map(ToOwned::to_owned);
                file_bytes = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| multipart_error("Reading version file failed", e))?
                        .to_vec(),
                );
            }
            "label" => {
                label = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| multipart_error("Reading version label failed", e))?,
                )
            }
            "anchor_to_arweave" => {
                anchor_to_arweave = bool_from_form_text(
                    &field
                        .text()
                        .await
                        .map_err(|e| multipart_error("Reading version Arweave flag failed", e))?,
                )
            }
            "change_summary" => {
                change_summary = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| multipart_error("Reading change summary failed", e))?,
                )
            }
            "editor_mode" => {
                editor_mode = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| multipart_error("Reading editor mode failed", e))?,
                )
            }
            "before_hash_hex" => {
                before_hash_hex = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| multipart_error("Reading before snapshot hash failed", e))?,
                )
            }
            _ => {}
        }
    }

    let bytes = file_bytes.ok_or_else(|| AppError::BadRequest("No version file uploaded".into()))?;
    let mime_type = mime_type.unwrap_or_else(|| parent.mime_type.clone());
    let label = label
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or(original_name)
        .or(parent.label.clone());

    let record = create_document_record(
        &st,
        &wallet,
        &bytes,
        label,
        mime_type,
        Some(parent_doc_id),
        Some(parent.version),
        anchor_to_arweave,
    )
    .await?;

    sqlx::query(
        "insert into document_events (doc_id, actor_wallet, event_type, payload) values ($1,$2,'VERSION_CREATED',$3)",
    )
    .bind(record.id)
    .bind(&wallet)
    .bind(custody_payload(
        json!({
            "hash_hex": record.hash_hex,
            "storage_path": record.storage_path,
            "version": record.version,
            "mime_type": record.mime_type,
            "label": record.label,
            "parent_id": record.parent_id,
            "parent_hash_hex": parent.hash_hex,
            "parent_version": parent.version,
            "arweave_tx": record.arweave_tx,
            "encryption_mode": "pq_envelope_server_managed",
            "change_summary": change_summary,
            "editor_mode": editor_mode,
            "before_snapshot_hash_hex": before_hash_hex
        }),
        &session,
        &headers,
    ))
    .execute(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({
        "ok": true,
        "id": record.id,
        "version": record.version,
        "parent_id": parent_doc_id,
        "arweave_tx": record.arweave_tx
    })))
}

async fn review_doc_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let session = require_session_from_headers(&st, &headers)?;
    let wallet = session.wallet.clone();
    let doc = load_document_access_record(&st.db, id, &wallet).await?;

    sqlx::query(
        "insert into document_events (doc_id, actor_wallet, event_type, payload) values ($1,$2,'VIEW',$3)",
    )
    .bind(id)
    .bind(&wallet)
    .bind(custody_payload(
        json!({
            "owner_wallet": doc.owner_wallet,
            "label": doc.label,
            "hash_hex": doc.hash_hex,
            "version": doc.version,
            "mime_type": doc.mime_type,
            "parent_id": doc.parent_id,
            "arweave_tx": doc.arweave_tx
        }),
        &session,
        &headers,
    ))
    .execute(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({
        "url": internal_blob_url(id),
        "blob_url": internal_blob_url(id),
        "label": doc.label,
        "hash_hex": doc.hash_hex,
        "version": doc.version,
        "mime_type": doc.mime_type,
        "parent_id": doc.parent_id,
        "arweave_tx": doc.arweave_tx,
        "encryption_mode": doc.encryption_mode,
        "ciphertext_hash_hex": doc.ciphertext_hash_hex,
        "onlyoffice_enabled": onlyoffice_editor_enabled() && is_office_mime_type(&doc.mime_type)
    })))
}

async fn doc_blob_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let wallet = require_wallet_from_headers(&st, &headers)?;
    let access = load_document_access_record(&st.db, id, &wallet).await?;
    let doc = load_document_bytes_for_access(&st, &access).await?;
    let disposition = params.get("download").map(|value| value == "1" || value == "true");
    let filename = doc
        .label
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("{id}.bin"));
    let content_disposition = if disposition.unwrap_or(false) {
        format!("attachment; filename=\"{}\"", filename.replace('"', ""))
    } else {
        "inline".to_string()
    };

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, doc.mime_type),
            (header::CONTENT_DISPOSITION, content_disposition),
            (header::HeaderName::from_static("x-tidbit-hash"), doc.hash_hex),
            (
                header::HeaderName::from_static("x-tidbit-version"),
                doc.version.to_string(),
            ),
            (
                header::HeaderName::from_static("x-tidbit-encryption-mode"),
                doc.encryption_mode,
            ),
        ],
        doc.bytes,
    )
        .into_response())
}

// ================================================================
// DOWNLOAD
// ================================================================

async fn download_doc_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let session = require_session_from_headers(&st, &headers)?;
    let wallet = session.wallet.clone();
    let doc = load_document_access_record(&st.db, id, &wallet).await?;

    sqlx::query(
        "insert into document_events (doc_id, actor_wallet, event_type, payload) values ($1,$2,'DOWNLOAD',$3)",
    )
    .bind(id)
    .bind(&wallet)
    .bind(custody_payload(
        json!({
            "owner_wallet": doc.owner_wallet,
            "label": doc.label,
            "hash_hex": doc.hash_hex,
            "version": doc.version,
            "mime_type": doc.mime_type,
            "parent_id": doc.parent_id,
            "arweave_tx": doc.arweave_tx
        }),
        &session,
        &headers,
    ))
    .execute(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({
        "url": format!("{}?download=1", internal_blob_url(id)),
        "blob_url": internal_blob_url(id),
        "encryption_mode": doc.encryption_mode
    })))
}

// ================================================================
// SIGN
// ================================================================

async fn sign_doc_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(doc_id): Path<uuid::Uuid>,
    Json(body): Json<SignRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let session = require_session_from_headers(&st, &headers)?;
    let wallet = session.wallet.clone();
    let doc = load_document_access_record(&st.db, doc_id, &wallet)
        .await
        .map_err(|_| AppError::Forbidden("You do not have signing access to this document".into()))?;

    if body.signature.trim().is_empty() {
        return Err(AppError::BadRequest("Missing signature".into()));
    }

    let signature_type = body
        .signature_type
        .clone()
        .unwrap_or_else(|| "evm_personal_sign".to_string());
    let canonical_message = document_sign_message(doc_id, &doc.hash_hex, &wallet, doc.version);

    let verification_payload = match signature_type.as_str() {
        "evm_personal_sign" => {
            let recovered = verify_evm_signature(&canonical_message, &body.signature)
                .map_err(|_| AppError::BadRequest("Invalid EVM signature".into()))?
                .to_lowercase();

            if recovered != wallet.to_lowercase() {
                return Err(AppError::Forbidden("Signature does not match the active wallet".into()));
            }

            json!({
                "signature_type": signature_type,
                "recovered_wallet": recovered
            })
        }
        "pq_dilithium3" => {
            let public_key_b64 = body
                .pq_public_key_b64
                .clone()
                .ok_or_else(|| AppError::BadRequest("Missing pq_public_key_b64".into()))?;
            let public_key = base64::engine::general_purpose::STANDARD
                .decode(&public_key_b64)
                .map_err(|_| AppError::BadRequest("Invalid pq_public_key_b64".into()))?;
            let signed_message = base64::engine::general_purpose::STANDARD
                .decode(&body.signature)
                .map_err(|_| AppError::BadRequest("Invalid PQ signed message encoding".into()))?;
            let verified = dilithium::verify(&public_key, canonical_message.as_bytes(), &signed_message)
                .map_err(|e| AppError::Internal(e.to_string()))?;

            if !verified {
                return Err(AppError::Forbidden("PQ signature verification failed".into()));
            }

            json!({
                "signature_type": signature_type,
                "pq_public_key_b64": public_key_b64
            })
        }
        _ => {
            return Err(AppError::BadRequest("Unsupported signature_type".into()));
        }
    };

    sqlx::query(
        "insert into document_events (doc_id, actor_wallet, event_type, payload) values ($1,$2,'SIGN',$3)",
    )
    .bind(doc_id)
    .bind(&wallet)
    .bind(custody_payload(
        json!({
            "signature": body.signature,
            "hash_hex": doc.hash_hex,
            "version": doc.version,
            "mime_type": doc.mime_type,
            "parent_id": doc.parent_id,
            "arweave_tx": doc.arweave_tx,
            "signing_message": canonical_message,
            "verification": verification_payload
        }),
        &session,
        &headers,
    ))
    .execute(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({ "ok": true })))
}

// ================================================================
// DELETE
// ================================================================

async fn delete_doc_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let session = require_session_from_headers(&st, &headers)?;
    let wallet = session.wallet.clone();

    let result = sqlx::query("update documents set is_deleted = true where id = $1 and owner_wallet = $2")
        .bind(id)
        .bind(&wallet)
        .execute(&st.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Document not found".into()));
    }

    sqlx::query(
        "insert into document_events (doc_id, actor_wallet, event_type, payload) values ($1,$2,'DELETE',$3)",
    )
    .bind(id)
    .bind(&wallet)
    .bind(custody_payload(json!({}), &session, &headers))
    .execute(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({ "ok": true })))
}

// ================================================================
// SHARE
// ================================================================

async fn share_doc_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(doc_id): Path<uuid::Uuid>,
    Json(body): Json<ShareRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let session = require_session_from_headers(&st, &headers)?;
    let sender = session.wallet.clone();
    let requested_wallet = body
        .recipient_wallet
        .clone()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let requested_email = body
        .recipient_email
        .clone()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let requested_phone = body
        .recipient_phone
        .clone()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    if requested_wallet.is_none() && requested_email.is_none() && requested_phone.is_none() {
        return Err(AppError::BadRequest(
            "Provide at least one recipient path: wallet, email, or phone".into(),
        ));
    }

    let doc = sqlx::query(
        "select label, hash_hex from documents where id = $1 and owner_wallet = $2 and is_deleted = false",
    )
    .bind(doc_id)
    .bind(&sender)
    .fetch_optional(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let Some(doc) = doc else {
        return Err(AppError::Forbidden("You can only share documents you own".into()));
    };

    let label: Option<String> = doc.get("label");
    let hash_hex: String = doc.get("hash_hex");
    let envelope_id = uuid::Uuid::new_v4();
    let access_token = uuid::Uuid::new_v4().simple().to_string();
    let recipient_wallet = requested_wallet.clone();
    let recipient_name = body
        .recipient_name
        .clone()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let signing_url = envelope_signing_url(&access_token);

    sqlx::query(
        r#"insert into document_shares
        (doc_id, sender_wallet, recipient_wallet, recipient_name, envelope_id, note, recipient_email, recipient_phone, access_token, status, delivery_json)
        values ($1,$2,$3,$4,$5,$6,$7,$8,$9,'sent',$10)"#,
    )
    .bind(doc_id)
    .bind(&sender)
    .bind(&recipient_wallet)
    .bind(&recipient_name)
    .bind(envelope_id)
    .bind(&body.note)
    .bind(&requested_email)
    .bind(&requested_phone)
    .bind(&access_token)
    .bind(json!([]))
    .execute(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let (deliveries, delivery_errors) = dispatch_share_deliveries(
        requested_email.as_deref(),
        requested_phone.as_deref(),
        label.as_deref(),
        doc_id,
        &hash_hex,
        envelope_id,
        recipient_name.as_deref(),
        &signing_url,
    )
    .await;

    sqlx::query("update document_shares set delivery_json = $2 where access_token = $1")
        .bind(&access_token)
        .bind(serde_json::to_value(&deliveries).map_err(|e| AppError::Internal(e.to_string()))?)
        .execute(&st.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    sqlx::query(
        "insert into document_events (doc_id, actor_wallet, event_type, payload) values ($1,$2,'SHARE',$3)",
    )
    .bind(doc_id)
    .bind(&sender)
    .bind(custody_payload(
        build_share_event_payload(
            recipient_wallet.as_deref(),
            body.note.as_deref(),
            envelope_id,
            body.signature.as_deref(),
            recipient_name.as_deref(),
            requested_email.as_deref(),
            requested_phone.as_deref(),
            Some(&access_token),
        ),
        &session,
        &headers,
    ))
    .execute(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    for outcome in &deliveries {
        sqlx::query(
            "insert into document_events (doc_id, actor_wallet, event_type, payload) values ($1,$2,'DELIVERY_DISPATCHED',$3)",
        )
        .bind(doc_id)
        .bind(&sender)
        .bind(custody_payload(
            json!({
                "envelope_id": envelope_id,
                "channel": outcome.channel,
                "provider": outcome.provider,
                "recipient": outcome.recipient,
                "external_id": outcome.external_id,
                "status": outcome.status
            }),
            &session,
            &headers,
        ))
        .execute(&st.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    for error in &delivery_errors {
        sqlx::query(
            "insert into document_events (doc_id, actor_wallet, event_type, payload) values ($1,$2,'DELIVERY_FAILED',$3)",
        )
        .bind(doc_id)
        .bind(&sender)
        .bind(custody_payload(
            json!({
                "envelope_id": envelope_id,
                "error": error
            }),
            &session,
            &headers,
        ))
        .execute(&st.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    Ok(Json(json!({
        "ok": true,
        "envelope_id": envelope_id,
        "doc_id": doc_id,
        "label": label,
        "hash_hex": hash_hex,
        "recipient_wallet": recipient_wallet,
        "recipient_name": recipient_name,
        "recipient_email": requested_email,
        "recipient_phone": requested_phone,
        "signing_url": signing_url,
        "delivery": deliveries,
        "delivery_errors": delivery_errors
    })))
}

async fn list_inbox_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let wallet = require_wallet_from_headers(&st, &headers)?;

    let rows = sqlx::query(
        r#"
        select
            s.doc_id,
            s.sender_wallet,
            s.recipient_wallet,
            s.envelope_id,
            s.note,
            d.label,
            d.hash_hex,
            d.version
        from document_shares s
        join documents d on d.id = s.doc_id
        where s.recipient_wallet = $1
          and d.is_deleted = false
        order by d.created_at desc
        "#,
    )
    .bind(&wallet)
    .fetch_all(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({
        "items": rows
            .into_iter()
            .map(|r| json!({
                "doc_id": r.get::<uuid::Uuid,_>("doc_id"),
                "sender_wallet": r.get::<String,_>("sender_wallet"),
                "recipient_wallet": r.get::<String,_>("recipient_wallet"),
                "envelope_id": r.get::<uuid::Uuid,_>("envelope_id"),
                "note": r.get::<Option<String>,_>("note"),
                "label": r.get::<Option<String>,_>("label"),
                "hash_hex": r.get::<String,_>("hash_hex"),
                "version": r.get::<i32,_>("version")
            }))
            .collect::<Vec<_>>()
    })))
}

async fn public_envelope_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let row = sqlx::query(
        r#"
        select
            s.id as share_id,
            s.doc_id,
            s.sender_wallet,
            s.recipient_wallet,
            s.recipient_name,
            s.recipient_email,
            s.recipient_phone,
            s.note,
            s.envelope_id,
            s.status,
            s.viewed_at,
            s.delivery_json,
            s.annotation_json,
            d.label,
            d.hash_hex,
            d.version,
            d.mime_type,
            d.storage_path,
            d.parent_id,
            d.arweave_tx
        from document_shares s
        join documents d on d.id = s.doc_id
        where s.access_token = $1
          and d.is_deleted = false
        "#,
    )
    .bind(token.trim())
    .fetch_optional(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let Some(row) = row else {
        return Err(AppError::NotFound("Envelope not found".into()));
    };

    let doc_id: uuid::Uuid = row.get("doc_id");
    let envelope_id: uuid::Uuid = row.get("envelope_id");
    let storage_path: String = row.get("storage_path");
    let status: String = row.get("status");
    let viewed_at: Option<chrono::DateTime<chrono::Utc>> = row.get("viewed_at");
    if viewed_at.is_none() {
        sqlx::query("update document_shares set viewed_at = now(), status = 'opened' where access_token = $1 and viewed_at is null")
            .bind(token.trim())
            .execute(&st.db)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        sqlx::query(
            "insert into document_events (doc_id, actor_wallet, event_type, payload) values ($1,$2,'ENVELOPE_OPENED',$3)",
        )
        .bind(doc_id)
        .bind(format!("guest-envelope:{envelope_id}"))
        .bind(public_custody_payload_for_envelope(
            json!({
                "envelope_id": envelope_id,
                "recipient_wallet": row.get::<Option<String>,_>("recipient_wallet"),
                "recipient_name": row.get::<Option<String>,_>("recipient_name"),
                "recipient_email": row.get::<Option<String>,_>("recipient_email"),
                "recipient_phone": row.get::<Option<String>,_>("recipient_phone"),
                "status": "opened"
            }),
            envelope_id,
            &headers,
        ))
        .execute(&st.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    Ok(Json(json!({
        "doc_id": doc_id,
        "envelope_id": envelope_id,
        "sender_wallet": row.get::<String,_>("sender_wallet"),
        "recipient_wallet": row.get::<Option<String>,_>("recipient_wallet"),
        "recipient_name": row.get::<Option<String>,_>("recipient_name"),
        "recipient_email": row.get::<Option<String>,_>("recipient_email"),
        "recipient_phone": row.get::<Option<String>,_>("recipient_phone"),
        "note": row.get::<Option<String>,_>("note"),
        "delivery": row.get::<serde_json::Value,_>("delivery_json"),
        "annotation_json": row.get::<serde_json::Value,_>("annotation_json"),
        "status": if viewed_at.is_none() { "opened" } else { status.as_str() },
        "label": row.get::<Option<String>,_>("label"),
        "hash_hex": row.get::<String,_>("hash_hex"),
        "version": row.get::<i32,_>("version"),
        "mime_type": row.get::<String,_>("mime_type"),
        "parent_id": row.get::<Option<uuid::Uuid>,_>("parent_id"),
        "arweave_tx": row.get::<Option<String>,_>("arweave_tx"),
        "url": public_blob_url(token.trim()),
        "blob_url": public_blob_url(token.trim())
    })))
}

async fn public_envelope_blob_handler(
    State(st): State<AppState>,
    Path(token): Path<String>,
) -> Result<Response, AppError> {
    let row = sqlx::query(
        r#"
        select
            d.id,
            d.storage_path,
            d.owner_wallet,
            d.label,
            d.hash_hex,
            d.version,
            d.mime_type,
            d.parent_id,
            d.arweave_tx,
            coalesce(d.encryption_mode, 'plaintext_server_managed') as encryption_mode,
            d.ciphertext_hash_hex
        from document_shares s
        join documents d on d.id = s.doc_id
        where s.access_token = $1
          and d.is_deleted = false
        "#,
    )
    .bind(token.trim())
    .fetch_optional(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let Some(row) = row else {
        return Err(AppError::NotFound("Envelope not found".into()));
    };

    let access = DocumentAccessRecord {
        id: row.get("id"),
        storage_path: row.get("storage_path"),
        owner_wallet: row.get("owner_wallet"),
        label: row.get("label"),
        hash_hex: row.get("hash_hex"),
        version: row.get("version"),
        mime_type: row.get("mime_type"),
        parent_id: row.get("parent_id"),
        arweave_tx: row.get("arweave_tx"),
        encryption_mode: row.get("encryption_mode"),
        ciphertext_hash_hex: row.get("ciphertext_hash_hex"),
    };

    let doc = load_document_bytes_for_access(&st, &access).await?;

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, doc.mime_type),
            (header::CONTENT_DISPOSITION, "inline".to_string()),
            (header::HeaderName::from_static("x-tidbit-hash"), doc.hash_hex),
            (
                header::HeaderName::from_static("x-tidbit-version"),
                doc.version.to_string(),
            ),
            (
                header::HeaderName::from_static("x-tidbit-encryption-mode"),
                doc.encryption_mode,
            ),
        ],
        doc.bytes,
    )
        .into_response())
}

async fn public_envelope_sign_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Json(body): Json<PublicEnvelopeSignRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let row = sqlx::query(
        r#"
        select
            s.doc_id,
            s.envelope_id,
            s.status,
            d.hash_hex,
            d.version,
            d.mime_type,
            d.parent_id,
            d.arweave_tx
        from document_shares s
        join documents d on d.id = s.doc_id
        where s.access_token = $1
          and d.is_deleted = false
        "#,
    )
    .bind(token.trim())
    .fetch_optional(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let Some(row) = row else {
        return Err(AppError::NotFound("Envelope not found".into()));
    };

    if !body.consent {
        return Err(AppError::BadRequest("Recipient consent is required".into()));
    }
    if body.signer_name.trim().is_empty() {
        return Err(AppError::BadRequest("Signer name is required".into()));
    }

    let doc_id: uuid::Uuid = row.get("doc_id");
    let envelope_id: uuid::Uuid = row.get("envelope_id");
    let hash_hex: String = row.get("hash_hex");
    let version: i32 = row.get("version");
    let signature_type = body
        .signature_type
        .clone()
        .unwrap_or_else(|| "guest_attestation".to_string());
    let signer_identity = body
        .wallet_address
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| body.signer_name.trim().to_string());
    let canonical_message = public_envelope_sign_message(envelope_id, doc_id, &hash_hex, &signer_identity, version);
    let annotation_fields = normalize_annotation_fields(body.annotation_fields.clone());

    let verification = match signature_type.as_str() {
        "guest_attestation" => json!({
            "signature_type": "guest_attestation",
            "consent": true
        }),
        "evm_personal_sign" => {
            let wallet_address = body
                .wallet_address
                .clone()
                .ok_or_else(|| AppError::BadRequest("wallet_address is required for EVM signing".into()))?;
            let signature = body
                .signature
                .clone()
                .ok_or_else(|| AppError::BadRequest("signature is required for EVM signing".into()))?;
            let recovered = verify_evm_signature(&canonical_message, &signature)
                .map_err(|_| AppError::BadRequest("Invalid EVM signature".into()))?
                .to_lowercase();

            if recovered != wallet_address.to_lowercase() {
                return Err(AppError::Forbidden("EVM signature does not match wallet_address".into()));
            }

            json!({
                "signature_type": "evm_personal_sign",
                "wallet_address": wallet_address,
                "signature": signature,
                "recovered_wallet": recovered
            })
        }
        "pq_dilithium3" => {
            let pq_public_key_b64 = body
                .pq_public_key_b64
                .clone()
                .ok_or_else(|| AppError::BadRequest("pq_public_key_b64 is required for PQ signing".into()))?;
            let signature = body
                .signature
                .clone()
                .ok_or_else(|| AppError::BadRequest("signature is required for PQ signing".into()))?;
            let public_key = base64::engine::general_purpose::STANDARD
                .decode(&pq_public_key_b64)
                .map_err(|_| AppError::BadRequest("Invalid pq_public_key_b64".into()))?;
            let signed_message = base64::engine::general_purpose::STANDARD
                .decode(&signature)
                .map_err(|_| AppError::BadRequest("Invalid PQ signed message encoding".into()))?;
            let verified = dilithium::verify(&public_key, canonical_message.as_bytes(), &signed_message)
                .map_err(|e| AppError::Internal(e.to_string()))?;

            if !verified {
                return Err(AppError::Forbidden("PQ signature verification failed".into()));
            }

            json!({
                "signature_type": "pq_dilithium3",
                "pq_public_key_b64": pq_public_key_b64,
                "signature": signature
            })
        }
        _ => return Err(AppError::BadRequest("Unsupported signature_type".into())),
    };

    let annotation_json = json!({
        "annotation_text": body.annotation_text,
        "annotation_fields": annotation_fields,
        "sign_reason": body.sign_reason,
        "consent": body.consent
    });

    sqlx::query(
        r#"
        update document_shares
        set
            status = 'completed',
            signed_at = now(),
            completed_at = now(),
            signer_name = $2,
            signer_email = $3,
            signer_title = $4,
            signer_org = $5,
            signer_wallet = $6,
            sign_reason = $7,
            annotation_json = $8,
            completion_signature_type = $9
        where access_token = $1
        "#,
    )
    .bind(token.trim())
    .bind(body.signer_name.trim())
    .bind(body.signer_email.as_deref())
    .bind(body.signer_title.as_deref())
    .bind(body.signer_org.as_deref())
    .bind(body.wallet_address.as_deref())
    .bind(body.sign_reason.as_deref())
    .bind(&annotation_json)
    .bind(&signature_type)
    .execute(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    sqlx::query(
        "insert into document_events (doc_id, actor_wallet, event_type, payload) values ($1,$2,'ENVELOPE_COMPLETED',$3)",
    )
    .bind(doc_id)
    .bind(format!("guest-envelope:{envelope_id}"))
    .bind(public_custody_payload_for_envelope(
        json!({
            "envelope_id": envelope_id,
            "hash_hex": hash_hex,
            "version": version,
            "mime_type": row.get::<String,_>("mime_type"),
            "parent_id": row.get::<Option<uuid::Uuid>,_>("parent_id"),
            "arweave_tx": row.get::<Option<String>,_>("arweave_tx"),
            "signer_name": body.signer_name.trim(),
            "signer_email": body.signer_email,
            "signer_title": body.signer_title,
            "signer_org": body.signer_org,
            "signer_wallet": body.wallet_address,
            "completion_signature_type": signature_type,
            "annotation_json": annotation_json,
            "signing_message": canonical_message,
            "verification": verification
        }),
        envelope_id,
        &headers,
    ))
    .execute(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({
        "ok": true,
        "envelope_id": envelope_id,
        "status": "completed"
    })))
}

// ================================================================
// SESSION
// ================================================================

async fn session_info_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let sid = headers
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Auth("Missing session".into()))?;

    let sess = st
        .auth
        .get_session(sid)
        .ok_or_else(|| AppError::Auth("Invalid session".into()))?;
    let keys = load_or_create_mlkem_keypair(&sess.wallet)
        .map_err(|e| AppError::Internal(format!("mlkem keystore: {e}")))?;

    Ok(Json(json!({
        "active": true,
        "wallet": sess.wallet,
        "chain": sess.chain,
        "created_at": sess.created_at,
        "mlkem_pk_b64": keys.pk_b64
    })))
}

async fn logout_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let sid = headers
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Auth("Missing session".into()))?;

    st.auth.revoke_session(sid);

    Ok(Json(json!({ "ok": true })))
}

// ================================================================
// PUBLIC VERIFY
// ================================================================

async fn public_verify_handler(
    State(st): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut bytes = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| multipart_error("Verification upload stream failed", e))?
    {
        if field.name() == Some("file") {
            bytes = Some(
                field
                    .bytes()
                    .await
                    .map_err(|e| multipart_error("Reading verification file failed", e))?
                    .to_vec(),
            );
        }
    }

    let bytes = bytes.ok_or_else(|| AppError::BadRequest("No file uploaded".into()))?;

    let hash_hex = hex::encode(pqc_sha3::sha3_256_bytes(&bytes));

    let row = sqlx::query("select 1 from documents where hash_hex = $1 and is_deleted = false")
        .bind(&hash_hex)
        .fetch_optional(&st.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({
        "verified": row.is_some(),
        "hash": hash_hex
    })))
}

#[cfg(test)]
mod tests {
    use super::{
        bool_from_form_text, build_share_event_payload, document_sign_message,
        normalize_annotation_fields, 
        wallet_can_access_document,
    };
    use crate::models::SignerAnnotationField;

    #[test]
    fn owner_or_share_recipient_can_access_document() {
        assert!(wallet_can_access_document("0xabc", "0xabc", false));
        assert!(wallet_can_access_document("0xabc", "0xdef", true));
        assert!(!wallet_can_access_document("0xabc", "0xdef", false));
    }

    #[test]
    fn share_event_payload_preserves_delivery_and_signature_metadata() {
        let envelope_id = uuid::Uuid::parse_str("66202c33-f9ee-45d4-83d5-5f970a4184e2").unwrap();
        let payload = build_share_event_payload(
            Some("0xrecipient"),
            Some("Review and sign"),
            envelope_id,
            Some("0xsig"),
            Some("Signer Example"),
            Some("signer@example.com"),
            Some("+15555555555"),
            Some("public-token-123"),
        );

        assert_eq!(payload["recipient_wallet"], "0xrecipient");
        assert_eq!(payload["recipient_name"], "Signer Example");
        assert_eq!(payload["note"], "Review and sign");
        assert_eq!(payload["signature"], "0xsig");
        assert_eq!(payload["recipient_email"], "signer@example.com");
        assert_eq!(payload["recipient_phone"], "+15555555555");
        assert_eq!(payload["access_token"], "public-token-123");
        assert_eq!(payload["envelope_id"], envelope_id.to_string());
    }

    #[test]
    fn parses_html_boolean_values_for_anchor_flags() {
        assert!(bool_from_form_text("true"));
        assert!(bool_from_form_text("YES"));
        assert!(bool_from_form_text("1"));
        assert!(!bool_from_form_text("false"));
        assert!(!bool_from_form_text(""));
    }

    #[test]
    fn canonical_document_sign_message_contains_doc_hash_wallet_and_version() {
        let doc_id = uuid::Uuid::parse_str("66202c33-f9ee-45d4-83d5-5f970a4184e2").unwrap();
        let message = document_sign_message(doc_id, "abc123", "0xwallet", 7);

        assert!(message.contains("Document ID: 66202c33-f9ee-45d4-83d5-5f970a4184e2"));
        assert!(message.contains("Hash: abc123"));
        assert!(message.contains("Wallet: 0xwallet"));
        assert!(message.contains("Version: 7"));
    }

    #[test]
    fn annotation_fields_are_trimmed_and_clamped() {
        let fields = normalize_annotation_fields(Some(vec![SignerAnnotationField {
            kind: " signature ".to_string(),
            label: Some("  Sign Here ".to_string()),
            value: Some("  Signed ".to_string()),
            x_pct: 140.0,
            y_pct: -8.0,
        }]));

        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].kind, "signature");
        assert_eq!(fields[0].label.as_deref(), Some("Sign Here"));
        assert_eq!(fields[0].value.as_deref(), Some("Signed"));
        assert_eq!(fields[0].x_pct, 100.0);
        assert_eq!(fields[0].y_pct, 0.0);
    }
}

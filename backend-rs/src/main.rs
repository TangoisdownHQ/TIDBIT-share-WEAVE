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
mod sqlx;
mod storage;

use axum::extract::{Multipart, Path, Query, State};
use axum::http::HeaderMap;
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use clap::Parser;
use cli::commands::{auth, c2c as cli_c2c, doc, wallet};
use cli::parser::{Cli, Commands};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;
use std::collections::HashMap;

use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};

use crate::error::AppError;
use crate::identity_web::evm::{evm_login_message, verify_evm_signature, EvmNonceResponse, EvmVerifyRequest};
use crate::identity_web::sol::verify_solana_signature;
use crate::identity_web::state::WalletSession;
use crate::delivery::{send_email_invite, send_sms_invite, DeliveryOutcome};
use crate::crypto::aes_gcm;
use crate::sqlx::postgres::PgPoolOptions;
use crate::sqlx::{PgPool, Row};
use crate::models::{
    AgentRegisterRequest, AgentSignRequest, AgentVersionRequest, DocumentPolicyUpdateRequest,
    InboxActionRequest, PublicEnvelopeSignRequest, ShareRequest, SignRequest, SignerAnnotationField,
};
use crate::crypto::canonical::{
    canonicalize::canonical_json,
    keystore::{load_mlkem_keypair_if_exists, MlKemKeypairFile},
    kem::mlkem_generate_keypair_b64,
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

    let result = match cli.command {
        Commands::Server => start_server().await,
        Commands::Auth { action } => auth::handle_auth(action).await,
        Commands::Wallet { action } => wallet::handle_wallet(action).await,
        Commands::Doc { action } => doc::handle_doc(action).await,
        Commands::C2c { action } => cli_c2c::handle_c2c(action).await,
    };

    if let Err(err) = &result {
        eprintln!("fatal error: {err:#}");
    }

    result
}

// ================================================================
// SERVER
// ================================================================

async fn start_server() -> anyhow::Result<()> {
    eprintln!("boot: starting server bootstrap");
    eprintln!("boot: loading DATABASE_URL");
    let database_url = std::env::var("DATABASE_URL")?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    eprintln!("boot: ensuring runtime schema");
    ensure_runtime_schema(&pool).await?;

    eprintln!("boot: connected to Supabase Postgres");
    let auth_state = identity_web::AuthState::new(pool.clone());

    eprintln!("boot: loading storage environment");
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
    let landing_page = ServeFile::new("web/landing.html");
    let login_page = ServeFile::new("web/index.html");
    let pricing_page = ServeFile::new("web/pricing.html");

    let app = Router::new()
        .route_service("/", landing_page)
        .route_service("/app", login_page.clone())
        .route_service("/app/", login_page)
        .route_service("/pricing", pricing_page.clone())
        .route_service("/pricing/", pricing_page)
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
        .route("/api/agent/list", get(list_agents_handler))
        .route("/api/agent/:id/rotate-token", post(rotate_agent_token_handler))
        .route("/api/agent/:id/revoke", post(revoke_agent_handler))
        .route("/api/overview", get(overview_handler))
        .route("/api/account/status", get(account_status_handler))
        .route("/api/doc/list", get(list_docs_handler))
        .route("/api/shared", get(list_shared_handler))
        .route("/api/activity/shared", get(list_shared_activity_handler))
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
        .route(
            "/api/doc/:id/share/:envelope_id/revoke",
            post(revoke_share_handler),
        )
        .route("/api/agent/doc/:id/review", get(agent_review_doc_handler))
        .route("/api/agent/doc/:id/sign", post(agent_sign_doc_handler))
        .route("/api/agent/doc/:id/version", post(agent_version_doc_handler))
        .route("/api/inbox", get(list_inbox_handler))
        .route("/api/inbox/:envelope_id/action", post(inbox_action_handler))
        .route("/auth/session", get(session_info_handler))
        .route("/auth/session/rotate", post(rotate_session_handler))
        .route("/auth/logout", post(logout_handler))
        .fallback_service(static_files)
        .with_state(state)
        .layer(configured_cors_layer()?);

    let port = std::env::var("PORT")
        .ok()
        .and_then(|value| value.trim().parse::<u16>().ok())
        .unwrap_or(4100);
    let addr: std::net::SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();

    eprintln!("boot: binding server to http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("boot: listener ready");
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

fn canonical_chain(chain: &str) -> Option<&'static str> {
    match chain.trim().to_ascii_lowercase().as_str() {
        "evm" | "ethereum" | "metamask" => Some("evm"),
        "sol" | "solana" | "phantom" => Some("sol"),
        _ => None,
    }
}

fn infer_wallet_chain(wallet: &str) -> &'static str {
    if wallet.trim().starts_with("0x") {
        "evm"
    } else {
        "sol"
    }
}

fn normalize_wallet_for_chain(wallet: &str, chain: &str) -> String {
    let trimmed = wallet.trim();
    if canonical_chain(chain) == Some("evm") {
        trimmed.to_ascii_lowercase()
    } else {
        trimmed.to_string()
    }
}

fn configured_cors_layer() -> Result<CorsLayer, AppError> {
    let configured = std::env::var("ALLOWED_ORIGINS").unwrap_or_default();
    let mut origins: Vec<String> = configured
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect();

    if origins.is_empty() {
        origins.push("http://127.0.0.1:4100".to_string());
        origins.push("http://localhost:4100".to_string());
        if let Ok(url) = reqwest::Url::parse(&public_app_url()) {
            origins.push(url.origin().ascii_serialization());
        }
    }

    let header_values = origins
        .into_iter()
        .map(|origin| {
            HeaderValue::from_str(&origin)
                .map_err(|_| AppError::Internal(format!("Invalid CORS origin: {origin}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            header::CONTENT_TYPE,
            header::ACCEPT,
            header::HeaderName::from_static("x-session-id"),
            header::HeaderName::from_static("x-device-id"),
            header::HeaderName::from_static("x-agent-token"),
        ])
        .allow_origin(header_values))
}

async fn ensure_runtime_schema(db: &PgPool) -> anyhow::Result<()> {
    sqlx::query("alter table document_shares add column if not exists recipient_chain text")
        .execute(db)
        .await?;
    sqlx::query(
        "create index if not exists idx_document_shares_recipient_chain_wallet_doc on document_shares (recipient_chain, recipient_wallet, doc_id)",
    )
    .execute(db)
    .await?;
    sqlx::query(
        r#"
        create table if not exists account_subscriptions (
            wallet text primary key,
            billing_status text not null default 'trialing',
            trial_started_at timestamptz not null default now(),
            trial_ends_at timestamptz not null default (now() + interval '30 days'),
            paid_through timestamptz null,
            stripe_customer_id text null,
            stripe_subscription_id text null,
            plan_amount_usd integer not null default 8,
            created_at timestamptz not null default now(),
            updated_at timestamptz not null default now()
        )
        "#,
    )
    .execute(db)
    .await?;
    sqlx::query(
        r#"
        create table if not exists wallet_mlkem_keys (
            wallet text primary key,
            kem text not null default 'mlkem768',
            pk_b64 text not null,
            sk_b64 text null,
            sk_b64_enc text null,
            sk_nonce_b64 text null,
            source text not null default 'generated',
            created_at timestamptz not null default now(),
            updated_at timestamptz not null default now()
        )
        "#,
    )
    .execute(db)
    .await?;
    sqlx::query("alter table wallet_mlkem_keys add column if not exists sk_b64 text null")
        .execute(db)
        .await?;
    sqlx::query("alter table wallet_mlkem_keys add column if not exists sk_b64_enc text null")
        .execute(db)
        .await?;
    sqlx::query("alter table wallet_mlkem_keys add column if not exists sk_nonce_b64 text null")
        .execute(db)
        .await?;
    sqlx::query(
        r#"
        create table if not exists wallet_auth_nonces (
            session_id text primary key,
            nonce text not null,
            created_at timestamptz not null default now(),
            expires_at timestamptz not null,
            consumed_at timestamptz null
        )
        "#,
    )
    .execute(db)
    .await?;
    sqlx::query(
        r#"
        create table if not exists wallet_sessions (
            session_id text primary key,
            session_family_id uuid not null,
            wallet text not null,
            chain text not null,
            created_at timestamptz not null default now(),
            last_seen_at timestamptz not null default now(),
            expires_at timestamptz not null,
            revoked_at timestamptz null,
            revoked_reason text null,
            replaced_by_session_id text null,
            device_id text null,
            user_agent text null,
            ip_address text null
        )
        "#,
    )
    .execute(db)
    .await?;
    sqlx::query(
        "create index if not exists idx_wallet_sessions_wallet_active on wallet_sessions (wallet, expires_at desc) where revoked_at is null",
    )
    .execute(db)
    .await?;
    sqlx::query(
        "create index if not exists idx_wallet_auth_nonces_expires on wallet_auth_nonces (expires_at)",
    )
    .execute(db)
    .await?;
    sqlx::query(
        r#"
        alter table document_shares
            add column if not exists access_token_hash text,
            add column if not exists expires_at timestamptz,
            add column if not exists revoked_at timestamptz,
            add column if not exists revoked_reason text,
            add column if not exists one_time_use boolean not null default false,
            add column if not exists download_allowed boolean not null default true,
            add column if not exists allow_guest_sign boolean,
            add column if not exists open_count integer not null default 0,
            add column if not exists completion_count integer not null default 0
        "#,
    )
    .execute(db)
    .await?;
    let legacy_share_rows = sqlx::query(
        "select id, access_token from document_shares where access_token is not null and access_token_hash is null",
    )
    .fetch_all(db)
    .await?;
    for row in legacy_share_rows {
        let share_id: uuid::Uuid = row.get("id");
        let access_token: String = row.get("access_token");
        sqlx::query(
            "update document_shares set access_token_hash = $2 where id = $1 and access_token_hash is null",
        )
        .bind(share_id)
        .bind(access_token_hash_hex(&access_token))
        .execute(db)
        .await?;
    }
    sqlx::query(
        "update document_shares set access_token = null where access_token is not null and access_token_hash is not null",
    )
    .execute(db)
    .await?;
    sqlx::query(
        "create unique index if not exists idx_document_shares_access_token_hash on document_shares (access_token_hash) where access_token_hash is not null",
    )
    .execute(db)
    .await?;
    sqlx::query(
        "create index if not exists idx_document_shares_public_active on document_shares (access_token_hash, expires_at, revoked_at)",
    )
    .execute(db)
    .await?;
    sqlx::query(
        r#"
        alter table document_events
            add column if not exists prev_event_hash_hex text,
            add column if not exists event_hash_hex text,
            add column if not exists event_hmac_b64 text
        "#,
    )
    .execute(db)
    .await?;
    Ok(())
}

fn load_mlkem_db_master_key() -> Result<[u8; 32], AppError> {
    let raw = std::env::var("MLKEM_DB_MASTER_KEY_B64")
        .map_err(|_| AppError::Internal("Missing MLKEM_DB_MASTER_KEY_B64".into()))?;
    let decoded = BASE64_STANDARD
        .decode(raw.trim())
        .map_err(|_| AppError::Internal("Invalid MLKEM_DB_MASTER_KEY_B64 encoding".into()))?;
    if decoded.len() != 32 {
        return Err(AppError::Internal("MLKEM_DB_MASTER_KEY_B64 must decode to 32 bytes".into()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

fn encrypt_mlkem_secret(sk_b64: &str) -> Result<(String, String), AppError> {
    let key = load_mlkem_db_master_key()?;
    let (nonce, ciphertext) = aes_gcm::encrypt_aes_gcm(&key, sk_b64.as_bytes())?;
    Ok((BASE64_STANDARD.encode(ciphertext), BASE64_STANDARD.encode(nonce)))
}

fn decrypt_mlkem_secret(sk_b64_enc: &str, sk_nonce_b64: &str) -> Result<String, AppError> {
    let key = load_mlkem_db_master_key()?;
    let ciphertext = BASE64_STANDARD
        .decode(sk_b64_enc)
        .map_err(|_| AppError::Internal("Invalid encrypted ML-KEM secret encoding".into()))?;
    let nonce = BASE64_STANDARD
        .decode(sk_nonce_b64)
        .map_err(|_| AppError::Internal("Invalid ML-KEM secret nonce encoding".into()))?;
    let plaintext = aes_gcm::decrypt_aes_gcm(&key, &nonce, &ciphertext)?;
    String::from_utf8(plaintext).map_err(|_| AppError::Internal("ML-KEM secret is not valid UTF-8".into()))
}

async fn load_server_mlkem_keypair(db: &PgPool, wallet: &str) -> Result<Option<MlKemKeypairFile>, AppError> {
    let wallet = wallet.trim().to_lowercase();
    let row = sqlx::query(
        "select wallet, kem, pk_b64, sk_b64, sk_b64_enc, sk_nonce_b64 from wallet_mlkem_keys where wallet = $1",
    )
    .bind(&wallet)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    row.map(|row| {
        let sk_b64_enc: Option<String> = row.get("sk_b64_enc");
        let sk_nonce_b64: Option<String> = row.get("sk_nonce_b64");
        let sk_b64 = match (sk_b64_enc, sk_nonce_b64) {
            (Some(cipher), Some(nonce)) => decrypt_mlkem_secret(&cipher, &nonce)?,
            _ => row.get("sk_b64"),
        };
        Ok(MlKemKeypairFile {
            wallet: row.get("wallet"),
            kem: row.get("kem"),
            pk_b64: row.get("pk_b64"),
            sk_b64,
        })
    })
    .transpose()
}

async fn persist_server_mlkem_keypair(
    db: &PgPool,
    keys: &MlKemKeypairFile,
    source: &str,
) -> Result<MlKemKeypairFile, AppError> {
    let (sk_b64_enc, sk_nonce_b64) = encrypt_mlkem_secret(&keys.sk_b64)?;
    let row = sqlx::query(
        r#"
        insert into wallet_mlkem_keys (
            wallet, kem, pk_b64, sk_b64, sk_b64_enc, sk_nonce_b64, source, created_at, updated_at
        )
        values ($1, $2, $3, null, $4, $5, $6, now(), now())
        on conflict (wallet) do update
            set pk_b64 = excluded.pk_b64,
                sk_b64 = null,
                sk_b64_enc = excluded.sk_b64_enc,
                sk_nonce_b64 = excluded.sk_nonce_b64,
                source = excluded.source,
                updated_at = now()
        returning wallet, kem, pk_b64, sk_b64_enc, sk_nonce_b64
        "#,
    )
    .bind(&keys.wallet)
    .bind(&keys.kem)
    .bind(&keys.pk_b64)
    .bind(&sk_b64_enc)
    .bind(&sk_nonce_b64)
    .bind(source)
    .fetch_one(db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(MlKemKeypairFile {
        wallet: row.get("wallet"),
        kem: row.get("kem"),
        pk_b64: row.get("pk_b64"),
        sk_b64: decrypt_mlkem_secret(&row.get::<String, _>("sk_b64_enc"), &row.get::<String, _>("sk_nonce_b64"))?,
    })
}

async fn load_or_create_server_mlkem_keypair(
    db: &PgPool,
    owner_wallet: &str,
) -> Result<MlKemKeypairFile, AppError> {
    let wallet = owner_wallet.trim().to_lowercase();
    if wallet.is_empty() {
        return Err(AppError::BadRequest("wallet is empty".into()));
    }

    if let Some(keys) = load_server_mlkem_keypair(db, &wallet).await? {
        return Ok(keys);
    }

    if let Some(keys) = load_mlkem_keypair_if_exists(&wallet)
        .map_err(|e| AppError::Internal(format!("mlkem keystore: {e}")))?
    {
        return persist_server_mlkem_keypair(db, &keys, "filesystem_import").await;
    }

    let kp = mlkem_generate_keypair_b64();
    let keys = MlKemKeypairFile {
        wallet: wallet.clone(),
        kem: "mlkem768".into(),
        pk_b64: kp.pk_b64,
        sk_b64: kp.sk_b64,
    };

    persist_server_mlkem_keypair(db, &keys, "generated").await
}

fn billing_trial_days() -> i64 {
    std::env::var("BILLING_TRIAL_DAYS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(30)
}

fn billing_plan_amount_usd() -> i32 {
    std::env::var("BILLING_PLAN_USD")
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(8)
}

fn billing_enforced() -> bool {
    std::env::var("BILLING_ENFORCEMENT")
        .ok()
        .map(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

async fn ensure_account_subscription_record(db: &PgPool, wallet: &str) -> Result<(), AppError> {
    let trial_days = billing_trial_days();
    let plan_amount = billing_plan_amount_usd();
    sqlx::query(
        r#"
        insert into account_subscriptions (
            wallet,
            billing_status,
            trial_started_at,
            trial_ends_at,
            plan_amount_usd,
            created_at,
            updated_at
        )
        values ($1, 'trialing', now(), now() + make_interval(days => $2::int), $3, now(), now())
        on conflict (wallet) do nothing
        "#,
    )
    .bind(wallet)
    .bind(trial_days as i32)
    .bind(plan_amount)
    .execute(db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

async fn account_status_value(db: &PgPool, wallet: &str) -> Result<serde_json::Value, AppError> {
    ensure_account_subscription_record(db, wallet).await?;

    let row = sqlx::query(
        r#"
        select
            wallet,
            billing_status,
            trial_started_at,
            trial_ends_at,
            paid_through,
            stripe_customer_id,
            stripe_subscription_id,
            plan_amount_usd,
            created_at,
            updated_at
        from account_subscriptions
        where wallet = $1
        "#,
    )
    .bind(wallet)
    .fetch_one(db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let trial_ends_at: chrono::DateTime<chrono::Utc> = row.get("trial_ends_at");
    let paid_through: Option<chrono::DateTime<chrono::Utc>> = row.get("paid_through");
    let now = chrono::Utc::now();
    let billing_status: String = row.get("billing_status");
    let in_trial = billing_status == "trialing" && trial_ends_at > now;
    let subscription_active = matches!(billing_status.as_str(), "active" | "paid")
        && paid_through.map(|value| value > now).unwrap_or(true);
    let write_access = in_trial || subscription_active || !billing_enforced();

    Ok(json!({
        "wallet": row.get::<String,_>("wallet"),
        "billing_status": billing_status,
        "trial_started_at": row.get::<chrono::DateTime<chrono::Utc>,_>("trial_started_at"),
        "trial_ends_at": trial_ends_at,
        "paid_through": paid_through,
        "stripe_customer_id": row.get::<Option<String>,_>("stripe_customer_id"),
        "stripe_subscription_id": row.get::<Option<String>,_>("stripe_subscription_id"),
        "plan_amount_usd": row.get::<i32,_>("plan_amount_usd"),
        "billing_enforced": billing_enforced(),
        "in_trial": in_trial,
        "subscription_active": subscription_active,
        "write_access": write_access,
        "created_at": row.get::<chrono::DateTime<chrono::Utc>,_>("created_at"),
        "updated_at": row.get::<chrono::DateTime<chrono::Utc>,_>("updated_at")
    }))
}

fn build_share_event_payload(
    recipient_wallet: Option<&str>,
    recipient_chain: Option<&str>,
    note: Option<&str>,
    envelope_id: uuid::Uuid,
    signature: Option<&str>,
    recipient_name: Option<&str>,
    recipient_email: Option<&str>,
    recipient_phone: Option<&str>,
    access_token_hash: Option<&str>,
) -> serde_json::Value {
    json!({
        "recipient_wallet": recipient_wallet,
        "recipient_chain": recipient_chain,
        "recipient_name": recipient_name,
        "note": note,
        "envelope_id": envelope_id,
        "signature": signature,
        "recipient_email": recipient_email,
        "recipient_phone": recipient_phone,
        "access_token_hash": access_token_hash
    })
}

fn device_id_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-device-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn ip_from_headers(headers: &HeaderMap) -> Option<String> {
    header_value(headers, "x-forwarded-for")
        .or_else(|| header_value(headers, "x-real-ip"))
        .map(|value| value.split(',').next().unwrap_or("").trim().to_string())
        .filter(|value| !value.is_empty())
}

fn user_agent_from_headers(headers: &HeaderMap) -> Option<String> {
    header_value(headers, "user-agent")
}

async fn require_wallet_from_headers(st: &AppState, headers: &HeaderMap) -> Result<String, AppError> {
    Ok(require_session_from_headers(st, headers).await?.wallet)
}

async fn require_session_from_headers(
    st: &AppState,
    headers: &HeaderMap,
) -> Result<WalletSession, AppError> {
    let sid = headers
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Auth("Missing x-session-id".into()))?;

    st.auth
        .get_session(sid, device_id_from_headers(headers).as_deref())
        .await
        ?
        .ok_or_else(|| AppError::Auth("Invalid or expired session".into()))
}

fn token_hash_hex(token: &str) -> String {
    hex::encode(pqc_sha3::sha3_256_bytes(token.as_bytes()))
}

fn access_token_hash_hex(token: &str) -> String {
    token_hash_hex(token)
}

type HmacSha256 = Hmac<Sha256>;

fn load_audit_hmac_key() -> Option<Vec<u8>> {
    if let Ok(raw) = std::env::var("AUDIT_HMAC_KEY_B64") {
        return BASE64_STANDARD.decode(raw.trim()).ok();
    }
    std::env::var("MLKEM_DB_MASTER_KEY_B64")
        .ok()
        .and_then(|raw| BASE64_STANDARD.decode(raw.trim()).ok())
}

fn audit_key_id() -> &'static str {
    if std::env::var("AUDIT_HMAC_KEY_B64").is_ok() {
        "audit_hmac_env"
    } else if std::env::var("MLKEM_DB_MASTER_KEY_B64").is_ok() {
        "mlkem_db_master_fallback"
    } else {
        "unsigned"
    }
}

fn sign_hmac_b64(bytes: &[u8]) -> Option<String> {
    let key = load_audit_hmac_key()?;
    let mut mac = HmacSha256::new_from_slice(&key).ok()?;
    mac.update(bytes);
    Some(BASE64_STANDARD.encode(mac.finalize().into_bytes()))
}

fn default_document_policy() -> serde_json::Value {
    json!({
        "allow_guest_sign": false,
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
    actor_chain: &str,
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
              where s.doc_id = d.id
                and s.recipient_wallet is not null
                and (
                  (coalesce(s.recipient_chain, '') = 'evm' and $3 = 'evm' and lower(s.recipient_wallet) = lower($2))
                  or
                  (coalesce(s.recipient_chain, '') = 'sol' and $3 = 'sol' and s.recipient_wallet = $2)
                  or
                  (s.recipient_chain is null and (
                    ($2 like '0x%' and lower(s.recipient_wallet) = lower($2))
                    or
                    ($2 not like '0x%' and s.recipient_wallet = $2)
                  ))
                )
            ) as shared_with_actor
        from documents d
        where d.id = $1
          and d.is_deleted = false
        "#,
    )
    .bind(doc_id)
    .bind(actor_wallet)
    .bind(actor_chain)
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

fn event_chain_hash_hex(
    doc_id: uuid::Uuid,
    actor_wallet: &str,
    event_type: &str,
    payload: &serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
    prev_event_hash_hex: Option<&str>,
) -> Result<String, AppError> {
    let canonical = canonical_json(&json!({
        "doc_id": doc_id,
        "actor_wallet": actor_wallet,
        "event_type": event_type,
        "payload": payload,
        "created_at": created_at.to_rfc3339(),
        "prev_event_hash_hex": prev_event_hash_hex
    }));
    Ok(hex::encode(pqc_sha3::sha3_256_bytes(&canonical)))
}

async fn insert_document_event(
    db: &PgPool,
    doc_id: uuid::Uuid,
    actor_wallet: &str,
    event_type: &str,
    payload: serde_json::Value,
) -> Result<uuid::Uuid, AppError> {
    let previous = crate::sqlx::query(
        r#"
        select event_hash_hex
        from document_events
        where doc_id = $1
        order by created_at desc, id desc
        limit 1
        "#,
    )
    .bind(doc_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    let prev_event_hash_hex = previous.and_then(|row| row.get::<Option<String>, _>("event_hash_hex"));
    let created_at = chrono::Utc::now();
    let event_hash_hex = event_chain_hash_hex(
        doc_id,
        actor_wallet,
        event_type,
        &payload,
        created_at,
        prev_event_hash_hex.as_deref(),
    )?;
    let event_hmac_b64 = sign_hmac_b64(event_hash_hex.as_bytes());
    let id = uuid::Uuid::new_v4();

    crate::sqlx::query(
        r#"
        insert into document_events (
            id,
            doc_id,
            actor_wallet,
            event_type,
            payload,
            created_at,
            prev_event_hash_hex,
            event_hash_hex,
            event_hmac_b64
        )
        values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(id)
    .bind(doc_id)
    .bind(actor_wallet)
    .bind(event_type)
    .bind(payload)
    .bind(created_at)
    .bind(prev_event_hash_hex)
    .bind(&event_hash_hex)
    .bind(event_hmac_b64)
    .execute(db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(id)
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

async fn build_document_envelope(
    db: &PgPool,
    owner_wallet: &str,
    document_id: uuid::Uuid,
    label: Option<&str>,
    mime_type: &str,
    plaintext: &[u8],
) -> Result<(Vec<u8>, String), AppError> {
    let keys = load_or_create_server_mlkem_keypair(db, owner_wallet).await?;
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

async fn decrypt_document_envelope(
    db: &PgPool,
    owner_wallet: &str,
    encrypted_bytes: &[u8],
) -> Result<Vec<u8>, AppError> {
    let keys = load_or_create_server_mlkem_keypair(db, owner_wallet).await?;
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
        decrypt_document_envelope(&st.db, &access.owner_wallet, &stored).await?
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

fn default_share_expiry_hours() -> i64 {
    std::env::var("DEFAULT_SHARE_EXPIRY_HOURS")
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(24 * 7)
}

fn clamp_share_expiry_hours(hours: Option<i64>) -> i64 {
    hours.unwrap_or_else(default_share_expiry_hours).clamp(1, 24 * 30)
}

fn public_guest_attestation_enabled() -> bool {
    std::env::var("ALLOW_PUBLIC_GUEST_ATTESTATION")
        .ok()
        .map(|value| bool_from_form_text(&value))
        .unwrap_or(false)
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

fn derive_share_status(
    has_wallet_route: bool,
    has_provider_request: bool,
    deliveries: &[DeliveryOutcome],
    delivery_errors: &[String],
) -> &'static str {
    if has_wallet_route {
        if has_provider_request
            && (delivery_errors.iter().next().is_some()
                || deliveries.iter().any(|outcome| outcome.status != "sent" && outcome.channel != "wallet"))
        {
            "wallet_shared_with_delivery_issues"
        } else {
            "wallet_shared"
        }
    } else if deliveries.iter().any(|outcome| outcome.status == "sent") {
        "sent"
    } else if has_provider_request {
        "delivery_issue"
    } else {
        "created"
    }
}

fn active_inbox_status(status: &str) -> bool {
    matches!(
        status,
        "wallet_shared" | "wallet_shared_with_delivery_issues" | "sent" | "created" | "delivery_issue" | "opened"
    )
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
        build_document_envelope(&st.db, owner_wallet, id, label.as_deref(), &mime_type, bytes).await?;
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

async fn evm_nonce_handler_app(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<EvmNonceResponse>, AppError> {
    let (session_id, nonce) = st.auth.create_nonce().await?;
    let message = evm_login_message(&nonce);
    let _ = headers;
    Ok(Json(EvmNonceResponse {
        session_id,
        nonce,
        message,
    }))
}

async fn evm_verify_handler_app(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<EvmVerifyRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let sid = body.session_id.trim();
    let address = body.address.trim().to_lowercase();
    let signature = body.signature.trim();

    if sid.is_empty() {
        return Err(AppError::Auth("Missing session_id".into()));
    }
    if address.is_empty() {
        return Err(AppError::Auth("Empty address".into()));
    }
    if signature.is_empty() {
        return Err(AppError::Auth("Empty signature".into()));
    }

    let nonce = st
        .auth
        .take_nonce(sid)
        .await?
        .ok_or_else(|| AppError::Auth("Unknown or expired session".into()))?;

    let message = evm_login_message(&nonce);
    let recovered = verify_evm_signature(&message, signature)
        .map_err(|_| AppError::Auth("Invalid signature".into()))?
        .to_lowercase();

    if recovered != address {
        return Err(AppError::Auth("Signature does not match address".into()));
    }

    let session = st
        .auth
        .bind_wallet(
            sid.to_string(),
            address.clone(),
            "evm",
            device_id_from_headers(&headers).as_deref(),
            user_agent_from_headers(&headers).as_deref(),
            ip_from_headers(&headers).as_deref(),
        )
        .await?;

    let keys = load_or_create_server_mlkem_keypair(&st.db, &address).await?;

    Ok(Json(json!({
        "ok": true,
        "session_id": session.session_id,
        "wallet": address,
        "chain": "evm",
        "mlkem_pk_b64": keys.pk_b64
    })))
}

async fn sol_nonce_handler_app(
    State(st): State<AppState>,
) -> Result<Json<identity_web::sol::SolNonceResponse>, AppError> {
    let (session_id, nonce) = st.auth.create_nonce().await?;
    let message = identity_web::sol::sol_login_message(&nonce);
    Ok(Json(identity_web::sol::SolNonceResponse {
        session_id,
        nonce,
        message,
    }))
}

async fn sol_verify_handler_app(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<identity_web::sol::SolVerifyRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let session_id = body.session_id.trim();
    let address = body.address.trim();
    let signature = body.signature.trim();

    if session_id.is_empty() {
        return Err(AppError::Auth("Missing session_id".into()));
    }
    if address.is_empty() {
        return Err(AppError::Auth("Empty address".into()));
    }
    if signature.is_empty() {
        return Err(AppError::Auth("Empty signature".into()));
    }

    let nonce = st
        .auth
        .take_nonce(session_id)
        .await?
        .ok_or_else(|| AppError::Auth("Unknown or expired session".into()))?;
    let message = identity_web::sol::sol_login_message(&nonce);
    verify_solana_signature(&message, address, signature)
        .map_err(|_| AppError::Auth("Invalid Solana signature".into()))?;
    let session = st
        .auth
        .bind_wallet(
            session_id.to_string(),
            address.to_string(),
            "sol",
            device_id_from_headers(&headers).as_deref(),
            user_agent_from_headers(&headers).as_deref(),
            ip_from_headers(&headers).as_deref(),
        )
        .await?;

    let keys = load_or_create_server_mlkem_keypair(&st.db, address).await?;

    Ok(Json(json!({
        "ok": true,
        "session_id": session.session_id,
        "wallet": address,
        "chain": "sol",
        "mlkem_pk_b64": keys.pk_b64
    })))
}

// ================================================================
// DOCUMENT LIST
// ================================================================

async fn list_docs_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    let session = require_session_from_headers(&st, &headers).await?;
    let wallet = normalize_wallet_for_chain(
        &session.wallet,
        canonical_chain(&session.chain).unwrap_or_else(|| infer_wallet_chain(&session.wallet)),
    );
    let chain = canonical_chain(&session.chain).unwrap_or_else(|| infer_wallet_chain(&session.wallet));

    let rows = sqlx::query(
        r#"
        select
            d.id,
            d.owner_wallet,
            d.hash_hex,
            d.label,
            d.created_at,
            d.version,
            d.mime_type,
            d.parent_id,
            d.arweave_tx,
            (
              select max(e.created_at)
              from document_events e
              where e.doc_id = d.id
                and e.event_type in ('SIGN', 'ENVELOPE_COMPLETED', 'AGENT_SIGN')
            ) as last_signed_at,
            case when d.owner_wallet = $1 then 'owned' else 'shared' end as access_kind
        from documents d
        where d.is_deleted = false
          and (
            d.owner_wallet = $1
            or exists (
              select 1
              from document_shares s
              where s.doc_id = d.id
                and s.recipient_wallet is not null
                and s.status not in ('dismissed')
                and (
                  (coalesce(s.recipient_chain, '') = 'evm' and $2 = 'evm' and lower(s.recipient_wallet) = lower($1))
                  or
                  (coalesce(s.recipient_chain, '') = 'sol' and $2 = 'sol' and s.recipient_wallet = $1)
                  or
                  (s.recipient_chain is null and (
                    ($1 like '0x%' and lower(s.recipient_wallet) = lower($1))
                    or
                    ($1 not like '0x%' and s.recipient_wallet = $1)
                  ))
                )
            )
          )
        order by d.created_at desc
        "#,
    )
    .bind(wallet)
    .bind(chain)
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
                    "arweave_tx": r.get::<Option<String>,_>("arweave_tx"),
                    "last_signed_at": r.get::<Option<chrono::DateTime<chrono::Utc>>,_>("last_signed_at"),
                    "access_kind": r.get::<String,_>("access_kind")
                })
            })
            .collect(),
    ))
}

async fn list_shared_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    let session = require_session_from_headers(&st, &headers).await?;

    let rows = sqlx::query(
        r#"
        select
            s.doc_id,
            s.envelope_id,
            s.recipient_wallet,
            s.recipient_chain,
            s.recipient_name,
            s.recipient_email,
            s.recipient_phone,
            s.status,
            s.delivery_json,
            s.expires_at,
            s.revoked_at,
            s.one_time_use,
            s.download_allowed,
            s.created_at,
            d.label,
            d.hash_hex,
            d.version
        from document_shares s
        join documents d on d.id = s.doc_id
        where s.sender_wallet = $1
          and d.is_deleted = false
        order by s.created_at desc
        "#,
    )
    .bind(session.wallet)
    .fetch_all(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| {
                json!({
                    "doc_id": r.get::<uuid::Uuid,_>("doc_id"),
                    "envelope_id": r.get::<uuid::Uuid,_>("envelope_id"),
                    "recipient_wallet": r.get::<Option<String>,_>("recipient_wallet"),
                    "recipient_chain": r.get::<Option<String>,_>("recipient_chain"),
                    "recipient_name": r.get::<Option<String>,_>("recipient_name"),
                    "recipient_email": r.get::<Option<String>,_>("recipient_email"),
                    "recipient_phone": r.get::<Option<String>,_>("recipient_phone"),
                    "status": r.get::<String,_>("status"),
                    "delivery_json": r.get::<serde_json::Value,_>("delivery_json"),
                    "expires_at": r.get::<Option<chrono::DateTime<chrono::Utc>>,_>("expires_at"),
                    "revoked_at": r.get::<Option<chrono::DateTime<chrono::Utc>>,_>("revoked_at"),
                    "one_time_use": r.get::<bool,_>("one_time_use"),
                    "download_allowed": r.get::<bool,_>("download_allowed"),
                    "created_at": r.get::<chrono::DateTime<chrono::Utc>,_>("created_at"),
                    "label": r.get::<Option<String>,_>("label"),
                    "hash_hex": r.get::<String,_>("hash_hex"),
                    "version": r.get::<i32,_>("version")
                })
            })
            .collect(),
    ))
}

async fn list_shared_activity_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    let session = require_session_from_headers(&st, &headers).await?;
    let wallet = normalize_wallet_for_chain(
        &session.wallet,
        canonical_chain(&session.chain).unwrap_or_else(|| infer_wallet_chain(&session.wallet)),
    );
    let chain = canonical_chain(&session.chain).unwrap_or_else(|| infer_wallet_chain(&session.wallet));

    let rows = sqlx::query(
        r#"
        select
            e.id,
            e.doc_id,
            e.event_type,
            e.actor_wallet,
            e.payload,
            e.created_at,
            d.label,
            d.owner_wallet,
            d.version
        from document_events e
        join documents d on d.id = e.doc_id
        where d.is_deleted = false
          and (
            d.owner_wallet = $1
            or exists (
              select 1
              from document_shares s
              where s.doc_id = d.id
                and s.recipient_wallet is not null
                and s.status not in ('dismissed')
                and (
                  (coalesce(s.recipient_chain, '') = 'evm' and $2 = 'evm' and lower(s.recipient_wallet) = lower($1))
                  or
                  (coalesce(s.recipient_chain, '') = 'sol' and $2 = 'sol' and s.recipient_wallet = $1)
                  or
                  (s.recipient_chain is null and (
                    ($1 like '0x%' and lower(s.recipient_wallet) = lower($1))
                    or
                    ($1 not like '0x%' and s.recipient_wallet = $1)
                  ))
                )
            )
          )
        order by e.created_at desc
        limit 120
        "#,
    )
    .bind(&wallet)
    .bind(chain)
    .fetch_all(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(
        rows.into_iter()
            .map(|row| {
                json!({
                    "id": row.get::<uuid::Uuid,_>("id"),
                    "doc_id": row.get::<uuid::Uuid,_>("doc_id"),
                    "event_type": row.get::<String,_>("event_type"),
                    "actor_wallet": row.get::<String,_>("actor_wallet"),
                    "payload": row.get::<serde_json::Value,_>("payload"),
                    "created_at": row.get::<chrono::DateTime<chrono::Utc>,_>("created_at"),
                    "label": row.get::<Option<String>,_>("label"),
                    "owner_wallet": row.get::<String,_>("owner_wallet"),
                    "version": row.get::<i32,_>("version")
                })
            })
            .collect(),
    ))
}

async fn overview_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let session = require_session_from_headers(&st, &headers).await?;
    let wallet = normalize_wallet_for_chain(
        &session.wallet,
        canonical_chain(&session.chain).unwrap_or_else(|| infer_wallet_chain(&session.wallet)),
    );
    let chain = canonical_chain(&session.chain).unwrap_or_else(|| infer_wallet_chain(&session.wallet));

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
        select
            count(*) filter (where sender_wallet = $1) as total_shares,
            count(*) filter (
                where recipient_wallet is not null
                  and status in ('wallet_shared', 'wallet_shared_with_delivery_issues', 'sent', 'created', 'delivery_issue', 'opened')
                  and (
                    (coalesce(recipient_chain, '') = 'evm' and $2 = 'evm' and lower(recipient_wallet) = lower($1))
                    or
                    (coalesce(recipient_chain, '') = 'sol' and $2 = 'sol' and recipient_wallet = $1)
                    or
                    (recipient_chain is null and (
                      ($1 like '0x%' and lower(recipient_wallet) = lower($1))
                      or
                      ($1 not like '0x%' and recipient_wallet = $1)
                    ))
                  )
            ) as inbox_pending
        from document_shares
        "#,
    )
    .bind(&wallet)
    .bind(chain)
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
            "total_shares": share_counts.get::<i64,_>("total_shares"),
            "inbox_pending": share_counts.get::<i64,_>("inbox_pending")
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

async fn account_status_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let session = require_session_from_headers(&st, &headers).await?;
    let wallet = normalize_wallet_for_chain(
        &session.wallet,
        canonical_chain(&session.chain).unwrap_or_else(|| infer_wallet_chain(&session.wallet)),
    );
    Ok(Json(account_status_value(&st.db, &wallet).await?))
}

// ================================================================
// DOCUMENT EVENTS
// ================================================================

async fn list_doc_events_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    let session = require_session_from_headers(&st, &headers).await?;
    let wallet = session.wallet.clone();
    load_document_access_record(&st.db, id, &wallet, &session.chain).await?;

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
    let session = require_session_from_headers(&st, &headers).await?;
    let wallet = session.wallet.clone();
    let access = load_document_access_record(&st.db, id, &wallet, &session.chain).await?;

    let doc_row = sqlx::query(
        r#"
        select id, owner_wallet, hash_hex, label, file_size, mime_type, storage_path, version, parent_id, arweave_tx, created_at
             , (
                 select max(e.created_at)
                 from document_events e
                 where e.doc_id = documents.id
                   and e.event_type in ('SIGN', 'ENVELOPE_COMPLETED', 'AGENT_SIGN')
               ) as last_signed_at
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
            recipient_chain,
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
            "created_at": doc_row.get::<chrono::DateTime<chrono::Utc>,_>("created_at"),
            "last_signed_at": doc_row.get::<Option<chrono::DateTime<chrono::Utc>>,_>("last_signed_at")
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
            "recipient_chain": row.get::<Option<String>,_>("recipient_chain"),
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
    let session = require_session_from_headers(&st, &headers).await?;
    let wallet = session.wallet.clone();
    let doc = load_document_access_record(&st.db, id, &wallet, &session.chain).await?;

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
    let session = require_session_from_headers(&st, &headers).await?;
    let wallet = session.wallet.clone();
    let doc = load_document_access_record(&st.db, id, &wallet, &session.chain).await?;

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
    let session = require_session_from_headers(&st, &headers).await?;
    let wallet = session.wallet.clone();
    let doc = load_document_access_record(&st.db, id, &wallet, &session.chain).await?;

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
    let session = require_session_from_headers(&st, &headers).await?;
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

async fn list_agents_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    let session = require_session_from_headers(&st, &headers).await?;
    let wallet = session.wallet.clone();

    let rows = sqlx::query(
        r#"
        select id, owner_wallet, label, provider, model, capabilities_json, is_active, created_at
        from agent_identities
        where owner_wallet = $1
        order by created_at desc
        "#,
    )
    .bind(&wallet)
    .fetch_all(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(
        rows.into_iter()
            .map(|row| {
                json!({
                    "id": row.get::<uuid::Uuid,_>("id"),
                    "owner_wallet": row.get::<String,_>("owner_wallet"),
                    "label": row.get::<String,_>("label"),
                    "provider": row.get::<Option<String>,_>("provider"),
                    "model": row.get::<Option<String>,_>("model"),
                    "capabilities": row.get::<serde_json::Value,_>("capabilities_json"),
                    "is_active": row.get::<bool,_>("is_active"),
                    "created_at": row.get::<chrono::DateTime<chrono::Utc>,_>("created_at")
                })
            })
            .collect(),
    ))
}

async fn rotate_agent_token_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let session = require_session_from_headers(&st, &headers).await?;
    let wallet = session.wallet.clone();
    let token = format!("agt_{}", uuid::Uuid::new_v4().simple());
    let token_hash = token_hash_hex(&token);

    let row = sqlx::query(
        r#"
        update agent_identities
        set api_token_hash = $3, updated_at = now()
        where id = $1
          and owner_wallet = $2
          and is_active = true
        returning label, provider, model, capabilities_json
        "#,
    )
    .bind(id)
    .bind(&wallet)
    .bind(&token_hash)
    .fetch_optional(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let Some(row) = row else {
        return Err(AppError::NotFound("Agent not found".into()));
    };

    Ok(Json(json!({
        "ok": true,
        "agent_id": id,
        "label": row.get::<String,_>("label"),
        "provider": row.get::<Option<String>,_>("provider"),
        "model": row.get::<Option<String>,_>("model"),
        "capabilities": row.get::<serde_json::Value,_>("capabilities_json"),
        "token": token
    })))
}

async fn revoke_agent_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let session = require_session_from_headers(&st, &headers).await?;
    let wallet = session.wallet.clone();

    let row = sqlx::query(
        r#"
        update agent_identities
        set is_active = false, updated_at = now()
        where id = $1
          and owner_wallet = $2
        returning label
        "#,
    )
    .bind(id)
    .bind(&wallet)
    .fetch_optional(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let Some(row) = row else {
        return Err(AppError::NotFound("Agent not found".into()));
    };

    Ok(Json(json!({
        "ok": true,
        "agent_id": id,
        "label": row.get::<String,_>("label"),
        "revoked": true
    })))
}

async fn agent_review_doc_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let agent = require_agent_from_headers(&st, &headers).await?;
    let doc = load_document_access_record(
        &st.db,
        id,
        &agent.owner_wallet,
        infer_wallet_chain(&agent.owner_wallet),
    )
    .await?;

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
    let doc = load_document_access_record(
        &st.db,
        id,
        &agent.owner_wallet,
        infer_wallet_chain(&agent.owner_wallet),
    )
    .await?;
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
    let parent = load_document_access_record(
        &st.db,
        parent_doc_id,
        &agent.owner_wallet,
        infer_wallet_chain(&agent.owner_wallet),
    )
    .await?;
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
    let session = require_session_from_headers(&st, &headers).await?;
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
    let session = require_session_from_headers(&st, &headers).await?;
    let wallet = session.wallet.clone();
    let parent = load_document_access_record(&st.db, parent_doc_id, &wallet, &session.chain).await?;

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
    let session = require_session_from_headers(&st, &headers).await?;
    let wallet = session.wallet.clone();
    let doc = load_document_access_record(&st.db, id, &wallet, &session.chain).await?;

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
        "owner_wallet": doc.owner_wallet,
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
    let session = require_session_from_headers(&st, &headers).await?;
    let access = load_document_access_record(&st.db, id, &session.wallet, &session.chain).await?;
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
    let session = require_session_from_headers(&st, &headers).await?;
    let wallet = session.wallet.clone();
    let doc = load_document_access_record(&st.db, id, &wallet, &session.chain).await?;

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
    let session = require_session_from_headers(&st, &headers).await?;
    let wallet = session.wallet.clone();
    let doc = load_document_access_record(&st.db, doc_id, &wallet, &session.chain)
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
        "sol_ed25519" => {
            verify_solana_signature(&canonical_message, &wallet, &body.signature)?;

            json!({
                "signature_type": signature_type,
                "verified_wallet": wallet,
                "chain": "sol"
            })
        }
        "pq_dilithium3" | "pq_mldsa65" => {
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
    let session = require_session_from_headers(&st, &headers).await?;
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
    let session = require_session_from_headers(&st, &headers).await?;
    let sender = session.wallet.clone();
    let sender_chain = canonical_chain(&session.chain).unwrap_or_else(|| infer_wallet_chain(&sender));
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
    let access_token_hash = access_token_hash_hex(&access_token);
    let expires_in_hours = clamp_share_expiry_hours(body.expires_in_hours);
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(expires_in_hours);
    let one_time_use = body.one_time_use.unwrap_or(false);
    let download_allowed = body.download_allowed.unwrap_or(true);
    let allow_guest_sign = body.allow_guest_sign;
    let recipient_chain = requested_wallet
        .as_deref()
        .map(|wallet| {
            body.recipient_chain
                .as_deref()
                .and_then(canonical_chain)
                .unwrap_or_else(|| infer_wallet_chain(wallet))
                .to_string()
        });
    let recipient_wallet = requested_wallet
        .as_deref()
        .map(|wallet| {
            normalize_wallet_for_chain(
                wallet,
                recipient_chain
                    .as_deref()
                    .unwrap_or_else(|| infer_wallet_chain(wallet)),
            )
        });
    let recipient_name = body
        .recipient_name
        .clone()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let signing_url = envelope_signing_url(&access_token);
    let has_wallet_route = recipient_wallet.is_some();
    let has_provider_request = requested_email.is_some() || requested_phone.is_some();
    let initial_status = if has_wallet_route { "wallet_shared" } else { "created" };

    sqlx::query(
        r#"insert into document_shares
        (doc_id, sender_wallet, recipient_wallet, recipient_chain, recipient_name, envelope_id, note, recipient_email, recipient_phone, access_token_hash, expires_at, one_time_use, download_allowed, allow_guest_sign, status, delivery_json)
        values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)"#,
    )
    .bind(doc_id)
    .bind(&sender)
    .bind(&recipient_wallet)
    .bind(&recipient_chain)
    .bind(&recipient_name)
    .bind(envelope_id)
    .bind(&body.note)
    .bind(&requested_email)
    .bind(&requested_phone)
    .bind(&access_token_hash)
    .bind(expires_at)
    .bind(one_time_use)
    .bind(download_allowed)
    .bind(allow_guest_sign)
    .bind(initial_status)
    .bind(json!([]))
    .execute(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let (mut deliveries, delivery_errors) = dispatch_share_deliveries(
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

    if let Some(wallet) = recipient_wallet.clone() {
        deliveries.insert(
            0,
            DeliveryOutcome {
                channel: "wallet",
                provider: "tidbit",
                recipient: wallet,
                external_id: Some(envelope_id.to_string()),
                status: "available_in_inbox",
            },
        );
    }

    let final_status = derive_share_status(
        has_wallet_route,
        has_provider_request,
        &deliveries,
        &delivery_errors,
    );

    sqlx::query("update document_shares set delivery_json = $2, status = $3 where access_token_hash = $1")
        .bind(&access_token_hash)
        .bind(serde_json::to_value(&deliveries).map_err(|e| AppError::Internal(e.to_string()))?)
        .bind(final_status)
        .execute(&st.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    insert_document_event(
        &st.db,
        doc_id,
        &sender,
        "SHARE",
        custody_payload(
            json!({
                "recipient_wallet": recipient_wallet,
                "recipient_chain": recipient_chain,
                "note": body.note,
                "envelope_id": envelope_id,
                "signature": body.signature,
                "recipient_name": recipient_name,
                "recipient_email": requested_email,
                "recipient_phone": requested_phone,
                "access_token_hash": access_token_hash,
                "expires_at": expires_at,
                "one_time_use": one_time_use,
                "download_allowed": download_allowed,
                "allow_guest_sign": allow_guest_sign
            }),
            &session,
            &headers,
        ),
    )
    .await?;

    for outcome in &deliveries {
        insert_document_event(
            &st.db,
            doc_id,
            &sender,
            "DELIVERY_DISPATCHED",
            custody_payload(
                json!({
                    "envelope_id": envelope_id,
                    "channel": outcome.channel,
                    "provider": outcome.provider,
                    "recipient": outcome.recipient,
                    "external_id": outcome.external_id,
                    "status": outcome.status,
                    "recipient_chain": recipient_chain,
                    "sender_chain": sender_chain
                }),
                &session,
                &headers,
            ),
        )
        .await?;
    }

    for error in &delivery_errors {
        insert_document_event(
            &st.db,
            doc_id,
            &sender,
            "DELIVERY_FAILED",
            custody_payload(
                json!({
                    "envelope_id": envelope_id,
                    "error": error
                }),
                &session,
                &headers,
            ),
        )
        .await?;
    }

    Ok(Json(json!({
        "ok": true,
        "envelope_id": envelope_id,
        "doc_id": doc_id,
        "label": label,
        "hash_hex": hash_hex,
        "recipient_wallet": recipient_wallet,
        "recipient_chain": recipient_chain,
        "recipient_name": recipient_name,
        "recipient_email": requested_email,
        "recipient_phone": requested_phone,
        "signing_url": signing_url,
        "status": final_status,
        "expires_at": expires_at,
        "one_time_use": one_time_use,
        "download_allowed": download_allowed,
        "allow_guest_sign": allow_guest_sign,
        "delivery": deliveries,
        "delivery_errors": delivery_errors
    })))
}

async fn revoke_share_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path((doc_id, envelope_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let session = require_session_from_headers(&st, &headers).await?;
    let sender = session.wallet.clone();

    let updated = sqlx::query(
        r#"
        update document_shares
        set
            revoked_at = now(),
            revoked_reason = 'sender_revoked',
            status = 'revoked'
        where doc_id = $1
          and envelope_id = $2
          and sender_wallet = $3
          and revoked_at is null
        returning recipient_wallet, recipient_chain, recipient_email, recipient_phone
        "#,
    )
    .bind(doc_id)
    .bind(envelope_id)
    .bind(&sender)
    .fetch_optional(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let Some(updated) = updated else {
        return Err(AppError::NotFound("Share not found or already revoked".into()));
    };

    insert_document_event(
        &st.db,
        doc_id,
        &sender,
        "SHARE_REVOKED",
        custody_payload(
            json!({
                "envelope_id": envelope_id,
                "recipient_wallet": updated.get::<Option<String>, _>("recipient_wallet"),
                "recipient_chain": updated.get::<Option<String>, _>("recipient_chain"),
                "recipient_email": updated.get::<Option<String>, _>("recipient_email"),
                "recipient_phone": updated.get::<Option<String>, _>("recipient_phone"),
                "reason": "sender_revoked"
            }),
            &session,
            &headers,
        ),
    )
    .await?;

    Ok(Json(json!({
        "ok": true,
        "doc_id": doc_id,
        "envelope_id": envelope_id,
        "status": "revoked"
    })))
}

async fn list_inbox_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let session = require_session_from_headers(&st, &headers).await?;
    let wallet = normalize_wallet_for_chain(&session.wallet, canonical_chain(&session.chain).unwrap_or_else(|| infer_wallet_chain(&session.wallet)));
    let chain = canonical_chain(&session.chain).unwrap_or_else(|| infer_wallet_chain(&session.wallet));

    let rows = sqlx::query(
        r#"
        select
            s.doc_id,
            s.sender_wallet,
            s.recipient_wallet,
            s.recipient_chain,
            s.envelope_id,
            s.note,
            s.status,
            d.label,
            d.hash_hex,
            d.version
        from document_shares s
        join documents d on d.id = s.doc_id
        where s.recipient_wallet is not null
          and (
            (coalesce(s.recipient_chain, '') = 'evm' and $2 = 'evm' and lower(s.recipient_wallet) = lower($1))
            or
            (coalesce(s.recipient_chain, '') = 'sol' and $2 = 'sol' and s.recipient_wallet = $1)
            or
            (s.recipient_chain is null and (
              ($1 like '0x%' and lower(s.recipient_wallet) = lower($1))
              or
              ($1 not like '0x%' and s.recipient_wallet = $1)
            ))
          )
          and s.status in ('wallet_shared', 'wallet_shared_with_delivery_issues', 'sent', 'created', 'delivery_issue', 'opened')
          and d.is_deleted = false
        order by d.created_at desc
        "#,
    )
    .bind(&wallet)
    .bind(chain)
    .fetch_all(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({
        "items": rows
            .into_iter()
            .map(|r| json!({
                "doc_id": r.get::<uuid::Uuid,_>("doc_id"),
                "sender_wallet": r.get::<String,_>("sender_wallet"),
                "recipient_wallet": r.get::<Option<String>,_>("recipient_wallet"),
                "recipient_chain": r.get::<Option<String>,_>("recipient_chain"),
                "envelope_id": r.get::<uuid::Uuid,_>("envelope_id"),
                "note": r.get::<Option<String>,_>("note"),
                "status": r.get::<String,_>("status"),
                "label": r.get::<Option<String>,_>("label"),
                "hash_hex": r.get::<String,_>("hash_hex"),
                "version": r.get::<i32,_>("version")
            }))
            .collect::<Vec<_>>()
    })))
}

async fn inbox_action_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(envelope_id): Path<uuid::Uuid>,
    Json(body): Json<InboxActionRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let session = require_session_from_headers(&st, &headers).await?;
    let wallet = normalize_wallet_for_chain(
        &session.wallet,
        canonical_chain(&session.chain).unwrap_or_else(|| infer_wallet_chain(&session.wallet)),
    );
    let chain = canonical_chain(&session.chain).unwrap_or_else(|| infer_wallet_chain(&session.wallet));
    let action = body.action.trim().to_ascii_lowercase();

    let row = sqlx::query(
        r#"
        select s.doc_id, s.status, s.recipient_wallet, s.recipient_chain
        from document_shares s
        join documents d on d.id = s.doc_id
        where s.envelope_id = $1
          and d.is_deleted = false
          and s.recipient_wallet is not null
          and (
            (coalesce(s.recipient_chain, '') = 'evm' and $3 = 'evm' and lower(s.recipient_wallet) = lower($2))
            or
            (coalesce(s.recipient_chain, '') = 'sol' and $3 = 'sol' and s.recipient_wallet = $2)
            or
            (s.recipient_chain is null and (
              ($2 like '0x%' and lower(s.recipient_wallet) = lower($2))
              or
              ($2 not like '0x%' and s.recipient_wallet = $2)
            ))
          )
        "#,
    )
    .bind(envelope_id)
    .bind(&wallet)
    .bind(chain)
    .fetch_optional(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let Some(row) = row else {
        return Err(AppError::NotFound("Inbox item not found".into()));
    };

    let doc_id: uuid::Uuid = row.get("doc_id");
    let next_status = match action.as_str() {
        "review" | "open" | "download" | "sign" => "accepted",
        "delete" | "dismiss" => "dismissed",
        _ => return Err(AppError::BadRequest("Unsupported inbox action".into())),
    };
    let event_type = match action.as_str() {
        "review" | "open" => "INBOX_REVIEWED",
        "download" => "INBOX_DOWNLOADED",
        "sign" => "INBOX_SIGNED",
        "delete" | "dismiss" => "INBOX_DISMISSED",
        _ => unreachable!(),
    };

    sqlx::query(
        "update document_shares set status = $2, viewed_at = coalesce(viewed_at, now()) where envelope_id = $1",
    )
    .bind(envelope_id)
    .bind(next_status)
    .execute(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    sqlx::query(
        "insert into document_events (doc_id, actor_wallet, event_type, payload) values ($1,$2,$3,$4)",
    )
    .bind(doc_id)
    .bind(&session.wallet)
    .bind(event_type)
    .bind(custody_payload(
        json!({
            "envelope_id": envelope_id,
            "inbox_action": action,
            "recipient_wallet": row.get::<Option<String>,_>("recipient_wallet"),
            "recipient_chain": row.get::<Option<String>,_>("recipient_chain"),
            "share_status": next_status
        }),
        &session,
        &headers,
    ))
    .execute(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({
        "ok": true,
        "doc_id": doc_id,
        "envelope_id": envelope_id,
        "status": next_status,
        "action": action
    })))
}

async fn public_envelope_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let token_hash = access_token_hash_hex(token.trim());
    let row = sqlx::query(
        r#"
        select
            s.id as share_id,
            s.doc_id,
            s.sender_wallet,
            s.recipient_wallet,
            s.recipient_chain,
            s.recipient_name,
            s.recipient_email,
            s.recipient_phone,
            s.note,
            s.envelope_id,
            s.status,
            s.viewed_at,
            s.delivery_json,
            s.annotation_json,
            s.expires_at,
            s.revoked_at,
            s.one_time_use,
            s.download_allowed,
            s.allow_guest_sign,
            s.completion_count,
            d.label,
            d.hash_hex,
            d.version,
            d.mime_type,
            d.storage_path,
            d.owner_wallet,
            d.parent_id,
            d.arweave_tx
        from document_shares s
        join documents d on d.id = s.doc_id
        where s.access_token_hash = $1
          and d.is_deleted = false
        "#,
    )
    .bind(&token_hash)
    .fetch_optional(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let Some(row) = row else {
        return Err(AppError::NotFound("Envelope not found".into()));
    };

    let doc_id: uuid::Uuid = row.get("doc_id");
    let envelope_id: uuid::Uuid = row.get("envelope_id");
    let status: String = row.get("status");
    let expires_at: Option<chrono::DateTime<chrono::Utc>> = row.get("expires_at");
    let revoked_at: Option<chrono::DateTime<chrono::Utc>> = row.get("revoked_at");
    let one_time_use: bool = row.get("one_time_use");
    let download_allowed: bool = row.get("download_allowed");
    let completion_count: i32 = row.get("completion_count");
    let viewed_at: Option<chrono::DateTime<chrono::Utc>> = row.get("viewed_at");
    if revoked_at.is_some() {
        return Err(AppError::Forbidden("This share link has been revoked".into()));
    }
    if expires_at.map(|value| value <= chrono::Utc::now()).unwrap_or(false) {
        return Err(AppError::Forbidden("This share link has expired".into()));
    }
    if one_time_use && completion_count > 0 {
        return Err(AppError::Forbidden("This one-time share link has already been used".into()));
    }
    let owner_wallet: String = row.get("owner_wallet");
    let policy = load_document_policy(&st.db, doc_id, &owner_wallet).await?;
    let allow_guest_sign = row
        .get::<Option<bool>, _>("allow_guest_sign")
        .unwrap_or_else(|| policy.get("allow_guest_sign").and_then(|value| value.as_bool()).unwrap_or(false));
    let allowed_signature_types = {
        let mut modes = Vec::new();
        if allow_guest_sign && public_guest_attestation_enabled() {
            modes.push("guest_attestation");
        }
        modes.push("evm_personal_sign");
        modes.push("sol_ed25519");
        modes.push("pq_mldsa65");
        modes
    };
    if viewed_at.is_none() {
        sqlx::query("update document_shares set viewed_at = now(), open_count = open_count + 1, status = 'opened' where access_token_hash = $1 and viewed_at is null")
            .bind(&token_hash)
            .execute(&st.db)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        insert_document_event(
            &st.db,
            doc_id,
            &format!("guest-envelope:{envelope_id}"),
            "ENVELOPE_OPENED",
            public_custody_payload_for_envelope(
                json!({
                    "envelope_id": envelope_id,
                    "recipient_wallet": row.get::<Option<String>,_>("recipient_wallet"),
                    "recipient_chain": row.get::<Option<String>,_>("recipient_chain"),
                    "recipient_name": row.get::<Option<String>,_>("recipient_name"),
                    "recipient_email": row.get::<Option<String>,_>("recipient_email"),
                    "recipient_phone": row.get::<Option<String>,_>("recipient_phone"),
                    "status": "opened"
                }),
                envelope_id,
                &headers,
            ),
        )
        .await?;
    }

    Ok(Json(json!({
        "doc_id": doc_id,
        "envelope_id": envelope_id,
        "sender_wallet": row.get::<String,_>("sender_wallet"),
        "recipient_wallet": row.get::<Option<String>,_>("recipient_wallet"),
        "recipient_chain": row.get::<Option<String>,_>("recipient_chain"),
        "recipient_name": row.get::<Option<String>,_>("recipient_name"),
        "recipient_email": row.get::<Option<String>,_>("recipient_email"),
        "recipient_phone": row.get::<Option<String>,_>("recipient_phone"),
        "note": row.get::<Option<String>,_>("note"),
        "delivery": row.get::<serde_json::Value,_>("delivery_json"),
        "annotation_json": row.get::<serde_json::Value,_>("annotation_json"),
        "status": if viewed_at.is_none() { "opened" } else { status.as_str() },
        "expires_at": expires_at,
        "one_time_use": one_time_use,
        "download_allowed": download_allowed,
        "allow_guest_sign": allow_guest_sign,
        "allowed_signature_types": allowed_signature_types,
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
    let token_hash = access_token_hash_hex(token.trim());
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
            s.expires_at,
            s.revoked_at,
            s.one_time_use,
            s.download_allowed,
            s.completion_count
        from document_shares s
        join documents d on d.id = s.doc_id
        where s.access_token_hash = $1
          and d.is_deleted = false
        "#,
    )
    .bind(&token_hash)
    .fetch_optional(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let Some(row) = row else {
        return Err(AppError::NotFound("Envelope not found".into()));
    };
    let expires_at: Option<chrono::DateTime<chrono::Utc>> = row.get("expires_at");
    let revoked_at: Option<chrono::DateTime<chrono::Utc>> = row.get("revoked_at");
    let one_time_use: bool = row.get("one_time_use");
    let download_allowed: bool = row.get("download_allowed");
    let completion_count: i32 = row.get("completion_count");

    if revoked_at.is_some() {
        return Err(AppError::Forbidden("This share link has been revoked".into()));
    }
    if expires_at.map(|value| value <= chrono::Utc::now()).unwrap_or(false) {
        return Err(AppError::Forbidden("This share link has expired".into()));
    }
    if one_time_use && completion_count > 0 {
        return Err(AppError::Forbidden("This one-time share link has already been used".into()));
    }

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
            (
                header::CONTENT_DISPOSITION,
                if download_allowed {
                    "inline".to_string()
                } else {
                    "inline; filename=\"preview\"".to_string()
                },
            ),
            (
                header::CACHE_CONTROL,
                "no-store, max-age=0".to_string(),
            ),
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
    let token_hash = access_token_hash_hex(token.trim());
    let row = sqlx::query(
        r#"
        select
            s.doc_id,
            s.envelope_id,
            s.status,
            s.expires_at,
            s.revoked_at,
            s.one_time_use,
            s.allow_guest_sign,
            s.completion_count,
            d.owner_wallet,
            d.hash_hex,
            d.version,
            d.mime_type,
            d.parent_id,
            d.arweave_tx
        from document_shares s
        join documents d on d.id = s.doc_id
        where s.access_token_hash = $1
          and d.is_deleted = false
        "#,
    )
    .bind(&token_hash)
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
    let expires_at: Option<chrono::DateTime<chrono::Utc>> = row.get("expires_at");
    let revoked_at: Option<chrono::DateTime<chrono::Utc>> = row.get("revoked_at");
    let one_time_use: bool = row.get("one_time_use");
    let completion_count: i32 = row.get("completion_count");
    let owner_wallet: String = row.get("owner_wallet");
    let policy = load_document_policy(&st.db, doc_id, &owner_wallet).await?;
    let allow_guest_sign = row
        .get::<Option<bool>, _>("allow_guest_sign")
        .unwrap_or_else(|| policy.get("allow_guest_sign").and_then(|value| value.as_bool()).unwrap_or(false));
    let guest_allowed = allow_guest_sign && public_guest_attestation_enabled();

    if revoked_at.is_some() {
        return Err(AppError::Forbidden("This share link has been revoked".into()));
    }
    if expires_at.map(|value| value <= chrono::Utc::now()).unwrap_or(false) {
        return Err(AppError::Forbidden("This share link has expired".into()));
    }
    if one_time_use && completion_count > 0 {
        return Err(AppError::Forbidden("This one-time share link has already been used".into()));
    }
    if row.get::<String, _>("status") == "completed" {
        return Err(AppError::Forbidden("This envelope has already been completed".into()));
    }

    let signature_type = body
        .signature_type
        .clone()
        .unwrap_or_else(|| {
            if guest_allowed {
                "guest_attestation".to_string()
            } else {
                "evm_personal_sign".to_string()
            }
        });
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
        "sol_ed25519" => {
            let wallet_address = body
                .wallet_address
                .clone()
                .ok_or_else(|| AppError::BadRequest("wallet_address is required for Solana signing".into()))?;
            let signature = body
                .signature
                .clone()
                .ok_or_else(|| AppError::BadRequest("signature is required for Solana signing".into()))?;

            verify_solana_signature(&canonical_message, &wallet_address, &signature)?;

            json!({
                "signature_type": "sol_ed25519",
                "wallet_address": wallet_address,
                "signature": signature,
                "chain": "sol"
            })
        }
        "pq_dilithium3" | "pq_mldsa65" => {
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
                "signature_type": "pq_mldsa65",
                "pq_public_key_b64": pq_public_key_b64,
                "signature": signature
            })
        }
        _ => return Err(AppError::BadRequest("Unsupported signature_type".into())),
    };

    if signature_type == "guest_attestation" && !guest_allowed {
        return Err(AppError::Forbidden("Guest attestation is disabled for this envelope".into()));
    }

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
            signer_name = $1,
            signer_email = $2,
            signer_title = $3,
            signer_org = $4,
            signer_wallet = $5,
            sign_reason = $6,
            annotation_json = $7,
            completion_signature_type = $8,
            completion_count = completion_count + 1
        where access_token_hash = $9
        "#,
    )
    .bind(body.signer_name.trim())
    .bind(body.signer_email.as_deref())
    .bind(body.signer_title.as_deref())
    .bind(body.signer_org.as_deref())
    .bind(body.wallet_address.as_deref())
    .bind(body.sign_reason.as_deref())
    .bind(&annotation_json)
    .bind(&signature_type)
    .bind(&token_hash)
    .execute(&st.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    insert_document_event(
        &st.db,
        doc_id,
        &format!("guest-envelope:{envelope_id}"),
        "ENVELOPE_COMPLETED",
        public_custody_payload_for_envelope(
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
        ),
    )
    .await?;

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
    let sess = require_session_from_headers(&st, &headers).await?;
    let keys = load_or_create_server_mlkem_keypair(&st.db, &sess.wallet).await?;

    Ok(Json(json!({
        "active": true,
        "session_id": sess.session_id,
        "wallet": sess.wallet,
        "chain": sess.chain,
        "created_at": sess.created_at,
        "expires_at": sess.expires_at,
        "rotation_recommended": sess.rotation_recommended(),
        "device_id": sess.device_id,
        "user_agent": sess.user_agent,
        "mlkem_pk_b64": keys.pk_b64
    })))
}

async fn rotate_session_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let sid = headers
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Auth("Missing session".into()))?;

    let rotated = st
        .auth
        .rotate_session(
            sid,
            device_id_from_headers(&headers).as_deref(),
            user_agent_from_headers(&headers).as_deref(),
            ip_from_headers(&headers).as_deref(),
        )
        .await?
        .ok_or_else(|| AppError::Auth("Invalid or expired session".into()))?;

    let keys = load_or_create_server_mlkem_keypair(&st.db, &rotated.wallet).await?;

    Ok(Json(json!({
        "active": true,
        "rotated": true,
        "session_id": rotated.session_id,
        "wallet": rotated.wallet,
        "chain": rotated.chain,
        "created_at": rotated.created_at,
        "expires_at": rotated.expires_at,
        "rotation_recommended": false,
        "device_id": rotated.device_id,
        "user_agent": rotated.user_agent,
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

    st.auth.revoke_session(sid).await?;

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
            Some("evm"),
            Some("Review and sign"),
            envelope_id,
            Some("0xsig"),
            Some("Signer Example"),
            Some("signer@example.com"),
            Some("+15555555555"),
            Some("public-token-hash-123"),
        );

        assert_eq!(payload["recipient_wallet"], "0xrecipient");
        assert_eq!(payload["recipient_chain"], "evm");
        assert_eq!(payload["recipient_name"], "Signer Example");
        assert_eq!(payload["note"], "Review and sign");
        assert_eq!(payload["signature"], "0xsig");
        assert_eq!(payload["recipient_email"], "signer@example.com");
        assert_eq!(payload["recipient_phone"], "+15555555555");
        assert_eq!(payload["access_token_hash"], "public-token-hash-123");
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

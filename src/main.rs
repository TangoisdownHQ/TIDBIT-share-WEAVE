// src/main.rs

// ================================================================
// MODULE DECLARATIONS
// ================================================================
// These expose internal subsystems to main.rs.
// Nothing C19-specific here — just wiring.

mod arweave;
mod c2c;
mod cli;
mod config;
mod crypto;
mod error;
mod identity;
mod identity_web;
mod pqc;
mod sanitizer;

// ================================================================
// IMPORTS
// ================================================================

use clap::Parser;

use base64::Engine as _;
use cli::commands;
use cli::parser::{Cli, Commands};

use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::IntoResponse,
    Json, Router,
};

use crate::c2c::types::C2CEvent;
use crate::c2c::{onchain as c2c_onchain, store as c2c_store};
use crate::cli::commands::doc::{load_index, DocEntry};
use crate::error::AppError;
use crate::pqc::sha3 as pqc_sha3;

// ================================================================
// ENTRY POINT
// ================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Wallet { action } => commands::wallet::handle_wallet(action).await?,
        Commands::Doc { action } => commands::doc::handle_doc(action).await?,
        Commands::C2c { action } => commands::c2c::handle_c2c(action).await?,
        Commands::Server => start_server().await?,
    }

    Ok(())
}

// ================================================================
// SERVER INITIALIZATION
// ================================================================
// This spins up the HTTP server and wires all routes.
// C19 introduces persistent wallet sessions via AuthState.

async fn start_server() -> anyhow::Result<()> {
    use axum::routing::{get, post};

    // ------------------------------------------------------------
    // AUTH STATE (C19 CORE)
    // ------------------------------------------------------------
    // AuthState holds:
    // - nonce store (pre-verify)
    // - session store (post-verify)
    //
    // This is the *single source of truth* for authentication.
    let auth_state = identity_web::AuthState::new();

    // ------------------------------------------------------------
    // STATIC FILE SERVING (FRONTEND)
    // ------------------------------------------------------------
    let static_files = ServeDir::new("web").append_index_html_on_directories(true);

    // ------------------------------------------------------------
    // ROUTER
    // ------------------------------------------------------------
    let app = Router::new()
        // ------------------------
        // Health / sanity check
        // ------------------------
        .route("/health", get(health_handler))
        // ------------------------
        // Authentication
        // ------------------------
        // Nonce → wallet signs → verify → session created
        .route("/auth/evm/nonce", post(identity_web::evm_nonce_handler))
        .route("/auth/evm/verify", post(identity_web::evm_verify_handler))
        .route("/auth/sol/nonce", get(identity_web::sol_nonce_handler))
        .route("/auth/sol/verify", post(identity_web::sol_verify_handler))
        .route("/api/envelope", axum::routing::post(envelope_put_handler))
        .route(
            "/api/envelope/:id",
            axum::routing::get(envelope_get_handler),
        )
        .route("/api/kem/pk/:wallet", get(kem_pk_handler)) // public read
        .route("/api/kem/pk", get(kem_my_pk_handler)) // auth-gated "me"
        // ------------------------
        // Document APIs (AUTH-GATED)
        // ------------------------
        // These require a valid session via x-session-id
        .route("/api/doc/list", get(list_docs_handler))
        .route("/api/doc/upload", post(upload_doc_handler))
        // C19 helper: verify doc ownership using session
        .route("/api/doc/verify", post(doc_verify_handler))
        .route("/auth/logout", post(logout_handler))
        .route("/auth/session", get(session_info_handler))
        // ------------------------
        // C2C (chain-of-custody)
        // ------------------------
        .route("/c2c/events", get(c2c_list_handler))
        .route("/c2c/events/:id", get(c2c_get_handler))
        .route("/c2c/events/:id/anchor", post(c2c_anchor_handler))
        // ------------------------
        // Frontend
        // ------------------------
        .nest_service("/", static_files)
        // --------------------------------------------------------
        // GLOBAL STATE + CORS
        // --------------------------------------------------------
        .with_state(auth_state)
        .layer(CorsLayer::permissive());

    let addr: std::net::SocketAddr = "0.0.0.0:4100".parse().unwrap();
    println!("🚀 Server running at http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ================================================================
// BASIC HANDLERS
// ================================================================

async fn health_handler() -> &'static str {
    "OK"
}

// ================================================================
// AUTH HELPERS (C19 CORE)
// ================================================================
// This is the *only* place where headers are translated into identity.
// Everything downstream trusts this.

fn require_wallet_from_headers(
    st: &identity_web::AuthState,
    headers: &HeaderMap,
) -> Result<String, AppError> {
    // Session ID is passed explicitly by the client.
    // This is intentionally simple and visible.
    let sid = headers
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Auth("Missing x-session-id header".into()))?;

    // AuthState resolves session → wallet
    let sess = st
        .get_session(sid)
        .ok_or_else(|| AppError::Auth("Invalid or expired session".into()))?;

    Ok(sess.wallet)
}

// ================================================================
// DOCUMENT HANDLERS (AUTH-GATED)
// ================================================================

async fn list_docs_handler(
    State(st): State<identity_web::AuthState>,
    headers: HeaderMap,
) -> Result<Json<Vec<DocEntry>>, AppError> {
    // Resolve wallet from session
    let wallet = require_wallet_from_headers(&st, &headers)?;

    let mut docs = load_index()?;

    // C17+ guarantee: documents are filtered by owner_wallet
    docs.retain(|d| d.owner_wallet.as_deref() == Some(wallet.as_str()));

    Ok(Json(docs))
}

async fn upload_doc_handler() -> impl IntoResponse {
    (
        axum::http::StatusCode::NOT_IMPLEMENTED,
        "Document upload via HTTP not implemented yet. Use CLI.",
    )
}

// ================================================================
// C19 HELPER: VERIFY DOCUMENT OWNERSHIP
// ================================================================

#[derive(Debug, serde::Deserialize)]
struct EnvelopePutRequest {
    /// canonical JSON bytes encoded as base64url (no padding)
    pub envelope_b64: String,
}

async fn envelope_put_handler(
    State(st): State<identity_web::AuthState>,
    headers: HeaderMap,
    Json(req): Json<EnvelopePutRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    // require session wallet (auth-gated)
    let wallet = require_wallet_from_headers(&st, &headers)?;

    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(req.envelope_b64.as_bytes())
        .map_err(|e| AppError::BadRequest(format!("envelope_b64 decode: {e}")))?;

    // validate it is a DocumentEnvelopeV1 and matches wallet
    let env: crate::crypto::canonical::DocumentEnvelopeV1 = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::BadRequest(format!("json parse: {e}")))?;

    if env.owner.to_lowercase() != wallet.to_lowercase() {
        return Err(AppError::Forbidden(
            "envelope owner does not match session wallet".into(),
        ));
    }

    let canon = crate::crypto::canonical::canonicalize::canonical_json(&env);
    let eid = crate::crypto::canonical::hash::envelope_id(&canon);

    crate::crypto::canonical::keystore::save_envelope_json(&eid, &canon)
        .map_err(|e| AppError::Internal(format!("save envelope: {e}")))?;

    Ok(Json(serde_json::json!({
        "ok": true,
        "envelope_id": eid
    })))
}

async fn envelope_get_handler(
    State(st): State<identity_web::AuthState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    // auth-gated
    let wallet = require_wallet_from_headers(&st, &headers)?;

    let bytes = crate::crypto::canonical::keystore::load_envelope_json(&id)
        .map_err(|e| AppError::BadRequest(e))?;

    let env: crate::crypto::canonical::DocumentEnvelopeV1 = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::BadRequest(format!("json parse: {e}")))?;

    if env.owner.to_lowercase() != wallet.to_lowercase() {
        return Err(AppError::Forbidden(
            "envelope owner does not match session wallet".into(),
        ));
    }

    Ok(Json(serde_json::json!({
        "ok": true,
        "envelope": env
    })))
}

#[derive(Debug, serde::Deserialize)]
struct DocVerifyRequest {
    pub logical_id: Option<String>,
    pub hash_hex: Option<String>,
}

async fn doc_verify_handler(
    State(st): State<identity_web::AuthState>,
    headers: HeaderMap,
    Json(req): Json<DocVerifyRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let wallet = require_wallet_from_headers(&st, &headers)?;

    let docs = load_index()?;

    let found = if let Some(id) = req.logical_id.as_deref() {
        docs.into_iter().find(|d| d.logical_id == id)
    } else if let Some(h) = req.hash_hex.as_deref() {
        docs.into_iter().find(|d| d.hash_hex == h)
    } else {
        return Err(AppError::BadRequest(
            "Provide logical_id or hash_hex".into(),
        ));
    };

    let Some(doc) = found else {
        return Err(AppError::BadRequest("Document not found".into()));
    };

    let owned = doc.owner_wallet.as_deref() == Some(wallet.as_str());

    Ok(Json(serde_json::json!({
        "ok": true,
        "owned": owned,
        "wallet": wallet,
        "logical_id": doc.logical_id,
        "hash_hex": doc.hash_hex,
        "owner_wallet": doc.owner_wallet,
        "arweave_tx": doc.arweave_tx,
    })))
}

// ================================================================
// C2C HANDLERS
// ================================================================

async fn c2c_list_handler() -> Result<Json<Vec<C2CEvent>>, AppError> {
    Ok(Json(c2c_store::load_all_events()?))
}

async fn c2c_get_handler(Path(id): Path<String>) -> Result<Json<C2CEvent>, AppError> {
    c2c_store::load_event_by_id(&id)?
        .map(Json)
        .ok_or_else(|| AppError::BadRequest(format!("No event id={id}")))
}

async fn c2c_anchor_handler(Path(id): Path<String>) -> Result<Json<serde_json::Value>, AppError> {
    let mut ev = c2c_store::load_event_by_id(&id)?
        .ok_or_else(|| AppError::BadRequest(format!("No event {id}")))?;

    // Strip signature before anchoring
    ev.signature_b64 = None;

    let bytes = serde_json::to_vec(&ev)
        .map_err(|e| AppError::Internal(format!("Serialize failed: {e}")))?;

    let hash = pqc_sha3::sha3_256_bytes(&bytes);
    c2c_onchain::anchor_event_hash(&hash).await?;

    Ok(Json(serde_json::json!({
        "status": "anchored",
        "id": id,
        "hash": hex::encode(hash)
    })))
}

async fn logout_handler(
    State(st): State<identity_web::AuthState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let sid = headers
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Auth("Missing x-session-id".into()))?;

    st.revoke_session(sid);

    Ok(Json(serde_json::json!({
        "ok": true,
        "logged_out": true
    })))
}

async fn session_info_handler(
    State(st): State<identity_web::AuthState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let sid = headers
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Auth("Missing x-session-id".into()))?;

    let sess = st
        .get_session(sid)
        .ok_or_else(|| AppError::Auth("Invalid or expired session".into()))?;

    Ok(Json(serde_json::json!({
        "active": true,
        "wallet": sess.wallet,
        "chain": format!("{:?}", sess.chain).to_lowercase(),
        "created_at_ms": sess.created_at_ms(),
        "expires_at_ms": sess.expires_at_ms()
    })))
}

async fn kem_pk_handler(Path(wallet): Path<String>) -> Result<Json<serde_json::Value>, AppError> {
    let pk = crate::crypto::canonical::keystore::load_mlkem_pk(&wallet)
        .map_err(|e| AppError::BadRequest(e))?;

    Ok(Json(serde_json::json!({
        "ok": true,
        "wallet": wallet.to_lowercase(),
        "kem": "mlkem768",
        "pk_b64": pk
    })))
}

async fn kem_my_pk_handler(
    State(st): State<identity_web::AuthState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let wallet = require_wallet_from_headers(&st, &headers)?;
    let pk = crate::crypto::canonical::keystore::load_mlkem_pk(&wallet)
        .map_err(|e| AppError::BadRequest(e))?;

    Ok(Json(serde_json::json!({
        "ok": true,
        "wallet": wallet.to_lowercase(),
        "kem": "mlkem768",
        "pk_b64": pk
    })))
}

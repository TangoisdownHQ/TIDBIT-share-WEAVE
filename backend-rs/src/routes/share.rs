use crate::c2c::record::record_share_event;
use crate::error::AppError;
use crate::identity_web::AuthState;
use axum::{extract::State, Json};

#[derive(serde::Deserialize)]
pub struct ShareRequest {
    pub to_wallet: String,
    pub envelope_id: String,
}

#[derive(serde::Serialize)]
pub struct ShareResponse {
    pub ok: bool,
}

pub async fn share_envelope_v2(
    State(st): State<AuthState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ShareRequest>,
) -> Result<Json<ShareResponse>, AppError> {
    let sid = headers
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Auth("missing x-session-id".into()))?;

    let session = st
        .get_session(sid)
        .ok_or_else(|| AppError::Auth("invalid session".into()))?;

    record_share_event(session.wallet, req.to_wallet, req.envelope_id)?;

    Ok(Json(ShareResponse { ok: true }))
}

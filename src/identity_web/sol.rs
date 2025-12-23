use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use super::state::AuthState;

#[derive(Serialize)]
pub struct SolNonceResponse {
    pub session_id: String,
    pub nonce: String,
}

pub async fn sol_nonce_handler(State(st): State<AuthState>) -> Json<SolNonceResponse> {
    let (session_id, nonce) = st.create_nonce();
    Json(SolNonceResponse { session_id, nonce })
}

#[derive(Deserialize)]
pub struct SolVerifyRequest {
    pub session_id: String,
    pub address: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct AuthSuccess {
    pub address: String,
    pub session_id: String,
}

pub async fn sol_verify_handler(
    State(st): State<AuthState>,
    Json(req): Json<SolVerifyRequest>,
) -> Result<Json<AuthSuccess>, (StatusCode, String)> {
    let Some(_nonce) = st.take_nonce(&req.session_id) else {
        return Err((StatusCode::BAD_REQUEST, "Unknown or expired session".into()));
    };

    st.bind_wallet(req.session_id.clone(), req.address.clone(), "sol");

    Ok(Json(AuthSuccess {
        address: req.address,
        session_id: req.session_id,
    }))
}

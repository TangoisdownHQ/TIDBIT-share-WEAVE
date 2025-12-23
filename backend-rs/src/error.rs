// src/error.rs

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    // --- Application-level errors ---
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("auth error: {0}")]
    Auth(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    // --- Wrapped lower-level errors ---
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
}

pub type AppResult<T> = Result<T, AppError>;

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::Auth(_) => StatusCode::UNAUTHORIZED,

            // Crypto errors are internal failures, not user mistakes
            AppError::Crypto(_) => StatusCode::INTERNAL_SERVER_ERROR,

            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::SerdeJson(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = Json(ErrorBody {
            error: self.to_string(),
        });

        (status, body).into_response()
    }
}

impl From<hex::FromHexError> for AppError {
    fn from(e: hex::FromHexError) -> Self {
        AppError::Internal(format!("hex decode error: {e}"))
    }
}

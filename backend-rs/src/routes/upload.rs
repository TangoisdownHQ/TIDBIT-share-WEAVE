use crate::error::AppError;
use crate::sanitizer::hybrid::hybrid_sanitize;
use axum::Json;

#[derive(serde::Serialize)]
pub struct UploadResponse {
    pub ok: bool,
}

pub async fn upload() -> Result<Json<UploadResponse>, AppError> {
    hybrid_sanitize(b"", "application/octet-stream", None)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(UploadResponse { ok: true }))
}

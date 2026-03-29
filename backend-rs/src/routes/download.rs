use crate::{error::AppError, models::DownloadResponse, sanitizer::hybrid::hybrid_sanitize};
use axum::{extract::Path, Json};
use base64::Engine as _;
use sha2::{Digest, Sha256};

pub async fn download(Path(txid): Path<String>) -> Result<Json<DownloadResponse>, AppError> {
    // TEMP stub until Arweave wiring is complete
    let plaintext = b"download stub".to_vec();
    let mime_type = "application/octet-stream".to_string();

    // Sanitize (manual error mapping)
    hybrid_sanitize(&plaintext, &mime_type, None)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let sha256_hex = hex::encode(Sha256::digest(&plaintext));

    Ok(Json(DownloadResponse {
        txid,
        mime_type,
        sha256_hex,
        base64_data: base64::engine::general_purpose::STANDARD.encode(plaintext),
    }))
}

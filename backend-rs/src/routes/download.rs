use axum::{Json, extract::{State, Path}};
use crate::{
    error::AppError,
    arweave::download_from_arweave,
    pqc::keywrap::hybrid_decrypt_file,
    sanitizer::hybrid::hybrid_sanitize,
    models::DownloadResponse,
    config::AppState
};
use sha2::{Sha256, Digest};

pub async fn download(
    State(app): State<AppState>,
    Path(txid): Path<String>,
) -> Result<Json<DownloadResponse>, AppError> {

    // Download encrypted file
    let encrypted_bytes = download_from_arweave(&txid).await?;

    // Decrypt using PQC
    let (plaintext, mime_type) = hybrid_decrypt_file(&encrypted_bytes)?;

    // Re-sanitize file after decryption
    let sha256_hex = hex::encode(Sha256::digest(&plaintext));

    hybrid_sanitize(
        &plaintext,
        &mime_type,
        &sha256_hex,
        &app.config.vt_api_key,
        &app.config.otx_api_key,
        &app.config.gsb_api_key,
        &app.config.hibp_api_key,
        &app.config.ipinfo_key,
        None,
        None,
    ).await?;

    Ok(Json(DownloadResponse {
        txid,
        mime_type,
        sha256_hex,
        base64_data: base64::encode(plaintext),
    }))
}


use axum::{
    extract::{Multipart, State},
    Json,
};
use sha2::{Sha256, Digest};
use crate::{
    error::AppError,
    models::{UploadResponse},
    sanitizer::hybrid::hybrid_sanitize,
    pqc::keywrap::hybrid_encrypt_file,
    arweave::upload_to_arweave,
    config::AppState
};

pub async fn upload(
    State(app): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, AppError> {

    let mut file_name = String::new();
    let mut mime_type = "application/octet-stream".to_string();
    let mut file_bytes: Vec<u8> = vec![];

    // Parse multipart file
    while let Some(field) = multipart.next_field().await? {
        let name = field.name().unwrap_or("").to_string();

        if name == "file" {
            file_name = field.file_name().unwrap_or("upload.bin").to_string();
            mime_type = field.content_type().unwrap_or("application/octet-stream").to_string();
            file_bytes = field.bytes().await?.to_vec();
        }
    }

    // Compute SHA256 hash
    let sha256_hex = {
        let mut hasher = Sha256::new();
        hasher.update(&file_bytes);
        hex::encode(hasher.finalize())
    };

    // Hybrid sanitization (online + local if available)
    hybrid_sanitize(
        &file_bytes,
        &mime_type,
        &sha256_hex,
        &app.config.vt_api_key,
        &app.config.otx_api_key,
        &app.config.gsb_api_key,
        &app.config.hibp_api_key,
        &app.config.ipinfo_key,
        None,   // No URL in uploads
        None,   // No email in uploads
    ).await?;

    // PQC hybrid encryption
    let (encrypted_bytes, wrapped_key) = hybrid_encrypt_file(&file_bytes)?;

    // Upload encrypted payload to Arweave via Bundlr
    let tx_id = upload_to_arweave(&app.bundlr, &encrypted_bytes).await?;

    // Build response
    let resp = UploadResponse {
        tx_id,
        file_name,
        mime_type,
        sha256_hex,
        wrapped_key: base64::encode(wrapped_key),
    };

    Ok(Json(resp))
}


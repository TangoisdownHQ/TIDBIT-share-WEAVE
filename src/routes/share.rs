use axum::{Json, extract::{State, Multipart}};
use crate::{
    error::AppError,
    models::ShareResponse,
    sanitizer::hybrid::hybrid_sanitize,
    pqc::keywrap::hybrid_encrypt_file,
    arweave::upload_to_arweave,
    identity::wallet_verify::verify_wallet_sig,
    c2c::event_format::C2CEvent
};
use sha2::{Sha256, Digest};

pub async fn share(
    State(app): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<ShareResponse>, AppError> {

    let mut recipient = String::new();
    let mut url_to_check = None;

    while let Some(field) = multipart.next_field().await? {
        let name = field.name().unwrap_or("");

        match name {
            "recipient" => { recipient = field.text().await?; }
            "url" => { url_to_check = Some(field.text().await?); }
            _ => {}
        }
    }

    // Validate URL if provided
    if let Some(url) = url_to_check.clone() {
        hybrid_sanitize(
            b"",
            "text/plain",
            "",
            &app.config.vt_api_key,
            &app.config.otx_api_key,
            &app.config.gsb_api_key,
            &app.config.hibp_api_key,
            &app.config.ipinfo_key,
            Some(&url),
            None,
        ).await?;
    }

    // Sign event
    let event = C2CEvent::new(recipient.clone());
    let signature = event.sign_with_wallet(&app.wallet_key)?;

    let resp = ShareResponse {
        recipient,
        url: url_to_check,
        signature,
        timestamp: event.timestamp,
    };

    Ok(Json(resp))
}


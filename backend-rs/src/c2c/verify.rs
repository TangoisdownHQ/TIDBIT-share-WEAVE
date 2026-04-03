use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;

use crate::c2c::types::C2CEvent;
use crate::crypto::canonical::canonicalize::canonical_json;
use crate::error::{AppError, AppResult};
use crate::identity_web::evm::verify_evm_signature;
use crate::identity_web::sol::verify_solana_signature;
use crate::pqc::dilithium;

fn payload_lookup<'a>(payload: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
    payload.get(key).or_else(|| payload.get("verification").and_then(|value| value.get(key)))
}

fn payload_string(payload: &serde_json::Value, key: &str) -> Option<String> {
    payload_lookup(payload, key)
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn canonical_event_message(ev: &C2CEvent) -> String {
    String::from_utf8(canonical_json(&serde_json::json!({
        "id": ev.id,
        "timestamp": ev.timestamp,
        "actor_wallet": ev.actor_wallet,
        "kind": ev.kind,
        "payload": ev.payload
    })))
    .unwrap_or_default()
}

pub fn verify_event(ev: &C2CEvent) -> AppResult<()> {
    let actor_wallet = ev.actor_wallet.trim();
    if actor_wallet.is_empty() {
        return Err(AppError::BadRequest(
            "Missing actor wallet identifier".into(),
        ));
    }

    let signature_type = payload_string(&ev.payload, "signature_type")
        .or_else(|| payload_string(&ev.payload, "completion_signature_type"))
        .ok_or_else(|| AppError::BadRequest("Event is missing signature_type".into()))?;
    let signing_message = payload_string(&ev.payload, "signing_message")
        .unwrap_or_else(|| canonical_event_message(ev));

    match signature_type.as_str() {
        "evm_personal_sign" => {
            let signature = payload_string(&ev.payload, "signature")
                .or_else(|| ev.signature_b64.clone())
                .ok_or_else(|| AppError::BadRequest("Event is missing EVM signature".into()))?;
            let recovered = verify_evm_signature(&signing_message, &signature)
                .map_err(|_| AppError::Forbidden("Invalid EVM signature".into()))?
                .to_lowercase();

            if recovered != actor_wallet.to_lowercase() {
                return Err(AppError::Forbidden(
                    "EVM signature does not match actor wallet".into(),
                ));
            }
        }
        "sol_ed25519" => {
            let signature = payload_string(&ev.payload, "signature")
                .or_else(|| ev.signature_b64.clone())
                .ok_or_else(|| AppError::BadRequest("Event is missing Solana signature".into()))?;
            verify_solana_signature(&signing_message, actor_wallet, &signature)?;
        }
        "pq_dilithium3" | "pq_mldsa65" => {
            let pq_public_key_b64 = payload_string(&ev.payload, "pq_public_key_b64")
                .ok_or_else(|| AppError::BadRequest("Event is missing pq_public_key_b64".into()))?;
            let signature = payload_string(&ev.payload, "signature")
                .or_else(|| ev.signature_b64.clone())
                .ok_or_else(|| AppError::BadRequest("Event is missing PQ signature".into()))?;
            let public_key = BASE64_STANDARD
                .decode(pq_public_key_b64)
                .map_err(|_| AppError::BadRequest("Invalid pq_public_key_b64".into()))?;
            let signed_message = BASE64_STANDARD
                .decode(signature)
                .map_err(|_| AppError::BadRequest("Invalid PQ signature encoding".into()))?;
            let verified = dilithium::verify(&public_key, signing_message.as_bytes(), &signed_message)
                .map_err(|e| AppError::Internal(e.to_string()))?;
            if !verified {
                return Err(AppError::Forbidden("PQ signature verification failed".into()));
            }
        }
        other => {
            return Err(AppError::BadRequest(format!(
                "Unsupported C2C signature_type: {other}"
            )));
        }
    }

    Ok(())
}

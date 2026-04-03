// src/models.rs (or routes/share.rs)

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct EnvelopeShareRequest {
    pub envelope_id: String,
    pub from_wallet: String,
    pub to_wallet: String,
    pub envelope_json: serde_json::Value,
}

#[derive(Serialize)]
pub struct EnvelopeShareResponse {
    pub status: String,
    pub envelope_id: String,
    pub from: String,
    pub to: String,
    pub c2c_event_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DownloadResponse {
    pub txid: String,
    pub mime_type: String,
    pub sha256_hex: String,
    pub base64_data: String,
}

#[derive(Deserialize)]
pub struct SignRequest {
    pub signature: String,
    pub signature_type: Option<String>,
    pub pq_public_key_b64: Option<String>,
}

#[derive(Deserialize)]
pub struct ShareRequest {
    pub recipient_wallet: Option<String>,
    pub recipient_chain: Option<String>,
    pub recipient_name: Option<String>,
    pub note: Option<String>,
    pub signature: Option<String>,
    pub recipient_email: Option<String>,
    pub recipient_phone: Option<String>,
    pub expires_in_hours: Option<i64>,
    pub one_time_use: Option<bool>,
    pub download_allowed: Option<bool>,
    pub allow_guest_sign: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerAnnotationField {
    pub kind: String,
    pub label: Option<String>,
    pub value: Option<String>,
    pub x_pct: f32,
    pub y_pct: f32,
}

#[derive(Deserialize)]
pub struct PublicEnvelopeSignRequest {
    pub signature_type: Option<String>,
    pub signer_name: String,
    pub signer_email: Option<String>,
    pub signer_title: Option<String>,
    pub signer_org: Option<String>,
    pub sign_reason: Option<String>,
    pub annotation_text: Option<String>,
    pub consent: bool,
    pub wallet_address: Option<String>,
    pub signature: Option<String>,
    pub pq_public_key_b64: Option<String>,
    pub annotation_fields: Option<Vec<SignerAnnotationField>>,
}

#[derive(Deserialize)]
pub struct AgentRegisterRequest {
    pub label: String,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub capabilities: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct DocumentPolicyUpdateRequest {
    pub policy_json: serde_json::Value,
}

#[derive(Deserialize)]
pub struct AgentSignRequest {
    pub summary: Option<String>,
    pub sign_reason: Option<String>,
}

#[derive(Deserialize)]
pub struct AgentVersionRequest {
    pub label: Option<String>,
    pub mime_type: Option<String>,
    pub content_b64: String,
    pub change_summary: Option<String>,
    pub anchor_to_arweave: Option<bool>,
}

#[derive(Deserialize)]
pub struct InboxActionRequest {
    pub action: String,
}

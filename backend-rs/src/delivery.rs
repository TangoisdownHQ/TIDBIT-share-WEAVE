use reqwest::Client;
use serde::Serialize;
use serde_json::json;

use crate::error::AppError;

#[derive(Debug, Clone, Serialize)]
pub struct DeliveryOutcome {
    pub channel: &'static str,
    pub provider: &'static str,
    pub recipient: String,
    pub external_id: Option<String>,
    pub status: &'static str,
}

pub async fn send_email_invite(
    recipient_email: &str,
    subject: &str,
    text_body: &str,
    html_body: &str,
) -> Result<Option<DeliveryOutcome>, AppError> {
    let api_key = match std::env::var("RESEND_API_KEY") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            return Ok(Some(DeliveryOutcome {
                channel: "email",
                provider: "resend",
                recipient: recipient_email.to_string(),
                external_id: None,
                status: "provider_unconfigured",
            }))
        }
    };
    let from = std::env::var("RESEND_FROM_EMAIL")
        .unwrap_or_else(|_| "TIDBIT-share-WEAVE <onboarding@resend.dev>".to_string());

    let client = Client::new();
    let response = match client
        .post("https://api.resend.com/emails")
        .bearer_auth(api_key)
        .json(&json!({
            "from": from,
            "to": [recipient_email],
            "subject": subject,
            "text": text_body,
            "html": html_body
        }))
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => {
            return Ok(Some(DeliveryOutcome {
                channel: "email",
                provider: "resend",
                recipient: recipient_email.to_string(),
                external_id: None,
                status: "provider_unavailable",
            }))
        }
    };

    let status = response.status();
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("Resend response parse failed: {e}")))?;

    if !status.is_success() {
        return Ok(Some(DeliveryOutcome {
            channel: "email",
            provider: "resend",
            recipient: recipient_email.to_string(),
            external_id: body["id"].as_str().map(ToOwned::to_owned),
            status: "provider_error",
        }));
    }

    Ok(Some(DeliveryOutcome {
        channel: "email",
        provider: "resend",
        recipient: recipient_email.to_string(),
        external_id: body["id"].as_str().map(ToOwned::to_owned),
        status: "sent",
    }))
}

pub async fn send_sms_invite(
    recipient_phone: &str,
    body: &str,
) -> Result<Option<DeliveryOutcome>, AppError> {
    let account_sid = match std::env::var("TWILIO_ACCOUNT_SID") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            return Ok(Some(DeliveryOutcome {
                channel: "sms",
                provider: "twilio",
                recipient: recipient_phone.to_string(),
                external_id: None,
                status: "provider_unconfigured",
            }))
        }
    };
    let auth_token = std::env::var("TWILIO_AUTH_TOKEN")
        .map_err(|_| AppError::Internal("TWILIO_AUTH_TOKEN is required when TWILIO_ACCOUNT_SID is set".into()))?;
    let from = std::env::var("TWILIO_FROM_NUMBER")
        .map_err(|_| AppError::Internal("TWILIO_FROM_NUMBER is required when Twilio SMS is enabled".into()))?;

    let endpoint = format!(
        "https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
    );
    let client = Client::new();
    let response = match client
        .post(endpoint)
        .basic_auth(&account_sid, Some(&auth_token))
        .form(&[
            ("To", recipient_phone),
            ("From", from.as_str()),
            ("Body", body),
        ])
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => {
            return Ok(Some(DeliveryOutcome {
                channel: "sms",
                provider: "twilio",
                recipient: recipient_phone.to_string(),
                external_id: None,
                status: "provider_unavailable",
            }))
        }
    };

    let status = response.status();
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("Twilio response parse failed: {e}")))?;

    if !status.is_success() {
        return Ok(Some(DeliveryOutcome {
            channel: "sms",
            provider: "twilio",
            recipient: recipient_phone.to_string(),
            external_id: body["sid"].as_str().map(ToOwned::to_owned),
            status: "provider_error",
        }));
    }

    Ok(Some(DeliveryOutcome {
        channel: "sms",
        provider: "twilio",
        recipient: recipient_phone.to_string(),
        external_id: body["sid"].as_str().map(ToOwned::to_owned),
        status: "sent",
    }))
}

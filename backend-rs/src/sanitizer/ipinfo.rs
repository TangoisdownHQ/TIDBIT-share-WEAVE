use crate::error::AppError;
use reqwest::Client;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct IpInfoSecurity {
    pub vpn: Option<bool>,
    pub proxy: Option<bool>,
    pub tor: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct IpInfoResponse {
    pub security: Option<IpInfoSecurity>,
}

pub async fn check_ipinfo(ip: &str, token: &str) -> Result<IpInfoSecurity, AppError> {
    let endpoint = format!("https://ipinfo.io/{}/security?token={}", ip, token);

    let resp = Client::new()
        .get(&endpoint)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("IPInfo request failed: {e}")))?
        .json::<IpInfoResponse>()
        .await
        .map_err(|e| AppError::Internal(format!("IPInfo JSON error: {e}")))?;

    Ok(resp.security.unwrap_or(IpInfoSecurity {
        vpn: None,
        proxy: None,
        tor: None,
    }))
}


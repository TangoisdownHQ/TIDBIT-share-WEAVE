// src/cli/commands/scan_url.rs

use crate::config::AppConfig;
use crate::sanitizer::hybrid::hybrid_sanitize;

pub async fn scan_url(url: &str) -> anyhow::Result<()> {
    let cfg = AppConfig::load();

    hybrid_sanitize(
        b"",
        "text/plain",
        "",
        &cfg.vt_api_key,
        &cfg.otx_api_key,
        &cfg.gsb_api_key,
        &cfg.hibp_api_key,
        &cfg.ipinfo_key,
        Some(url),
        None,
    )
    .await?;

    println!("🌐 URL appears clean: {url}");
    Ok(())
}


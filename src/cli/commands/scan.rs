// src/cli/commands/scan.rs

use crate::config::AppConfig;
use crate::sanitizer::hybrid::hybrid_sanitize;
use sha2::{Sha256, Digest};

pub async fn scan_file(path: &str) -> anyhow::Result<()> {
    let cfg = AppConfig::load();
    let bytes = std::fs::read(path)?;
    let mime = tree_magic_mini::from_u8(&bytes);

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha256_hex = hex::encode(hasher.finalize());

    hybrid_sanitize(
        &bytes,
        &mime,
        &sha256_hex,
        &cfg.vt_api_key,
        &cfg.otx_api_key,
        &cfg.gsb_api_key,
        &cfg.hibp_api_key,
        &cfg.ipinfo_key,
        None,
        None,
    )
    .await?;

    println!("✅ File is clean: {path} ({mime})");
    Ok(())
}


// src/sanitizer/hybrid.rs

use anyhow::Result;

/// Extremely minimal sanitizer placeholder.
/// Later we’ll plug in all your multi-engine checks.
pub async fn hybrid_sanitize(bytes: &[u8], mime_type: &str, url: Option<&str>) -> Result<()> {
    println!(
        "(sanitizer) size={} bytes, mime={mime_type}, url={url:?}",
        bytes.len()
    );
    Ok(())
}

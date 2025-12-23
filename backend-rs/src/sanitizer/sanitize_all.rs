

use crate::error::{AppError, AppResult};
use super::hybrid::hybrid_sanitize;

/// Wrapper that can expand later to add more checks.
pub async fn sanitize_all(
    bytes: &[u8],
    mime_type: &str,
) -> AppResult<()> {
    hybrid_sanitize(bytes, mime_type).await
}


use crate::error::AppError;
use crate::pqc::dilithium;

/// Verify a Dilithium PQC signature against a given public key.
pub fn verify_pqc_with_pubkey(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, AppError> {
    dilithium::verify(public_key, message, signature)
}

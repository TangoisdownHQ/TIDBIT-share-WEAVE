//src/crypto/canonical/kem.rs

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};

#[derive(Debug, Clone)]
pub struct MlKemKeypair {
    pub pk_b64: String,
    pub sk_b64: String,
}

/// Generate ML-KEM-768 keypair (base64, URL-safe, no padding)
pub fn mlkem_generate_keypair_b64() -> MlKemKeypair {
    let (pk, sk) = kyber768::keypair();

    MlKemKeypair {
        pk_b64: URL_SAFE_NO_PAD.encode(pk.as_bytes()),
        sk_b64: URL_SAFE_NO_PAD.encode(sk.as_bytes()),
    }
}

/// Encapsulate to recipient public key (base64)
pub fn mlkem_encapsulate_b64(recipient_pk_b64: &str) -> Result<(String, Vec<u8>), String> {
    let pk_bytes = URL_SAFE_NO_PAD
        .decode(recipient_pk_b64)
        .map_err(|e| format!("pk decode failed: {e}"))?;

    let pk = kyber768::PublicKey::from_bytes(&pk_bytes)
        .map_err(|_| "invalid mlkem public key bytes".to_string())?;

    // ✅ CORRECT ORDER
    let (ss, ct) = kyber768::encapsulate(&pk);

    let expected = kyber768::ciphertext_bytes();
    let actual = ct.as_bytes().len();
    if actual != expected {
        return Err(format!(
            "encapsulate: ciphertext len mismatch (got {}, expected {})",
            actual, expected
        ));
    }

    Ok((
        URL_SAFE_NO_PAD.encode(ct.as_bytes()),
        ss.as_bytes().to_vec(),
    ))
}

/// Decapsulate using owner secret key (base64)
pub fn mlkem_decapsulate_b64(owner_sk_b64: &str, ct_b64: &str) -> Result<Vec<u8>, String> {
    let sk_bytes = URL_SAFE_NO_PAD
        .decode(owner_sk_b64)
        .map_err(|e| format!("sk decode failed: {e}"))?;

    let ct_bytes = URL_SAFE_NO_PAD
        .decode(ct_b64)
        .map_err(|e| format!("ct decode failed: {e}"))?;

    let expected = kyber768::ciphertext_bytes();
    let actual = ct_bytes.len();
    if actual != expected {
        return Err(format!(
            "decapsulate: ciphertext len mismatch (got {}, expected {})",
            actual, expected
        ));
    }

    let sk = kyber768::SecretKey::from_bytes(&sk_bytes)
        .map_err(|_| "invalid mlkem secret key bytes".to_string())?;

    let ct = kyber768::Ciphertext::from_bytes(&ct_bytes)
        .map_err(|_| "invalid mlkem ciphertext bytes".to_string())?;

    let ss = kyber768::decapsulate(&ct, &sk);

    Ok(ss.as_bytes().to_vec())
}

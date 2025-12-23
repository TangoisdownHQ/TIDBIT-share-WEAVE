// src/crypto/canonical/metadata.rs

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedCekV1 {
    /// "mlkem768"
    pub kem: String,

    /// recipient identifier (for now: owner wallet string).
    pub recipient: String,

    /// ML-KEM ciphertext (encapsulation result) base64
    pub kem_ct_b64: String,

    /// Nonce used to wrap CEK with XChaCha20-Poly1305 (24 bytes) base64
    pub wrap_nonce_b64: String,

    /// AEAD ciphertext of CEK (base64)
    pub wrapped_cek_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionInfoV1 {
    /// "xchacha20poly1305"
    pub alg: String,

    /// Payload encryption nonce (24 bytes) base64
    pub nonce_b64: String,

    /// How CEK is protected: "mlkem"
    pub cek_wrap: String,

    /// One or more wrapped keys (owner + recipients)
    pub wrapped_keys: Vec<WrappedCekV1>,
}

// src/crypto/canonical/envelope.rs

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};

use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::canonical::canonicalize::canonical_json;
use crate::crypto::canonical::hash::envelope_id;
use crate::crypto::canonical::kem::{mlkem_decapsulate_b64, mlkem_encapsulate_b64};
use crate::crypto::canonical::{CanonicalDocumentV1, EncryptionInfoV1, WrappedCekV1};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentEnvelopeV1 {
    pub v: u16,
    pub owner: String,
    pub created_at: i64,
    pub doc: CanonicalDocumentV1,
    pub encryption: EncryptionInfoV1,
    pub ciphertext_b64: String,
}

impl DocumentEnvelopeV1 {
    /// Owner-only convenience wrapper (kept for backwards compatibility).
    pub fn create_mlkem_owner(
        owner_wallet: String,
        owner_mlkem_pk_b64: &str,
        created_at: i64,
        doc: CanonicalDocumentV1,
        plaintext: &[u8],
    ) -> Result<(Self, String), String> {
        Self::create_mlkem_recipients(
            owner_wallet.clone(),
            vec![(owner_wallet, owner_mlkem_pk_b64.to_string())],
            created_at,
            doc,
            plaintext,
        )
    }

    /// Multi-recipient envelope:
    /// - single CEK encrypts payload
    /// - CEK wrapped independently per-recipient via ML-KEM + HKDF + XChaCha20-Poly1305
    pub fn create_mlkem_recipients(
        owner_wallet: String,
        recipients: Vec<(String, String)>, // (wallet, pk_b64)
        created_at: i64,
        doc: CanonicalDocumentV1,
        plaintext: &[u8],
    ) -> Result<(DocumentEnvelopeV1, String), String> {
        // 1) CEK
        let mut cek = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut cek);

        // 2) Encrypt payload
        let mut payload_nonce_bytes = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut payload_nonce_bytes);
        let payload_nonce = XNonce::from_slice(&payload_nonce_bytes);

        let payload_cipher = XChaCha20Poly1305::new((&cek).into());
        let ciphertext = payload_cipher
            .encrypt(payload_nonce, plaintext)
            .map_err(|_| "payload encryption failed".to_string())?;

        // 3) Wrap CEK for each recipient
        let mut wrapped_keys = Vec::new();

        for (wallet, pk_b64) in recipients {
            let (kem_ct_b64, shared_secret) = mlkem_encapsulate_b64(&pk_b64)?;

            let hk = Hkdf::<Sha256>::new(None, &shared_secret);
            let mut wrap_key = [0u8; 32];
            hk.expand(b"tidbit-cek-wrap-v1", &mut wrap_key)
                .map_err(|_| "hkdf expand failed".to_string())?;

            let mut wrap_nonce_bytes = [0u8; 24];
            rand::thread_rng().fill_bytes(&mut wrap_nonce_bytes);
            let wrap_nonce = XNonce::from_slice(&wrap_nonce_bytes);

            let wrap_cipher = XChaCha20Poly1305::new((&wrap_key).into());
            let wrapped_cek = wrap_cipher
                .encrypt(wrap_nonce, cek.as_ref())
                .map_err(|_| "cek wrap failed".to_string())?;

            wrapped_keys.push(WrappedCekV1 {
                kem: "mlkem768".into(),
                recipient: wallet.to_lowercase(),
                kem_ct_b64,
                wrap_nonce_b64: URL_SAFE_NO_PAD.encode(wrap_nonce_bytes),
                wrapped_cek_b64: URL_SAFE_NO_PAD.encode(wrapped_cek),
            });
        }

        // 4) Metadata
        let encryption = EncryptionInfoV1 {
            alg: "xchacha20poly1305".into(),
            nonce_b64: URL_SAFE_NO_PAD.encode(payload_nonce_bytes),
            cek_wrap: "mlkem".into(),
            wrapped_keys,
        };

        // 5) Envelope
        let env = DocumentEnvelopeV1 {
            v: 1,
            owner: owner_wallet.to_lowercase(),
            created_at,
            doc,
            encryption,
            ciphertext_b64: URL_SAFE_NO_PAD.encode(ciphertext),
        };

        // 6) ID
        let canon = canonical_json(&env);
        let eid = envelope_id(&canon);

        Ok((env, eid))
    }

    /// Generic decrypt for ANY recipient wallet present in wrapped_keys.
    pub fn decrypt_for_wallet_mlkem(
        &self,
        wallet: &str,
        mlkem_sk_b64: &str,
    ) -> Result<Vec<u8>, String> {
        let wallet_lc = wallet.to_lowercase();

        let wk = self
            .encryption
            .wrapped_keys
            .iter()
            .find(|k| k.recipient == wallet_lc)
            .ok_or_else(|| "no wrapped key for this wallet".to_string())?;

        // 1) Decapsulate
        let shared_secret = mlkem_decapsulate_b64(mlkem_sk_b64, &wk.kem_ct_b64)?;

        // 2) Derive wrap key
        let hk = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut wrap_key = [0u8; 32];
        hk.expand(b"tidbit-cek-wrap-v1", &mut wrap_key)
            .map_err(|_| "hkdf expand failed".to_string())?;

        // 3) Unwrap CEK
        let wrap_nonce_bytes = URL_SAFE_NO_PAD
            .decode(&wk.wrap_nonce_b64)
            .map_err(|e| format!("wrap nonce decode: {e}"))?;

        if wrap_nonce_bytes.len() != 24 {
            return Err("wrap nonce invalid length".into());
        }

        let wrap_nonce = XNonce::from_slice(&wrap_nonce_bytes);

        let wrapped_cek = URL_SAFE_NO_PAD
            .decode(&wk.wrapped_cek_b64)
            .map_err(|e| format!("wrapped cek decode: {e}"))?;

        let wrap_cipher = XChaCha20Poly1305::new((&wrap_key).into());
        let cek = wrap_cipher
            .decrypt(wrap_nonce, wrapped_cek.as_ref())
            .map_err(|_| "cek unwrap failed".to_string())?;

        if cek.len() != 32 {
            return Err("invalid CEK length".into());
        }

        let mut cek_arr = [0u8; 32];
        cek_arr.copy_from_slice(&cek[..32]);

        // 4) Decrypt payload
        let payload_nonce_bytes = URL_SAFE_NO_PAD
            .decode(&self.encryption.nonce_b64)
            .map_err(|e| format!("payload nonce decode: {e}"))?;

        if payload_nonce_bytes.len() != 24 {
            return Err("payload nonce invalid length".into());
        }

        let payload_nonce = XNonce::from_slice(&payload_nonce_bytes);

        let ciphertext = URL_SAFE_NO_PAD
            .decode(&self.ciphertext_b64)
            .map_err(|e| format!("ciphertext decode: {e}"))?;

        let payload_cipher = XChaCha20Poly1305::new((&cek_arr).into());
        payload_cipher
            .decrypt(payload_nonce, ciphertext.as_ref())
            .map_err(|_| "payload decryption failed".to_string())
    }

    /// Owner convenience wrapper.
    pub fn decrypt_for_owner_mlkem(&self, owner_mlkem_sk_b64: &str) -> Result<Vec<u8>, String> {
        self.decrypt_for_wallet_mlkem(&self.owner, owner_mlkem_sk_b64)
    }
}

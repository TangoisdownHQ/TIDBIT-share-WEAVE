// src/crypto/canonical/envelope.rs

use serde::{Deserialize, Serialize};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

use crate::crypto::canonical::{
    canonicalize::canonical_json,
    hash::envelope_id,
    kem::{mlkem_decapsulate_b64, mlkem_encapsulate_b64},
    CanonicalDocumentV1, EncryptionInfoV1, WrappedCekV1,
};

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
    /// Create an envelope encrypted for the owner using:
    /// - XChaCha20-Poly1305 (payload)
    /// - ML-KEM-768 (shared secret)
    /// - HKDF-SHA256 (derive wrap key)
    /// - XChaCha20-Poly1305 (wrap CEK)
    pub fn create_mlkem_owner(
        owner_wallet: String,
        owner_mlkem_pk_b64: &str,
        created_at: i64,
        doc: CanonicalDocumentV1,
        plaintext: &[u8],
    ) -> Result<(Self, String), String> {
        // 1) Generate CEK
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

        // 3) ML-KEM encapsulation
        let (kem_ct_b64, shared_secret) = mlkem_encapsulate_b64(owner_mlkem_pk_b64)?;

        // 4) Derive wrapping key
        let hk = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut wrap_key = [0u8; 32];
        hk.expand(b"tidbit-cek-wrap-v1", &mut wrap_key)
            .map_err(|_| "hkdf expand failed".to_string())?;

        // 5) Wrap CEK
        let mut wrap_nonce_bytes = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut wrap_nonce_bytes);
        let wrap_nonce = XNonce::from_slice(&wrap_nonce_bytes);

        let wrap_cipher = XChaCha20Poly1305::new((&wrap_key).into());
        let wrapped_cek = wrap_cipher
            .encrypt(wrap_nonce, cek.as_ref())
            .map_err(|_| "cek wrap failed".to_string())?;

        // 6) Build metadata
        let wrapped_keys = vec![WrappedCekV1 {
            kem: "mlkem768".into(),
            recipient: owner_wallet.to_lowercase(),
            kem_ct_b64,
            wrap_nonce_b64: URL_SAFE_NO_PAD.encode(wrap_nonce_bytes),
            wrapped_cek_b64: URL_SAFE_NO_PAD.encode(wrapped_cek),
        }];

        let encryption = EncryptionInfoV1 {
            alg: "xchacha20poly1305".into(),
            nonce_b64: URL_SAFE_NO_PAD.encode(payload_nonce_bytes),
            cek_wrap: "mlkem".into(),
            wrapped_keys,
        };

        // 7) Assemble envelope
        let envelope = Self {
            v: 1,
            owner: owner_wallet.to_lowercase(),
            created_at,
            doc,
            encryption,
            ciphertext_b64: URL_SAFE_NO_PAD.encode(ciphertext),
        };

        // 8) Compute envelope ID
        let canon = canonical_json(&envelope);
        let eid = envelope_id(&canon);

        Ok((envelope, eid))
    }

    /// Decrypt envelope for owner using ML-KEM secret key (base64url no pad)
    pub fn decrypt_for_owner_mlkem(&self, owner_mlkem_sk_b64: &str) -> Result<Vec<u8>, String> {
        let wk = self
            .encryption
            .wrapped_keys
            .iter()
            .find(|k| k.recipient == self.owner)
            .ok_or_else(|| "no wrapped key for owner".to_string())?;

        // 1) ML-KEM decapsulation -> shared secret
        let shared_secret = mlkem_decapsulate_b64(owner_mlkem_sk_b64, &wk.kem_ct_b64)?;

        // 2) Derive wrapping key
        let hk = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut wrap_key = [0u8; 32];
        hk.expand(b"tidbit-cek-wrap-v1", &mut wrap_key)
            .map_err(|_| "hkdf expand failed".to_string())?;

        // 3) Unwrap CEK
        let wrap_nonce_bytes = URL_SAFE_NO_PAD
            .decode(&wk.wrap_nonce_b64)
            .map_err(|e| format!("wrap nonce decode: {e}"))?;
        if wrap_nonce_bytes.len() != 24 {
            return Err("wrap nonce invalid length".to_string());
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
            return Err("invalid CEK length".to_string());
        }
        let mut cek_arr = [0u8; 32];
        cek_arr.copy_from_slice(&cek[..32]);

        // 4) Decrypt payload
        let payload_nonce_bytes = URL_SAFE_NO_PAD
            .decode(&self.encryption.nonce_b64)
            .map_err(|e| format!("payload nonce decode: {e}"))?;
        if payload_nonce_bytes.len() != 24 {
            return Err("payload nonce invalid length".to_string());
        }
        let payload_nonce = XNonce::from_slice(&payload_nonce_bytes);

        let ciphertext = URL_SAFE_NO_PAD
            .decode(&self.ciphertext_b64)
            .map_err(|e| format!("ciphertext decode: {e}"))?;

        let payload_cipher = XChaCha20Poly1305::new((&cek_arr).into());
        let plaintext = payload_cipher
            .decrypt(payload_nonce, ciphertext.as_ref())
            .map_err(|_| "payload decryption failed".to_string())?;

        Ok(plaintext)
    }

    /// Multi-recipient envelope (wrap CEK once per recipient).
    /// `recipients`: Vec<(wallet, pk_b64)>
    pub fn create_mlkem_recipients(
        owner_wallet: String,
        recipients: Vec<(String, String)>,
        created_at: i64,
        doc: CanonicalDocumentV1,
        plaintext: &[u8],
    ) -> Result<(Self, String), String> {
        // 1) Generate CEK
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
        let mut wrapped_keys: Vec<WrappedCekV1> = Vec::with_capacity(recipients.len());

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

        // 5) Envelope + ID
        let env = Self {
            v: 1,
            owner: owner_wallet.to_lowercase(),
            created_at,
            doc,
            encryption,
            ciphertext_b64: URL_SAFE_NO_PAD.encode(ciphertext),
        };

        let canon = canonical_json(&env);
        let eid = envelope_id(&canon);

        Ok((env, eid))
    }
}

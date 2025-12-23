// src/cli/commands/encrypt.rs

use crate::crypto::aes_gcm;
use crate::pqc::kyber; // or your hybrid wrapper

pub async fn encrypt_file(path: &str) -> anyhow::Result<()> {
    let bytes = std::fs::read(path)?;

    // Symmetric AES-256-GCM encrypt
    let aes_key = aes_gcm::generate_aes256_key();
    let (ciphertext, nonce) = aes_gcm::encrypt(&aes_key, &bytes)?;

    std::fs::write(format!("{path}.enc"), &ciphertext)?;
    std::fs::write(format!("{path}.nonce"), &nonce)?;

    println!("🔐 Encrypted file: {path}.enc");
    println!("🧬 Nonce stored at: {path}.nonce");
    println!("(PQC wrapping of AES key is usually done when sharing/uploading)");

    Ok(())
}


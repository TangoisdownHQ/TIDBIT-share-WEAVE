// src/cli/commands/decrypt.rs

use std::path::PathBuf;

use crate::crypto::canonical::{
    DocumentEnvelopeV1,
    keystore::{load_or_create_mlkem_keypair, load_envelope_json},
};

use crate::error::AppError;

#[derive(clap::Args, Debug)]
pub struct DecryptArgs {
    /// Envelope id (filename without .json) stored under ~/.tidbit/envelopes/
    pub envelope_id: String,

    /// Owner wallet (defaults to env TIDBIT_WALLET if set)
    #[arg(long)]
    pub wallet: Option<String>,

    /// Optional output path (if omitted, prints to stdout as bytes)
    #[arg(long)]
    pub out: Option<PathBuf>,
}

pub async fn handle_decrypt(args: DecryptArgs) -> Result<(), AppError> {
    let owner_wallet = args
        .wallet
        .or_else(|| std::env::var("TIDBIT_WALLET").ok())
        .ok_or_else(|| AppError::BadRequest("Missing --wallet (or set TIDBIT_WALLET)".into()))?
        .to_lowercase();

    let kp = load_or_create_mlkem_keypair(&owner_wallet)
        .map_err(|e| AppError::Crypto(format!("mlkem keystore: {e}")))?;

    let bytes = load_envelope_json(&args.envelope_id)
        .map_err(|e| AppError::BadRequest(format!("load envelope: {e}")))?;

    let env: DocumentEnvelopeV1 =
        serde_json::from_slice(&bytes).map_err(|e| AppError::BadRequest(format!("parse envelope: {e}")))?;

    if env.owner.to_lowercase() != owner_wallet {
        return Err(AppError::Forbidden("this envelope is not owned by the provided wallet".into()));
    }

    let plaintext = env
        .decrypt_for_owner_mlkem(&kp.sk_b64)
        .map_err(|e| AppError::Crypto(format!("decrypt: {e}")))?;

    if let Some(out) = args.out {
        std::fs::write(&out, &plaintext)
            .map_err(|e| AppError::Internal(format!("write {:?}: {e}", out)))?;
        println!("✅ Decrypted -> {}", out.display());
    } else {
        // stdout raw bytes (good for piping)
        use std::io::Write;
        std::io::stdout()
            .write_all(&plaintext)
            .map_err(|e| AppError::Internal(format!("stdout: {e}")))?;
    }

    Ok(())
}


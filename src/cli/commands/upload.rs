// src/cli/commands/upload.rs

use std::path::PathBuf;

use crate::crypto::canonical::{
    CanonicalDocumentV1,
    DocumentEnvelopeV1,
    canonicalize::canonical_json,
    hash::envelope_id,
    keystore::{load_or_create_mlkem_keypair, save_envelope_json, envelope_path},
};

use crate::error::AppError;

#[derive(clap::Args, Debug)]
pub struct UploadArgs {
    /// Path to file to encrypt into an envelope
    pub path: PathBuf,

    /// Optional label shown in metadata
    #[arg(long)]
    pub label: Option<String>,

    /// Owner wallet (defaults to env TIDBIT_WALLET if set)
    #[arg(long)]
    pub wallet: Option<String>,
}

pub async fn handle_upload(args: UploadArgs) -> Result<(), AppError> {
    let plaintext = std::fs::read(&args.path)
        .map_err(|e| AppError::BadRequest(format!("read {:?}: {e}", args.path)))?;

    let owner_wallet = args
        .wallet
        .or_else(|| std::env::var("TIDBIT_WALLET").ok())
        .ok_or_else(|| AppError::BadRequest("Missing --wallet (or set TIDBIT_WALLET)".into()))?
        .to_lowercase();

    // create/load local ML-KEM keys for this wallet (client-side only)
    let kp = load_or_create_mlkem_keypair(&owner_wallet)
        .map_err(|e| AppError::Crypto(format!("mlkem keystore: {e}")))?;

    let file_name = args
        .path
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string());

    let doc = CanonicalDocumentV1::from_plaintext(
        // logical id: stable-ish string for now
        format!("doc-{}", uuid::Uuid::new_v4()),
        &plaintext,
        file_name,
        args.label.clone(),
    );

    let created_at = time::OffsetDateTime::now_utc().unix_timestamp();

    let (env, eid) = DocumentEnvelopeV1::create_mlkem_owner(
        owner_wallet.clone(),
        &kp.pk_b64,
        created_at,
        doc,
        &plaintext,
    )
    .map_err(|e| AppError::Crypto(format!("envelope create: {e}")))?;

    // canonical bytes -> store
    let canon = canonical_json(&env);
    // recompute eid from stored bytes (hard guarantee)
    let eid2 = envelope_id(&canon);
    if eid2 != eid {
        return Err(AppError::Crypto("envelope id mismatch after canonicalization".into()));
    }

    save_envelope_json(&eid, &canon)
        .map_err(|e| AppError::Internal(format!("save envelope: {e}")))?;

    let p = envelope_path(&eid).map_err(|e| AppError::Internal(e))?;
    println!("✅ Envelope created");
    println!("owner_wallet: {owner_wallet}");
    println!("envelope_id: {eid}");
    println!("saved: {}", p.display());
    println!("note: plaintext never stored by server in this flow.");

    Ok(())
}


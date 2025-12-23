// src/c2c/verify.rs

//! Temporary C2C event verification module.
//!
//! Your identity system is being rebuilt (Hybrid B model).
//! Dilithium signatures will return later. For now, this
//! accepts any event that *has* a signature, so the system
//! can progress to C2C + Arweave integration safely.

use crate::c2c::types::C2CEvent;
use crate::error::{AppError, AppResult};

/// For now we only check:
/// - does the event contain a signature?
/// - does it contain an actor wallet reference?
///
/// Once your PQC wallet subsystem is stable,
/// we plug in real verification logic here.
pub fn verify_event(ev: &C2CEvent) -> AppResult<()> {
    if ev.actor_wallet.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Missing actor wallet identifier".into(),
        ));
    }

    if ev.signature_b64.is_none() {
        return Err(AppError::BadRequest("Event is missing signature".into()));
    }

    // TODO (later):
    //  - decode PQC public key
    //  - decode PQC signature
    //  - call dilithium verify()
    //  - return Auth error on failure

    println!("[C2C-VERIFY] ⚠️  Verification stub used — real PQC verify is pending.");
    Ok(())
}

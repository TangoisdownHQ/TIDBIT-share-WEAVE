// src/c2c/record.rs

use crate::c2c::event::new_doc_event;
use crate::c2c::store::store_local_event;
use crate::c2c::types::{C2CEvent, C2CEventKind};
use crate::error::AppResult;

/// Record a "document uploaded" C2C event.
pub fn record_upload_event(
    actor_wallet: String,
    doc_hash_hex: String,
    arweave_tx: Option<String>,
) -> AppResult<C2CEvent> {
    let ev = new_doc_event(
        actor_wallet,
        C2CEventKind::DocumentUploaded,
        doc_hash_hex,
        arweave_tx,
        None,
    );
    store_local_event(&ev)?;
    Ok(ev)
}

/// Record a "document signed" C2C event.
pub fn record_sign_event(actor_wallet: String, doc_hash_hex: String) -> AppResult<C2CEvent> {
    let ev = new_doc_event(
        actor_wallet,
        C2CEventKind::DocumentSigned,
        doc_hash_hex,
        None,
        None,
    );
    store_local_event(&ev)?;
    Ok(ev)
}

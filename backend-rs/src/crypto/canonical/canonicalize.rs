// src/crypto/canonical/canonicalize.rs

use serde::Serialize;

pub fn canonical_json<T: Serialize>(value: &T) -> Vec<u8> {
    // serde_json already preserves field order in structs
    // and does not insert whitespace
    serde_json::to_vec(value).expect("canonical serialize")
}

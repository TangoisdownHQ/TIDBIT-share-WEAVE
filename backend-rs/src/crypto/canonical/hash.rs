// src/crypto/canonical/hash.rs

use crate::pqc::sha3;

pub fn envelope_id(canonical_bytes: &[u8]) -> String {
    let hash = sha3::sha3_256_bytes(canonical_bytes);
    hex::encode(hash)
}

// src/pqc/sha3.rs

use sha3::{Digest, Sha3_256};

pub fn sha3_256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

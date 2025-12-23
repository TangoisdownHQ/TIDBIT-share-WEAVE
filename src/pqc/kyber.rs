// src/pqc/kyber.rs

use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{PublicKey, SecretKey};

#[derive(Debug, Clone)]
pub struct KyberKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

pub fn generate_keypair() -> KyberKeypair {
    let (pk, sk) = kyber1024::keypair();
    KyberKeypair {
        public_key: pk.as_bytes().to_vec(),
        secret_key: sk.as_bytes().to_vec(),
    }
}

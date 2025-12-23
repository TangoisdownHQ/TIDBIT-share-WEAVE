// src/crypto/canonical/keystore.rs

use std::{fs, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::crypto::canonical::kem::mlkem_generate_keypair_b64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlKemKeypairFile {
    pub wallet: String,
    pub kem: String, // "mlkem768"
    pub pk_b64: String,
    pub sk_b64: String,
}

fn tidbit_dir() -> PathBuf {
    let mut dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    dir.push(".tidbit");
    dir
}

fn keys_root() -> PathBuf {
    let mut d = tidbit_dir();
    d.push("keys");
    d
}

fn wallet_key_dir(owner_wallet: &str) -> Result<PathBuf, String> {
    let w = owner_wallet.trim().to_lowercase();
    if w.is_empty() {
        return Err("wallet is empty".into());
    }
    let mut d = keys_root();
    d.push(w);
    Ok(d)
}

fn mlkem_key_path(owner_wallet: &str) -> Result<PathBuf, String> {
    let mut d = wallet_key_dir(owner_wallet)?;
    d.push("mlkem768.json");
    Ok(d)
}

pub fn load_or_create_mlkem_keypair(owner_wallet: &str) -> Result<MlKemKeypairFile, String> {
    let path = mlkem_key_path(owner_wallet)?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create_dir_all: {e}"))?;
    }

    if path.exists() {
        let data = fs::read_to_string(&path).map_err(|e| format!("read: {e}"))?;
        let kf: MlKemKeypairFile =
            serde_json::from_str(&data).map_err(|e| format!("json parse: {e}"))?;
        return Ok(kf);
    }

    let kp = mlkem_generate_keypair_b64();
    let kf = MlKemKeypairFile {
        wallet: owner_wallet.trim().to_lowercase(),
        kem: "mlkem768".into(),
        pk_b64: kp.pk_b64,
        sk_b64: kp.sk_b64,
    };

    let json = serde_json::to_string_pretty(&kf).map_err(|e| format!("json: {e}"))?;
    fs::write(&path, json).map_err(|e| format!("write: {e}"))?;

    Ok(kf)
}

pub fn load_mlkem_pk(owner_wallet: &str) -> Result<String, String> {
    let kf = load_or_create_mlkem_keypair(owner_wallet)?;
    Ok(kf.pk_b64)
}

fn envelope_dir() -> Result<PathBuf, String> {
    let mut dir = dirs::home_dir().ok_or("Cannot resolve home dir")?;
    dir.push(".tidbit");
    dir.push("envelopes");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

pub fn save_envelope_json(envelope_id: &str, json: &[u8]) -> Result<(), String> {
    let mut path = envelope_dir()?;
    path.push(format!("{envelope_id}.json"));
    fs::write(path, json).map_err(|e| e.to_string())
}

pub fn load_envelope_json(envelope_id: &str) -> Result<Vec<u8>, String> {
    let mut path = envelope_dir()?;
    path.push(format!("{envelope_id}.json"));
    fs::read(path).map_err(|e| e.to_string())
}

use std::{fs, path::PathBuf};
use serde::{Serialize, Deserialize};

use crate::crypto::canonical::kem::mlkem_generate_keypair_b64;

#[derive(Debug, Serialize, Deserialize)]
pub struct MlKemKeypairFile {
    pub wallet: String,
    pub pk_b64: String,
    pub sk_b64: String,
}

fn key_path(wallet: &str) -> PathBuf {
    let mut p = dirs::home_dir().expect("home dir");
    p.push(".tidbit/keys/mlkem");
    fs::create_dir_all(&p).ok();
    p.push(format!("{}.json", wallet));
    p
}

pub fn load_or_create_mlkem_keys(wallet: &str) -> MlKemKeypairFile {
    let path = key_path(wallet);

    if path.exists() {
        let bytes = fs::read(&path).expect("read mlkem key");
        return serde_json::from_slice(&bytes).expect("parse mlkem key");
    }

    let kp = mlkem_generate_keypair_b64();
    let file = MlKemKeypairFile {
        wallet: wallet.to_lowercase(),
        pk_b64: kp.pk_b64,
        sk_b64: kp.sk_b64,
    };

    let bytes = serde_json::to_vec_pretty(&file).expect("serialize mlkem key");
    fs::write(&path, bytes).expect("write mlkem key");

    file
}


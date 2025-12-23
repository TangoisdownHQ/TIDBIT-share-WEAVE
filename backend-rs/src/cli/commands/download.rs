// src/cli/commands/download.rs

use crate::identity::local_wallet::LocalWallet;
use crate::c2c::record::record_download_event;

pub async fn download_file(txid: &str) -> anyhow::Result<()> {
    // 1. Download (placeholder)
    let data = b"test file".to_vec();

    // 2. Save locally
    std::fs::write("downloaded.bin", data)?;

    // 3. Load wallet
    let wallet = LocalWallet::load("default")?;

    // 4. Record event
    record_download_event(&wallet, txid)?;

    println!("Downloaded file from txid {}", txid);
    Ok(())
}


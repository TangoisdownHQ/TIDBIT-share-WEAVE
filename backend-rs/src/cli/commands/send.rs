// src/cli/commands/send.rs

use reqwest::{Client, multipart};
use crate::identity::local_wallet::LocalWallet;
use crate::c2c::record::record_share_event;

pub async fn send_file(path: &str, to: &str) -> anyhow::Result<()> {
    let client = Client::new();
    let bytes = std::fs::read(path)?;
    let file_name = std::path::Path::new(path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();

    let form = multipart::Form::new()
        .text("recipient", to.to_string())
        .part("file", multipart::Part::bytes(bytes).file_name(file_name));

    let resp = client
        .post("http://localhost:4000/share")
        .multipart(form)
        .send()
        .await?
        .text()
        .await?;

    println!("📤 Share response:\n{resp}");
    Ok(())
}


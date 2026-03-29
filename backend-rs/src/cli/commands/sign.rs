use anyhow::Result;
use reqwest::Client;
use ethers_signers::{LocalWallet, Signer};
use std::str::FromStr;

pub async fn sign_doc(api: &str, session_id: &str, doc_id: &str, hash_hex: &str, wallet: &str, private_key: &str) -> Result<()> {
    let message = format!(
        "TIDBIT Document Attestation\n\
Document ID: {}\n\
Hash: {}\n\
Action: SIGN\n\
Wallet        : {}\n\
Version: 1",
        doc_id, hash_hex, wallet
    );

    let wallet = LocalWallet::from_str(private_key)?;
    let signature = wallet.sign_message(message).await?;

    let client = Client::new();
    let res = client
        .post(format!("{}/api/doc/{}/sign", api, doc_id))
        .header("x-session-id", session_id)
        .json(&serde_json::json!({
            "signature": signature.to_string()
        }))
        .send()
        .await?;

    let text = res.text().await?;
    println!("{}", text);

    Ok(())
}


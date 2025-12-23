// src/cli/commands/wallet.rs

use crate::cli::parser::WalletCommands;
use crate::crypto::canonical::keystore::load_or_create_mlkem_keypair;

/// Entry point from main.rs
pub async fn handle_wallet(cmd: WalletCommands) -> anyhow::Result<()> {
    match cmd {
        WalletCommands::Init => wallet_init().await?,
        WalletCommands::Show => wallet_show().await?,
    }
    Ok(())
}

/// Deterministic local wallet ID for CLI usage
/// (Later we can bind this to MetaMask / EVM)
fn default_wallet_id() -> String {
    "local-owner".to_string()
}

async fn wallet_init() -> anyhow::Result<()> {
    let wallet = default_wallet_id();

    let keys = load_or_create_mlkem_keypair(&wallet).map_err(|e| anyhow::anyhow!(e))?;

    println!("✅ Wallet initialized");
    println!("wallet: {}", keys.wallet);
    println!("kem: {}", keys.kem);
    println!("mlkem_pk_b64: {}", keys.pk_b64);

    Ok(())
}

async fn wallet_show() -> anyhow::Result<()> {
    let wallet = default_wallet_id();

    let keys = load_or_create_mlkem_keypair(&wallet).map_err(|e| anyhow::anyhow!(e))?;

    println!("wallet: {}", keys.wallet);
    println!("kem: {}", keys.kem);
    println!("mlkem_pk_b64: {}", keys.pk_b64);

    Ok(())
}

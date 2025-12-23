// src/cli/commands/config.rs

use crate::cli::parser::ConfigCommands;
use crate::config::AppConfig;

pub async fn handle_config(cmd: ConfigCommands) -> anyhow::Result<()> {
    match cmd {
        ConfigCommands::Show => {
            let cfg = AppConfig::load();
            println!("{:#?}", cfg);
        }
        ConfigCommands::Edit => {
            let mut cfg = AppConfig::load();

            println!("Enter VirusTotal API key (leave blank to keep current):");
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            let key = line.trim();
            if !key.is_empty() {
                cfg.vt_api_key = key.to_string();
            }

            cfg.save();
            println!("✅ Config updated.");
        }
    }

    Ok(())
}


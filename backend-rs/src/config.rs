// backend-rs/src/config.rs

use dirs::config_dir;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub arweave_gateway: String,
    pub bundlr_url: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            arweave_gateway: "https://arweave.net".into(),
            bundlr_url: "https://node1.bundlr.network".into(),
        }
    }
}

impl AppConfig {
    fn path() -> PathBuf {
        let base = config_dir().unwrap_or_else(|| PathBuf::from("."));
        base.join("tidbit").join("config.toml")
    }

    pub fn load_or_default() -> anyhow::Result<Self> {
        let path = Self::path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let txt = fs::read_to_string(&path)?;
        let cfg: AppConfig = toml::from_str(&txt)?;
        Ok(cfg)
    }

    #[allow(dead_code)]
    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let txt = toml::to_string_pretty(self)?;
        fs::write(path, txt)?;
        Ok(())
    }
}

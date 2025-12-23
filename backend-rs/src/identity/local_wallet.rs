//src/identity/local_wallet.rs

use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalWallet {
    /// Logical identifier for now (later: PQC keys, EVM address, etc.)
    pub id: String,
}

impl LocalWallet {
    fn path() -> PathBuf {
        let mut dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        dir.push(".tidbit");
        dir.push("wallet.json");
        dir
    }

    /// Create a new wallet and persist it. Passphrase is ignored *for now*.
    pub fn generate(_passphrase: &str) -> AppResult<Self> {
        let wallet = LocalWallet {
            id: "local-dev-wallet".to_string(),
        };

        if let Some(parent) = Self::path().parent() {
            fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(&wallet)?;
        fs::write(Self::path(), json)?;

        Ok(wallet)
    }

    pub fn load() -> AppResult<Self> {
        let data = fs::read_to_string(Self::path()).map_err(|e| AppError::Io(e))?;
        let w = serde_json::from_str(&data)?;
        Ok(w)
    }

    pub fn actor_id(&self) -> String {
        self.id.clone()
    }
}

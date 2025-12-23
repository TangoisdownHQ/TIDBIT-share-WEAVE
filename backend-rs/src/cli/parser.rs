// src/cli/parser.rs

use clap::{Parser, Subcommand};

// ============================================================
// ROOT CLI
// ============================================================

#[derive(Parser)]
#[command(author, version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

// ============================================================
// TOP-LEVEL COMMANDS
// ============================================================

#[derive(Subcommand)]
pub enum Commands {
    /// Manage local wallet
    Wallet {
        #[command(subcommand)]
        action: WalletCommands,
    },

    /// Manage documents
    Doc {
        #[command(subcommand)]
        action: DocCommands,
    },

    /// Chain-of-custody
    C2c {
        #[command(subcommand)]
        action: C2cCommands,
    },

    /// Run HTTP server
    Server,
}

// ============================================================
// WALLET COMMANDS
// ============================================================

#[derive(Subcommand, Debug)]
pub enum WalletCommands {
    /// Initialize local wallet (stub)
    Init,

    /// Show wallet identity
    Show,
}

// ============================================================
// DOCUMENT COMMANDS
// ============================================================

#[derive(Subcommand, Debug)]
pub enum DocCommands {
    Upload {
        path: String,
        label: Option<String>,
        #[clap(default_value = "local")]
        store: String,
    },

    Download {
        id: Option<String>,
        hash: Option<String>,
        out: String,
    },

    Sign {
        id: Option<String>,
        hash: Option<String>,
    },

    History {
        id: Option<String>,
        hash: Option<String>,
    },

    // ========================================================
    // 🔐 C20: ENVELOPE COMMANDS
    // ========================================================
    /// Create encrypted envelope from file
    EnvelopeCreate {
        #[clap(long)]
        input: String,
    },

    /// Decrypt envelope for owner
    EnvelopeDecrypt {
        #[clap(long)]
        envelope_id: String,
        #[clap(long)]
        out: String,
    },
}

// ============================================================
// C2C COMMANDS
// ============================================================

#[derive(clap::Subcommand)]
pub enum C2cCommands {
    /// List all chain-of-custody events
    List,

    /// Show a single event
    Show { id: String },

    /// Anchor an event hash on-chain (or Arweave later)
    Anchor { id: String },
}

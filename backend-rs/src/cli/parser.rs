// src/cli/parser.rs

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "tidbit",
    version,
    propagate_version = true,
    about = "TIDBIT-share-WEAVE backend CLI"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

// ======================================================
// TOP-LEVEL COMMANDS
// ======================================================

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run the HTTP server
    Server,

    /// Authentication (CLI login / session)
    Auth {
        #[command(subcommand)]
        action: AuthCommands,
    },

    /// Wallet operations
    Wallet {
        #[command(subcommand)]
        action: WalletCommands,
    },

    /// Document operations
    Doc {
        #[command(subcommand)]
        action: DocCommands,
    },

    /// Chain-of-custody (C2C)
    C2c {
        #[command(subcommand)]
        action: C2cCommands,
    },
}

// ======================================================
// AUTH
// ======================================================

#[derive(Subcommand, Debug)]
pub enum AuthCommands {
    /// Login using an EVM private key
    Evm {
        #[arg(long, default_value = "http://localhost:4100")]
        api: String,

        #[arg(long)]
        private_key: String,
    },

    /// Show current authenticated session
    Whoami {
        #[arg(long, default_value = "http://localhost:4100")]
        api: String,
    },

    /// Logout current session
    Logout {
        #[arg(long, default_value = "http://localhost:4100")]
        api: String,
    },
}

// ======================================================
// WALLET
// ======================================================

#[derive(Subcommand, Debug)]
pub enum WalletCommands {
    Init,
    Show,
}

// ======================================================
// DOC
// ======================================================

#[derive(Subcommand, Debug)]
pub enum DocCommands {
    /// Upload a document
    Upload {
        path: String,

        #[arg(long)]
        label: Option<String>,

        #[arg(long)]
        use_session: bool,

        #[arg(long)]
        owner_wallet: Option<String>,

        #[arg(long, default_value = "local")]
        store: String,
    },

    /// Download a document
    Download {
        #[arg(long)]
        id: Option<String>,

        #[arg(long)]
        hash: Option<String>,

        #[arg(long)]
        out: String,
    },

    /// Sign a document (CLI stub, frontend signing is canonical)
    Sign {
        #[arg(long, default_value = "http://localhost:4100")]
        api: String,

        #[arg(long)]
        session_id: String,

        #[arg(long)]
        doc_id: String,

        #[arg(long)]
        wallet: String,

        #[arg(long)]
        private_key: String,
    },

    /// Show document history (C2C)
    History {
        #[arg(long)]
        id: Option<String>,

        #[arg(long)]
        hash: Option<String>,
    },

    EnvelopeCreate {
        #[arg(long)]
        input: String,
    },

    EnvelopeShare {
        #[arg(long)]
        input: String,

        #[arg(long)]
        to_wallet: String,

        #[arg(long)]
        to_pk_b64: String,

        #[arg(long)]
        from_wallet: Option<String>,
    },

    EnvelopeDecrypt {
        #[arg(long)]
        envelope_id: String,

        #[arg(long)]
        out: String,

        #[arg(long)]
        wallet: Option<String>,
    },

    /// Repair legacy Supabase storage paths for document rows
    RepairStoragePaths {
        /// Apply the changes. Without this flag, prints a dry-run plan.
        #[arg(long)]
        apply: bool,

        /// Repair only one document id
        #[arg(long)]
        id: Option<String>,

        /// Limit how many document rows to inspect
        #[arg(long)]
        limit: Option<i64>,
    },
}

// ======================================================
// C2C
// ======================================================

#[derive(Subcommand, Debug)]
pub enum C2cCommands {
    List,
    Show { id: String },
    Anchor { id: String },
}

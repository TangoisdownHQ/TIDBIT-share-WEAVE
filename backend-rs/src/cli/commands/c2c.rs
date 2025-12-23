// src/cli/commands/c2c.rs

use anyhow::Result;

use crate::c2c::{onchain as c2c_onchain, store as c2c_store};
use crate::cli::parser::C2cCommands;
use crate::pqc::sha3 as pqc_sha3;

pub async fn handle_c2c(cmd: C2cCommands) -> Result<()> {
    match cmd {
        // ===================================================
        // LIST EVENTS
        // ===================================================
        C2cCommands::List => {
            let events = c2c_store::load_all_events()?;
            for ev in events {
                println!(
                    "{} | {} | {:?} | actor={}",
                    ev.id, ev.timestamp, ev.kind, ev.actor_wallet
                );
            }
        }

        // ===================================================
        // SHOW EVENT
        // ===================================================
        C2cCommands::Show { id } => match c2c_store::load_event_by_id(&id)? {
            Some(ev) => {
                println!("{}", serde_json::to_string_pretty(&ev)?);
            }
            None => {
                println!("No event with id={id}");
            }
        },

        // ===================================================
        // ANCHOR EVENT (HASH ONLY)
        // ===================================================
        C2cCommands::Anchor { id } => {
            let ev = match c2c_store::load_event_by_id(&id)? {
                Some(ev) => ev,
                None => {
                    println!("No event with id={id}");
                    return Ok(());
                }
            };

            // IMPORTANT:
            // Strip signature before anchoring
            let mut bare = ev.clone();
            bare.signature_b64 = None;

            let json = serde_json::to_vec(&bare)?;
            let hash = pqc_sha3::sha3_256_bytes(&json);

            // Currently anchors hash (EVM / stub / Arweave later)
            c2c_onchain::anchor_event_hash(&hash).await?;

            println!("Anchored event {} with hash {}", id, hex::encode(hash));
        }
    }

    Ok(())
}

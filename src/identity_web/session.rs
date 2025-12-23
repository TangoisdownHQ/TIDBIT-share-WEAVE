use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use uuid::Uuid;

pub type SessionId = String;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chain {
    Evm,
    Sol,
}

#[derive(Clone, Debug)]
pub struct WalletSession {
    pub session_id: SessionId,
    pub wallet_address: String,
    pub chain: Chain,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
}

impl WalletSession {
    pub fn is_expired(&self, now: SystemTime) -> bool {
        now >= self.expires_at
    }

    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64
    }
}

#[derive(Clone, Default)]
pub struct SessionStore {
    inner: Arc<RwLock<HashMap<SessionId, WalletSession>>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_session(
        &self,
        wallet: String,
        chain: Chain,
        ttl: Duration,
    ) -> WalletSession {
        let now = SystemTime::now();
        let expires_at = now + ttl;

        let session_id = format!("sess_{}", Uuid::new_v4());

        let session = WalletSession {
            session_id: session_id.clone(),
            wallet_address: wallet,
            chain,
            created_at: now,
            expires_at,
        };

        self.inner
            .write()
            .expect("session store poisoned")
            .insert(session_id, session.clone());

        session
    }

    pub fn get(&self, session_id: &str) -> Option<WalletSession> {
        let now = SystemTime::now();

        let session = self
            .inner
            .read()
            .ok()
            .and_then(|m| m.get(session_id).cloned())?;

        if session.is_expired(now) {
            self.revoke(session_id);
            return None;
        }

        Some(session)
    }

    pub fn revoke(&self, session_id: &str) {
        self.inner
            .write()
            .ok()
            .and_then(|mut m| m.remove(session_id));
    }
}

impl WalletSession {
    pub fn created_at_ms(&self) -> u64 {
        use std::time::UNIX_EPOCH;

        self.created_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    pub fn expires_at_ms(&self) -> u64 {
        use std::time::UNIX_EPOCH;

        self.expires_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}


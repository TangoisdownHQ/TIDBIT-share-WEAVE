use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

/// How long a wallet session is valid (seconds)
const SESSION_TTL_SECONDS: i64 = 60 * 60 * 24; // 24 hours

#[derive(Clone, Debug)]
pub struct WalletSession {
    pub wallet: String,
    pub chain: String,
    pub created_at: i64, // unix timestamp (seconds)
}

impl WalletSession {
    /// Unix timestamp (seconds) when session expires
    pub fn expires_at(&self) -> i64 {
        self.created_at + SESSION_TTL_SECONDS
    }

    /// Whether the session is expired right now
    pub fn is_expired(&self) -> bool {
        OffsetDateTime::now_utc().unix_timestamp() >= self.expires_at()
    }

    /// Unix timestamp in **milliseconds** (for API responses)
    pub fn created_at_ms(&self) -> i64 {
        self.created_at * 1_000
    }

    /// Expiry timestamp in **milliseconds** (for API responses)
    pub fn expires_at_ms(&self) -> i64 {
        self.expires_at() * 1_000
    }
}

#[derive(Clone)]
pub struct AuthState {
    nonces: Arc<Mutex<HashMap<String, String>>>,
    sessions: Arc<Mutex<HashMap<String, WalletSession>>>,
}

impl AuthState {
    pub fn new() -> Self {
        Self {
            nonces: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // ============================================================
    // NONCE LIFECYCLE (C18)
    // ============================================================

    pub fn create_nonce(&self) -> (String, String) {
        let sid = uuid::Uuid::new_v4().to_string();
        let nonce = uuid::Uuid::new_v4().to_string();
        self.nonces
            .lock()
            .unwrap()
            .insert(sid.clone(), nonce.clone());
        (sid, nonce)
    }

    pub fn take_nonce(&self, sid: &str) -> Option<String> {
        self.nonces.lock().unwrap().remove(sid)
    }

    // ============================================================
    // SESSION LIFECYCLE (C19)
    // ============================================================

    /// Bind a verified wallet to a session ID
    pub fn bind_wallet(&self, sid: String, wallet: String, chain: &str) {
        self.sessions.lock().unwrap().insert(
            sid,
            WalletSession {
                wallet,
                chain: chain.to_string(),
                created_at: OffsetDateTime::now_utc().unix_timestamp(),
            },
        );
    }

    /// Get a session if valid; expired sessions are revoked automatically
    pub fn get_session(&self, sid: &str) -> Option<WalletSession> {
        let mut sessions = self.sessions.lock().unwrap();
        let sess = sessions.get(sid)?.clone();

        if sess.is_expired() {
            sessions.remove(sid);
            return None;
        }

        Some(sess)
    }

    /// Explicit logout
    pub fn revoke_session(&self, sid: &str) {
        self.sessions.lock().unwrap().remove(sid);
    }

    /// Opportunistic cleanup
    pub fn cleanup_sessions(&self) {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        self.sessions
            .lock()
            .unwrap()
            .retain(|_, sess| sess.created_at + SESSION_TTL_SECONDS > now);
    }
}

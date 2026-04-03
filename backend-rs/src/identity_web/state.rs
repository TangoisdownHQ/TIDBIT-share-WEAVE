use crate::error::AppError;
use crate::sqlx::{PgPool, Row};
use time::OffsetDateTime;

const SESSION_TTL_SECONDS: i64 = 60 * 60 * 24;
const NONCE_TTL_SECONDS: i64 = 60 * 15;
const SESSION_ROTATE_AFTER_SECONDS: i64 = 60 * 60 * 12;

#[derive(Clone, Debug)]
pub struct WalletSession {
    pub session_id: String,
    pub wallet: String,
    pub chain: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_seen_at: i64,
    pub device_id: Option<String>,
    pub user_agent: Option<String>,
}

impl WalletSession {
    pub fn is_expired(&self) -> bool {
        OffsetDateTime::now_utc().unix_timestamp() >= self.expires_at
    }

    pub fn expires_at_ms(&self) -> i64 {
        self.expires_at * 1_000
    }

    pub fn created_at_ms(&self) -> i64 {
        self.created_at * 1_000
    }

    pub fn rotation_recommended(&self) -> bool {
        (self.last_seen_at - self.created_at) >= SESSION_ROTATE_AFTER_SECONDS
    }
}

#[derive(Clone)]
pub struct AuthState {
    db: PgPool,
}

impl AuthState {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub async fn create_nonce(&self) -> Result<(String, String), AppError> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let nonce = uuid::Uuid::new_v4().to_string();
        let now = OffsetDateTime::now_utc();
        let expires_at = now + time::Duration::seconds(NONCE_TTL_SECONDS);

        crate::sqlx::query(
            r#"
            insert into wallet_auth_nonces (session_id, nonce, created_at, expires_at)
            values ($1, $2, to_timestamp($3), to_timestamp($4))
            "#,
        )
        .bind(&session_id)
        .bind(&nonce)
        .bind(now.unix_timestamp())
        .bind(expires_at.unix_timestamp())
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok((session_id, nonce))
    }

    pub async fn take_nonce(&self, session_id: &str) -> Result<Option<String>, AppError> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let row = crate::sqlx::query(
            r#"
            update wallet_auth_nonces
            set consumed_at = to_timestamp($2)
            where session_id = $1
              and consumed_at is null
              and expires_at > to_timestamp($2)
            returning nonce
            "#,
        )
        .bind(session_id.trim())
        .bind(now)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(row.map(|record| record.get("nonce")))
    }

    pub async fn bind_wallet(
        &self,
        session_id: String,
        wallet: String,
        chain: &str,
        device_id: Option<&str>,
        user_agent: Option<&str>,
        ip_address: Option<&str>,
    ) -> Result<WalletSession, AppError> {
        let now = OffsetDateTime::now_utc();
        let expires_at = now + time::Duration::seconds(SESSION_TTL_SECONDS);
        let session_family_id = uuid::Uuid::new_v4();

        crate::sqlx::query(
            r#"
            insert into wallet_sessions (
                session_id,
                session_family_id,
                wallet,
                chain,
                created_at,
                last_seen_at,
                expires_at,
                device_id,
                user_agent,
                ip_address
            )
            values (
                $1,
                $2,
                $3,
                $4,
                to_timestamp($5),
                to_timestamp($5),
                to_timestamp($6),
                $7,
                $8,
                $9
            )
            on conflict (session_id)
            do update set
                wallet = excluded.wallet,
                chain = excluded.chain,
                last_seen_at = excluded.last_seen_at,
                expires_at = excluded.expires_at,
                device_id = excluded.device_id,
                user_agent = excluded.user_agent,
                ip_address = excluded.ip_address,
                revoked_at = null,
                revoked_reason = null,
                replaced_by_session_id = null
            "#,
        )
        .bind(&session_id)
        .bind(session_family_id)
        .bind(&wallet)
        .bind(chain)
        .bind(now.unix_timestamp())
        .bind(expires_at.unix_timestamp())
        .bind(device_id.map(str::trim))
        .bind(user_agent.map(str::trim))
        .bind(ip_address.map(str::trim))
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(WalletSession {
            session_id,
            wallet,
            chain: chain.to_string(),
            created_at: now.unix_timestamp(),
            expires_at: expires_at.unix_timestamp(),
            last_seen_at: now.unix_timestamp(),
            device_id: device_id.map(str::to_string),
            user_agent: user_agent.map(str::to_string),
        })
    }

    pub async fn get_session(
        &self,
        session_id: &str,
        presented_device_id: Option<&str>,
    ) -> Result<Option<WalletSession>, AppError> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let row = crate::sqlx::query(
            r#"
            select
                session_id,
                wallet,
                chain,
                extract(epoch from created_at)::bigint as created_at,
                extract(epoch from expires_at)::bigint as expires_at,
                extract(epoch from last_seen_at)::bigint as last_seen_at,
                device_id,
                user_agent
            from wallet_sessions
            where session_id = $1
              and revoked_at is null
              and expires_at > to_timestamp($2)
            "#,
        )
        .bind(session_id.trim())
        .bind(now)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

        let Some(row) = row else {
            return Ok(None);
        };

        let stored_device_id: Option<String> = row.get("device_id");
        if let Some(expected) = stored_device_id.as_deref() {
            match presented_device_id.map(str::trim).filter(|value| !value.is_empty()) {
                Some(presented) if presented == expected => {}
                _ => return Ok(None),
            }
        }

        crate::sqlx::query(
            "update wallet_sessions set last_seen_at = to_timestamp($2) where session_id = $1",
        )
        .bind(session_id.trim())
        .bind(now)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(Some(WalletSession {
            session_id: row.get("session_id"),
            wallet: row.get("wallet"),
            chain: row.get("chain"),
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
            last_seen_at: now,
            device_id: stored_device_id,
            user_agent: row.get("user_agent"),
        }))
    }

    pub async fn revoke_session(&self, session_id: &str) -> Result<(), AppError> {
        crate::sqlx::query(
            "update wallet_sessions set revoked_at = now(), revoked_reason = coalesce(revoked_reason, 'logout') where session_id = $1",
        )
        .bind(session_id.trim())
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn rotate_session(
        &self,
        session_id: &str,
        presented_device_id: Option<&str>,
        user_agent: Option<&str>,
        ip_address: Option<&str>,
    ) -> Result<Option<WalletSession>, AppError> {
        let Some(current) = self.get_session(session_id, presented_device_id).await? else {
            return Ok(None);
        };

        let new_session_id = uuid::Uuid::new_v4().to_string();
        let now = OffsetDateTime::now_utc();
        let expires_at = now + time::Duration::seconds(SESSION_TTL_SECONDS);

        let family_row = crate::sqlx::query(
            "select session_family_id from wallet_sessions where session_id = $1",
        )
        .bind(session_id.trim())
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
        let session_family_id: uuid::Uuid = family_row.get("session_family_id");

        crate::sqlx::query(
            r#"
            insert into wallet_sessions (
                session_id,
                session_family_id,
                wallet,
                chain,
                created_at,
                last_seen_at,
                expires_at,
                device_id,
                user_agent,
                ip_address
            )
            values (
                $1,
                $2,
                $3,
                $4,
                to_timestamp($5),
                to_timestamp($5),
                to_timestamp($6),
                $7,
                $8,
                $9
            )
            "#,
        )
        .bind(&new_session_id)
        .bind(session_family_id)
        .bind(&current.wallet)
        .bind(&current.chain)
        .bind(now.unix_timestamp())
        .bind(expires_at.unix_timestamp())
        .bind(presented_device_id.or(current.device_id.as_deref()))
        .bind(user_agent.or(current.user_agent.as_deref()))
        .bind(ip_address)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

        crate::sqlx::query(
            r#"
            update wallet_sessions
            set revoked_at = now(),
                revoked_reason = 'rotated',
                replaced_by_session_id = $2
            where session_id = $1
            "#,
        )
        .bind(session_id.trim())
        .bind(&new_session_id)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(Some(WalletSession {
            session_id: new_session_id,
            wallet: current.wallet,
            chain: current.chain,
            created_at: now.unix_timestamp(),
            expires_at: expires_at.unix_timestamp(),
            last_seen_at: now.unix_timestamp(),
            device_id: presented_device_id
                .map(str::to_string)
                .or(current.device_id),
            user_agent: user_agent.map(str::to_string).or(current.user_agent),
        }))
    }
}

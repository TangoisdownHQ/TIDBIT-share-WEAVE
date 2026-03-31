# Dependency Inventory - 2026-03-30

Command reference:

```bash
cd backend-rs
cargo tree --depth 2
```

## Primary Dependency Groups

### Web Server

- `axum`
- `tower-http`
- `tokio`
- `reqwest`

### Database And Storage

- `sqlx`
- Supabase Postgres via `DATABASE_URL`
- Supabase Storage client code in the application

### Cryptography

- `aes-gcm`
- `chacha20poly1305`
- `sha2`
- `sha3`
- `k256`
- `ed25519-dalek`
- `pqcrypto-mlkem`
- `pqcrypto-mldsa`

### Identity And Signing

- `ethers-core`
- `ethers-signers`
- `bs58`
- `ed25519-dalek`

### Data / Serialization / Utility

- `serde`
- `serde_json`
- `chrono`
- `uuid`
- `clap`
- `anyhow`
- `thiserror`

## High-Level Tree Snapshot

```text
tidbit_share_weave_backend
├── axum
├── sqlx
├── reqwest
├── ethers-core
├── ethers-signers
├── ed25519-dalek
├── pqcrypto-mlkem
├── pqcrypto-mldsa
├── aes-gcm
├── chacha20poly1305
├── sha3
└── tokio
```

## Why These Dependencies Exist

- `axum` powers the HTTP API and page serving.
- `sqlx` powers Postgres persistence for documents, shares, and events.
- `reqwest` powers outbound calls to Resend, Twilio, and future external services.
- `ethers-*` is used for EVM wallet flows.
- `ed25519-dalek` and `bs58` are used for Solana signature verification.
- `pqcrypto-*` provides the current PQ verification and envelope primitives.

## Operational Note

The app's dependency graph is broader than the runtime path it uses every day. That matters for audits. A crate can appear in the graph even if the day-to-day application flow does not directly exercise it.

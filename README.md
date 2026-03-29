<p align="center">
  <img src="image/tidbit-share-weave-logo.png" width="420" alt="TIDBIT-share-WEAVE logo">
</p>

<h1 align="center">TIDBIT-share-WEAVE</h1>

<p align="center">
  <strong>Quantum-Resistant · Zero-Trust · Wallet-Native File Custody</strong>
</p>

> A cryptographic constellation representing file lineage, custody, and trust without central authority.

## 🌐 TIDBIT-share-WEAVE

Quantum-Resistant, Zero-Trust File Custody & Sharing

TIDBIT-share-WEAVE is a decentralized, post-quantum-resilient file creation, versioning, review, signing, and sharing system designed for zero-trust environments, long-term data integrity, and wallet-native identity.

It provides cryptographically verifiable chain-of-custody for files, ensuring confidentiality, authenticity, and auditability even under future quantum threat models.

No central authority.
No silent mutation.
Every action is signed, linked, and traceable.

## 🧠 What Makes TIDBIT-share-WEAVE Different

Unlike traditional file-sharing platforms, TIDBIT-share-WEAVE treats files as cryptographic entities, not just data blobs.

Each file:

- Is enveloped for tamper-evident custody
- Has an immutable event history
- Is owned and controlled via wallet identity
- Remains verifiable decades into the future

This makes it suitable for high-assurance environments where trust cannot be assumed.

## 🔐 Core Capabilities

### 🧬 Post-Quantum Cryptography (PQC)

- AES-256-GCM / XChaCha20-Poly1305 payload protection
- ML-KEM (Kyber) quantum-resistant key encapsulation
- Dilithium post-quantum signatures
- SHA3-256 tamper-evident hashing

### 🧾 Zero-Trust Chain-of-Custody

- Every file action creates a signed, append-only event
- Immutable linkage between versions and actions
- Forensic-grade audit trails

### 👤 Wallet-Based Identity

- EVM and Solana wallets as identity roots
- No usernames or passwords
- Ownership and access tied to cryptographic proof

### 📂 Secure File Versioning

- Logical document separation
- Hash-based deduplication
- Verifiable version history with parent-child lineage

### 🌍 Decentralized Storage / Anchoring

- Supabase Storage for active application storage
- Optional Arweave-style anchoring for file and evidence hashes
- Infrastructure-independent verification

## 🧾 Chain-of-Custody Model

Every file interaction generates a cryptographically linked event containing:

- Actor identity
- Timestamp
- File hash
- Signature or attestation metadata
- Optional decentralized storage anchor

This forms a verifiable file-trail ledger suitable for:

- Compliance and audit
- Legal evidence
- Long-term archival
- Incident response and forensics

## 🧬 Design Philosophy

- Zero Trust by Default
- Post-Quantum First
- Wallets as Identity
- No Silent State Changes
- Verifiability Over Convenience

Trust is never implied. It is cryptographically proven.

## 🧪 Project Status

Current state includes:

- Wallet login for MetaMask and Phantom
- Secure file uploads
- Review-before-sign flow
- Public signing links
- Document version creation
- Evidence export
- Inbox and share records
- Optional Arweave anchoring
- Policy and agent API groundwork

Still in progress:

- Browser-side PQ crypto generation/signing
- Real provider-backed outbound delivery setup
- Public deployment and production billing
- Office-class collaborative editing

## 🗺️ Roadmap

- End-to-end browser-side PQ encryption/signing
- Provider-backed email and SMS delivery
- Wallet-to-wallet delivery flows
- Human and AI agent policy routing
- Evidence bundle anchoring
- Subscription billing
- Production deployment

## 🧬 Why This Exists

TIDBIT-share-WEAVE is built for a future where:

- Quantum computers are real
- Centralized trust collapses
- Data must remain verifiable for decades

This project is about cryptographic continuity, not just encryption.

## 📂 Project Structure

```text
TIDBIT-share-WEAVE/
├── backend-rs/
│   ├── Cargo.toml
│   ├── migrations/
│   ├── src/
│   │   ├── main.rs
│   │   ├── config.rs
│   │   ├── error.rs
│   │   ├── models.rs
│   │   ├── crypto/
│   │   ├── pqc/
│   │   ├── c2c/
│   │   ├── identity/
│   │   ├── routes/
│   │   ├── storage/
│   │   └── cli/
│   └── web/
├── docker/
├── image/
└── README.md
```

## 🔐 Security Architecture

### 🔒 Encryption Pipeline

```text
plaintext file
  ↓ envelope / payload protection
ciphertext + nonce
  ↓ ML-KEM wrapping
wrapped encryption keys
  ↓ canonical envelope
PQC-verifiable structure
  ↓ optional Arweave anchor
hash-anchored evidence
```

Everything is designed to be tamper-evident and verifiable. Some production flows are still evolving toward full browser-side zero-trust PQ execution.

## 🧪 Backend Setup

```bash
cd backend-rs
cargo build
cargo run -- server
```

Default local server:

```text
http://127.0.0.1:4100
```

Use `.env.example` as the environment template for:

- Supabase Postgres
- Supabase Storage
- PUBLIC_APP_URL
- Resend
- Twilio
- Arweave / Bundlr-style anchoring

## CLI Examples

```bash
cargo run -- doc repair-storage-paths
cargo run -- c2c list
cargo run -- wallet show
```

## 🌌 Use Cases

- Secure document drafting
- Encrypted communication
- Multi-chain file transfer
- Legal, medical, and financial records
- Collaboration with provable custody
- Post-quantum secure archives
- Blockchain ecosystem file exchange
- Human and AI agent review flows

## ⚖️ License

MIT (subject to change)

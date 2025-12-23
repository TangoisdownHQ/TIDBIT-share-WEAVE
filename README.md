<p align="center">
  <img src="image/tidbit-share-weave-logo.png" width="420" alt="TIDBIT-share-WEAVE logo">
</p>

<h1 align="center">TIDBIT-share-WEAVE</h1>

<p align="center">
  <strong>Quantum-Resistant · Zero-Trust · Wallet-Native File Custody</strong>
</p>
> A cryptographic constellation representing file lineage, custody, and trust without central authority.


🌐 TIDBIT-share-WEAVE

Quantum-Resistant, Zero-Trust File Custody & Sharing

TIDBIT-share-WEAVE is a decentralized, post-quantum–resilient file creation, versioning, and sharing system designed for zero-trust environments, long-term data integrity, and wallet-native identity.

It provides cryptographically verifiable chain-of-custody for files — ensuring confidentiality, authenticity, and auditability even under future quantum threat models.

No central authority.
No silent mutation.
Every action is signed, linked, and traceable.

🧠 What Makes TIDBIT-share-WEAVE Different

Unlike traditional file-sharing platforms, TIDBIT-share-WEAVE treats files as cryptographic entities, not just data blobs.

Each file:

Is encrypted client-side

Has an immutable event history

Is owned and controlled via wallet identity

Remains verifiable decades into the future

This makes it suitable for high-assurance environments where trust cannot be assumed.

🔐 Core Capabilities
🧬 Post-Quantum Cryptography (PQC)

AES-256-GCM — payload encryption

ML-KEM (Kyber) — quantum-resistant key encapsulation

Dilithium — post-quantum signatures

SHA3-256 — tamper-evident hashing

🧾 Zero-Trust Chain-of-Custody

Every file action creates a signed, append-only event

Immutable linkage between versions and actions

Forensic-grade audit trails

👤 Wallet-Based Identity

EVM & Solana wallets as identity roots

No usernames or passwords

Ownership = cryptographic proof

📂 Secure File Versioning

Logical document separation

Hash-based deduplication

Verifiable version history

🌍 Decentralized Storage (Optional)

Encrypted payload anchoring via Arweave

Custody metadata anchoring

Infrastructure-independent verification

🧾 Chain-of-Custody Model (Simple Explanation)

Every file interaction generates a cryptographically linked event containing:

Wallet identity of the actor

Timestamp

File hash

PQC signature

Optional decentralized storage anchor

This forms a verifiable FileTrail ledger, suitable for:

Compliance & audit

Legal evidence

Long-term archival

Incident response & forensics

🧬 Design Philosophy

Zero Trust by Default

Post-Quantum First

Wallets as Identity

No Silent State Changes

Verifiability Over Convenience

Trust is never implied — it is cryptographically proven.

🧪 Project Status

Current Phase: C18 / C19

✅ Secure file uploads
✅ FileTrail chain-of-custody
✅ Wallet identity (CLI + API)
✅ PQC-encrypted document envelopes
✅ Optional Arweave anchoring

🟡 Access control & sharing policies
🟡 Wallet-to-wallet delivery flows

🗺 Roadmap

Encrypted wallet-to-wallet file delivery

PQC-signed access grants

Secure sharing links (email / SMS)

Malware & content sanitization

Web UI with wallet-native auth

Long-term verification tooling

🧬 Why This Exists

TIDBIT-share-WEAVE is built for a future where:

Quantum computers are real

Centralized trust collapses

Data must remain verifiable for decades

This project is about cryptographic continuity, not just encryption.

📂 Project Structure
TIDBIT-share-WEAVE/
├── backend-rs/                 # Rust backend (core system)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── config.rs
│       ├── error.rs
│       ├── models.rs
│       │
│       ├── crypto/             # Canonical crypto + PQC
│       │   └── canonical/
│       │       ├── document.rs
│       │       ├── envelope.rs
│       │       ├── kem.rs
│       │       ├── keystore.rs
│       │       └── hash.rs
│       │
│       ├── pqc/                # Kyber / Dilithium / SHA3
│       ├── c2c/                # Chain-of-custody system
│       ├── identity/           # Wallet + identity logic
│       ├── routes/             # HTTP API (upload/download/share)
│       └── cli/                # CLI tooling
│
├── docker/                     # Deployment tooling
├── image/                      # Assets / diagrams
└── README.md

🔐 Security Architecture
🔒 Encryption Pipeline
plaintext file
   ↓ AES-256-GCM
ciphertext + nonce
   ↓ ML-KEM (Kyber)
wrapped encryption keys
   ↓ Canonical Envelope
PQC-verifiable structure
   ↓ Optional Arweave anchor


Everything is quantum-resistant, tamper-evident, and verifiable.

🧪 Backend Setup
cd backend-rs
cargo build
cargo run


Default server:

http://localhost:4000


CLI examples:

cargo run -- doc upload file.txt
cargo run -- doc envelope-create --input file.txt
cargo run -- c2c list
cargo run -- c2c anchor <event-id>

🌌 Use Cases

Secure document drafting

Encrypted communication

Multi-chain file transfer

Legal, medical, financial records

Collaboration with provable custody

Post-quantum secure archives

Blockchain ecosystem file exchange

⚖️ License

MIT (subject to change)

🌐 TIDBIT-share-WEAVE

Zero-trust. Post-quantum encrypted. Wallet-connected file custody.

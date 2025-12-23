🌐 TIDBIT-share-WEAVE (Quantum-Resistant Edition)
Zero-trust. Post-quantum encrypted. Wallet-connected secure file creation and sharing.

TIDBIT-share-WEAVE is a decentralized, post-quantum secure, end-to-end encrypted file creation, editing, and sharing system designed for the next generation of:

decentralized organizations

multi-chain identities

secure communications

long-term storage

post-quantum threat models

Built with:

🦀 Rust (Axum) backend

🔐 AES-256-GCM file encryption

🧬 Kyber-1024 PQC key encapsulation

✍️ Dilithium-3 PQC signatures

🛢 Arweave + Bundlr permanent storage

🔗 Polygon/Web3 wallets for identity

🧹 Optional sanitization/scanning for malware & unsafe links

🧾 PQC-signed chain-of-custody for file versioning

Users can securely create, edit, save, and send encrypted files to:

Wallet addresses

Email addresses

Phone numbers (SMS)

External users

Internal team members

Everything is protected with quantum-resistant encryption and optional malware scanning.

🚀 Features
🔐 Post-Quantum Encryption (PQC)

AES-256-GCM for all file encryption

Kyber-1024 for wrapping AES keys

Dilithium-3 signatures for integrity and identity

SHA3-256 hashing for tamper detection

🧾 Permanent Storage

Encrypted data stored on Arweave via Bundlr

Metadata + chain-of-custody events also stored on Arweave

📝 Create / Edit / Save Files Securely

Users can create documents inside the app

Modify or update files

Every new save becomes a new version

Each version has its own PQC-signed C2C event

📤 Send Files to Anyone

Send encrypted files via:

Wallet → wallet

Email

Text message

Secure PQC link

Internal user address

🛡 Optional Sanitization Layer

Users can enable scanning for:

Malware

Phishing links

Unsafe attachments

MIME inconsistencies

Executable masquerading (PDF/exe trickery)

✔ Zero-Trust Architecture

Backend never stores plaintext

All encryption happens client-side or in sandbox

PQC identity required for all sensitive operations

🔗 Hybrid Identity

Authentication can combine:

Wallet signature (ECDSA)
+  
Dilithium PQC signature

📂 Project Structure
tidbit-share-weave/
├── backend-rs/                      # Rust PQC backend
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── config.rs
│       ├── error.rs
│       ├── models.rs
│       ├── arweave.rs
│       │
│       ├── pqc/                     # Post-Quantum Crypto
│       │   ├── mod.rs
│       │   ├── kyber.rs            # Kyber-1024 KEM utilities
│       │   ├── dilithium.rs        # Dilithium-3 signature utilities
│       │   └── sha3.rs             # SHA3 hashing
│       │
│       ├── crypto/                  # Symmetric crypto
│       │   ├── mod.rs
│       │   ├── aes_gcm.rs          # AES-256-GCM file encryption
│       │   └── keywrap.rs          # (Phase 2) PQC-AES hybrid key wrap
│       │
│       ├── sanitizer/               # (Phase 3) Optional sanitization layer
│       │   ├── mod.rs
│       │   ├── file_scan.rs
│       │   ├── link_scan.rs
│       │   ├── mime_check.rs
│       │   └── sandbox.rs
│       │
│       ├── routes/                  # Application API
│       │   ├── mod.rs
│       │   ├── health.rs
│       │   ├── upload.rs           # Upload encrypted files
│       │   ├── download.rs         # Download + decrypt
│       │   └── share.rs            # Send files to users/wallet/email
│       │
│       ├── c2c/                     # Chain-of-Custody
│       │   ├── mod.rs
│       │   ├── types.rs
│       │   ├── record.rs           # Create C2C events
│       │   └── verify.rs           # Verify signed C2C chains
│       │
│       └── identity/                # Wallet + PQC identity
│           ├── mod.rs
│           ├── registry.rs          # Polygon on-chain access control
│           ├── wallet_verify.rs     # ECDSA signature verification
│           └── proof_of_key.rs      # PQC challenge/response
│
├── frontend/                         # (Upcoming) React/Tailwind UI
├── contracts/                        # Solidity Access/Identity contracts
└── README.md

🔐 Security Architecture
🔒 Encryption Pipeline
plaintext file
   ↓ AES-256-GCM
ciphertext + nonce
   ↓ Kyber-1024
AES key wrapped for recipient
   ↓ Dilithium-3
signed metadata
   ↓ Arweave/Bundlr
permanent storage


Everything is quantum-resistant and tamper-evident.

🛡 Sanitization Architecture (Optional)

Users may toggle:

🔍 File Malware Scan

ClamAV

YARA rules

Magic byte validation

MIME sniffing

🌐 Link Scanner

Redirect detection

Phishing detection

URL normalization

Safe domain whitelist/blacklist

🧪 Safe Viewer Sandbox

For dangerous file formats:

PDFs

DOCX (macro risk)

HTML files

Executables

The viewer runs in:

WASM sandbox

Firejail

Bubblewrap (bwrap)

Recipient sees:

“Opened safely in sandbox mode — device protected.”

🧾 Chain-of-Custody (C2C)

Every file and every version generates a PQC-signed event:

C2C Event
├── file_id
├── sha3_hash
├── action (UPLOAD/EDIT/SHARE)
├── timestamp
├── previous_event_hash
├── dilithium_signature
└── arweave_tx


This is stored on Arweave as:

tamper-proof

immutable

permanent

cryptographically verifiable

Perfect for compliance, forensics, and enterprise use.

👤 Identity & Access
🌐 Web3 Wallets (MetaMask, Phantom, etc.)

Users authenticate via:

ECDSA wallet signature

Optional Dilithium signature

PQC challenge/response

👥 Recipient Model Supports:

Wallet-to-wallet

Email addresses

Phone/SMS (opens a secure PQC link)

Internal usernames in your system

🧪 Backend Setup
cd backend-rs
cargo build
cargo run


Backend default:
http://localhost:4000

🌌 Use Cases

Secure document drafting

Encrypted communication

Multi-chain file transfer

Legal, medical, financial records

Collaboration with provable C2C

Post-quantum secure archives

Blockchain ecosystem file exchange

🗺 Roadmap
✔ Phase 1

PQC primitives (Kyber/Dilithium/SHA3)

✔ Phase 2

AES-256-GCM implementation

🔜 Phase 3

Hybrid keywrap (AES + Kyber)

🔜 Phase 4

File upload/download API routes

🔜 Phase 5

Sanitization module (optional scanning)

🔜 Phase 6

Chain-of-custody integration

🔜 Phase 7

Frontend React UI + Wallet login

🔜 Phase 8

Email/SMS recipient delivery

⚖️ License

MIT (or anything you choose)

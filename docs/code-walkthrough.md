# Code Walkthrough

![Code map](./assets/code-map.svg)

## Core Runtime

### `backend-rs/src/main.rs`

This is the application entrypoint and route host.

It is responsible for:

- constructing `AppState`
- connecting to Supabase Postgres
- creating the Supabase Storage client
- ensuring runtime schema safety checks
- mounting all major HTTP routes

Important route groups:

- wallet auth
- document CRUD and review
- share and inbox routes
- evidence export and anchoring
- agent routes
- public signing routes
- billing/account status

`main.rs` is currently large because the project has been moving quickly. Functionally, it already contains the core business logic, but structurally it is still a strong candidate for future service extraction.

## Key Backend Areas

### Identity

Folders:

- `backend-rs/src/identity`
- `backend-rs/src/identity_web`

What they do:

- hold wallet session logic
- issue nonces
- bind wallet sessions
- verify EVM and Solana login flows

### Crypto

Folders:

- `backend-rs/src/crypto`
- `backend-rs/src/crypto/canonical`
- `backend-rs/src/pqc`

What they do:

- canonical message building
- envelope building
- hashing
- PQ signature verification helpers
- key wrapping helpers

Important current split:

- ML-KEM envelope helpers are still in the PQ/envelope path
- ML-DSA signing verification now uses the maintained `fips204` implementation inside `pqc/dilithium.rs`

### Storage

Folder:

- `backend-rs/src/storage`

What it does:

- uploads and retrieves object blobs from Supabase Storage
- handles storage paths and object lifecycle helpers

This area matters because storage paths, envelope storage, and access-controlled blob retrieval are part of the actual zero-trust boundary for the app.

### Delivery

File:

- `backend-rs/src/delivery.rs`

What it does:

- Resend email calls
- Twilio SMS calls
- delivery outcome struct and provider result normalization

### Frontend Runtime

Files:

- `backend-rs/web/app.js`
- `backend-rs/web/style.css`

What they do:

- login handling
- page bootstrapping
- dashboard tab state
- upload/share/sign/download flows
- inbox and shared activity rendering
- billing status rendering
- custody timeline rendering

## Important Functions To Understand

### `create_document_record`

Purpose:

- create a new stored document record
- generate the server-managed PQ envelope
- upload the envelope blob
- insert metadata into `documents`

This function is one of the best places to study if you want to understand how the app bridges a normal upload flow and a custody-first storage model.

### `load_document_access_record`

Purpose:

- decide whether the current actor can access a document
- support owner access and chain-aware share access

This is one of the most important trust boundaries in the app.

If this function is wrong, the rest of the cryptography does not save the product. Access control is foundational.

### `share_doc_handler`

Purpose:

- create the share row
- determine wallet route vs provider route
- create the public token/signing URL
- write custody events

This function is important because it shows that "share" in this product is not one thing. It can involve:

- wallet routing
- public signing links
- provider delivery
- ledger events for each stage

### `sign_doc_handler`

Purpose:

- verify a canonical signature
- accept EVM, Solana, and PQ verification paths
- write a `SIGN` event to the custody ledger

This is the main function to read if you want to understand how the product supports multiple signing modes without treating them as identical under the hood.

### `public_envelope_sign_handler`

Purpose:

- support public signing links
- allow guest, EVM, Solana, or PQ completion flow
- mark envelope completion and record event history

This is the best example of the product's "practical usability plus high-assurance audit" balance. It supports easier public flows while still writing structured custody history.

### `backend-rs/src/sqlx.rs`

Purpose:

- expose only the Postgres-specific pieces this app actually needs
- avoid the broader umbrella `sqlx` dependency graph

This file exists because the project deliberately removed the heavier `sqlx` umbrella crate from the dependency graph to mitigate prior audit findings.

## Frontend Page Responsibilities

### `dashboard.html`

Main workspace entry point with:

- home stats
- inbox/documents
- shared files
- shared activity
- billing

### `document.html`

Single-document control surface with:

- metadata
- preview
- lineage
- share state
- custody timeline

### `review.html`

Focused review-before-sign page.

### `public-sign.html`

Unauthenticated or public token signing page.

## How The Tool Is Made

The tool is not a single blockchain app and not a single storage app. It is a layered system:

1. **Wallet identity layer**
   MetaMask and Phantom identify users.
2. **Application custody layer**
   Every important action becomes a ledger event in Postgres.
3. **Object storage layer**
   Supabase stores the live encrypted object.
4. **Verification layer**
   Hashes and signatures verify what happened.
5. **Anchoring layer**
   Arweave can anchor evidence externally.

That layered approach is why the app can behave like a document-signing product while still preserving cryptographic custody and future decentralization options.

## Review Concepts For Engineers

When reviewing the code, it helps to separate five concerns:

1. Identity
   Wallets, guest links, and agents are not the same actor type.
2. Authorization
   Who can access the document is separate from who can sign it.
3. Integrity
   Hash checks and canonical signing messages tie actions to exact content.
4. Custody
   Important actions must become ledger events.
5. Delivery
   A link being created is not the same as a provider successfully delivering it.

That mental model makes the code much easier to reason about.

## Current Engineering Gaps

These are the main code-level areas still worth improving:

- split `main.rs` into route modules and service layers
- tighten or remove currently unused legacy modules
- finish billing checkout and enforcement
- finish browser-side PQ path
- add stronger integration tests around shared activity and delivery

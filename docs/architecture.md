# Architecture

![System overview](./assets/system-overview.svg)

![Custody ledger](./assets/custody-ledger.svg)

## High-Level Design

TIDBIT-share-WEAVE is a static frontend plus Rust backend system.

The important architectural idea is that the application separates:

- identity
- storage
- metadata
- custody events
- external anchoring

That separation is what lets the app behave like a document-signing workspace without collapsing everything into one opaque storage layer.

### Frontend

Location:

- `backend-rs/web`

Key files:

- `index.html`
- `dashboard.html`
- `document.html`
- `review.html`
- `public-sign.html`
- `app.js`
- `style.css`

The frontend is plain HTML, CSS, and JavaScript. It talks directly to backend HTTP routes and renders:

- dashboard surfaces
- document details
- review/sign flows
- shared activity
- inbox flows
- billing state

### Backend

Location:

- `backend-rs/src`

The backend is centered in `main.rs` and composes:

- wallet auth state
- database access
- storage client
- signing verification
- sharing and delivery
- evidence export

The central app state is:

- `AuthState`
- `PgPool`
- `SupabaseStorage`

In practice, the backend is the trust coordinator. It decides:

- whether an actor can access a document
- how a canonical signing message is built
- when a custody event is written
- whether a share is wallet-routed, provider-routed, or both

## Data Systems

### Supabase Postgres

Supabase Postgres stores:

- document metadata
- document shares
- document events
- billing/account state
- policies
- agent identities

This is the authoritative metadata and custody ledger store.

If you want to know what happened to a document, Postgres is the first place to look because that is where the application ledger lives.

### Supabase Storage

Supabase Storage holds the live stored file objects.

In the current flow, the app stores the PQ envelope object there and serves verified/decrypted content through backend routes.

This means the browser is not fetching arbitrary direct storage links as the primary trust path. The backend remains responsible for access checks and object decoding.

### Arweave

Arweave is optional and used for anchoring:

- file hash evidence
- evidence bundle references

It is not the primary active file store.

This is an important design choice:

- Supabase is optimized for application storage and retrieval
- Arweave is treated as an external anchoring and permanence layer

## Request And Storage Flow

### Upload Flow

1. User logs in with wallet.
2. Frontend sends multipart upload to `/api/doc/upload`.
3. Backend creates a document id and PQ envelope structure.
4. Envelope object is uploaded to Supabase Storage.
5. Document metadata is inserted into `documents`.
6. `UPLOAD` event is written into `document_events`.
7. Optional Arweave anchoring records a tx id on the document.

This is where the app begins the formal chain of custody for a file.

### Review Flow

1. Frontend requests `/api/doc/:id/review`.
2. Backend verifies access via owner or share recipient rules.
3. Backend records a `VIEW` event.
4. Frontend fetches the blob through the internal blob route.
5. Frontend recomputes the hash and compares it with the custody hash.

That is the core review integrity check.

### Sign Flow

1. Frontend builds a canonical signing message.
2. Wallet signs using EVM or Solana flow, or PQ data is supplied.
3. Backend verifies the signature type.
4. Backend writes a `SIGN` event into `document_events`.
5. Frontend refreshes timeline and document state.

The important boundary here is that signing is not accepted just because a client says "signed." The backend verifies the signature against the canonical message first.

### Share Flow

1. Owner calls `/api/doc/:id/share`.
2. Backend inserts a `document_shares` row.
3. Backend creates a signing URL / access token.
4. If email or SMS is requested, delivery providers may be called.
5. Backend writes:
   - `SHARE`
   - `DELIVERY_DISPATCHED` or `DELIVERY_FAILED`
6. Recipient sees the file in inbox if wallet routing applies.

The share flow can create several different outcomes:

- wallet-only route
- public-link route
- provider-backed route
- mixed route

Those are related but not identical, which is why delivery metadata is part of the custody story.

## Access Model

The access model is wallet-first.

A document is visible if:

- the active wallet owns it
- or a share row grants access to that wallet/chain

This is important because shared documents are not copied into a separate workspace store. Both sender and recipient interact with the same document ledger by `doc_id`.

That is also why recipient actions should be visible on the same custody timeline as sender actions.

## Shared Activity Model

The shared activity feed is an aggregate view over `document_events` for:

- documents the current wallet owns
- documents shared with the current wallet

That means the app supports:

- per-document custody timeline
- cross-document shared activity feed

The per-document timeline remains the source of truth.

Think of it as:

- document timeline = exact ledger for one file
- shared activity = workspace feed across many files

## Billing Model

The current billing model is scaffolded around an `account_subscriptions` table.

It stores:

- wallet
- billing status
- trial start
- trial end
- paid through
- plan amount
- Stripe identifiers

Current status:

- billing status is visible in the app
- trial metadata is created automatically
- enforcement can be toggled by env
- full Stripe checkout is not implemented yet

## Audit Progress

The dependency audit progressed in two meaningful steps:

1. The project removed the umbrella `sqlx` crate and replaced it with `sqlx-core` plus `sqlx-postgres`, which removed unused MySQL and SQLite branches from the resolved graph.
2. The project replaced the prior PQ signing dependency with the maintained `fips204` ML-DSA implementation.

That is why the current Rust audit state is now clean.

## Security Notes

### Strong Points

- wallet-based identity
- custody event logging
- Solana and EVM signature verification
- optional PQ signature verification
- version lineage
- evidence export
- clean Rust dependency audit at the current checkpoint

### Current Boundaries

- browser-side PQ encryption/signing is not the default web path yet
- object storage is still backed by Supabase
- on-chain attestation is not the default signature model
- billing enforcement is not production-complete

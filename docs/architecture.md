# Architecture

![System overview](./assets/system-overview.svg)

![Custody ledger](./assets/custody-ledger.svg)

## High-Level Design

TIDBIT-share-WEAVE is a static frontend plus Rust backend system.

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

### Supabase Storage

Supabase Storage holds the live stored file objects.

In the current flow, the app stores the PQ envelope object there and serves verified/decrypted content through backend routes.

### Arweave

Arweave is optional and used for anchoring:

- file hash evidence
- evidence bundle references

It is not the primary active file store.

## Request And Storage Flow

### Upload Flow

1. User logs in with wallet.
2. Frontend sends multipart upload to `/api/doc/upload`.
3. Backend creates a document id and PQ envelope structure.
4. Envelope object is uploaded to Supabase Storage.
5. Document metadata is inserted into `documents`.
6. `UPLOAD` event is written into `document_events`.
7. Optional Arweave anchoring records a tx id on the document.

### Review Flow

1. Frontend requests `/api/doc/:id/review`.
2. Backend verifies access via owner or share recipient rules.
3. Backend records a `VIEW` event.
4. Frontend fetches the blob through the internal blob route.
5. Frontend recomputes the hash and compares it with the custody hash.

### Sign Flow

1. Frontend builds a canonical signing message.
2. Wallet signs using EVM or Solana flow, or PQ data is supplied.
3. Backend verifies the signature type.
4. Backend writes a `SIGN` event into `document_events`.
5. Frontend refreshes timeline and document state.

### Share Flow

1. Owner calls `/api/doc/:id/share`.
2. Backend inserts a `document_shares` row.
3. Backend creates a signing URL / access token.
4. If email or SMS is requested, delivery providers may be called.
5. Backend writes:
   - `SHARE`
   - `DELIVERY_DISPATCHED` or `DELIVERY_FAILED`
6. Recipient sees the file in inbox if wallet routing applies.

## Access Model

The access model is wallet-first.

A document is visible if:

- the active wallet owns it
- or a share row grants access to that wallet/chain

This is important because shared documents are not copied into a separate workspace store. Both sender and recipient interact with the same document ledger by `doc_id`.

## Shared Activity Model

The shared activity feed is an aggregate view over `document_events` for:

- documents the current wallet owns
- documents shared with the current wallet

That means the app supports:

- per-document custody timeline
- cross-document shared activity feed

The per-document timeline remains the source of truth.

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

## Security Notes

### Strong Points

- wallet-based identity
- custody event logging
- Solana and EVM signature verification
- optional PQ signature verification
- version lineage
- evidence export

### Current Boundaries

- browser-side PQ encryption/signing is not the default web path yet
- object storage is still backed by Supabase
- on-chain attestation is not the default signature model
- billing enforcement is not production-complete

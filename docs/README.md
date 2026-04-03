# TIDBIT-share-WEAVE Documentation

This documentation set explains what the app does, how the backend and frontend fit together, how users move through the product, and where the current security and dependency audit stands.

This documentation set currently tracks production release `1.0.0`.

## Documentation Map

- [User Guide](./user-guide.md)
- [Review And Custody Concepts](./review-and-custody-concepts.md)
- [Agent Workflows](./agent-workflows.md)
- [Architecture](./architecture.md)
- [Code Walkthrough](./code-walkthrough.md)
- [Security Audit Folder](../audit/README.md)

## Visual Overview

![System overview](./assets/system-overview.svg)

![User flow](./assets/user-flow.svg)

These diagrams are intended to answer different questions:

- `system-overview.svg` shows the trust boundary: browser surfaces, browser-local ML-DSA signing, backend verification, sessions, storage, and anchoring
- `user-flow.svg` shows the human path through login, session control, review, sharing, signing, and evidence export
- `code-map.svg` shows where the runtime pieces live in the repository when you need to trace implementation details

## What The App Is

TIDBIT-share-WEAVE is a wallet-native file custody and signing platform built around:

- static frontend pages in `backend-rs/web`
- a Rust backend in `backend-rs/src/main.rs`
- Supabase Postgres for metadata and custody events
- Supabase Storage for active encrypted object storage
- optional Arweave anchoring for evidence and file hashes
- EVM and Solana wallet identity
- public signing links and agent-oriented APIs

## How To Read These Docs

If you are new to the project:

1. Start with the [User Guide](./user-guide.md) to understand the screens and flows.
2. Read [Review And Custody Concepts](./review-and-custody-concepts.md) to understand why review, signing, versioning, and custody are treated as separate concepts.
3. Read [Agent Workflows](./agent-workflows.md) to understand how individual agents and swarms can review, version, and sign with policy controls.
4. Read [Architecture](./architecture.md) to understand how the browser, backend, Supabase, and Arweave fit together.
5. Read [Code Walkthrough](./code-walkthrough.md) to understand how the implementation is organized.
6. Read the [Security Audit Folder](../audit/README.md) to understand dependency and audit history.

## Current Product Surface

The app currently supports:

- MetaMask and Phantom login
- device-bound wallet sessions with current / active / revoked session visibility
- automatic revocation of older wallet sessions when the same wallet logs in again
- upload, review, download, sign, delete, and share
- public signing links
- wallet-to-wallet sharing
- shared inbox and shared activity feed
- evidence export
- linked document versions
- browser-local ML-DSA key generation, backup/import, and signing for web review flows
- optional Arweave anchoring
- delivery provider integration points for Resend and Twilio
- billing status scaffolding for a 30-day trial and `$8/month` plan

## Current Security Position

The app has a real custody ledger and real signature verification, but there are still important boundaries:

- Supabase object storage is active application storage
- the current web path supports browser-local ML-DSA signing, but not browser-generated PQ encryption yet
- signatures are cryptographically verified by the app, but they are not on-chain attestations by default
- billing status exists, but Stripe checkout and hard billing enforcement are not finished yet

## Current Audit Position

As of the current March 2026 audit pass:

- Rust dependency audit: clean
- prior `sqlx` umbrella dependency issue: mitigated
- prior unmaintained PQ signing dependency issue: mitigated

The audit details and remediation path are documented in the [Audit Folder](../audit/README.md).

## CI Position

The repo now uses:

- SecureCI for repository security scanning and alert publication
- a repo-owned validation workflow for Rust and frontend syntax checks

For production discipline, these workflows should be required in GitHub branch protection.

## Recommended Reading Order

1. Read the [User Guide](./user-guide.md) to understand the product from the user side.
2. Read the [Agent Workflows](./agent-workflows.md) to understand agent onboarding, policy, and multi-agent collaboration.
3. Read the [Architecture](./architecture.md) to understand the data flow and security model.
4. Read the [Code Walkthrough](./code-walkthrough.md) to understand how the code is organized.
5. Read the [Audit Folder](../audit/README.md) to review dependencies and the current Rust audit status.

# Audit Folder

This folder holds the current project audit and dependency documentation for TIDBIT-share-WEAVE.

## Files

- [Current Rust Audit](./cargo-audit-2026-03-30.md)
- [Dependency Inventory](./dependencies-2026-03-30.md)

## Summary

Current Rust audit state as of March 30, 2026:

- 0 active vulnerability paths
- 0 active warnings

## Interpretation

The prior `rsa` issue was mitigated by removing the umbrella `sqlx` crate from the backend dependency graph and switching the app to `sqlx-core` plus `sqlx-postgres` directly. That dropped the unused MySQL and SQLite branches out of `Cargo.lock`, and `cargo audit` no longer reports `RUSTSEC-2023-0071`.

The prior `paste` warning was mitigated by replacing `pqcrypto-mldsa` with the maintained `fips204` ML-DSA implementation. The current dependency graph audits cleanly.

## Why This Matters

This folder is not just a snapshot of one command. It documents engineering progress.

The project started with two meaningful dependency concerns:

- a RustSec finding that was reachable through an unnecessary SQL dependency branch
- an unmaintained PQ signing dependency in the ML-DSA path

Those were mitigated through real dependency changes, not by suppressing the audit output.

## Audit Progress So Far

### Step 1: SQL Dependency Cleanup

The backend no longer depends on the umbrella `sqlx` crate. It now depends directly on:

- `sqlx-core`
- `sqlx-postgres`

That matters because the app uses Postgres, not MySQL or SQLite, and the old umbrella dependency carried a broader graph than the application needed.

### Step 2: PQ Signing Dependency Cleanup

The backend no longer depends on `pqcrypto-mldsa` for the signing path.

It now uses:

- `fips204` for ML-DSA signing and verification

That matters because the previous graph included an unmaintained dependency warning under the PQ signing path.

## How To Review Audit State

If you are reviewing the project, ask these questions:

1. Are the current dependencies justified by the active runtime path?
2. Are unused database backends or protocol features being pulled in?
3. Are PQ dependencies maintained enough for a high-assurance roadmap?
4. Does the current audit status match the documentation in this folder?
5. Are there any suppressed findings, or were the findings actually mitigated?

For the current state of this repo, the answer to the last question is important: the findings were actually mitigated.

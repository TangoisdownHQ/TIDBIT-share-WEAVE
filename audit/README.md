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

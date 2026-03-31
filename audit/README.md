# Audit Folder

This folder holds the current project audit and dependency documentation for TIDBIT-share-WEAVE.

## Files

- [Current Rust Audit](./cargo-audit-2026-03-30.md)
- [Dependency Inventory](./dependencies-2026-03-30.md)

## Summary

Current Rust audit state as of March 30, 2026:

- 1 active vulnerability path
- 1 unmaintained crate warning

### Active Vulnerability

- `rsa 0.9.10`
- reported through `sqlx-mysql 0.8.6`
- advisory: `RUSTSEC-2023-0071`

### Warning

- `paste 1.0.15`
- reported as unmaintained
- advisory: `RUSTSEC-2024-0436`
- path: `pqcrypto-mldsa -> paste`

## Interpretation

The current app uses Postgres, not MySQL, so the `rsa` issue is coming from an unnecessary dependency path in the broader `sqlx` graph rather than from an active MySQL feature used by the app.

The `paste` warning is more important for the post-quantum roadmap because it sits under the PQ signature dependency chain.

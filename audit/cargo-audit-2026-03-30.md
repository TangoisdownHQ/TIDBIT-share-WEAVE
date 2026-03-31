# Cargo Audit - 2026-03-30

Command run:

```bash
cd backend-rs
cargo audit
```

## Result

The audit reported:

- 0 vulnerabilities
- 0 warnings

## Practical Meaning

The backend dependency graph is currently clean under `cargo audit`.

That does not mean the security work is finished. It means the Rust dependency graph is in a materially better place than it was before the remediation steps documented in [README.md](./README.md).

## Remediation Summary

### Removed SQL Graph Bloat

The project removed the broader `sqlx` umbrella dependency and kept only the Postgres-specific pieces required by the backend.

Effect:

- removed unused MySQL and SQLite branches from the lockfile
- removed the prior `rsa` advisory path

### Replaced The PQ Signing Crate

The project replaced the previous PQ signing crate with `fips204`.

Effect:

- removed the prior unmaintained warning under the ML-DSA path
- aligned the PQ signing layer with a maintained implementation

## What This Audit Does Not Prove

`cargo audit` is important, but it is not the same thing as a full application security review.

It does not prove:

- that access control is correct
- that custody events are complete
- that delivery flows are semantically correct
- that the browser path is fully zero-trust
- that the product is production-hardened

It proves something narrower and still useful:

- the Rust dependency graph is currently clean against the RustSec advisory database used by `cargo audit`

## Recommended Follow-Up

- Review PQ dependency maintenance before expanding browser-side PQ support further.
- Re-run `cargo audit` after dependency updates or before production deploys.

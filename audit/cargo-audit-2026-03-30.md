# Cargo Audit - 2026-03-30

Command run:

```bash
cd backend-rs
cargo audit
```

## Result

The audit reported:

- 1 vulnerability
- 1 allowed warning

## Vulnerability

### `RUSTSEC-2023-0071`

- Crate: `rsa`
- Version: `0.9.10`
- Title: `Marvin Attack: potential key recovery through timing sidechannels`
- Severity: `medium`
- Fixed version: none reported by the advisory

Dependency path:

```text
rsa 0.9.10
└── sqlx-mysql 0.8.6
    ├── sqlx-macros-core 0.8.6
    │   └── sqlx-macros 0.8.6
    │       └── sqlx 0.8.6
    │           └── tidbit_share_weave_backend
    └── sqlx 0.8.6
```

## Unmaintained Warning

### `RUSTSEC-2024-0436`

- Crate: `paste`
- Version: `1.0.15`
- Status: `unmaintained`

Dependency path:

```text
paste 1.0.15
└── pqcrypto-mldsa 0.1.2
    └── tidbit_share_weave_backend
```

## Practical Meaning

### `rsa`

This is not being pulled in by the app's Postgres runtime path directly. It is present because `sqlx` still brings along a MySQL-related subtree in the current dependency graph.

### `paste`

This matters because the PQ signing roadmap depends on maintained PQ dependencies. Even though the app compiles and works, the PQ dependency chain should be watched closely and replaced if a better maintained alternative becomes available.

## Recommended Follow-Up

- Continue trying to trim the MySQL subtree out of the `sqlx` graph.
- Review PQ dependency maintenance before expanding browser-side PQ support.
- Re-run `cargo audit` after dependency updates or before production deploys.

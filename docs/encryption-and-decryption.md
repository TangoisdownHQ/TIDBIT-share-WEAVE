# Encryption And Decryption

This document explains the exact encryption, decryption, signing, and anchoring paths that exist in the current codebase.

It is intended to answer four review questions:

1. Where is plaintext created and where is it exposed?
2. What is encrypted in the browser versus on the backend?
3. Who can decrypt a stored document?
4. What is application evidence versus what is anchored to Arweave?

## Current Storage Modes

The app currently stores documents as canonical PQ envelope objects in Supabase Storage.

There are now two supported envelope creation paths:

### `pq_envelope_server_managed`

Legacy and compatibility path.

- Browser uploads plaintext bytes to `/api/doc/upload` or `/api/doc/:id/version`
- Backend creates `DocumentEnvelopeV1`
- Backend encrypts payload with a random CEK using `XChaCha20-Poly1305`
- Backend wraps the CEK for the owner using server-held ML-KEM-768 keys
- Backend stores the canonical envelope JSON in Supabase Storage

### `pq_envelope_browser_encrypted`

Current web upload path.

- Browser reads the file bytes locally
- Browser generates a random CEK
- Browser encrypts the payload locally with `XChaCha20-Poly1305`
- Browser encapsulates to the active wallet's server-managed ML-KEM public key
- Browser derives the CEK wrap key with `HKDF-SHA256`
- Browser wraps the CEK locally with `XChaCha20-Poly1305`
- Browser uploads the canonical envelope JSON, not plaintext
- Backend validates the envelope, assigns the real document id into metadata, and stores it

The browser path is implemented through:

- `backend-rs/web/app.js`
- `backend-rs/web/pq-worker.js`
- `backend-rs/pq-wasm/src/lib.rs`

The backend validation and storage path is implemented through:

- `backend-rs/src/main.rs`
- `backend-rs/src/crypto/canonical/envelope.rs`

## Envelope Format

Stored envelopes use `DocumentEnvelopeV1`.

Important fields:

- `v`: envelope version
- `owner`: normalized wallet id for the owner
- `created_at`: envelope creation timestamp
- `doc.logical_id`: logical document id
- `doc.filename`: custody label / display label
- `doc.mime`: original document mime type
- `doc.plaintext_sha3_256_hex`: custody hash of plaintext
- `doc.size_bytes`: plaintext byte length
- `encryption.alg`: payload cipher, currently `xchacha20poly1305`
- `encryption.cek_wrap`: CEK protection mode, currently `mlkem`
- `encryption.wrapped_keys[*]`: per-recipient ML-KEM ciphertext plus wrapped CEK
- `ciphertext_b64`: encrypted payload bytes

The current browser upload path uses one wrapped recipient key: the active owner wallet's server-managed ML-KEM key.

The schema is already multi-recipient capable, which is the main foundation for future org-managed custody and recovery.

## Browser Encryption Flow

For browser uploads, versions, and browser text-editor saves:

1. Browser loads the active wallet session.
2. Browser fetches `mlkem_pk_b64` from `/auth/session`.
3. Browser computes the plaintext SHA3-256 custody hash.
4. Browser generates:
   - a 32-byte CEK
   - a 24-byte payload nonce
   - a 24-byte CEK-wrap nonce
   - a 32-byte ML-KEM encapsulation seed
5. Browser encrypts plaintext with `XChaCha20-Poly1305`.
6. Browser performs ML-KEM-768 encapsulation to the owner public key.
7. Browser derives a wrap key with `HKDF-SHA256` using info string `tidbit-cek-wrap-v1`.
8. Browser wraps the CEK with `XChaCha20-Poly1305`.
9. Browser serializes canonical `DocumentEnvelopeV1` JSON.
10. Browser uploads the envelope blob with `encryption_source=browser_pq_envelope_v1`.

Important trust note:

- plaintext is not sent to the backend on this path
- this is browser-side encryption
- it is not full end-to-end user-held decryption because the owner ML-KEM secret key is still server-managed

## Backend Decryption Flow

When an owner or authorized recipient downloads or reviews a document:

1. Backend loads the stored envelope bytes from Supabase Storage.
2. Backend parses `DocumentEnvelopeV1`.
3. Backend loads the owner wallet's ML-KEM secret key from `wallet_mlkem_keys`.
4. Backend selects the wrapped key entry for the owner wallet.
5. Backend decapsulates the ML-KEM ciphertext to recover the shared secret.
6. Backend derives the wrap key with `HKDF-SHA256`.
7. Backend decrypts the wrapped CEK with `XChaCha20-Poly1305`.
8. Backend decrypts the payload ciphertext with `XChaCha20-Poly1305`.
9. Backend serves plaintext bytes only after access control passes.

This is why the current system should be described as:

- browser-side encrypted upload
- server-managed owner custody
- backend-enforced access-controlled decryption

## ML-KEM And ML-DSA Roles

These are separate:

### ML-KEM

Used for document envelope key wrapping.

- current storage path: ML-KEM-768
- purpose: protect the CEK used for document payload encryption
- browser path: encapsulation in wasm
- backend path: decapsulation on download/review

### ML-DSA

Used for signatures and attestations.

- current signing path: ML-DSA-65 via `fips204`
- browser path: device-local key generation, backup/import, sign, and verify
- backend path: verify signature proof and write custody evidence

Browser-local ML-DSA keys are independent from document decryption keys.

## Share Anchoring On Arweave

Share activity is primarily application evidence inside:

- `document_shares`
- `document_events`
- `growth_events`

The app can now also anchor share issuance records to Arweave.

What is anchored:

- a SHA3-256 hash of the share issuance record
- document id and document hash context
- sender wallet / chain
- recipient routing fields
- envelope id
- expiry and one-time/download/guest-sign settings

What is stored in the app:

- `share_anchor_hash_hex`
- `share_arweave_tx`
- `share_anchored_at`

Important boundary:

- the Arweave anchor represents share issuance evidence
- mutable follow-up activity like open, download, revoke, and completion still lives in the application custody ledger

## Crypto Agility Status

The code now has practical crypto-agility groundwork, but not a full algorithm-negotiation system yet.

Already present:

- envelope version field `v`
- explicit payload algorithm field `encryption.alg`
- explicit CEK wrap field `encryption.cek_wrap`
- per-recipient wrapped-key entries with `kem`
- separate browser and backend envelope creation paths using the same stored format

Still not finished:

- multi-recipient org custody rollout in the web app
- automatic recipient key fan-out for org recovery/admins
- migration tooling between envelope versions and algorithm sets
- user-held decryption without server-managed owner custody

## Reviewer Summary

If you are reviewing the current implementation, the precise statement is:

- browser uploads are now encrypted in the browser before they are sent
- stored objects remain canonical PQ envelopes
- decryption still depends on server-managed owner ML-KEM secret keys
- browser-local ML-DSA signing is separate and remains device-local
- Arweave anchoring is optional for both document evidence and share issuance evidence

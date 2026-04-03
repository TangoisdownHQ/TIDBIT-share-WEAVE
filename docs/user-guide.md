# User Guide

![User flow](./assets/user-flow.svg)

## What Users Can Do

TIDBIT-share-WEAVE lets users:

- log in with MetaMask or Phantom
- upload a file and start a custody record
- review and verify files before signing
- create linked versions
- share files by wallet, email, phone, or public signing link
- receive shared files in an inbox
- sign as sender or recipient
- export evidence and audit history
- inspect shared activity across files

The app is designed for users who need more than simple "send a PDF and collect a click" behavior. It is aimed at flows where the user needs to know:

- which file was seen
- which version was signed
- who took an action
- when the action happened
- how that action can be proven later

## Main Pages

### Login

The login page lets the user choose a wallet provider and authenticate with:

- MetaMask / EVM
- Phantom / Solana

Wallet identity is the root of user identity in the app.

That means access, signing, and activity attribution are tied to cryptographic identity instead of a username/password account model.

### Home

The Home tab shows top-level counts such as:

- active files
- linked versions
- Arweave anchored files
- shares created
- inbox waiting

Home is intentionally a summary page. It is the place to understand workspace state quickly, not the place to inspect every event.

Home also now includes an `Account Sessions` panel. It shows:

- the current browser session
- other recent active sessions for the same wallet
- revoked or displaced sessions
- revoke controls for other devices

When the same wallet signs in again on another device or browser, older active sessions are revoked automatically.

### Inbox / Documents

This view is split into:

- **Your Documents**
  Files the active wallet owns or can access
- **Inbox**
  Shared documents addressed to the active wallet

From here, users can:

- open details
- review
- download
- sign
- share
- delete or dismiss inbox items

`Inbox` is for documents that were routed to the active wallet.

`Your Documents` is for documents the active wallet owns or has already accepted into active use.

### Shared

This tab shows files the current wallet has sent to other people or wallets.

It surfaces:

- recipient identity
- recipient chain
- share status
- wallet route presence
- provider delivery summary

This is where a sender confirms whether a file was:

- routed to a wallet recipient
- prepared as a public signing link
- sent through a delivery provider
- blocked by delivery configuration or provider failure

### Shared Activity

This is the shared-workspace audit feed.

It shows sender and recipient actions across all visible documents, including:

- upload
- share
- review
- view
- download
- sign
- version creation
- delivery attempts

The event cards are color-coded:

- dark red for sender-side activity
- dark green for recipient-side activity
- neutral styling for guest/system activity

This tab is the fastest way to understand collaboration activity across multiple files without opening each document one by one.

### Billing

The Billing tab currently shows workspace billing status for the active wallet:

- billing status
- trial end
- plan amount
- subscription state
- write access state
- Stripe placeholders

This is the scaffolding for the planned `30-day free -> $8/month` model.

## Reviewing A Document Correctly

The recommended review flow is:

1. Open the file from `Inbox / Documents` or `Document Details`.
2. Confirm the file label, version, and hash context.
3. Review the preview content.
4. If the flow requires a signature, sign only after the preview matches what you expect.
5. Re-open details and confirm the custody history and `Last signed` state.

Why this matters:

- review and sign are separate actions
- the app logs them separately
- the correct version matters
- the hash and signing message matter

## Typical User Flows

### 1. Upload And Sign Your Own File

1. Log in with MetaMask or Phantom.
2. Open `Home`.
3. Upload a document from the upload panel.
4. Open the document details page.
5. Review the preview.
6. Sign the file.
7. Confirm `Last signed` and custody timeline entries.
8. Export evidence if you need a portable proof package.

### 2. Share A File To Another Wallet

1. Open a document.
2. Click `Share`.
3. Enter the recipient wallet.
4. Select the recipient wallet network.
5. Confirm the wallet network popup.
6. Create the signing link.
7. The recipient receives access through the app inbox if the wallet route exists.

If the wrong network is selected, sharing can fail or route incorrectly. The app prompts the sender to confirm the recipient network because EVM and Solana wallet identities are not interchangeable.

### 3. Share A File By Email Or SMS

1. Open a document.
2. Click `Share`.
3. Enter recipient email or phone.
4. Create the signing link.
5. If providers are configured, the app can attempt delivery.
6. If providers are not configured, the app still creates the signing URL and records that delivery was not provider-backed.

Important:

- a signing URL can exist even if an email or SMS was not actually sent
- wallet routing and provider delivery are different concepts
- the `Shared` tab is the best place to confirm what really happened

### 4. Review And Sign A Shared File

1. Log in with the recipient wallet.
2. Open `Inbox / Documents`.
3. Review the shared file from the inbox.
4. Sign the file with the correct wallet mode.
5. Check the details page and shared activity feed.

If you are a recipient, your actions should still appear on the document's custody history because sender and recipient activity share the same ledger by `doc_id`.

## Signing Modes

### MetaMask / EVM

Used for Ethereum-style wallet signatures via `personal_sign`.

### Phantom / Solana

Used for Solana Ed25519 signature verification.

### PQ / ML-DSA

Optional high-assurance mode where ML-DSA keys can be generated and used locally inside the browser.

The maintained implementation in the current codebase is ML-DSA through `fips204`.

In the current web flow:

- the browser generates the ML-DSA keypair locally
- the signer can export or import a local backup file
- signing happens locally in the browser
- the server receives the public key and signature proof for verification and evidence recording

This is different from the older manual paste flow. The browser now handles PQ signing directly for review and public-envelope signing pages.

## Session And Device Behavior

Wallet login is still the root identity model, but sessions are now managed more strictly.

Current behavior:

- a successful new login for the same wallet revokes older active sessions
- each browser session is tied to a device id header
- the dashboard shows current, active, and revoked sessions
- users can manually revoke other device sessions from the `Account Sessions` panel

This means a signer can see when a prior browser session was displaced by a newer login, instead of silently leaving multiple old sessions active.

## What Users See In The Audit Trail

Every important action is recorded into the document ledger.

Examples include:

- `UPLOAD`
- `VIEW`
- `DOWNLOAD`
- `SIGN`
- `SHARE`
- `DELIVERY_DISPATCHED`
- `DELIVERY_FAILED`
- `VERSION_CREATED`
- `INBOX_REVIEWED`
- `INBOX_SIGNED`
- `ENVELOPE_OPENED`
- `ENVELOPE_COMPLETED`

Each event may also carry details such as:

- actor wallet or signer identity
- chain
- recorded server time
- request origin and user-agent metadata
- version references
- signature metadata
- delivery metadata
- annotation metadata

That is what makes the timeline useful for more than just UI history.

## What "Last Signed" Means

`Last signed` is a convenience summary, not the whole proof record.

It helps the user answer:

- has this file been signed recently?
- when was the most recent signature event?

The full custody timeline is still the deeper source of truth.

## Evidence Export

Evidence export is meant to package the important facts around a document so the history can be reviewed later outside the live app.

Users should use evidence export when they need:

- a portable summary of the document history
- a record of who signed
- a record of the hash and version lineage
- a record of delivery and envelope events
- a record of anchoring information if present

## Important Current Boundaries

- Files are stored in Supabase Storage as app-managed PQ envelope objects.
- Browser-local ML-DSA signing is available, but browser-side PQ encryption is not the default web path yet.
- Arweave anchoring is optional, not mandatory.
- Billing exists as status scaffolding, not full paid checkout yet.
- Email/SMS delivery depends on provider configuration.
- Office-class browser editing is not fully implemented yet.

## Recommended User Mindset

Users should think of the platform this way:

- `Home` answers "what is happening in my workspace?"
- `Inbox / Documents` answers "what files can I act on?"
- `Shared` answers "what did I send and how was it routed?"
- `Shared Activity` answers "what actions happened across my files?"
- `Document Details` answers "what is the exact custody history of this file?"

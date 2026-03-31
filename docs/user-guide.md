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

## Main Pages

### Login

The login page lets the user choose a wallet provider and authenticate with:

- MetaMask / EVM
- Phantom / Solana

Wallet identity is the root of user identity in the app.

### Home

The Home tab shows top-level counts such as:

- active files
- linked versions
- Arweave anchored files
- shares created
- inbox waiting

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

### Shared

This tab shows files the current wallet has sent to other people or wallets.

It surfaces:

- recipient identity
- recipient chain
- share status
- wallet route presence
- provider delivery summary

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

### Billing

The Billing tab currently shows workspace billing status for the active wallet:

- billing status
- trial end
- plan amount
- subscription state
- write access state
- Stripe placeholders

This is the scaffolding for the planned `30-day free -> $8/month` model.

## Typical User Flows

### 1. Upload And Sign Your Own File

1. Log in with MetaMask or Phantom.
2. Open `Home`.
3. Upload a document from the upload panel.
4. Open the document details page.
5. Review the preview.
6. Sign the file.
7. Confirm `Last signed` and custody timeline entries.

### 2. Share A File To Another Wallet

1. Open a document.
2. Click `Share`.
3. Enter the recipient wallet.
4. Select the recipient wallet network.
5. Confirm the wallet network popup.
6. Create the signing link.
7. The recipient receives access through the app inbox if the wallet route exists.

### 3. Share A File By Email Or SMS

1. Open a document.
2. Click `Share`.
3. Enter recipient email or phone.
4. Create the signing link.
5. If providers are configured, the app can attempt delivery.
6. If providers are not configured, the app still creates the signing URL and records that delivery was not provider-backed.

### 4. Review And Sign A Shared File

1. Log in with the recipient wallet.
2. Open `Inbox / Documents`.
3. Review the shared file from the inbox.
4. Sign the file with the correct wallet mode.
5. Check the details page and shared activity feed.

## Signing Modes

### MetaMask / EVM

Used for Ethereum-style wallet signatures via `personal_sign`.

### Phantom / Solana

Used for Solana Ed25519 signature verification.

### PQ / ML-DSA

Optional high-assurance mode where PQ signature material is provided and verified by the backend.

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

## Important Current Boundaries

- Files are stored in Supabase Storage as app-managed PQ envelope objects.
- Arweave anchoring is optional, not mandatory.
- Billing exists as status scaffolding, not full paid checkout yet.
- Email/SMS delivery depends on provider configuration.
- Office-class browser editing is not fully implemented yet.

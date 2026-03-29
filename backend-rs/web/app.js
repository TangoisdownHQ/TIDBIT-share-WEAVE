console.log("app.js loaded");

const API = window.location.origin.startsWith("http")
  ? window.location.origin
  : "http://127.0.0.1:4100";
let currentWallet = null;
let selectedShareDoc = null;
let reviewDocument = null;
let selectedVersionParent = null;
let activeFieldTool = null;
let currentDocumentDetails = null;

// ================== SESSION ==================
function saveSessionId(sid) {
  localStorage.setItem("TIDBIT_SESSION_ID", sid);
}
function getSessionId() {
  return localStorage.getItem("TIDBIT_SESSION_ID");
}
function clearSession() {
  localStorage.removeItem("TIDBIT_SESSION_ID");
}

function getMetaMaskProvider() {
  const injected = window.ethereum;
  if (!injected) return null;

  const providers = Array.isArray(injected.providers) ? injected.providers : [injected];
  return (
    providers.find((provider) => provider?.isMetaMask && !provider?.isPhantom) ||
    providers.find((provider) => provider?.isMetaMask) ||
    null
  );
}

function getPhantomProvider() {
  if (window.phantom?.solana?.isPhantom) {
    return window.phantom.solana;
  }
  if (window.solana?.isPhantom) {
    return window.solana;
  }
  return null;
}

// ================== AUTH ==================
async function loginWithMetamask() {
  const status = document.getElementById("status");
  const provider = getMetaMaskProvider();

  if (!provider) {
    alert("MetaMask is required");
    return;
  }

  try {
    status && (status.innerText = "Requesting nonce...");

    const nonceRes = await fetch(`${API}/api/identity/evm/nonce`, { method: "POST" });
    if (!nonceRes.ok) throw new Error(await nonceRes.text());

    const { session_id, nonce } = await nonceRes.json();

    const [address] = await provider.request({ method: "eth_requestAccounts" });

    const message = `TIDBIT Authentication
Nonce: ${nonce}
Purpose: Login
Version: 1`;

    status && (status.innerText = "Signing message...");

    const signature = await provider.request({
      method: "personal_sign",
      params: [message, address],
    });

    status && (status.innerText = "Verifying...");

    const verifyRes = await fetch(`${API}/api/identity/evm/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id, address, signature }),
    });

    if (!verifyRes.ok) throw new Error(await verifyRes.text());

    saveSessionId(session_id);
    window.location.replace("/dashboard.html");
  } catch (err) {
    console.error(err);
    alert("Login failed: " + err.message);
    status && (status.innerText = "Login failed");
  }
}

async function loginWithPhantom() {
  const status = document.getElementById("status");
  const provider = getPhantomProvider();

  if (!provider?.isPhantom) {
    alert("Phantom is required");
    return;
  }

  try {
    status && (status.innerText = "Requesting Phantom nonce...");

    const nonceRes = await fetch(`${API}/api/identity/sol/nonce`, { method: "POST" });
    if (!nonceRes.ok) throw new Error(await nonceRes.text());

    const { session_id, nonce } = await nonceRes.json();
    const connectRes = await provider.connect();
    const address = connectRes.publicKey.toString();
    const message = `TIDBIT Authentication\nNonce: ${nonce}\nPurpose: Login\nVersion: 1`;

    status && (status.innerText = "Signing with Phantom...");
    const encoded = new TextEncoder().encode(message);
    const signed = await provider.signMessage(encoded, "utf8");
    const signature = Array.from(signed.signature || [])
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");

    status && (status.innerText = "Verifying...");

    const verifyRes = await fetch(`${API}/api/identity/sol/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id, address, signature }),
    });

    if (!verifyRes.ok) throw new Error(await verifyRes.text());

    saveSessionId(session_id);
    window.location.replace("/dashboard.html");
  } catch (err) {
    console.error(err);
    alert("Phantom login failed: " + err.message);
    status && (status.innerText = "Login failed");
  }
}

async function loginWithSelectedWallet() {
  const provider = document.getElementById("walletProvider")?.value || "metamask";
  if (provider === "phantom") {
    return loginWithPhantom();
  }
  return loginWithMetamask();
}

async function logout() {
  const sid = getSessionId();
  if (sid) {
    await fetch(`${API}/auth/logout`, {
      method: "POST",
      headers: { "x-session-id": sid },
    });
  }
  clearSession();
  window.location.replace("/index.html");
}

// ================== API ==================
async function apiGet(path) {
  const sid = getSessionId();
  const resp = await fetch(`${API}${path}`, {
    headers: { "x-session-id": sid },
  });
  if (!resp.ok) throw new Error(await resp.text());
  return resp.json();
}

async function apiPost(path, body) {
  const sid = getSessionId();
  const resp = await fetch(`${API}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-session-id": sid,
    },
    body: JSON.stringify(body || {}),
  });
  if (!resp.ok) throw new Error(await resp.text());
  return resp.json();
}

async function apiPublicGet(path) {
  const resp = await fetch(`${API}${path}`);
  if (!resp.ok) throw new Error(await resp.text());
  return resp.json();
}

async function apiPublicPost(path, body) {
  const resp = await fetch(`${API}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  if (!resp.ok) throw new Error(await resp.text());
  return resp.json();
}

async function apiFetchBlob(path, publicFetch = false) {
  const headers = publicFetch
    ? {}
    : { "x-session-id": getSessionId() };
  const resp = await fetch(`${API}${path}`, { headers });
  if (!resp.ok) throw new Error(await resp.text());
  return resp.blob();
}

async function computeCustodyHash(blob) {
  if (typeof sha3_256 === "function") {
    const buf = await blob.arrayBuffer();
    return sha3_256(new Uint8Array(buf));
  }

  const form = new FormData();
  form.append("file", blob, "verification.bin");
  const resp = await fetch(`${API}/api/public/verify`, {
    method: "POST",
    body: form,
  });
  if (!resp.ok) throw new Error(await resp.text());
  const data = await resp.json();
  return data.hash;
}

function isEditableMimeType(mimeType) {
  return Boolean(
    mimeType &&
      (
        mimeType.startsWith("text/") ||
        mimeType === "application/json" ||
        mimeType === "application/xml" ||
        mimeType === "application/javascript" ||
        mimeType === "text/csv"
      )
  );
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function copyText(value, successMessage) {
  await navigator.clipboard.writeText(value);
  if (successMessage) alert(successMessage);
}

// ================== DASHBOARD ==================
async function loadSessionInfo() {
  const data = await apiGet("/auth/session");
  const sessionRoot = document.getElementById("sessionInfo");
  if (sessionRoot) {
    sessionRoot.innerHTML = `
      <div><strong>Wallet</strong></div>
      <div class="doc-meta">${data.wallet}</div>
      <div><strong>Chain</strong></div>
      <div class="doc-meta">${data.chain}</div>
      <div><strong>Session</strong></div>
      <div class="doc-meta">Active since ${new Date(data.created_at * 1000).toLocaleString()}</div>
      <div><strong>ML-KEM PK</strong></div>
      <div class="doc-meta">${(data.mlkem_pk_b64 || "").slice(0, 48)}${data.mlkem_pk_b64 ? "…" : ""}</div>
    `;
  }
  currentWallet = data.wallet;
}

async function loadDocuments() {
  const docs = await apiGet("/api/doc/list");
  const list = document.getElementById("docList");
  list.innerHTML = docs.length ? "" : "<div class='doc-card'><strong>No documents yet.</strong><div class='doc-meta'>Upload a file to begin a custody trail.</div></div>";

  docs.forEach((doc) => {
    const div = document.createElement("div");
    div.className = "doc-card";
    div.innerHTML = `
      <h4>${doc.label || "(untitled document)"}</h4>
      <div class="doc-meta">Hash: ${doc.hash_hex}</div>
      <div class="doc-meta">Document ID: ${doc.id}</div>
      <div class="doc-meta">Version: v${doc.version}</div>
      <div class="doc-meta">Type: ${doc.mime_type || "application/octet-stream"}</div>
      <div class="doc-meta">Created: ${new Date(doc.created_at).toLocaleString()}</div>
      <div class="doc-meta">Arweave: ${doc.arweave_tx || "not anchored"}</div>
      <div class="doc-actions">
        <a class="button-link" href="/document.html?id=${encodeURIComponent(doc.id)}">Details</a>
        <button data-action="review">Review</button>
        <button data-action="download">Download</button>
        <button data-action="share">Share</button>
        <button data-action="sign">Sign</button>
        <button class="button-danger" data-action="delete">Delete</button>
      </div>
    `;
    div.querySelector('[data-action="review"]').onclick = () => openReview(doc.id);
    div.querySelector('[data-action="download"]').onclick = () => downloadAndVerify(doc).catch((err) => alert(err.message));
    div.querySelector('[data-action="sign"]').onclick = () => signDocument(doc).catch((err) => alert(err.message));
    div.querySelector('[data-action="share"]').onclick = () => openShareModal(doc);
    div.querySelector('[data-action="delete"]').onclick = () => deleteDoc(doc.id).catch((err) => alert(err.message));
    list.appendChild(div);
  });
}

async function loadOverview() {
  const statsRoot = document.getElementById("overviewStats");
  if (!statsRoot) return;

  const overview = await apiGet("/api/overview");
  const counts = overview.counts || {};

  statsRoot.innerHTML = `
    <article class="stat-card"><strong>${counts.total_docs || 0}</strong><span class="muted">Active files</span></article>
    <article class="stat-card"><strong>${counts.total_versions || 0}</strong><span class="muted">Linked versions</span></article>
    <article class="stat-card"><strong>${counts.anchored_docs || 0}</strong><span class="muted">Arweave anchored</span></article>
    <article class="stat-card"><strong>${counts.total_shares || 0}</strong><span class="muted">Shares created</span></article>
  `;
}

function switchDashboardTab(tabName) {
  const homePanel = document.getElementById("homeTabPanel");
  const docsPanel = document.getElementById("docsTabPanel");
  const homeBtn = document.getElementById("homeTabBtn");
  const docsBtn = document.getElementById("docsTabBtn");
  if (!homePanel || !docsPanel || !homeBtn || !docsBtn) return;

  const showHome = tabName !== "docs";
  homePanel.classList.toggle("hidden", !showHome);
  docsPanel.classList.toggle("hidden", showHome);
  homeBtn.classList.toggle("button-primary", showHome);
  docsBtn.classList.toggle("button-primary", !showHome);
}

// ================== UPLOAD ==================
async function uploadDoc() {
  const file = document.getElementById("uploadFile").files[0];
  const label = document.getElementById("uploadLabel").value;
  const progress = document.getElementById("uploadProgress");
  const status = document.getElementById("uploadStatus");
  const anchor = document.getElementById("uploadAnchor")?.checked;
  if (!file) return alert("Pick a file");

  const sid = getSessionId();
  const form = new FormData();
  form.append("file", file);
  if (label) form.append("label", label);
  form.append("anchor_to_arweave", anchor ? "true" : "false");

  progress.value = 0;
  status.innerText = "Uploading...";

  const xhr = new XMLHttpRequest();
  xhr.open("POST", `${API}/api/doc/upload`);
  xhr.setRequestHeader("x-session-id", sid);
  xhr.upload.onprogress = (event) => {
    if (!event.lengthComputable) return;
    const pct = Math.round((event.loaded / event.total) * 100);
    progress.value = pct;
    status.innerText = `Uploading... ${pct}%`;
  };

  xhr.onload = () => {
    if (xhr.status >= 200 && xhr.status < 300) {
      progress.value = 100;
      status.innerText = "Upload complete";
      loadDocuments();
      document.getElementById("uploadFile").value = "";
      document.getElementById("uploadLabel").value = "";
      if (document.getElementById("uploadAnchor")) {
        document.getElementById("uploadAnchor").checked = false;
      }
    } else {
      progress.value = 0;
      status.innerText = "Upload failed";
      alert("Upload failed: " + xhr.responseText);
    }
  };

  xhr.onerror = () => {
    progress.value = 0;
    status.innerText = "Upload failed";
    alert("Upload failed");
  };

  xhr.send(form);
}

// ================== DOWNLOAD + VERIFY ==================
async function downloadAndVerify(doc) {
  const { blob_url } = await apiGet(`/api/doc/${doc.id}/download`);
  const blob = await apiFetchBlob(`${blob_url}?download=1`);
  const hash = await computeCustodyHash(blob);

  if (hash !== doc.hash_hex) {
    alert("Hash mismatch");
    return;
  }

  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = doc.label || doc.id;
  a.click();

  alert("Download verified");
}

function downloadJsonFile(name, value) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = name;
  link.click();
}

async function exportEvidence(docId, label) {
  const evidence = await apiGet(`/api/doc/${docId}/evidence`);
  const safeLabel = String(label || docId)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60) || "tidbit-evidence";
  downloadJsonFile(`${safeLabel}-evidence.json`, evidence);
}

// ================== DELETE ==================
async function deleteDoc(id) {
  if (!confirm("Delete document permanently?")) return;
  await apiPost(`/api/doc/${id}/delete`, {});
  loadDocuments();
}

// ================== SIGN ==================
async function signDocument(doc) {
  const message = buildDocumentSignatureMessage(doc);
  const signatureMode = document.getElementById("signatureMode")?.value || "evm_personal_sign";

  if (signatureMode === "pq_dilithium3") {
    const pqPublicKey = document.getElementById("pqPublicKey")?.value.trim();
    const pqSignature = document.getElementById("pqSignature")?.value.trim();

    if (!pqPublicKey || !pqSignature) {
      alert("PQ public key and signed message are required.");
      return;
    }

    await apiPost(`/api/doc/${doc.id}/sign`, {
      signature: pqSignature,
      signature_type: "pq_dilithium3",
      pq_public_key_b64: pqPublicKey,
    });
    alert("PQ signature verified and recorded");
    return;
  }

  const provider = getMetaMaskProvider();
  if (!provider) {
    alert("MetaMask is required to sign.");
    return;
  }

  const signature = await provider.request({
    method: "personal_sign",
    params: [message, currentWallet],
  });

  await apiPost(`/api/doc/${doc.id}/sign`, {
    signature,
    signature_type: "evm_personal_sign",
  });
  alert("Signed & recorded");
}

function buildDocumentSignatureMessage(doc) {
  return `TIDBIT Document Attestation
Document ID: ${doc.id}
Hash: ${doc.hash_hex}
Action: SIGN
Wallet: ${currentWallet}
Version: ${doc.version || 1}`;
}

// ================== INBOX ==================
async function loadInbox() {
  const box = document.getElementById("inboxList");
  try {
    const data = await apiGet("/api/inbox");
    box.innerHTML = data.items.length ? "" : "<div class='inbox-card'><strong>No inbound shares.</strong><div class='doc-meta'>Shares addressed to your wallet will appear here.</div></div>";

    data.items.forEach((item) => {
      const card = document.createElement("div");
      card.className = "inbox-card";
      card.innerHTML = `
        <h4>${item.label || "(shared document)"}</h4>
        <div class="doc-meta">From: ${item.sender_wallet}</div>
        <div class="doc-meta">Hash: ${item.hash_hex}</div>
        <div class="doc-meta">Envelope ID: ${item.envelope_id}</div>
        <div class="doc-meta">Version: v${item.version}</div>
        <div class="doc-meta">Note: ${item.note || "No note"}</div>
        <div class="doc-actions">
          <button data-action="review">Review</button>
          <button data-action="download">Download</button>
          <button data-action="sign">Sign</button>
        </div>
      `;
      card.querySelector('[data-action="review"]').onclick = () => openReview(item.doc_id);
      card.querySelector('[data-action="download"]').onclick = () =>
        downloadSharedDocument(item.doc_id, item.hash_hex, item.label).catch((err) => alert(err.message));
      card.querySelector('[data-action="sign"]').onclick = () =>
        signSharedDocument(item.doc_id, item.hash_hex, item.label, item.version).catch((err) => alert(err.message));
      box.appendChild(card);
    });
  } catch (err) {
    box.innerHTML = `<div class='inbox-card'><strong>Inbox unavailable.</strong><div class='doc-meta'>${err.message}</div></div>`;
  }
}

// ================== SHARE ==================
function prepareShare(doc) {
  selectedShareDoc = doc;
  ["modalRecipientName", "modalRecipientWallet", "modalRecipientEmail", "modalRecipientPhone", "modalAgentHandle", "modalShareNote"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.value = "";
  });
  const stateRoot = document.getElementById("shareModalState");
  if (!stateRoot) return;
  stateRoot.innerHTML = `
    <strong>Selected document</strong>
    <div class="doc-meta">${doc.label || "(untitled document)"}</div>
    <div class="doc-meta">ID: ${doc.id}</div>
    <div class="doc-meta">Hash: ${doc.hash_hex}</div>
  `;
  const title = document.getElementById("shareModalTitle");
  if (title) title.textContent = `Create signing link for ${doc.label || "document"}`;
  document.getElementById("shareResult").innerText = "Ready to create a signing link.";
}

function openShareModal(doc) {
  prepareShare(doc);
  const modal = document.getElementById("shareModal");
  if (!modal) return;
  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
}

function closeShareModal() {
  const modal = document.getElementById("shareModal");
  if (!modal) return;
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
}

function prepareVersion(doc) {
  selectedVersionParent = doc;
  document.getElementById("versionState").innerHTML = `
    <strong>Parent document</strong>
    <div class="doc-meta">${doc.label || "(untitled document)"}</div>
    <div class="doc-meta">ID: ${doc.id}</div>
    <div class="doc-meta">Current version: v${doc.version}</div>
    <div class="doc-meta">Arweave: ${doc.arweave_tx || "not anchored"}</div>
  `;
  document.getElementById("versionResult").innerText = "Ready to create a linked version.";
}

function setInviteLinks(result, doc) {
  const email = document.getElementById("modalRecipientEmail").value.trim();
  const phone = document.getElementById("modalRecipientPhone").value.trim();
  const emailLink = document.getElementById("emailShareLink");
  const smsLink = document.getElementById("smsShareLink");
  const socialLink = document.getElementById("socialShareLink");
  const label = doc.label || doc.id;
  const signingUrl = result.signing_url;
  const agentHandle = document.getElementById("modalAgentHandle").value.trim();
  const inviteBody =
    `TIDBIT-share-WEAVE signature request\n\n` +
    `Document: ${label}\n` +
    `Document ID: ${doc.id}\n` +
    `Hash: ${doc.hash_hex}\n` +
    `Envelope ID: ${result.envelope_id}\n` +
    `Recipient: ${document.getElementById("modalRecipientName").value.trim() || result.recipient_wallet || "signer"}\n` +
    `AI Agent: ${agentHandle || "none"}\n` +
    `Open secure signing link: ${signingUrl}`;

  if (email) {
    emailLink.href = `mailto:${encodeURIComponent(email)}?subject=${encodeURIComponent(`Signature request for ${label}`)}&body=${encodeURIComponent(inviteBody)}`;
    emailLink.classList.remove("disabled");
    emailLink.removeAttribute("aria-disabled");
  } else {
    emailLink.href = "#";
    emailLink.classList.add("disabled");
    emailLink.setAttribute("aria-disabled", "true");
  }

  if (phone) {
    smsLink.href = `sms:${encodeURIComponent(phone)}?body=${encodeURIComponent(inviteBody)}`;
    smsLink.classList.remove("disabled");
    smsLink.removeAttribute("aria-disabled");
  } else {
    smsLink.href = "#";
    smsLink.classList.add("disabled");
    smsLink.setAttribute("aria-disabled", "true");
  }

  const shareChannel = document.getElementById("modalShareChannel")?.value || "email";
  const encodedBody = encodeURIComponent(inviteBody);
  const socialUrls = {
    whatsapp: `https://wa.me/?text=${encodedBody}`,
    telegram: `https://t.me/share/url?url=${encodeURIComponent(signingUrl)}&text=${encodedBody}`,
    linkedin: `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(signingUrl)}`,
    x: `https://twitter.com/intent/tweet?text=${encodedBody}`,
  };
  if (socialLink) {
    if (socialUrls[shareChannel]) {
      socialLink.href = socialUrls[shareChannel];
      socialLink.classList.remove("disabled");
      socialLink.removeAttribute("aria-disabled");
      socialLink.textContent = `Open ${shareChannel}`;
    } else {
      socialLink.href = "#";
      socialLink.classList.add("disabled");
      socialLink.setAttribute("aria-disabled", "true");
      socialLink.textContent = "Social";
    }
  }
}

function buildShareSignatureMessage(doc, recipient, note) {
  return `TIDBIT Document Share
Document ID: ${doc.id}
Hash: ${doc.hash_hex}
Recipient Wallet: ${recipient}
Note: ${note || ""}
Action: SHARE
Wallet: ${currentWallet}
Version: ${doc.version || 1}`;
}

async function shareDocument(docId) {
  const recipient = document.getElementById("modalRecipientWallet").value.trim() || null;
  const recipientName = document.getElementById("modalRecipientName")?.value || null;
  const note = document.getElementById("modalShareNote")?.value || null;
  const recipientEmail = document.getElementById("modalRecipientEmail")?.value || null;
  const recipientPhone = document.getElementById("modalRecipientPhone")?.value || null;
  const agentHandle = document.getElementById("modalAgentHandle")?.value.trim() || null;

  if (!recipient && !recipientEmail && !recipientPhone) {
    return alert("Provide a wallet, email, or phone number for the recipient.");
  }

  let signature = null;
  const provider = getMetaMaskProvider();
  if (provider && currentWallet && selectedShareDoc) {
    signature = await provider.request({
      method: "personal_sign",
      params: [
        buildShareSignatureMessage(selectedShareDoc, recipient || recipientEmail || recipientPhone || "guest", note),
        currentWallet,
      ],
    });
  }

  const res = await apiPost(`/api/doc/${docId}/share`, {
    recipient_wallet: recipient,
    recipient_name: recipientName,
    note: [note, agentHandle ? `AI agent: ${agentHandle}` : null].filter(Boolean).join("\n"),
    signature,
    recipient_email: recipientEmail,
    recipient_phone: recipientPhone,
  });

  return { ...res, recipient_wallet: recipient };
}

async function shareSelectedDocument() {
  if (!selectedShareDoc) {
    alert("Select a document to share first.");
    return;
  }

  const res = await shareDocument(selectedShareDoc.id);
  window.lastShareResult = res;
  setInviteLinks(res, selectedShareDoc);
  document.getElementById("shareResult").innerText = JSON.stringify(res, null, 2);
}

function buildAgentSharePayload(result, doc) {
  return {
    tool: "TIDBIT-share-WEAVE",
    action: "review_and_sign",
    document_id: doc.id,
    label: doc.label || doc.id,
    hash_hex: doc.hash_hex,
    envelope_id: result.envelope_id,
    signing_url: result.signing_url,
    recipient_name: document.getElementById("modalRecipientName")?.value.trim() || null,
    recipient_wallet: result.recipient_wallet || null,
    recipient_email: result.recipient_email || null,
    recipient_phone: result.recipient_phone || null,
    ai_agent_handle: document.getElementById("modalAgentHandle")?.value.trim() || null,
  };
}

async function createVersion() {
  if (!selectedVersionParent) {
    alert("Select a parent document first.");
    return;
  }

  const file = document.getElementById("versionFile").files[0];
  if (!file) {
    alert("Pick the updated file to upload.");
    return;
  }

  const form = new FormData();
  form.append("file", file);
  const label = document.getElementById("versionLabel").value.trim();
  if (label) form.append("label", label);
  const changeSummary = document.getElementById("versionChangeSummary")?.value.trim();
  if (changeSummary) form.append("change_summary", changeSummary);
  form.append(
    "anchor_to_arweave",
    document.getElementById("versionAnchor")?.checked ? "true" : "false"
  );

  const sid = getSessionId();
  const resp = await fetch(`${API}/api/doc/${selectedVersionParent.id}/version`, {
    method: "POST",
    headers: { "x-session-id": sid },
    body: form,
  });

  if (!resp.ok) {
    throw new Error(await resp.text());
  }

  const result = await resp.json();
  document.getElementById("versionResult").innerText = JSON.stringify(result, null, 2);
  document.getElementById("versionFile").value = "";
  document.getElementById("versionLabel").value = "";
  document.getElementById("versionAnchor").checked = false;
  if (document.getElementById("versionChangeSummary")) {
    document.getElementById("versionChangeSummary").value = "";
  }
  if (document.getElementById("docList")) {
    await loadDocuments();
  }
  if (document.getElementById("detailMeta")) {
    await loadDocumentDetailsPage();
  }
}

async function downloadSharedDocument(docId, hashHex, label) {
  await downloadAndVerify({ id: docId, hash_hex: hashHex, label });
}

async function signSharedDocument(docId, hashHex, label, version) {
  await signDocument({ id: docId, hash_hex: hashHex, label, version });
}

function openReview(docId) {
  window.location.href = `/review.html?id=${encodeURIComponent(docId)}`;
}

function toggleSignatureMode() {
  const mode = document.getElementById("signatureMode")?.value;
  const pqFields = document.getElementById("pqFields");
  if (!pqFields) return;
  pqFields.classList.toggle("hidden", mode !== "pq_dilithium3");
}

function togglePublicSignatureMode() {
  const mode = document.getElementById("publicSignatureMode")?.value;
  const evmFields = document.getElementById("publicEvmFields");
  const pqFields = document.getElementById("publicPqFields");
  if (evmFields) evmFields.classList.toggle("hidden", mode !== "evm_personal_sign");
  if (pqFields) pqFields.classList.toggle("hidden", mode !== "pq_dilithium3");
}

function selectFieldTool(kind) {
  activeFieldTool = kind;
  document.querySelectorAll("[data-field-tool]").forEach((button) => {
    button.classList.toggle("button-primary", button.getAttribute("data-field-tool") === kind);
  });
}

function renderHistoryCards(events) {
  if (!events.length) {
    return "<div class='event-card'><strong>No custody events yet.</strong><div class='event-meta'>Review, share, download, and signature activity will appear here.</div></div>";
  }

  return events
    .map(
      (event) => `
        <article class="event-card">
          <div class="event-top">
            <strong>${event.event_type}</strong>
            <span class="muted">${new Date(event.created_at).toLocaleString()}</span>
          </div>
          <div class="event-meta">Actor: ${event.actor_wallet || "system"}</div>
          <div class="event-meta">Event ID: ${event.id}</div>
          <pre>${JSON.stringify(event.payload || {}, null, 2)}</pre>
        </article>
      `
    )
    .join("");
}

function renderLineageCards(lineage) {
  if (!lineage?.length) {
    return "<div class='event-card'><strong>No lineage yet.</strong><div class='event-meta'>Root document.</div></div>";
  }

  return lineage
    .map(
      (item) => `
        <article class="event-card compact-card">
          <div class="event-top">
            <strong>${escapeHtml(item.label || "Untitled document")}</strong>
            <span class="muted">v${item.version}</span>
          </div>
          <div class="event-meta">Hash: ${escapeHtml(item.hash_hex)}</div>
          <div class="event-meta">Created: ${new Date(item.created_at).toLocaleString()}</div>
          <div class="event-meta">Arweave: ${escapeHtml(item.arweave_tx || "not anchored")}</div>
          <div class="doc-actions">
            <a class="button-link" href="/document.html?id=${encodeURIComponent(item.id)}">Open</a>
          </div>
        </article>
      `
    )
    .join("");
}

function renderShareCards(shares) {
  if (!shares?.length) {
    return "<div class='event-card'><strong>No shares yet.</strong><div class='event-meta'>Create a share to send this file for review or signing.</div></div>";
  }

  return shares
    .map(
      (share) => `
        <article class="event-card compact-card">
          <div class="event-top">
            <strong>${escapeHtml(share.recipient_name || share.recipient_email || share.recipient_phone || share.recipient_wallet || "Recipient")}</strong>
            <span class="muted">${escapeHtml(share.status)}</span>
          </div>
          <div class="event-meta">Envelope: ${escapeHtml(share.envelope_id)}</div>
          <div class="event-meta">Wallet: ${escapeHtml(share.recipient_wallet || "not provided")}</div>
          <div class="event-meta">Email: ${escapeHtml(share.recipient_email || "not provided")}</div>
          <div class="event-meta">Phone: ${escapeHtml(share.recipient_phone || "not provided")}</div>
          <div class="event-meta">Created: ${new Date(share.created_at).toLocaleString()}</div>
        </article>
      `
    )
    .join("");
}

function ensurePreviewModal() {
  let modal = document.getElementById("previewModal");
  if (modal) return modal;

  modal = document.createElement("section");
  modal.id = "previewModal";
  modal.className = "modal-shell hidden preview-modal-shell";
  modal.setAttribute("aria-hidden", "true");
  modal.innerHTML = `
    <div class="modal-panel preview-modal-panel">
      <div class="section-head">
        <h3 id="previewModalTitle">Large preview</h3>
        <button type="button" id="closePreviewModal" class="button-secondary">Close</button>
      </div>
      <div id="previewModalBody" class="preview-modal-body"></div>
    </div>
  `;
  document.body.appendChild(modal);
  document.getElementById("closePreviewModal").onclick = hidePreviewModal;
  return modal;
}

function showPreviewModal(title, blob, mimeType, annotationFields = []) {
  const modal = ensurePreviewModal();
  document.getElementById("previewModalTitle").textContent = title || "Large preview";
  const body = document.getElementById("previewModalBody");
  body.innerHTML = "";
  body.appendChild(renderPreviewNode(blob, mimeType, { annotationFields }));
  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
}

function hidePreviewModal() {
  const modal = document.getElementById("previewModal");
  if (!modal) return;
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
}

function defaultFieldValue(kind) {
  if (kind === "signature") return "Sign Here";
  if (kind === "date") return new Date().toLocaleDateString();
  return "Note";
}

function createFieldBadge(field) {
  const badge = document.createElement("div");
  badge.className = `annotation-badge annotation-${field.kind || "note"}`;
  badge.style.left = `${field.x_pct}%`;
  badge.style.top = `${field.y_pct}%`;
  badge.textContent = field.value || field.label || defaultFieldValue(field.kind);
  return badge;
}

function renderAnnotationOverlay(overlay, fields, interactive) {
  overlay.innerHTML = "";
  (fields || []).forEach((field) => overlay.appendChild(createFieldBadge(field)));
  overlay.classList.toggle("interactive-overlay", Boolean(interactive));
}

function updateAnnotationFieldList(fields) {
  const root = document.getElementById("publicFieldList");
  if (!root) return;
  if (!fields.length) {
    root.innerHTML = "<div class='muted'>No signer fields placed yet. Choose a field type and click on the preview.</div>";
    return;
  }

  root.innerHTML = "";
  fields.forEach((field, index) => {
    const row = document.createElement("div");
    row.className = "field-chip";
    row.innerHTML = `
      <span>${field.kind} · ${Math.round(field.x_pct)}%, ${Math.round(field.y_pct)}%</span>
      <button type="button" data-remove-field="${index}">Remove</button>
    `;
    root.appendChild(row);
  });

  root.querySelectorAll("[data-remove-field]").forEach((button) => {
    button.onclick = () => {
      const index = Number(button.getAttribute("data-remove-field"));
      window.publicEnvelopeFields.splice(index, 1);
      if (window.publicEnvelopeOverlay) {
        renderAnnotationOverlay(window.publicEnvelopeOverlay, window.publicEnvelopeFields, true);
      }
      updateAnnotationFieldList(window.publicEnvelopeFields);
    };
  });
}

function bindInteractivePreview(stage, overlay) {
  window.publicEnvelopeOverlay = overlay;
  stage.addEventListener("click", (event) => {
    if (!activeFieldTool) return;
    const rect = stage.getBoundingClientRect();
    if (!rect.width || !rect.height) return;

    const xPct = ((event.clientX - rect.left) / rect.width) * 100;
    const yPct = ((event.clientY - rect.top) / rect.height) * 100;
    window.publicEnvelopeFields = window.publicEnvelopeFields || [];
    window.publicEnvelopeFields.push({
      kind: activeFieldTool,
      label: activeFieldTool === "note" ? "Note" : null,
      value: defaultFieldValue(activeFieldTool),
      x_pct: Math.max(0, Math.min(100, xPct)),
      y_pct: Math.max(0, Math.min(100, yPct)),
    });
    renderAnnotationOverlay(overlay, window.publicEnvelopeFields, true);
    updateAnnotationFieldList(window.publicEnvelopeFields);
  });
}

function renderPreviewNode(blob, mimeType, options = {}) {
  const shell = document.createElement("div");
  shell.className = "preview-shell";
  const stage = document.createElement("div");
  stage.className = "preview-stage";
  const objectUrl = URL.createObjectURL(blob);

  if (mimeType.startsWith("image/")) {
    const img = document.createElement("img");
    img.src = objectUrl;
    img.alt = "Document preview";
    img.className = "preview-image";
    stage.appendChild(img);
  } else if (mimeType === "application/pdf") {
    const frame = document.createElement("iframe");
    frame.src = objectUrl;
    frame.className = "preview-frame";
    frame.title = "PDF preview";
    stage.appendChild(frame);
  } else if (mimeType.startsWith("video/")) {
    const video = document.createElement("video");
    video.src = objectUrl;
    video.className = "preview-video";
    video.controls = true;
    stage.appendChild(video);
  } else if (mimeType.startsWith("audio/")) {
    const audio = document.createElement("audio");
    audio.src = objectUrl;
    audio.className = "preview-audio";
    audio.controls = true;
    shell.appendChild(audio);
  } else if (
    mimeType.startsWith("text/") ||
    mimeType === "application/json" ||
    mimeType === "application/xml"
  ) {
    const pre = document.createElement("pre");
    pre.className = "preview-fallback";
    blob.text().then((text) => {
      pre.textContent = text;
    });
    shell.appendChild(pre);
  } else {
    const fallback = document.createElement("div");
    fallback.className = "preview-fallback";
    fallback.innerHTML = `
      <strong>Preview unavailable for ${mimeType || "this file type"}.</strong>
      <div class="doc-meta">Use the verified download to inspect it locally before signing.</div>
    `;
    shell.appendChild(fallback);
  }

  if (stage.childNodes.length) {
    const overlay = document.createElement("div");
    overlay.className = "annotation-overlay";
    renderAnnotationOverlay(overlay, options.annotationFields || [], options.interactive);
    stage.appendChild(overlay);
    if (options.interactive) {
      bindInteractivePreview(stage, overlay);
    }
    shell.appendChild(stage);
  }

  return shell;
}

async function loadReviewPage() {
  const params = new URLSearchParams(window.location.search);
  const id = params.get("id");
  const previewRoot = document.getElementById("reviewPreview");
  const metaRoot = document.getElementById("reviewMeta");
  const eventsRoot = document.getElementById("reviewEvents");

  if (!id || !previewRoot || !metaRoot || !eventsRoot) {
    return;
  }

  try {
    const review = await apiGet(`/api/doc/${id}/review`);
    const events = await apiGet(`/api/doc/${id}/events`);
    const blob = await apiFetchBlob(review.blob_url);
    const hash = await computeCustodyHash(blob);
    const verified = hash === review.hash_hex;

    reviewDocument = {
      id,
      label: review.label,
      hash_hex: review.hash_hex,
      version: review.version,
      mime_type: review.mime_type,
      parent_id: review.parent_id,
      arweave_tx: review.arweave_tx,
    };

    document.getElementById("reviewTitle").textContent = review.label || "Document Review";
    document.getElementById("reviewSubtitle").textContent =
      verified
        ? "Preview verified against the stored custody hash."
        : "Preview loaded, but the file hash does not match the recorded custody hash.";

    metaRoot.innerHTML = `
      <div class="doc-meta">Document ID: ${id}</div>
      <div class="doc-meta">Hash: ${review.hash_hex}</div>
      <div class="doc-meta">Version: v${review.version}</div>
      <div class="doc-meta">Type: ${review.mime_type || "application/octet-stream"}</div>
      <div class="doc-meta">Parent: ${review.parent_id || "root document"}</div>
      <div class="doc-meta">Arweave: ${review.arweave_tx || "not anchored"}</div>
      <div class="doc-meta">Integrity: ${verified ? "verified" : "mismatch detected"}</div>
    `;

    previewRoot.innerHTML = "";
    previewRoot.appendChild(renderPreviewNode(blob, review.mime_type || "application/octet-stream"));
    eventsRoot.innerHTML = renderHistoryCards(events);

    const signBtn = document.getElementById("reviewSignBtn");
    const downloadBtn = document.getElementById("reviewDownloadBtn");
    const historyLink = document.getElementById("reviewHistoryLink");

    signBtn.disabled = !verified;
    signBtn.onclick = () => signDocument(reviewDocument);
    downloadBtn.onclick = () => downloadAndVerify(reviewDocument);
    document.getElementById("reviewEnlargeBtn").onclick = () =>
      showPreviewModal(review.label || "Large preview", blob, review.mime_type || "application/octet-stream");
    document.getElementById("reviewEditBtn").onclick = () =>
      (window.location.href = `/edit.html?id=${encodeURIComponent(id)}`);
    historyLink.href = `/document.html?id=${encodeURIComponent(id)}`;
    document.getElementById("reviewDetailLink").href = `/document.html?id=${encodeURIComponent(id)}`;
    toggleSignatureMode();
  } catch (err) {
    console.error(err);
    previewRoot.innerHTML = `<div class='preview-fallback'><strong>Preview failed.</strong><div class='doc-meta'>${err.message}</div></div>`;
    metaRoot.innerHTML = "";
    eventsRoot.innerHTML = "";
  }
}

async function loadDocumentDetailsPage() {
  const id = new URLSearchParams(window.location.search).get("id");
  const historyRoot = document.getElementById("history");
  const metaRoot = document.getElementById("detailMeta");
  const previewRoot = document.getElementById("detailPreview");
  const lineageRoot = document.getElementById("detailLineage");
  const sharesRoot = document.getElementById("detailShares");
  if (!id || !historyRoot || !metaRoot || !previewRoot || !lineageRoot || !sharesRoot) {
    return;
  }

  const evidence = await apiGet(`/api/doc/${id}/evidence`);
  const review = await apiGet(`/api/doc/${id}/review`);
  const blob = await apiFetchBlob(review.blob_url);

  currentDocumentDetails = {
    id,
    label: review.label || evidence.document?.label,
    hash_hex: review.hash_hex || evidence.document?.hash_hex,
    version: review.version || evidence.document?.version,
    mime_type: review.mime_type || evidence.document?.mime_type,
    parent_id: review.parent_id || evidence.document?.parent_id,
    arweave_tx: review.arweave_tx || evidence.document?.arweave_tx,
  };
  selectedVersionParent = currentDocumentDetails;

  document.getElementById("detailTitle").textContent =
    currentDocumentDetails.label || "Document details";
  document.getElementById("detailSubtitle").textContent =
    `Version v${currentDocumentDetails.version}. Review, share, edit, and inspect all custody metadata from here.`;

  metaRoot.innerHTML = `
    <div class="doc-meta">Document ID: ${escapeHtml(id)}</div>
    <div class="doc-meta">Hash: ${escapeHtml(currentDocumentDetails.hash_hex)}</div>
    <div class="doc-meta">Type: ${escapeHtml(currentDocumentDetails.mime_type || "application/octet-stream")}</div>
    <div class="doc-meta">Version: v${escapeHtml(currentDocumentDetails.version)}</div>
    <div class="doc-meta">Parent: ${escapeHtml(currentDocumentDetails.parent_id || "root document")}</div>
    <div class="doc-meta">Owner: ${escapeHtml(evidence.document?.owner_wallet || "")}</div>
    <div class="doc-meta">Created: ${new Date(evidence.document?.created_at).toLocaleString()}</div>
    <div class="doc-meta">Arweave: ${escapeHtml(currentDocumentDetails.arweave_tx || "not anchored")}</div>
  `;
  previewRoot.innerHTML = "";
  previewRoot.appendChild(renderPreviewNode(blob, currentDocumentDetails.mime_type || "application/octet-stream"));
  lineageRoot.innerHTML = renderLineageCards(evidence.lineage || []);
  sharesRoot.innerHTML = renderShareCards(evidence.shares || []);
  historyRoot.innerHTML = renderHistoryCards(evidence.events || []);

  prepareVersion(currentDocumentDetails);
  document.getElementById("detailReviewBtn").onclick = () => openReview(id);
  document.getElementById("detailOpenReviewBtn").onclick = () => openReview(id);
  document.getElementById("detailDownloadBtn").onclick = () => downloadAndVerify(currentDocumentDetails).catch((err) => alert(err.message));
  document.getElementById("detailShareBtn").onclick = () => openShareModal(currentDocumentDetails);
  document.getElementById("detailVersionBtn").onclick = () => document.getElementById("versionFile")?.focus();
  document.getElementById("detailEvidenceBtn").onclick = () => exportEvidence(id, currentDocumentDetails.label || id).catch((err) => alert(err.message));
  document.getElementById("detailEnlargeBtn").onclick = () =>
    showPreviewModal(currentDocumentDetails.label || "Large preview", blob, currentDocumentDetails.mime_type || "application/octet-stream");
}

async function loadEditorPage() {
  const id = new URLSearchParams(window.location.search).get("id");
  const contentRoot = document.getElementById("editableContent");
  const beforeRoot = document.getElementById("beforeSnapshot");
  if (!id || !contentRoot || !beforeRoot) return;

  const review = await apiGet(`/api/doc/${id}/review`);
  const blob = await apiFetchBlob(review.blob_url);

  document.getElementById("editTitle").textContent = review.label || "Browser editor";
  document.getElementById("editBackLink").href = `/document.html?id=${encodeURIComponent(id)}`;
  document.getElementById("editMeta").innerHTML = `
    <div class="doc-meta">Document ID: ${escapeHtml(id)}</div>
    <div class="doc-meta">Hash: ${escapeHtml(review.hash_hex)}</div>
    <div class="doc-meta">Version: v${escapeHtml(review.version)}</div>
    <div class="doc-meta">Type: ${escapeHtml(review.mime_type || "application/octet-stream")}</div>
  `;

  if (!isEditableMimeType(review.mime_type)) {
    document.getElementById("editSubtitle").textContent =
      "This file type is not editable in the browser editor yet. Use document details to upload a new version after editing externally.";
    contentRoot.value = "";
    contentRoot.disabled = true;
    beforeRoot.textContent = "Browser editing currently supports text-like files only.";
    document.getElementById("saveEditedVersionBtn").disabled = true;
    return;
  }

  const text = await blob.text();
  beforeRoot.textContent = text;
  contentRoot.value = text;
  document.getElementById("editVersionLabel").value = `${review.label || "Edited document"} v${Number(review.version || 1) + 1}`;
  document.getElementById("saveEditedVersionBtn").onclick = async () => {
    const form = new FormData();
    const updatedText = contentRoot.value;
    const label = document.getElementById("editVersionLabel").value.trim();
    const changeSummary = document.getElementById("editChangeSummary").value.trim();
    form.append("file", new Blob([updatedText], { type: review.mime_type || "text/plain" }), review.label || "edited.txt");
    if (label) form.append("label", label);
    form.append("anchor_to_arweave", document.getElementById("editAnchor").checked ? "true" : "false");
    form.append("change_summary", changeSummary || "Browser editor save");
    form.append("editor_mode", "browser_text_editor");
    form.append("before_hash_hex", review.hash_hex);

    document.getElementById("editStatus").textContent = "Saving edited version…";
    const sid = getSessionId();
    const resp = await fetch(`${API}/api/doc/${id}/version`, {
      method: "POST",
      headers: { "x-session-id": sid },
      body: form,
    });
    if (!resp.ok) throw new Error(await resp.text());
    const result = await resp.json();
    document.getElementById("editStatus").textContent = "Edited version saved.";
    window.location.href = `/document.html?id=${encodeURIComponent(result.id)}`;
  };
}

async function loadPublicSignPage() {
  const token = new URLSearchParams(window.location.search).get("token");
  const previewRoot = document.getElementById("publicEnvelopePreview");
  const metaRoot = document.getElementById("publicEnvelopeMeta");
  const statusRoot = document.getElementById("publicEnvelopeStatus");

  if (!token || !previewRoot || !metaRoot || !statusRoot) {
    return;
  }

  try {
    const envelope = await apiPublicGet(`/api/public/envelope/${encodeURIComponent(token)}`);
    const blob = await apiFetchBlob(envelope.blob_url, true);
    const hash = await computeCustodyHash(blob);
    const verified = hash === envelope.hash_hex;

    window.publicEnvelope = envelope;
    window.publicEnvelopeFields =
      envelope.annotation_json?.annotation_fields ||
      [];
    document.getElementById("publicEnvelopeTitle").textContent =
      envelope.label || "Review And Sign";
    statusRoot.textContent = verified
      ? `Envelope ${envelope.status}. File hash verified.`
      : "File loaded, but the preview hash does not match the recorded custody hash.";

    metaRoot.innerHTML = `
      <div class="doc-meta">Envelope ID: ${envelope.envelope_id}</div>
      <div class="doc-meta">From: ${envelope.sender_wallet}</div>
      <div class="doc-meta">Hash: ${envelope.hash_hex}</div>
      <div class="doc-meta">Version: v${envelope.version}</div>
      <div class="doc-meta">Arweave: ${envelope.arweave_tx || "not anchored"}</div>
      <div class="doc-meta">Recipient name: ${envelope.recipient_name || "not provided"}</div>
      <div class="doc-meta">Recipient wallet: ${envelope.recipient_wallet || "guest link"}</div>
      <div class="doc-meta">Recipient email: ${envelope.recipient_email || "not provided"}</div>
      <div class="doc-meta">Recipient phone: ${envelope.recipient_phone || "not provided"}</div>
      <div class="doc-meta">Delivery: ${Array.isArray(envelope.delivery) && envelope.delivery.length ? envelope.delivery.map((item) => `${item.channel}/${item.provider}`).join(", ") : "draft link only"}</div>
      <div class="doc-meta">Note: ${envelope.note || "No note"}</div>
      <div class="doc-meta">Integrity: ${verified ? "verified" : "mismatch detected"}</div>
    `;

    previewRoot.innerHTML = "";
    previewRoot.appendChild(
      renderPreviewNode(blob, envelope.mime_type || "application/octet-stream", {
        interactive: true,
        annotationFields: window.publicEnvelopeFields,
      })
    );
    updateAnnotationFieldList(window.publicEnvelopeFields);
    document.getElementById("publicSignSubmit").disabled = !verified;
    togglePublicSignatureMode();
  } catch (err) {
    previewRoot.innerHTML = `<div class="preview-fallback"><strong>Envelope unavailable.</strong><div class="doc-meta">${err.message}</div></div>`;
  }
}

async function submitPublicEnvelopeSign() {
  const token = new URLSearchParams(window.location.search).get("token");
  if (!token || !window.publicEnvelope) {
    alert("Envelope context missing.");
    return;
  }

  const signatureType = document.getElementById("publicSignatureMode").value;
  const signerName = document.getElementById("publicSignerName").value.trim();
  const signerEmail = document.getElementById("publicSignerEmail").value.trim() || null;
  const signerTitle = document.getElementById("publicSignerTitle").value.trim() || null;
  const signerOrg = document.getElementById("publicSignerOrg").value.trim() || null;
  const signReason = document.getElementById("publicSignReason").value.trim() || null;
  const annotationText = document.getElementById("publicAnnotation").value.trim() || null;
  const consent = document.getElementById("publicConsent").checked;

  const payload = {
    signature_type: signatureType,
    signer_name: signerName,
    signer_email: signerEmail,
    signer_title: signerTitle,
    signer_org: signerOrg,
    sign_reason: signReason,
    annotation_text: annotationText,
    annotation_fields: window.publicEnvelopeFields || [],
    consent,
  };

  if (signatureType === "evm_personal_sign") {
    const provider = getMetaMaskProvider();
    if (!provider) {
      alert("MetaMask is required for wallet signing.");
      return;
    }
    const [address] = await provider.request({ method: "eth_requestAccounts" });
    const message =
      `TIDBIT Public Envelope Signature\n` +
      `Envelope ID: ${window.publicEnvelope.envelope_id}\n` +
      `Document ID: ${window.publicEnvelope.doc_id}\n` +
      `Hash: ${window.publicEnvelope.hash_hex}\n` +
      `Signer: ${address}\n` +
      `Version: ${window.publicEnvelope.version}`;
    const signature = await provider.request({
      method: "personal_sign",
      params: [message, address],
    });
    payload.wallet_address = address;
    payload.signature = signature;
  }

  if (signatureType === "pq_dilithium3") {
    payload.pq_public_key_b64 = document.getElementById("publicPqPublicKey").value.trim();
    payload.signature = document.getElementById("publicPqSignature").value.trim();
    if (!payload.pq_public_key_b64 || !payload.signature) {
      alert("PQ public key and signature are required.");
      return;
    }
  }

  await apiPublicPost(`/api/public/envelope/${encodeURIComponent(token)}/sign`, payload);
  document.getElementById("publicEnvelopeStatus").textContent =
    "Envelope completed and recorded.";
  alert("Envelope completed");
}

// ================== BOOT ==================
document.addEventListener("DOMContentLoaded", () => {
  const loginBtn = document.getElementById("login-wallet");
  if (loginBtn) loginBtn.onclick = loginWithSelectedWallet;

  document.getElementById("closeShareModal")?.addEventListener("click", closeShareModal);
  document.getElementById("copySigningLink")?.addEventListener("click", async () => {
    if (!window.lastShareResult?.signing_url) return alert("Create a share first.");
    await copyText(window.lastShareResult.signing_url, "Signing link copied.");
  });
  document.getElementById("copyAgentPayload")?.addEventListener("click", async () => {
    if (!window.lastShareResult || !selectedShareDoc) return alert("Create a share first.");
    await copyText(
      JSON.stringify(buildAgentSharePayload(window.lastShareResult, selectedShareDoc), null, 2),
      "AI agent payload copied."
    );
  });

  if (document.getElementById("docList")) {
    loadSessionInfo();
    loadOverview().catch((err) => alert(err.message));
    loadDocuments();
    loadInbox();
    document.getElementById("homeTabBtn")?.addEventListener("click", () => switchDashboardTab("home"));
    document.getElementById("docsTabBtn")?.addEventListener("click", () => switchDashboardTab("docs"));
    switchDashboardTab("home");
    document.getElementById("uploadBtn").onclick = uploadDoc;
    document.getElementById("shareBtn").onclick = shareSelectedDocument;
  }

  if (document.getElementById("reviewPreview")) {
    loadSessionInfo();
    loadReviewPage();
    document.getElementById("signatureMode")?.addEventListener("change", toggleSignatureMode);
  }

  if (document.getElementById("detailMeta")) {
    loadSessionInfo();
    loadDocumentDetailsPage().catch((err) => {
      console.error(err);
      document.getElementById("history").innerHTML = `<div class="event-card"><strong>Failed to load document.</strong><div class="event-meta">${err.message}</div></div>`;
    });
    document.getElementById("shareBtn").onclick = shareSelectedDocument;
    document.getElementById("createVersionBtn").onclick = () =>
      createVersion().catch((err) => alert(err.message));
  }

  if (document.getElementById("editableContent")) {
    loadSessionInfo();
    loadEditorPage().catch((err) => {
      console.error(err);
      document.getElementById("editStatus").textContent = err.message;
    });
  }

  if (document.getElementById("publicEnvelopePreview")) {
    loadPublicSignPage();
    document
      .getElementById("publicSignatureMode")
      ?.addEventListener("change", togglePublicSignatureMode);
    document.querySelectorAll("[data-field-tool]").forEach((button) => {
      button.addEventListener("click", () => selectFieldTool(button.getAttribute("data-field-tool")));
    });
    document.getElementById("clearFieldPlacements")?.addEventListener("click", () => {
      window.publicEnvelopeFields = [];
      if (window.publicEnvelopeOverlay) {
        renderAnnotationOverlay(window.publicEnvelopeOverlay, window.publicEnvelopeFields, true);
      }
      updateAnnotationFieldList(window.publicEnvelopeFields);
    });
    selectFieldTool("signature");
    document.getElementById("publicSignSubmit").onclick = () =>
      submitPublicEnvelopeSign().catch((err) => alert(err.message));
  }
});

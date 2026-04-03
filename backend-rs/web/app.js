console.log("app.js loaded");

const API = window.location.origin.startsWith("http")
  ? window.location.origin
  : "http://127.0.0.1:4100";
let currentWallet = null;
let currentChain = null;
let selectedShareDoc = null;
let reviewDocument = null;
let selectedVersionParent = null;
let activeFieldTool = null;
let currentDocumentDetails = null;
let ownedDocumentsCache = [];
let agentsCache = [];
let pqWorkerPromise = null;

const PQ_KEY_STORAGE = "TIDBIT_PQ_MLDSA65_KEYPAIR_V1";
const PQ_BACKUP_VERSION = 1;

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
function getDeviceId() {
  let deviceId = localStorage.getItem("TIDBIT_DEVICE_ID");
  if (!deviceId) {
    deviceId =
      typeof crypto?.randomUUID === "function"
        ? crypto.randomUUID()
        : `tidbit-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    localStorage.setItem("TIDBIT_DEVICE_ID", deviceId);
  }
  return deviceId;
}

function authHeaders(extra = {}) {
  const headers = { ...extra };
  const sid = getSessionId();
  if (sid) headers["x-session-id"] = sid;
  headers["x-device-id"] = getDeviceId();
  return headers;
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

function inferWalletChainFromAddress(address) {
  const trimmed = String(address || "").trim();
  if (!trimmed) return null;
  return trimmed.startsWith("0x") ? "evm" : "sol";
}

function bytesToBase64(bytes) {
  const array = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  array.forEach((value) => {
    binary += String.fromCharCode(value);
  });
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function utf8ToBase64(value) {
  return bytesToBase64(new TextEncoder().encode(value));
}

function randomBytes(len) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return bytes;
}

function randomBase64(len) {
  return bytesToBase64(randomBytes(len));
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}

async function pqKeyFingerprint(publicKeyB64) {
  const digest = await sha256Hex(base64ToBytes(publicKeyB64));
  return digest.slice(0, 16);
}

function loadStoredPqKeypair() {
  try {
    const raw = localStorage.getItem(PQ_KEY_STORAGE);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (
      parsed?.algorithm !== "pq_mldsa65" ||
      typeof parsed?.public_key_b64 !== "string" ||
      typeof parsed?.secret_key_b64 !== "string"
    ) {
      return null;
    }
    return parsed;
  } catch (_) {
    return null;
  }
}

function saveStoredPqKeypair(keypair) {
  localStorage.setItem(PQ_KEY_STORAGE, JSON.stringify(keypair));
}

function clearStoredPqKeypair() {
  localStorage.removeItem(PQ_KEY_STORAGE);
}

async function getPqWorker() {
  if (pqWorkerPromise) return pqWorkerPromise;

  pqWorkerPromise = new Promise((resolve, reject) => {
    const worker = new Worker("/pq-worker.js");
    let nextRequestId = 1;
    const pending = new Map();

    worker.onmessage = (event) => {
      const { id, ok, result, error } = event.data || {};
      const handler = pending.get(id);
      if (!handler) return;
      pending.delete(id);
      if (ok) handler.resolve(result);
      else handler.reject(new Error(error || "PQ worker request failed"));
    };

    worker.onerror = (event) => {
      reject(new Error(event.message || "PQ worker failed to start"));
    };

    worker.call = (action, payload = {}) =>
      new Promise((resolveCall, rejectCall) => {
        const id = nextRequestId;
        nextRequestId += 1;
        pending.set(id, { resolve: resolveCall, reject: rejectCall });
        worker.postMessage({ id, action, payload });
      });

    worker
      .call("init")
      .then(() => resolve(worker))
      .catch(reject);
  });

  return pqWorkerPromise;
}

async function callPqWorker(action, payload = {}) {
  const worker = await getPqWorker();
  return worker.call(action, payload);
}

async function generateBrowserPqKeypair() {
  const generated = await callPqWorker("generateKeypair", {
    seed_b64: randomBase64(32),
  });
  const keypair = {
    algorithm: "pq_mldsa65",
    version: PQ_BACKUP_VERSION,
    created_at: new Date().toISOString(),
    public_key_b64: generated.public_key_b64,
    secret_key_b64: generated.secret_key_b64,
  };
  saveStoredPqKeypair(keypair);
  return keypair;
}

async function signWithStoredPqKey(message) {
  const keypair = loadStoredPqKeypair();
  if (!keypair) {
    throw new Error("No device-local ML-DSA key is available.");
  }

  const signed = await callPqWorker("signMessage", {
    secret_key_b64: keypair.secret_key_b64,
    message_b64: utf8ToBase64(message),
    signing_seed_b64: randomBase64(32),
  });
  const verified = await callPqWorker("verifySignature", {
    public_key_b64: keypair.public_key_b64,
    message_b64: utf8ToBase64(message),
    signature_b64: signed.signature_b64,
  });

  if (!verified?.verified) {
    throw new Error("Local PQ signature self-check failed.");
  }

  return {
    signature_type: "pq_mldsa65",
    pq_public_key_b64: keypair.public_key_b64,
    signature: signed.signature_b64,
  };
}

function buildPqBackupPayload(keypair) {
  return {
    type: "tidbit_pq_key_backup",
    version: PQ_BACKUP_VERSION,
    algorithm: "pq_mldsa65",
    created_at: keypair.created_at || new Date().toISOString(),
    public_key_b64: keypair.public_key_b64,
    secret_key_b64: keypair.secret_key_b64,
  };
}

async function exportStoredPqKeypair() {
  const keypair = loadStoredPqKeypair();
  if (!keypair) {
    throw new Error("No device-local ML-DSA key is available.");
  }
  const fingerprint = await pqKeyFingerprint(keypair.public_key_b64);
  downloadJsonFile(`tidbit-pq-mldsa65-${fingerprint}.json`, buildPqBackupPayload(keypair));
}

async function importStoredPqKeypair(file) {
  const text = await file.text();
  const parsed = JSON.parse(text);
  if (
    parsed?.algorithm !== "pq_mldsa65" ||
    typeof parsed?.public_key_b64 !== "string" ||
    typeof parsed?.secret_key_b64 !== "string"
  ) {
    throw new Error("Unsupported PQ backup file.");
  }

  const challenge = `TIDBIT PQ Import Check\nTimestamp: ${new Date().toISOString()}`;
  const signed = await callPqWorker("signMessage", {
    secret_key_b64: parsed.secret_key_b64,
    message_b64: utf8ToBase64(challenge),
    signing_seed_b64: randomBase64(32),
  });
  const verified = await callPqWorker("verifySignature", {
    public_key_b64: parsed.public_key_b64,
    message_b64: utf8ToBase64(challenge),
    signature_b64: signed.signature_b64,
  });
  if (!verified?.verified) {
    throw new Error("The imported ML-DSA backup failed verification.");
  }

  saveStoredPqKeypair({
    algorithm: "pq_mldsa65",
    version: parsed.version || PQ_BACKUP_VERSION,
    created_at: parsed.created_at || new Date().toISOString(),
    public_key_b64: parsed.public_key_b64,
    secret_key_b64: parsed.secret_key_b64,
  });
}

async function signTextWithActiveWallet(message) {
  if (!currentWallet || !currentChain) {
    throw new Error("Active wallet session missing.");
  }

  if (currentChain === "sol") {
    const provider = getPhantomProvider();
    if (!provider) {
      throw new Error("Phantom is required to sign with Solana.");
    }

    const encoded = new TextEncoder().encode(message);
    const signed = await provider.signMessage(encoded, "utf8");
    const signatureBytes = signed?.signature || signed;
    return {
      signature: bytesToBase64(signatureBytes),
      signature_type: "sol_ed25519",
      wallet: provider.publicKey?.toString?.() || currentWallet,
    };
  }

  const provider = getMetaMaskProvider();
  if (!provider) {
    throw new Error("MetaMask is required to sign.");
  }

  const signature = await provider.request({
    method: "personal_sign",
    params: [message, currentWallet],
  });

  return {
    signature,
    signature_type: "evm_personal_sign",
    wallet: currentWallet,
  };
}

function confirmRecipientNetwork(recipient, recipientChain) {
  if (!recipient) return true;
  const detectedChain = inferWalletChainFromAddress(recipient);
  const selectedChain = recipientChain || detectedChain || "unknown";
  const mismatch = detectedChain && selectedChain && detectedChain !== selectedChain;
  const message = [
    "Confirm recipient wallet network before creating this share.",
    "",
    `Recipient wallet: ${recipient}`,
    `Selected network: ${selectedChain}`,
    `Detected address format: ${detectedChain || "unknown"}`,
    "",
    mismatch
      ? "The selected network does not match the wallet format. Continue only if you are certain."
      : "This share will be routed only to the selected wallet network.",
  ].join("\n");
  return window.confirm(message);
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

    const nonceRes = await fetch(`${API}/api/identity/evm/nonce`, {
      method: "POST",
      headers: authHeaders(),
    });
    if (!nonceRes.ok) throw new Error(await nonceRes.text());

    const { session_id, nonce, message: nonceMessage } = await nonceRes.json();

    const [address] = await provider.request({ method: "eth_requestAccounts" });

    const message =
      nonceMessage ||
      `TIDBIT Authentication
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
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ session_id, address, signature }),
    });

    if (!verifyRes.ok) throw new Error(await verifyRes.text());

    const verified = await verifyRes.json();
    saveSessionId(verified.session_id || session_id);
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

    const nonceRes = await fetch(`${API}/api/identity/sol/nonce`, {
      method: "POST",
      headers: authHeaders(),
    });
    if (!nonceRes.ok) throw new Error(await nonceRes.text());

    const { session_id, nonce, message: nonceMessage } = await nonceRes.json();
    const connectRes = await provider.connect();
    const address = connectRes.publicKey.toString();
    const message =
      nonceMessage ||
      `TIDBIT Authentication\nNonce: ${nonce}\nPurpose: Login\nVersion: 1`;

    status && (status.innerText = "Signing with Phantom...");
    const encoded = new TextEncoder().encode(message);
    const signed = await provider.signMessage(encoded, "utf8");
    const signature = Array.from(signed.signature || [])
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");

    status && (status.innerText = "Verifying...");

    const verifyRes = await fetch(`${API}/api/identity/sol/verify`, {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ session_id, address, signature }),
    });

    if (!verifyRes.ok) throw new Error(await verifyRes.text());

    const verified = await verifyRes.json();
    saveSessionId(verified.session_id || session_id);
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
      headers: authHeaders(),
    });
  }
  clearSession();
  window.location.replace("/index.html");
}

// ================== API ==================
async function apiGet(path) {
  const resp = await fetch(`${API}${path}`, {
    headers: authHeaders(),
  });
  if (!resp.ok) throw new Error(await resp.text());
  return resp.json();
}

async function apiPost(path, body) {
  const resp = await fetch(`${API}${path}`, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
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
  const headers = publicFetch ? {} : authHeaders();
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

function escapeErrorMessage(err) {
  return escapeHtml(err?.message || "Unexpected error");
}

function textNode(value) {
  return document.createTextNode(String(value ?? ""));
}

function createElement(tag, options = {}) {
  const el = document.createElement(tag);
  if (options.className) el.className = options.className;
  if (options.text !== undefined) el.textContent = String(options.text);
  if (options.htmlFor) el.htmlFor = options.htmlFor;
  if (options.type) el.type = options.type;
  if (options.href) el.href = options.href;
  if (options.id) el.id = options.id;
  if (options.role) el.setAttribute("role", options.role);
  if (options.ariaHidden !== undefined) el.setAttribute("aria-hidden", String(options.ariaHidden));
  return el;
}

function setContent(root, ...children) {
  root.replaceChildren(...children.filter(Boolean));
  return root;
}

function createMetaLine(label, value, options = {}) {
  const row = createElement("div", { className: options.className || "doc-meta" });
  if (!label) {
    row.textContent = String(value ?? "");
    return row;
  }

  row.append(textNode(`${label}: `));
  if (options.important) {
    const span = createElement("span", { className: "important-value", text: value });
    row.appendChild(span);
  } else {
    row.append(textNode(value));
  }
  return row;
}

function createMessageCard(className, title, message, metaClass = "doc-meta") {
  const card = createElement("div", { className });
  card.appendChild(createElement("strong", { text: title }));
  card.appendChild(createElement("div", { className: metaClass, text: message }));
  return card;
}

function createSessionInfoNode(data) {
  const fragment = document.createDocumentFragment();
  const items = [
    ["Wallet", data.wallet],
    ["Chain", data.chain],
    ["Session", `Active since ${new Date(data.created_at * 1000).toLocaleString()}`],
    ["Expires", data.expires_at ? new Date(data.expires_at * 1000).toLocaleString() : "unknown"],
    ["Device", data.device_id || "browser-managed"],
    ["Rotation", data.rotation_recommended ? "recommended now" : "healthy"],
    ["ML-KEM PK", `${(data.mlkem_pk_b64 || "").slice(0, 48)}${data.mlkem_pk_b64 ? "…" : ""}`],
  ];
  items.forEach(([label, value]) => {
    fragment.appendChild(createElement("div"));
    fragment.lastChild.appendChild(createElement("strong", { text: label }));
    fragment.appendChild(createElement("div", { className: "doc-meta", text: value }));
  });
  return fragment;
}

function createDocumentCard(doc) {
  const card = createElement("div", { className: "doc-card" });
  card.appendChild(createElement("h4", { text: doc.label || "(untitled document)" }));
  card.appendChild(createMetaLine("Access", doc.access_kind === "shared" ? "Shared with you" : "Owned by you"));
  card.appendChild(createMetaLine("Hash", doc.hash_hex));
  card.appendChild(createMetaLine("Document ID", doc.id));
  card.appendChild(createMetaLine("Version", `v${doc.version}`));
  card.appendChild(createMetaLine("Type", doc.mime_type || "application/octet-stream"));
  card.appendChild(createMetaLine("Created", new Date(doc.created_at).toLocaleString()));
  card.appendChild(createMetaLine("Last signed", doc.last_signed_at ? new Date(doc.last_signed_at).toLocaleString() : "not signed yet"));
  card.appendChild(createMetaLine("Arweave", doc.arweave_tx || "not anchored"));

  const actions = createElement("div", { className: "doc-actions" });
  const details = createElement("a", { className: "button-link", href: `/document.html?id=${encodeURIComponent(doc.id)}`, text: "Details" });
  const review = createElement("button", { text: "Review" });
  const download = createElement("button", { text: "Download" });
  const share = createElement("button", { text: "Share" });
  const sign = createElement("button", { text: "Sign" });
  const remove = createElement("button", { className: "button-danger", text: "Delete" });
  review.onclick = () => openReview(doc.id);
  download.onclick = () => downloadAndVerify(doc).catch((err) => alert(err.message));
  share.onclick = () => openShareModal(doc);
  sign.onclick = () => signDocument(doc).catch((err) => alert(err.message));
  remove.onclick = () => deleteDoc(doc.id).catch((err) => alert(err.message));
  actions.append(details, review, download, share, sign, remove);
  card.appendChild(actions);
  return card;
}

function createStatCard(value, label) {
  const article = createElement("article", { className: "stat-card" });
  article.appendChild(createElement("strong", { text: value }));
  article.appendChild(createElement("span", { className: "muted", text: label }));
  return article;
}

function createInboxCard(item) {
  const card = createElement("div", { className: "inbox-card" });
  card.appendChild(createElement("h4", { text: item.label || "(shared document)" }));
  card.appendChild(createMetaLine("From", item.sender_wallet));
  card.appendChild(createMetaLine("Hash", item.hash_hex));
  card.appendChild(createMetaLine("Envelope ID", item.envelope_id));
  card.appendChild(createMetaLine("Version", `v${item.version}`));
  card.appendChild(createMetaLine("Note", item.note || "No note"));
  card.appendChild(createMetaLine("Status", item.status || "pending"));
  const actions = createElement("div", { className: "doc-actions" });
  const review = createElement("button", { text: "Review" });
  const download = createElement("button", { text: "Download" });
  const sign = createElement("button", { text: "Sign" });
  const remove = createElement("button", { className: "button-danger", text: "Delete" });
  review.onclick = () => reviewInboxDocument(item).catch((err) => alert(err.message));
  download.onclick = () => downloadSharedDocument(item).catch((err) => alert(err.message));
  sign.onclick = () => signSharedDocument(item).catch((err) => alert(err.message));
  remove.onclick = () => dismissInboxDocument(item).catch((err) => alert(err.message));
  actions.append(review, download, sign, remove);
  card.appendChild(actions);
  return card;
}

function createSharedFileCard(item) {
  const card = createElement("div", { className: "inbox-card" });
  card.appendChild(createElement("h4", { text: item.label || "(shared document)" }));
  card.appendChild(createMetaLine("Recipient", shareRecipientLabel(item)));
  card.appendChild(createMetaLine("Network", item.recipient_chain || "n/a"));
  card.appendChild(createMetaLine("Status", item.status));
  card.appendChild(createMetaLine("Wallet route", item.recipient_wallet ? "yes" : "no"));
  card.appendChild(createMetaLine("Delivery", shareDeliverySummary(item)));
  card.appendChild(createMetaLine("Expires", item.expires_at ? new Date(item.expires_at).toLocaleString() : "server default"));
  card.appendChild(createMetaLine("Guest signing", item.allow_guest_sign ? "allowed" : "wallet/PQ only"));
  card.appendChild(createMetaLine("Version", `v${item.version}`));
  card.appendChild(createMetaLine("Created", new Date(item.created_at).toLocaleString()));
  const actions = createElement("div", { className: "doc-actions" });
  actions.appendChild(createElement("a", { className: "button-link", href: `/document.html?id=${encodeURIComponent(item.doc_id)}`, text: "Open document" }));
  const reissue = createElement("button", { text: "Reissue" });
  reissue.onclick = () =>
    openShareModal(
      {
        id: item.doc_id,
        label: item.label,
        hash_hex: item.hash_hex,
        version: item.version,
      },
      item
    );
  actions.appendChild(reissue);
  if (shareCanBeRevoked(item)) {
    const revoke = createElement("button", { className: "button-danger", text: "Revoke" });
    revoke.onclick = async () => {
      await revokeShare(item.doc_id, item.envelope_id);
      await refreshDashboardData();
    };
    actions.appendChild(revoke);
  }
  card.appendChild(actions);
  return card;
}

function normalizeCapabilityList(raw) {
  if (Array.isArray(raw)) return raw.filter(Boolean).map((item) => String(item).trim()).filter(Boolean);
  return String(raw || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function createAgentCard(agent) {
  const card = createElement("div", { className: "doc-card" });
  card.appendChild(createElement("h4", { text: agent.label || "(unnamed agent)" }));
  card.appendChild(createMetaLine("Provider", agent.provider || "not specified"));
  card.appendChild(createMetaLine("Model", agent.model || "not specified"));
  card.appendChild(createMetaLine("Status", agent.is_active ? "active" : "inactive", { important: true }));
  card.appendChild(createMetaLine("Agent ID", agent.id));
  const capabilityWrap = createElement("div", { className: "capability-badges" });
  const capabilities = normalizeCapabilityList(agent.capabilities);
  if (capabilities.length) {
    capabilities.forEach((capability) => {
      capabilityWrap.appendChild(createElement("span", { className: "capability-chip", text: capability }));
    });
  } else {
    capabilityWrap.appendChild(createElement("span", { className: "capability-chip", text: "no capabilities listed" }));
  }
  card.appendChild(capabilityWrap);
  card.appendChild(createMetaLine("Created", new Date(agent.created_at).toLocaleString()));
  const actions = createElement("div", { className: "doc-actions" });
  const rotate = createElement("button", { text: "Rotate token" });
  const revoke = createElement("button", { className: "button-danger", text: "Revoke" });
  rotate.onclick = () => rotateAgentToken(agent).catch((err) => alert(err.message));
  revoke.onclick = () => revokeAgent(agent).catch((err) => alert(err.message));
  actions.append(rotate, revoke);
  card.appendChild(actions);
  return card;
}

function createSimpleInfoBlock(title, rows) {
  const fragment = document.createDocumentFragment();
  if (title) {
    fragment.appendChild(createElement("strong", { text: title }));
  }
  rows.forEach((row) => {
    fragment.appendChild(createMetaLine(row.label, row.value, row.options));
  });
  return fragment;
}

function createImportantMetaNodes(event) {
  const nodes = [];
  if (event.label) {
    nodes.push(createMetaLine("Document", event.label, { className: "event-meta", important: true }));
  }
  const version = event.version || event?.payload?.version;
  if (version) {
    nodes.push(createMetaLine("Version", `v${String(version)}`, { className: "event-meta", important: true }));
  }
  const signatureType = event?.payload?.verification?.signature_type || event?.payload?.completion_signature_type;
  if (signatureType) {
    nodes.push(createMetaLine("Signature", signatureType, { className: "event-meta", important: true }));
  }
  const chain = event?.payload?.actor_chain || event?.payload?.verification?.chain || event?.payload?.actor?.chain;
  if (chain) {
    nodes.push(createMetaLine("Chain", chain, { className: "event-meta", important: true }));
  }
  return nodes;
}

function friendlyEventLabel(eventType) {
  const labels = {
    AGENT_REVIEW: "Agent Review",
    AGENT_SIGN: "Agent Sign",
    AGENT_SIGN_PROPOSED: "Agent Sign Proposed",
    AGENT_VERSION_CREATED: "Agent Version Created",
    POLICY_UPDATED: "Policy Updated",
  };
  return labels[eventType] || eventType;
}

async function copyText(value, successMessage) {
  await navigator.clipboard.writeText(value);
  if (successMessage) alert(successMessage);
}

function shareRecipientLabel(share) {
  return (
    share.recipient_name ||
    share.recipient_email ||
    share.recipient_phone ||
    share.recipient_wallet ||
    "Recipient"
  );
}

function shareCanBeRevoked(share) {
  return !share.revoked_at && share.status !== "completed" && share.status !== "revoked";
}

function shareDeliverySummary(share) {
  return Array.isArray(share.delivery_json) && share.delivery_json.length
    ? share.delivery_json.map((entry) => `${entry.channel}:${entry.status}`).join(", ")
    : "no provider delivery recorded";
}

async function revokeShare(docId, envelopeId) {
  if (!window.confirm(`Revoke share ${envelopeId}? The current recipient link will stop working.`)) return;
  await apiPost(`/api/doc/${encodeURIComponent(docId)}/share/${encodeURIComponent(envelopeId)}/revoke`, {});
}

async function rotateAgentToken(agent) {
  const result = await apiPost(`/api/agent/${encodeURIComponent(agent.id)}/rotate-token`, {});
  await copyText(result.token, "New agent token copied.");
  const resultBox = document.getElementById("agentRegisterResult");
  if (resultBox) {
    resultBox.textContent = JSON.stringify(
      {
        ok: result.ok,
        agent_id: result.agent_id,
        label: result.label,
        provider: result.provider,
        model: result.model,
        capabilities: result.capabilities,
        token: result.token,
        note: "Previous token is no longer valid.",
      },
      null,
      2
    );
  }
  await loadAgents();
}

async function revokeAgent(agent) {
  if (!window.confirm(`Revoke ${agent.label || "this agent"}? Its token will stop working.`)) return;
  const result = await apiPost(`/api/agent/${encodeURIComponent(agent.id)}/revoke`, {});
  const resultBox = document.getElementById("agentRegisterResult");
  if (resultBox) {
    resultBox.textContent = JSON.stringify(result, null, 2);
  }
  await loadAgents();
  await loadAgentActivity();
}

// ================== DASHBOARD ==================
async function loadSessionInfo() {
  let data = await apiGet("/auth/session");
  if (data.rotation_recommended) {
    const rotated = await apiPost("/auth/session/rotate", {});
    if (rotated?.session_id) {
      saveSessionId(rotated.session_id);
      data = rotated;
    }
  }
  const sessionRoot = document.getElementById("sessionInfo");
  if (sessionRoot) {
    setContent(sessionRoot, createSessionInfoNode(data));
  }
  currentWallet = data.wallet;
  currentChain = data.chain;
  const signatureMode = document.getElementById("signatureMode");
  if (signatureMode && !signatureMode.dataset.userSelected) {
    signatureMode.value = currentChain === "sol" ? "sol_ed25519" : "evm_personal_sign";
    toggleSignatureMode();
  }
}

async function loadDocuments() {
  const docs = await apiGet("/api/doc/list");
  ownedDocumentsCache = docs.filter((doc) => doc.access_kind !== "shared");
  const list = document.getElementById("docList");
  if (!docs.length) {
    setContent(list, createMessageCard("doc-card", "No documents yet.", "Upload a file to begin a custody trail."));
    return;
  }
  setContent(list, ...docs.map((doc) => createDocumentCard(doc)));
}

function populateAgentPolicyDocOptions() {
  const select = document.getElementById("agentPolicyDoc");
  const resultBox = document.getElementById("agentPolicyResult");
  if (!select) return;
  select.replaceChildren();

  if (!ownedDocumentsCache.length) {
    const option = createElement("option", { text: "No owned documents available" });
    option.value = "";
    select.appendChild(option);
    if (resultBox) resultBox.textContent = "No owner-controlled documents available for agent policy yet.";
    return;
  }

  ownedDocumentsCache.forEach((doc) => {
    const option = createElement("option", { text: `${doc.label || "(untitled document)"} · v${doc.version}` });
    option.value = doc.id;
    select.appendChild(option);
  });

  if (!select.value && ownedDocumentsCache[0]) {
    select.value = ownedDocumentsCache[0].id;
  }
}

async function loadOverview() {
  const statsRoot = document.getElementById("overviewStats");
  if (!statsRoot) return;

  const overview = await apiGet("/api/overview");
  const counts = overview.counts || {};
  setContent(
    statsRoot,
    createStatCard(counts.total_docs || 0, "Active files"),
    createStatCard(counts.total_versions || 0, "Linked versions"),
    createStatCard(counts.anchored_docs || 0, "Arweave anchored"),
    createStatCard(counts.total_shares || 0, "Shares created"),
    createStatCard(counts.inbox_pending || 0, "Inbox waiting")
  );
}

function switchDashboardTab(tabName) {
  const homePanel = document.getElementById("homeTabPanel");
  const docsPanel = document.getElementById("docsTabPanel");
  const sharedPanel = document.getElementById("sharedTabPanel");
  const activityPanel = document.getElementById("activityTabPanel");
  const agentsPanel = document.getElementById("agentsTabPanel");
  const billingPanel = document.getElementById("billingTabPanel");
  const homeBtn = document.getElementById("homeTabBtn");
  const docsBtn = document.getElementById("docsTabBtn");
  const sharedBtn = document.getElementById("sharedTabBtn");
  const activityBtn = document.getElementById("activityTabBtn");
  const agentsBtn = document.getElementById("agentsTabBtn");
  const billingBtn = document.getElementById("billingTabBtn");
  if (!homePanel || !docsPanel || !sharedPanel || !activityPanel || !agentsPanel || !billingPanel || !homeBtn || !docsBtn || !sharedBtn || !activityBtn || !agentsBtn || !billingBtn) return;

  const showHome = tabName === "home";
  const showDocs = tabName === "docs";
  const showShared = tabName === "shared";
  const showActivity = tabName === "activity";
  const showAgents = tabName === "agents";
  const showBilling = tabName === "billing";
  homePanel.classList.toggle("hidden", !showHome);
  docsPanel.classList.toggle("hidden", !showDocs);
  sharedPanel.classList.toggle("hidden", !showShared);
  activityPanel.classList.toggle("hidden", !showActivity);
  agentsPanel.classList.toggle("hidden", !showAgents);
  billingPanel.classList.toggle("hidden", !showBilling);
  homeBtn.classList.toggle("button-primary", showHome);
  docsBtn.classList.toggle("button-primary", showDocs);
  sharedBtn.classList.toggle("button-primary", showShared);
  activityBtn.classList.toggle("button-primary", showActivity);
  agentsBtn.classList.toggle("button-primary", showAgents);
  billingBtn.classList.toggle("button-primary", showBilling);
}

// ================== UPLOAD ==================
async function uploadDoc() {
  const file = document.getElementById("uploadFile").files[0];
  const label = document.getElementById("uploadLabel").value;
  const progress = document.getElementById("uploadProgress");
  const status = document.getElementById("uploadStatus");
  const anchor = document.getElementById("uploadAnchor")?.checked;
  if (!file) return alert("Pick a file");

  const form = new FormData();
  form.append("file", file);
  if (label) form.append("label", label);
  form.append("anchor_to_arweave", anchor ? "true" : "false");

  progress.value = 0;
  status.innerText = "Uploading...";

  const xhr = new XMLHttpRequest();
  xhr.open("POST", `${API}/api/doc/upload`);
  Object.entries(authHeaders()).forEach(([name, value]) => xhr.setRequestHeader(name, value));
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
  const signatureMode =
    document.getElementById("signatureMode")?.value ||
    (currentChain === "sol" ? "sol_ed25519" : "evm_personal_sign");

  if (signatureMode === "pq_mldsa65") {
    let signed;
    try {
      signed = await signWithStoredPqKey(message);
    } catch (error) {
      alert(`${error.message} Generate or import a browser-local PQ key first.`);
      return;
    }
    const pqPublicKey = document.getElementById("pqPublicKey");
    const pqSignature = document.getElementById("pqSignature");
    if (pqPublicKey) pqPublicKey.value = signed.pq_public_key_b64;
    if (pqSignature) pqSignature.value = signed.signature;

    await apiPost(`/api/doc/${doc.id}/sign`, {
      signature: signed.signature,
      signature_type: "pq_mldsa65",
      pq_public_key_b64: signed.pq_public_key_b64,
    });
    await afterDocumentSigned(doc.id);
    await refreshAllPqStatus({ clearSignature: false });
    alert("Browser-local PQ signature verified and recorded");
    return;
  }

  if (signatureMode === "sol_ed25519" && currentChain !== "sol") {
    alert("Phantom / Solana signing requires a Solana session.");
    return;
  }
  if (signatureMode === "evm_personal_sign" && currentChain === "sol") {
    alert("This session is using Phantom / Solana. Switch the signing mode to Phantom / Solana.");
    return;
  }

  const signed = await signTextWithActiveWallet(message);

  await apiPost(`/api/doc/${doc.id}/sign`, {
    signature: signed.signature,
    signature_type: signed.signature_type,
  });
  await afterDocumentSigned(doc.id);
  alert("Signed & recorded");
}

async function afterDocumentSigned(docId) {
  if (document.getElementById("overviewStats")) await loadOverview();
  if (document.getElementById("docList")) await loadDocuments();
  if (document.getElementById("inboxList")) await loadInbox();
  if (document.getElementById("sharedList")) await loadSharedFiles();
  if (document.getElementById("sharedActivityList")) await loadSharedActivity();
  if (document.getElementById("reviewPreview")) await loadReviewPage();
  if (document.getElementById("detailMeta")) await loadDocumentDetailsPage();
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
    if (!data.items.length) {
      setContent(box, createMessageCard("inbox-card", "No inbound shares.", "Shares addressed to your wallet will appear here."));
      return;
    }
    setContent(box, ...data.items.map((item) => createInboxCard(item)));
  } catch (err) {
    setContent(box, createMessageCard("inbox-card", "Inbox unavailable.", err?.message || "Unexpected error"));
  }
}

async function loadSharedFiles() {
  const box = document.getElementById("sharedList");
  if (!box) return;
  try {
    const items = await apiGet("/api/shared");
    if (!items.length) {
      setContent(box, createMessageCard("inbox-card", "No shared files yet.", "Files you send out will appear here."));
      return;
    }
    setContent(box, ...items.map((item) => createSharedFileCard(item)));
  } catch (err) {
    setContent(box, createMessageCard("inbox-card", "Shared files unavailable.", err?.message || "Unexpected error"));
  }
}

async function loadSharedActivity() {
  const box = document.getElementById("sharedActivityList");
  if (!box) return;
  try {
    const items = await apiGet("/api/activity/shared");
    if (!items.length) {
      setContent(box, createMessageCard("event-card neutral-event", "No shared activity yet.", "Actions across shared files will appear here.", "event-meta"));
      return;
    }
    setContent(box, renderHistoryCards(items, { currentWallet, aggregate: true }));
  } catch (err) {
    setContent(box, createMessageCard("event-card neutral-event", "Shared activity unavailable.", err?.message || "Unexpected error", "event-meta"));
  }
}

async function loadBillingStatus() {
  const box = document.getElementById("billingStatus");
  if (!box) return;
  try {
    const status = await apiGet("/api/account/status");
    setContent(
      box,
      createMetaLine("Wallet", status.wallet, { important: true }),
      createMetaLine("Status", status.billing_status, { important: true }),
      createMetaLine("Trial ends", status.trial_ends_at ? new Date(status.trial_ends_at).toLocaleString() : "n/a", { important: true }),
      createMetaLine("Plan", `$${String(status.plan_amount_usd)}/month`, { important: true }),
      createMetaLine("Subscription active", status.subscription_active ? "yes" : "no", { important: true }),
      createMetaLine("Write access", status.write_access ? "enabled" : "blocked", { important: true }),
      createMetaLine("Billing enforcement", status.billing_enforced ? "enabled" : "disabled", { important: true }),
      createMetaLine("Stripe customer", status.stripe_customer_id || "not linked yet"),
      createMetaLine("Stripe subscription", status.stripe_subscription_id || "not linked yet"),
      createMetaLine("Paid through", status.paid_through ? new Date(status.paid_through).toLocaleString() : "not set")
    );
  } catch (err) {
    setContent(box, createMessageCard("event-card neutral-event", "Billing unavailable.", err?.message || "Unexpected error", "event-meta"));
  }
}

async function loadAgents() {
  const box = document.getElementById("agentList");
  if (!box) return;
  try {
    const agents = await apiGet("/api/agent/list");
    agentsCache = agents;
    renderAllowedAgentChecklist();
    if (document.getElementById("agentPolicyDoc")?.value) {
      loadAgentPolicy().catch(() => {});
    }
    if (!agents.length) {
      setContent(
        box,
        createMessageCard("doc-card", "No agents registered yet.", "Create one agent for focused work or several role-based agents for a swarm.")
      );
      return;
    }
    setContent(box, ...agents.map((agent) => createAgentCard(agent)));
  } catch (err) {
    setContent(box, createMessageCard("doc-card", "Agents unavailable.", err?.message || "Unexpected error"));
  }
}

function renderAllowedAgentChecklist(selectedIds = []) {
  const root = document.getElementById("agentPolicyAllowedList");
  if (!root) return;

  if (!agentsCache.length) {
    setContent(root, createMessageCard("field-chip", "No agents available.", "Register an agent first."));
    return;
  }

  setContent(
    root,
    ...agentsCache.map((agent) => {
      const wrapper = createElement("label", { className: "field-chip" });
      const textWrap = createElement("div");
      textWrap.appendChild(createElement("strong", { text: agent.label || "(unnamed agent)" }));
      textWrap.appendChild(
        createElement("div", {
          className: "doc-meta",
          text: `${agent.provider || "provider?"} · ${agent.model || "model?"} · ${normalizeCapabilityList(agent.capabilities).join(", ") || "no capabilities listed"}`,
        })
      );
      const checkbox = createElement("input", { type: "checkbox" });
      checkbox.value = agent.id;
      checkbox.checked = selectedIds.includes(String(agent.id));
      wrapper.append(textWrap, checkbox);
      return wrapper;
    })
  );
}

async function loadAgentPolicy() {
  const select = document.getElementById("agentPolicyDoc");
  const resultBox = document.getElementById("agentPolicyResult");
  if (!select) return;
  const docId = select.value;
  if (!docId) {
    resultBox && (resultBox.textContent = "No owner-controlled document selected.");
    return;
  }

  const response = await apiGet(`/api/doc/${encodeURIComponent(docId)}/policy`);
  const policy = response.policy_json || {};
  document.getElementById("agentPolicyAllowReview").checked = Boolean(policy.allow_agent_review);
  document.getElementById("agentPolicyAllowSign").checked = Boolean(policy.allow_agent_sign);
  document.getElementById("agentPolicyRequireCountersign").checked = Boolean(policy.require_human_countersign);
  document.getElementById("agentPolicyAllowGuest").checked = Boolean(policy.allow_guest_sign);
  renderAllowedAgentChecklist((policy.allowed_agent_ids || []).map(String));
  if (resultBox) {
    resultBox.textContent = JSON.stringify(policy, null, 2);
  }
}

function currentPolicyFromForm() {
  const selectedIds = Array.from(document.querySelectorAll('#agentPolicyAllowedList input[type="checkbox"]:checked'))
    .map((input) => input.value);

  return {
    allow_guest_sign: document.getElementById("agentPolicyAllowGuest").checked,
    allow_agent_review: document.getElementById("agentPolicyAllowReview").checked,
    allow_agent_sign: document.getElementById("agentPolicyAllowSign").checked,
    require_human_countersign: document.getElementById("agentPolicyRequireCountersign").checked,
    allowed_agent_ids: selectedIds,
    allowed_wallet_signers: [],
  };
}

async function saveAgentPolicy() {
  const docId = document.getElementById("agentPolicyDoc")?.value;
  const resultBox = document.getElementById("agentPolicyResult");
  if (!docId) {
    alert("Choose a document first.");
    return;
  }
  const policy_json = currentPolicyFromForm();
  const result = await apiPost(`/api/doc/${encodeURIComponent(docId)}/policy`, { policy_json });
  if (resultBox) {
    resultBox.textContent = JSON.stringify(result, null, 2);
  }
  await loadSharedActivity();
  await loadAgentActivity();
}

function applySwarmTemplate() {
  const template = document.getElementById("swarmTemplate")?.value || "single-reviewer";
  const allAgentIds = agentsCache.map((agent) => String(agent.id));
  let policy;

  if (template === "review-plus-human-sign") {
    policy = {
      allow_guest_sign: true,
      allow_agent_review: true,
      allow_agent_sign: false,
      require_human_countersign: true,
      allowed_agent_ids: allAgentIds,
      allowed_wallet_signers: [],
    };
  } else if (template === "swarm-review-board") {
    policy = {
      allow_guest_sign: false,
      allow_agent_review: true,
      allow_agent_sign: false,
      require_human_countersign: true,
      allowed_agent_ids: allAgentIds,
      allowed_wallet_signers: [],
    };
  } else if (template === "agent-autonomous-sign") {
    policy = {
      allow_guest_sign: false,
      allow_agent_review: true,
      allow_agent_sign: true,
      require_human_countersign: false,
      allowed_agent_ids: allAgentIds,
      allowed_wallet_signers: [],
    };
  } else {
    policy = {
      allow_guest_sign: true,
      allow_agent_review: true,
      allow_agent_sign: false,
      require_human_countersign: true,
      allowed_agent_ids: allAgentIds.slice(0, 1),
      allowed_wallet_signers: [],
    };
  }

  document.getElementById("agentPolicyAllowReview").checked = Boolean(policy.allow_agent_review);
  document.getElementById("agentPolicyAllowSign").checked = Boolean(policy.allow_agent_sign);
  document.getElementById("agentPolicyRequireCountersign").checked = Boolean(policy.require_human_countersign);
  document.getElementById("agentPolicyAllowGuest").checked = Boolean(policy.allow_guest_sign);
  renderAllowedAgentChecklist(policy.allowed_agent_ids);
  const resultBox = document.getElementById("agentPolicyResult");
  if (resultBox) {
    resultBox.textContent = JSON.stringify(
      {
        template,
        policy,
        note: "Template applied locally. Save policy to persist it on the selected document.",
      },
      null,
      2
    );
  }
}

async function loadAgentActivity() {
  const box = document.getElementById("agentActivityList");
  if (!box) return;
  try {
    const items = await apiGet("/api/activity/shared");
    const agentItems = items.filter((event) => {
      const actorKind = event?.payload?.actor?.kind;
      const actorChain = event?.payload?.actor_chain;
      return actorKind === "agent" || actorChain === "agent-api" || String(event.actor_wallet || "").startsWith("agent:");
    });
    if (!agentItems.length) {
      setContent(
        box,
        createMessageCard("event-card neutral-event", "No agent activity yet.", "Agent review, version, and sign events will appear here.", "event-meta")
      );
      return;
    }
    setContent(box, renderHistoryCards(agentItems, { currentWallet, aggregate: true }));
  } catch (err) {
    setContent(box, createMessageCard("event-card neutral-event", "Agent activity unavailable.", err?.message || "Unexpected error", "event-meta"));
  }
}

async function exportAgentActivity() {
  const items = await apiGet("/api/activity/shared");
  const agentItems = items.filter((event) => {
    const actorKind = event?.payload?.actor?.kind;
    const actorChain = event?.payload?.actor_chain;
    return actorKind === "agent" || actorChain === "agent-api" || String(event.actor_wallet || "").startsWith("agent:");
  });
  downloadJsonFile("tidbit-agent-activity.json", {
    exported_at: new Date().toISOString(),
    owner_wallet: currentWallet,
    events: agentItems,
  });
}

async function registerAgent() {
  const label = document.getElementById("agentLabel")?.value.trim();
  const provider = document.getElementById("agentProvider")?.value.trim();
  const model = document.getElementById("agentModel")?.value.trim();
  const capabilities = normalizeCapabilityList(document.getElementById("agentCapabilities")?.value);
  const resultBox = document.getElementById("agentRegisterResult");

  if (!label) {
    alert("Agent label is required.");
    return;
  }

  const result = await apiPost("/api/agent/register", {
    label,
    provider: provider || null,
    model: model || null,
    capabilities,
  });

  if (resultBox) {
    resultBox.textContent = JSON.stringify(
      {
        ok: result.ok,
        agent_id: result.agent_id,
        owner_wallet: result.owner_wallet,
        label: result.label,
        provider: result.provider,
        model: result.model,
        capabilities: result.capabilities,
        token: result.token,
        note: "Store this token now. It is the runtime credential for the agent API.",
      },
      null,
      2
    );
  }

  ["agentLabel", "agentProvider", "agentModel", "agentCapabilities"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.value = "";
  });

  await loadAgents();
}

// ================== SHARE ==================
function prepareShare(doc, seedShare = null) {
  selectedShareDoc = doc;
  const fieldValues = {
    modalRecipientName: seedShare?.recipient_name || "",
    modalRecipientWallet: seedShare?.recipient_wallet || "",
    modalRecipientEmail: seedShare?.recipient_email || "",
    modalRecipientPhone: seedShare?.recipient_phone || "",
    modalAgentHandle: "",
    modalShareNote: seedShare?.note || "",
  };
  Object.entries(fieldValues).forEach(([id, value]) => {
    const el = document.getElementById(id);
    if (el) el.value = value;
  });
  const expiry = document.getElementById("modalShareExpiresHours");
  if (expiry) expiry.value = seedShare?.expires_at ? Math.max(1, Math.ceil((new Date(seedShare.expires_at).getTime() - Date.now()) / 3600000)).toString() : "168";
  const oneTime = document.getElementById("modalShareOneTimeUse");
  if (oneTime) oneTime.checked = Boolean(seedShare?.one_time_use);
  const downloadAllowed = document.getElementById("modalDownloadAllowed");
  if (downloadAllowed) downloadAllowed.checked = seedShare?.download_allowed ?? true;
  const allowGuestSign = document.getElementById("modalAllowGuestSign");
  if (allowGuestSign) allowGuestSign.checked = Boolean(seedShare?.allow_guest_sign);
  const recipientChain = document.getElementById("modalRecipientChain");
  if (recipientChain) recipientChain.value = seedShare?.recipient_chain || (currentChain === "sol" ? "sol" : "evm");
  const stateRoot = document.getElementById("shareModalState");
  if (!stateRoot) return;
  setContent(
    stateRoot,
    createSimpleInfoBlock("Selected document", [
      { label: null, value: doc.label || "(untitled document)" },
      { label: "ID", value: doc.id },
      { label: "Hash", value: doc.hash_hex },
    ])
  );
  const title = document.getElementById("shareModalTitle");
  if (title) title.textContent = seedShare ? `Reissue signing link for ${doc.label || "document"}` : `Create signing link for ${doc.label || "document"}`;
  document.getElementById("shareResult").innerText = seedShare
    ? "Share fields restored from the earlier envelope. Create a replacement link when ready."
    : "Ready to create a signing link.";
}

function openShareModal(doc, seedShare = null) {
  prepareShare(doc, seedShare);
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
  setContent(
    document.getElementById("versionState"),
    createSimpleInfoBlock("Parent document", [
      { label: null, value: doc.label || "(untitled document)" },
      { label: "ID", value: doc.id },
      { label: "Current version", value: `v${doc.version}` },
      { label: "Arweave", value: doc.arweave_tx || "not anchored" },
    ])
  );
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
Wallet Chain: ${currentChain || "unknown"}
Version: ${doc.version || 1}`;
}

async function shareDocument(docId) {
  const recipient = document.getElementById("modalRecipientWallet").value.trim() || null;
  const recipientChain = document.getElementById("modalRecipientChain")?.value || null;
  const recipientName = document.getElementById("modalRecipientName")?.value || null;
  const note = document.getElementById("modalShareNote")?.value || null;
  const recipientEmail = document.getElementById("modalRecipientEmail")?.value || null;
  const recipientPhone = document.getElementById("modalRecipientPhone")?.value || null;
  const agentHandle = document.getElementById("modalAgentHandle")?.value.trim() || null;
  const expiresInHoursRaw = document.getElementById("modalShareExpiresHours")?.value || null;
  const expiresInHours = expiresInHoursRaw ? Number.parseInt(expiresInHoursRaw, 10) : null;
  const oneTimeUse = Boolean(document.getElementById("modalShareOneTimeUse")?.checked);
  const downloadAllowed = Boolean(document.getElementById("modalDownloadAllowed")?.checked);
  const allowGuestSign = Boolean(document.getElementById("modalAllowGuestSign")?.checked);

  if (!recipient && !recipientEmail && !recipientPhone) {
    return alert("Provide a wallet, email, or phone number for the recipient.");
  }
  if (expiresInHoursRaw && (!Number.isFinite(expiresInHours) || expiresInHours <= 0)) {
    return alert("Expiry hours must be a positive number.");
  }
  if (recipient && !confirmRecipientNetwork(recipient, recipientChain)) {
    throw new Error("Share canceled while verifying recipient network.");
  }

  let signature = null;
  if (currentWallet && selectedShareDoc) {
    const signed = await signTextWithActiveWallet(
      buildShareSignatureMessage(selectedShareDoc, recipient || recipientEmail || recipientPhone || "guest", note)
    );
    signature = signed.signature;
  }

  const res = await apiPost(`/api/doc/${docId}/share`, {
    recipient_wallet: recipient,
    recipient_chain: recipient ? recipientChain : null,
    recipient_name: recipientName,
    note: [note, agentHandle ? `AI agent: ${agentHandle}` : null].filter(Boolean).join("\n"),
    signature,
    recipient_email: recipientEmail,
    recipient_phone: recipientPhone,
    expires_in_hours: Number.isFinite(expiresInHours) ? expiresInHours : null,
    one_time_use: oneTimeUse,
    download_allowed: downloadAllowed,
    allow_guest_sign: allowGuestSign,
  });

  return { ...res, recipient_wallet: recipient, recipient_chain: recipient ? recipientChain : null };
}

async function shareSelectedDocument() {
  if (!selectedShareDoc) {
    alert("Select a document to share first.");
    return;
  }

  const res = await shareDocument(selectedShareDoc.id);
  window.lastShareResult = res;
  setInviteLinks(res, selectedShareDoc);
  const summary = [
    `Status: ${res.status || "created"}`,
    `Signing URL: ${res.signing_url}`,
    `Expires: ${res.expires_at ? new Date(res.expires_at).toLocaleString() : "server default"}`,
    `One-time use: ${res.one_time_use ? "yes" : "no"}`,
    `Guest signing: ${res.allow_guest_sign ? "allowed" : "wallet/PQ only"}`,
    `Wallet route: ${res.recipient_wallet ? `ready for ${res.recipient_chain || "wallet"} inbox` : "not used"}`,
    `Provider delivery issues: ${res.delivery_errors?.length || 0}`,
  ].join("\n");
  document.getElementById("shareResult").innerText = `${summary}\n\n${JSON.stringify(res, null, 2)}`;
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

  const resp = await fetch(`${API}/api/doc/${selectedVersionParent.id}/version`, {
    method: "POST",
    headers: authHeaders(),
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

async function logInboxAction(envelopeId, action) {
  return apiPost(`/api/inbox/${encodeURIComponent(envelopeId)}/action`, { action });
}

async function refreshDashboardData() {
  if (document.getElementById("overviewStats")) await loadOverview();
  if (document.getElementById("docList")) await loadDocuments();
  if (document.getElementById("inboxList")) await loadInbox();
  if (document.getElementById("sharedList")) await loadSharedFiles();
  if (document.getElementById("sharedActivityList")) await loadSharedActivity();
  if (document.getElementById("agentList")) await loadAgents();
  if (document.getElementById("agentActivityList")) await loadAgentActivity();
  if (document.getElementById("billingStatus")) await loadBillingStatus();
}

async function reviewInboxDocument(item) {
  await logInboxAction(item.envelope_id, "review");
  await refreshDashboardData();
  openReview(item.doc_id);
}

async function downloadSharedDocument(item) {
  await logInboxAction(item.envelope_id, "download");
  await downloadAndVerify({ id: item.doc_id, hash_hex: item.hash_hex, label: item.label, version: item.version });
  await refreshDashboardData();
}

async function signSharedDocument(item) {
  await logInboxAction(item.envelope_id, "sign");
  await signDocument({ id: item.doc_id, hash_hex: item.hash_hex, label: item.label, version: item.version });
  await refreshDashboardData();
}

async function dismissInboxDocument(item) {
  if (!confirm("Remove this shared file from your inbox?")) return;
  await logInboxAction(item.envelope_id, "delete");
  await refreshDashboardData();
}

function openReview(docId) {
  window.location.href = `/review.html?id=${encodeURIComponent(docId)}`;
}

function getReviewPqConfig() {
  return {
    statusId: "pqDeviceStatus",
    publicKeyId: "pqPublicKey",
    signatureId: "pqSignature",
    generateBtnId: "pqGenerateKeyBtn",
    exportBtnId: "pqExportKeyBtn",
    importBtnId: "pqImportKeyBtn",
    clearBtnId: "pqClearKeyBtn",
    importInputId: "pqImportFile",
  };
}

function getPublicPqConfig() {
  return {
    statusId: "publicPqDeviceStatus",
    publicKeyId: "publicPqPublicKey",
    signatureId: "publicPqSignature",
    generateBtnId: "publicPqGenerateKeyBtn",
    exportBtnId: "publicPqExportKeyBtn",
    importBtnId: "publicPqImportKeyBtn",
    clearBtnId: "publicPqClearKeyBtn",
    importInputId: "publicPqImportFile",
  };
}

async function renderPqStatus(config, { clearSignature = true } = {}) {
  const statusRoot = document.getElementById(config.statusId);
  const publicKeyField = document.getElementById(config.publicKeyId);
  const signatureField = document.getElementById(config.signatureId);
  const exportBtn = document.getElementById(config.exportBtnId);
  const clearBtn = document.getElementById(config.clearBtnId);
  const keypair = loadStoredPqKeypair();

  if (publicKeyField) {
    publicKeyField.value = keypair?.public_key_b64 || "";
  }
  if (signatureField && clearSignature) {
    signatureField.value = "";
  }
  if (exportBtn) exportBtn.disabled = !keypair;
  if (clearBtn) clearBtn.disabled = !keypair;

  if (!statusRoot) return;

  if (!keypair) {
    statusRoot.textContent =
      "No browser-local ML-DSA key is loaded on this device. Generate one here or import a backup before choosing the PQ signing mode.";
    return;
  }

  const fingerprint = await pqKeyFingerprint(keypair.public_key_b64);
  setContent(
    statusRoot,
    createMetaLine("Signer", "Browser-local ML-DSA-65"),
    createMetaLine("Fingerprint", fingerprint),
    createMetaLine("Stored", keypair.created_at ? new Date(keypair.created_at).toLocaleString() : "this browser"),
    createMetaLine("Public key", `${keypair.public_key_b64.slice(0, 24)}…`)
  );
}

async function refreshAllPqStatus(options = {}) {
  if (document.getElementById("pqDeviceStatus")) {
    await renderPqStatus(getReviewPqConfig(), options);
  }
  if (document.getElementById("publicPqDeviceStatus")) {
    await renderPqStatus(getPublicPqConfig(), options);
  }
}

function bindPqControls(config) {
  const generateBtn = document.getElementById(config.generateBtnId);
  const exportBtn = document.getElementById(config.exportBtnId);
  const importBtn = document.getElementById(config.importBtnId);
  const clearBtn = document.getElementById(config.clearBtnId);
  const importInput = document.getElementById(config.importInputId);

  generateBtn?.addEventListener("click", async () => {
    try {
      await generateBrowserPqKeypair();
      await refreshAllPqStatus();
      alert("Browser-local ML-DSA key generated.");
    } catch (error) {
      alert(error.message);
    }
  });

  exportBtn?.addEventListener("click", async () => {
    try {
      await exportStoredPqKeypair();
    } catch (error) {
      alert(error.message);
    }
  });

  importBtn?.addEventListener("click", () => importInput?.click());
  importInput?.addEventListener("change", async (event) => {
    const [file] = Array.from(event.target.files || []);
    event.target.value = "";
    if (!file) return;
    try {
      await importStoredPqKeypair(file);
      await refreshAllPqStatus();
      alert("Browser-local ML-DSA backup imported.");
    } catch (error) {
      alert(error.message);
    }
  });

  clearBtn?.addEventListener("click", async () => {
    if (!confirm("Remove the browser-local ML-DSA key from this device?")) return;
    clearStoredPqKeypair();
    await refreshAllPqStatus();
  });
}

function toggleSignatureMode() {
  const mode = document.getElementById("signatureMode")?.value;
  const pqFields = document.getElementById("pqFields");
  if (!pqFields) return;
  pqFields.classList.toggle("hidden", mode !== "pq_mldsa65");
}

function togglePublicSignatureMode() {
  const mode = document.getElementById("publicSignatureMode")?.value;
  const evmFields = document.getElementById("publicEvmFields");
  const solFields = document.getElementById("publicSolFields");
  const pqFields = document.getElementById("publicPqFields");
  if (evmFields) evmFields.classList.toggle("hidden", mode !== "evm_personal_sign");
  if (solFields) solFields.classList.toggle("hidden", mode !== "sol_ed25519");
  if (pqFields) pqFields.classList.toggle("hidden", mode !== "pq_mldsa65");
}

function configurePublicSignatureModes(envelope) {
  const select = document.getElementById("publicSignatureMode");
  if (!select) return;
  const labels = {
    guest_attestation: "Guided Guest Attestation",
    evm_personal_sign: "MetaMask / EVM",
    sol_ed25519: "Phantom / Solana",
    pq_mldsa65: "ML-DSA PQ",
  };
  const allowed = Array.isArray(envelope.allowed_signature_types) && envelope.allowed_signature_types.length
    ? envelope.allowed_signature_types
    : ["evm_personal_sign", "sol_ed25519", "pq_mldsa65"];

  select.replaceChildren(
    ...allowed.map((value) => {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = labels[value] || value;
      return option;
    })
  );

  if (!select.dataset.userSelected) {
    const preferred =
      envelope.recipient_chain === "sol" && allowed.includes("sol_ed25519")
        ? "sol_ed25519"
        : allowed.includes("evm_personal_sign")
          ? "evm_personal_sign"
          : allowed[0];
    if (preferred) select.value = preferred;
  } else if (!allowed.includes(select.value) && allowed[0]) {
    select.value = allowed[0];
  }
}

function selectFieldTool(kind) {
  activeFieldTool = kind;
  document.querySelectorAll("[data-field-tool]").forEach((button) => {
    button.classList.toggle("button-primary", button.getAttribute("data-field-tool") === kind);
  });
}

function classifyEventActor(event, context = {}) {
  const actorWallet = String(event.actor_wallet || event?.payload?.actor?.wallet || "");
  const ownerWallet = String(context.ownerWallet || event.owner_wallet || "");
  const activeWallet = String(context.currentWallet || currentWallet || "");

  if (ownerWallet && actorWallet && actorWallet.toLowerCase() === ownerWallet.toLowerCase()) {
    return {
      role: "sender",
      label: activeWallet && actorWallet.toLowerCase() === activeWallet.toLowerCase() ? "Sender · You" : "Sender",
    };
  }
  if (activeWallet && actorWallet && actorWallet.toLowerCase() === activeWallet.toLowerCase()) {
    return { role: "recipient", label: "Recipient · You" };
  }
  if (actorWallet.startsWith("guest-envelope:")) {
    return { role: "neutral", label: "Guest Envelope" };
  }
  return { role: "recipient", label: "Recipient" };
}

function renderHistoryCards(events, context = {}) {
  if (!events.length) {
    return createMessageCard("event-card", "No custody events yet.", "Review, share, download, and signature activity will appear here.", "event-meta");
  }

  const fragment = document.createDocumentFragment();
  events.forEach((event) => {
    const actor = classifyEventActor(event, context);
    const article = createElement("article", { className: `event-card ${actor.role}-event` });
    const top = createElement("div", { className: "event-top" });
    top.appendChild(createElement("strong", { text: friendlyEventLabel(event.event_type) }));
    top.appendChild(createElement("span", { className: "muted", text: new Date(event.created_at).toLocaleString() }));
    article.appendChild(top);

    const badgeRow = createElement("div", { className: "event-meta" });
    badgeRow.appendChild(createElement("span", { className: `role-badge ${actor.role}-role`, text: actor.label }));
    article.appendChild(badgeRow);
    article.appendChild(createMetaLine("Actor", event.actor_wallet || "system", { className: "event-meta" }));
    article.appendChild(createMetaLine("Event ID", event.id, { className: "event-meta" }));
    createImportantMetaNodes(event).forEach((node) => article.appendChild(node));
    article.appendChild(createElement("pre", { text: JSON.stringify(event.payload || {}, null, 2) }));
    fragment.appendChild(article);
  });
  return fragment;
}

function renderLineageCards(lineage) {
  if (!lineage?.length) {
    return createMessageCard("event-card", "No lineage yet.", "Root document.", "event-meta");
  }
  const fragment = document.createDocumentFragment();
  lineage.forEach((item) => {
    const article = createElement("article", { className: "event-card compact-card" });
    const top = createElement("div", { className: "event-top" });
    top.appendChild(createElement("strong", { text: item.label || "Untitled document" }));
    top.appendChild(createElement("span", { className: "muted", text: `v${item.version}` }));
    article.appendChild(top);
    article.appendChild(createMetaLine("Hash", item.hash_hex, { className: "event-meta" }));
    article.appendChild(createMetaLine("Created", new Date(item.created_at).toLocaleString(), { className: "event-meta" }));
    article.appendChild(createMetaLine("Arweave", item.arweave_tx || "not anchored", { className: "event-meta" }));
    const actions = createElement("div", { className: "doc-actions" });
    actions.appendChild(createElement("a", { className: "button-link", href: `/document.html?id=${encodeURIComponent(item.id)}`, text: "Open" }));
    article.appendChild(actions);
    fragment.appendChild(article);
  });
  return fragment;
}

function renderShareCards(shares) {
  if (!shares?.length) {
    return createMessageCard("event-card", "No shares yet.", "Create a share to send this file for review or signing.", "event-meta");
  }
  const fragment = document.createDocumentFragment();
  shares.forEach((share) => {
    const article = createElement("article", { className: "event-card compact-card" });
    const top = createElement("div", { className: "event-top" });
    top.appendChild(createElement("strong", { text: shareRecipientLabel(share) }));
    top.appendChild(createElement("span", { className: "muted", text: share.status }));
    article.appendChild(top);
    article.appendChild(createMetaLine("Envelope", share.envelope_id, { className: "event-meta" }));
    article.appendChild(createMetaLine("Wallet", share.recipient_wallet || "not provided", { className: "event-meta" }));
    article.appendChild(createMetaLine("Email", share.recipient_email || "not provided", { className: "event-meta" }));
    article.appendChild(createMetaLine("Phone", share.recipient_phone || "not provided", { className: "event-meta" }));
    article.appendChild(createMetaLine("Delivery", shareDeliverySummary(share), { className: "event-meta" }));
    article.appendChild(createMetaLine("Expires", share.expires_at ? new Date(share.expires_at).toLocaleString() : "server default", { className: "event-meta" }));
    article.appendChild(createMetaLine("Viewed", share.viewed_at ? new Date(share.viewed_at).toLocaleString() : "not yet", { className: "event-meta" }));
    article.appendChild(createMetaLine("Completed", share.completed_at ? new Date(share.completed_at).toLocaleString() : "not yet", { className: "event-meta" }));
    article.appendChild(createMetaLine("One-time use", share.one_time_use ? "yes" : "no", { className: "event-meta" }));
    article.appendChild(createMetaLine("Downloads", share.download_allowed ? "allowed" : "preview only", { className: "event-meta" }));
    article.appendChild(createMetaLine("Guest signing", share.allow_guest_sign ? "allowed" : "disabled", { className: "event-meta" }));
    article.appendChild(createMetaLine("Signer", share.signer_name || share.signer_wallet || "not completed", { className: "event-meta" }));
    article.appendChild(createMetaLine("Signature type", share.completion_signature_type || "not completed", { className: "event-meta" }));
    if (share.revoked_at) {
      article.appendChild(createMetaLine("Revoked", new Date(share.revoked_at).toLocaleString(), { className: "event-meta", important: true }));
    }
    article.appendChild(createMetaLine("Created", new Date(share.created_at).toLocaleString(), { className: "event-meta" }));
    const actions = createElement("div", { className: "doc-actions" });
    const reissue = createElement("button", { text: "Reissue" });
    reissue.onclick = () => openShareModal(currentDocumentDetails, share);
    actions.appendChild(reissue);
    if (shareCanBeRevoked(share)) {
      const revoke = createElement("button", { className: "button-danger", text: "Revoke" });
      revoke.onclick = async () => {
        await revokeShare(currentDocumentDetails.id, share.envelope_id);
        await loadDocumentDetailsPage();
      };
      actions.appendChild(revoke);
    }
    article.appendChild(actions);
    fragment.appendChild(article);
  });
  return fragment;
}

function ensurePreviewModal() {
  let modal = document.getElementById("previewModal");
  if (modal) return modal;

  modal = document.createElement("section");
  modal.id = "previewModal";
  modal.className = "modal-shell hidden preview-modal-shell";
  modal.setAttribute("aria-hidden", "true");
  const panel = createElement("div", { className: "modal-panel preview-modal-panel" });
  const head = createElement("div", { className: "section-head" });
  const title = createElement("h3", { id: "previewModalTitle", text: "Large preview" });
  const close = createElement("button", {
    id: "closePreviewModal",
    className: "button-secondary",
    text: "Close",
    type: "button",
  });
  const body = createElement("div", { id: "previewModalBody", className: "preview-modal-body" });
  head.append(title, close);
  panel.append(head, body);
  modal.appendChild(panel);
  document.body.appendChild(modal);
  document.getElementById("closePreviewModal").onclick = hidePreviewModal;
  return modal;
}

function showPreviewModal(title, blob, mimeType, annotationFields = []) {
  const modal = ensurePreviewModal();
  document.getElementById("previewModalTitle").textContent = title || "Large preview";
  const body = document.getElementById("previewModalBody");
  body.replaceChildren(renderPreviewNode(blob, mimeType, { annotationFields }));
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
  overlay.replaceChildren(...(fields || []).map((field) => createFieldBadge(field)));
  overlay.classList.toggle("interactive-overlay", Boolean(interactive));
}

function updateAnnotationFieldList(fields) {
  const root = document.getElementById("publicFieldList");
  if (!root) return;
  if (!fields.length) {
    setContent(root, createElement("div", { className: "muted", text: "No signer fields placed yet. Choose a field type and click on the preview." }));
    return;
  }

  root.replaceChildren();
  fields.forEach((field, index) => {
    const row = document.createElement("div");
    row.className = "field-chip";
    row.appendChild(createElement("span", { text: `${field.kind} · ${Math.round(field.x_pct)}%, ${Math.round(field.y_pct)}%` }));
    const remove = createElement("button", { text: "Remove", type: "button" });
    remove.setAttribute("data-remove-field", String(index));
    row.appendChild(remove);
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
    fallback.appendChild(createElement("strong", { text: `Preview unavailable for ${mimeType || "this file type"}.` }));
    fallback.appendChild(createElement("div", { className: "doc-meta", text: "Use the verified download to inspect it locally before signing." }));
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
      owner_wallet: review.owner_wallet,
    };

    document.getElementById("reviewTitle").textContent = review.label || "Document Review";
    document.getElementById("reviewSubtitle").textContent =
      verified
        ? "Preview verified against the stored custody hash."
        : "Preview loaded, but the file hash does not match the recorded custody hash.";

    setContent(
      metaRoot,
      createMetaLine("Document ID", id),
      createMetaLine("Hash", review.hash_hex),
      createMetaLine("Version", `v${review.version}`),
      createMetaLine("Type", review.mime_type || "application/octet-stream"),
      createMetaLine("Parent", review.parent_id || "root document"),
      createMetaLine("Owner", review.owner_wallet || "unknown"),
      createMetaLine("Arweave", review.arweave_tx || "not anchored"),
      createMetaLine("Integrity", verified ? "verified" : "mismatch detected")
    );

    setContent(previewRoot, renderPreviewNode(blob, review.mime_type || "application/octet-stream"));
    setContent(eventsRoot, renderHistoryCards(events, { currentWallet, ownerWallet: review.owner_wallet }));

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
    await renderPqStatus(getReviewPqConfig());
  } catch (err) {
    console.error(err);
    setContent(previewRoot, createMessageCard("preview-fallback", "Preview failed.", err?.message || "Unexpected error"));
    metaRoot.replaceChildren();
    eventsRoot.replaceChildren();
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
    owner_wallet: review.owner_wallet || evidence.document?.owner_wallet,
  };
  selectedVersionParent = currentDocumentDetails;

  document.getElementById("detailTitle").textContent =
    currentDocumentDetails.label || "Document details";
  document.getElementById("detailSubtitle").textContent =
    `Version v${currentDocumentDetails.version}. Review, share, edit, and inspect all custody metadata from here.`;

  setContent(
    metaRoot,
    createMetaLine("Document ID", id),
    createMetaLine("Hash", currentDocumentDetails.hash_hex),
    createMetaLine("Type", currentDocumentDetails.mime_type || "application/octet-stream"),
    createMetaLine("Version", `v${currentDocumentDetails.version}`),
    createMetaLine("Parent", currentDocumentDetails.parent_id || "root document"),
    createMetaLine("Owner", evidence.document?.owner_wallet || ""),
    createMetaLine("Created", new Date(evidence.document?.created_at).toLocaleString()),
    createMetaLine("Last signed", evidence.document?.last_signed_at ? new Date(evidence.document.last_signed_at).toLocaleString() : "not signed yet"),
    createMetaLine("Arweave", currentDocumentDetails.arweave_tx || "not anchored"),
    createMetaLine(
      "Evidence chain",
      evidence.evidence_bundle?.events_chain_valid
        ? "valid"
        : evidence.evidence_bundle?.events_chain_complete
          ? "invalid"
          : "partial coverage"
    ),
    createMetaLine(
      "Evidence bundle",
      evidence.evidence_bundle?.bundle_hash_hex
        ? `${String(evidence.evidence_bundle.bundle_hash_hex).slice(0, 24)}…`
        : "not generated"
    ),
    createMetaLine(
      "Evidence anchor",
      evidence.evidence_bundle?.evidence_bundle_arweave_tx || "not anchored"
    )
  );
  setContent(previewRoot, renderPreviewNode(blob, currentDocumentDetails.mime_type || "application/octet-stream"));
  setContent(lineageRoot, renderLineageCards(evidence.lineage || []));
  setContent(sharesRoot, renderShareCards(evidence.shares || []));
  setContent(
    historyRoot,
    renderHistoryCards([...(evidence.events || [])].reverse(), {
      currentWallet,
      ownerWallet: currentDocumentDetails.owner_wallet,
    })
  );

  prepareVersion(currentDocumentDetails);
  document.getElementById("detailReviewBtn").onclick = () => openReview(id);
  document.getElementById("detailOpenReviewBtn").onclick = () => openReview(id);
  document.getElementById("detailDownloadBtn").onclick = () => downloadAndVerify(currentDocumentDetails).catch((err) => alert(err.message));
  document.getElementById("detailShareBtn").onclick = () => openShareModal(currentDocumentDetails);
  document.getElementById("detailVersionBtn").onclick = () => document.getElementById("versionFile")?.focus();
  document.getElementById("detailEvidenceBtn").onclick = () => exportEvidence(id, currentDocumentDetails.label || id).catch((err) => alert(err.message));
  document.getElementById("detailDeleteBtn").onclick = async () => {
    await deleteDoc(id);
    window.location.href = "/dashboard.html";
  };
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
  setContent(
    document.getElementById("editMeta"),
    createMetaLine("Document ID", id),
    createMetaLine("Hash", review.hash_hex),
    createMetaLine("Version", `v${review.version}`),
    createMetaLine("Type", review.mime_type || "application/octet-stream")
  );

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
    const resp = await fetch(`${API}/api/doc/${id}/version`, {
      method: "POST",
      headers: authHeaders(),
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

    setContent(
      metaRoot,
      createMetaLine("Envelope ID", envelope.envelope_id),
      createMetaLine("From", envelope.sender_wallet),
      createMetaLine("Hash", envelope.hash_hex),
      createMetaLine("Version", `v${envelope.version}`),
      createMetaLine("Expires", envelope.expires_at ? new Date(envelope.expires_at).toLocaleString() : "no expiry"),
      createMetaLine("One-time use", envelope.one_time_use ? "yes" : "no"),
      createMetaLine("Downloads", envelope.download_allowed ? "allowed" : "preview only"),
      createMetaLine("Guest signing", envelope.allow_guest_sign ? "allowed" : "disabled"),
      createMetaLine("Arweave", envelope.arweave_tx || "not anchored"),
      createMetaLine("Recipient name", envelope.recipient_name || "not provided"),
      createMetaLine("Recipient wallet", envelope.recipient_wallet || "guest link"),
      createMetaLine("Recipient email", envelope.recipient_email || "not provided"),
      createMetaLine("Recipient phone", envelope.recipient_phone || "not provided"),
      createMetaLine("Delivery", Array.isArray(envelope.delivery) && envelope.delivery.length ? envelope.delivery.map((item) => `${item.channel}/${item.provider}`).join(", ") : "draft link only"),
      createMetaLine("Note", envelope.note || "No note"),
      createMetaLine("Integrity", verified ? "verified" : "mismatch detected")
    );

    setContent(
      previewRoot,
      renderPreviewNode(blob, envelope.mime_type || "application/octet-stream", {
        interactive: true,
        annotationFields: window.publicEnvelopeFields,
      })
    );
    updateAnnotationFieldList(window.publicEnvelopeFields);
    configurePublicSignatureModes(envelope);
    document.getElementById("publicSignSubmit").disabled = !verified;
    togglePublicSignatureMode();
    await renderPqStatus(getPublicPqConfig());
  } catch (err) {
    setContent(previewRoot, createMessageCard("preview-fallback", "Envelope unavailable.", err?.message || "Unexpected error"));
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

  if (signatureType === "sol_ed25519") {
    const provider = getPhantomProvider();
    if (!provider) {
      alert("Phantom is required for Solana signing.");
      return;
    }
    await provider.connect({ onlyIfTrusted: false }).catch(() => null);
    const address = provider.publicKey?.toString?.();
    if (!address) {
      alert("Phantom wallet address unavailable.");
      return;
    }
    const message =
      `TIDBIT Public Envelope Signature\n` +
      `Envelope ID: ${window.publicEnvelope.envelope_id}\n` +
      `Document ID: ${window.publicEnvelope.doc_id}\n` +
      `Hash: ${window.publicEnvelope.hash_hex}\n` +
      `Signer: ${address}\n` +
      `Version: ${window.publicEnvelope.version}`;
    const signed = await provider.signMessage(new TextEncoder().encode(message), "utf8");
    payload.wallet_address = address;
    payload.signature = bytesToBase64(signed?.signature || signed);
  }

  if (signatureType === "pq_mldsa65") {
    let signed;
    try {
      signed = await signWithStoredPqKey(
        `TIDBIT Public Envelope Signature\n` +
        `Envelope ID: ${window.publicEnvelope.envelope_id}\n` +
        `Document ID: ${window.publicEnvelope.doc_id}\n` +
        `Hash: ${window.publicEnvelope.hash_hex}\n` +
        `Signer: ${signerName}\n` +
        `Version: ${window.publicEnvelope.version}`
      );
    } catch (error) {
      alert(`${error.message} Generate or import a browser-local PQ key first.`);
      return;
    }
    payload.pq_public_key_b64 = signed.pq_public_key_b64;
    payload.signature = signed.signature;
    document.getElementById("publicPqPublicKey").value = signed.pq_public_key_b64;
    document.getElementById("publicPqSignature").value = signed.signature;
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
    loadDocuments()
      .then(async () => {
        populateAgentPolicyDocOptions();
        if (document.getElementById("agentPolicyDoc")?.value) {
          await loadAgentPolicy();
        }
      })
      .catch((err) => alert(err.message));
    loadInbox();
    loadSharedFiles();
    loadSharedActivity();
    loadAgents();
    loadAgentActivity();
    loadBillingStatus();
    document.getElementById("homeTabBtn")?.addEventListener("click", () => switchDashboardTab("home"));
    document.getElementById("docsTabBtn")?.addEventListener("click", () => switchDashboardTab("docs"));
    document.getElementById("sharedTabBtn")?.addEventListener("click", () => switchDashboardTab("shared"));
    document.getElementById("activityTabBtn")?.addEventListener("click", () => switchDashboardTab("activity"));
    document.getElementById("agentsTabBtn")?.addEventListener("click", () => switchDashboardTab("agents"));
    document.getElementById("billingTabBtn")?.addEventListener("click", () => switchDashboardTab("billing"));
    document.getElementById("docsBackHomeBtn")?.addEventListener("click", () => switchDashboardTab("home"));
    document.getElementById("inboxBackHomeBtn")?.addEventListener("click", () => switchDashboardTab("home"));
    document.getElementById("sharedBackHomeBtn")?.addEventListener("click", () => switchDashboardTab("home"));
    document.getElementById("activityBackHomeBtn")?.addEventListener("click", () => switchDashboardTab("home"));
    document.getElementById("agentsBackHomeBtn")?.addEventListener("click", () => switchDashboardTab("home"));
    document.getElementById("billingBackHomeBtn")?.addEventListener("click", () => switchDashboardTab("home"));
    document.getElementById("registerAgentBtn")?.addEventListener("click", () => registerAgent().catch((err) => alert(err.message)));
    document.getElementById("refreshAgentsBtn")?.addEventListener("click", () => loadAgents().catch((err) => alert(err.message)));
    document.getElementById("agentPolicyDoc")?.addEventListener("change", () => loadAgentPolicy().catch((err) => alert(err.message)));
    document.getElementById("refreshAgentPolicyBtn")?.addEventListener("click", () => loadAgentPolicy().catch((err) => alert(err.message)));
    document.getElementById("saveAgentPolicyBtn")?.addEventListener("click", () => saveAgentPolicy().catch((err) => alert(err.message)));
    document.getElementById("applySwarmTemplateBtn")?.addEventListener("click", applySwarmTemplate);
    document.getElementById("refreshAgentActivityBtn")?.addEventListener("click", () => loadAgentActivity().catch((err) => alert(err.message)));
    document.getElementById("exportAgentActivityBtn")?.addEventListener("click", () => exportAgentActivity().catch((err) => alert(err.message)));
    switchDashboardTab("home");
    document.getElementById("uploadBtn").onclick = uploadDoc;
    document.getElementById("shareBtn").onclick = shareSelectedDocument;
  }

  if (document.getElementById("reviewPreview")) {
    loadSessionInfo();
    loadReviewPage();
    bindPqControls(getReviewPqConfig());
    document.getElementById("signatureMode")?.addEventListener("change", (event) => {
      event.currentTarget.dataset.userSelected = "true";
      toggleSignatureMode();
    });
  }

  if (document.getElementById("detailMeta")) {
    loadSessionInfo();
    loadDocumentDetailsPage().catch((err) => {
      console.error(err);
      setContent(
        document.getElementById("history"),
        createMessageCard("event-card", "Failed to load document.", err?.message || "Unexpected error", "event-meta")
      );
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
    bindPqControls(getPublicPqConfig());
    document
      .getElementById("publicSignatureMode")
      ?.addEventListener("change", (event) => {
        event.currentTarget.dataset.userSelected = "true";
        togglePublicSignatureMode();
      });
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

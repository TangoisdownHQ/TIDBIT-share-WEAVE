// ===================================================
// BOOT CONFIRMATION
// ===================================================
console.log("✅ app.js loaded");

// ===================================================
// CONFIG
// ===================================================
const API = "http://localhost:4100";

// ===================================================
// SESSION MANAGEMENT
// ===================================================
function saveSessionId(sid) {
  localStorage.setItem("tidbit_session_id", sid);
}

function getSessionId() {
  return localStorage.getItem("tidbit_session_id");
}

function clearSession() {
  localStorage.removeItem("tidbit_session_id");
}

// ===================================================
// AUTH: EVM Login (MetaMask)
// ===================================================
async function loginWithMetamask() {
  alert("🦊 MetaMask login clicked");

  const status = document.getElementById("status");

  if (!window.ethereum) {
    alert("MetaMask not found");
    return;
  }

  try {
    status.innerText = "Requesting nonce…";

    // 1️⃣ Get nonce
    const nonceRes = await fetch(`${API}/auth/evm/nonce`, {
      method: "POST",
    });

    if (!nonceRes.ok) {
      throw new Error("Nonce request failed");
    }

    const { session_id, nonce } = await nonceRes.json();

    console.log("Nonce:", nonce);
    console.log("Session ID:", session_id);

    // 2️⃣ Request wallet
    const accounts = await ethereum.request({
      method: "eth_requestAccounts",
    });

    const address = accounts[0];
    console.log("Wallet:", address);

    // 3️⃣ Build EXACT message backend expects
    const message =
`TIDBIT Authentication
Nonce: ${nonce}
Purpose: Login
Version: 1`;

    status.innerText = "Signing message…";

    // 4️⃣ Sign message
    const signature = await ethereum.request({
      method: "personal_sign",
      params: [message, address],
    });

    console.log("Signature:", signature);

    status.innerText = "Verifying…";

    // 5️⃣ Verify
    const verifyRes = await fetch(`${API}/auth/evm/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session_id,
        address,
        signature,
      }),
    });

    if (!verifyRes.ok) {
      const text = await verifyRes.text();
      console.error("Verify failed:", text);
      throw new Error("Verification failed");
    }

    const verifyJson = await verifyRes.json();
    console.log("Verify OK:", verifyJson);

    // 6️⃣ Persist session
    saveSessionId(session_id);

    status.innerText = "Authenticated";

    // 7️⃣ Redirect (FORCED)
    window.location.replace("/dashboard.html");

  } catch (err) {
    console.error(err);
    if (status) status.innerText = "Login failed";
  }
}

// ===================================================
// LOGOUT
// ===================================================
async function logout() {
  const sid = getSessionId();
  if (!sid) return;

  await fetch(`${API}/auth/logout`, {
    method: "POST",
    headers: { "x-session-id": sid },
  });

  clearSession();
  window.location.replace("/index.html");
}

// ===================================================
// AUTH-GATED API
// ===================================================
async function apiGet(path) {
  const sid = getSessionId();
  if (!sid) {
    window.location.replace("/index.html");
    return;
  }

  const resp = await fetch(`${API}${path}`, {
    headers: { "x-session-id": sid },
  });

  if (resp.status === 401) {
    clearSession();
    window.location.replace("/index.html");
    return;
  }

  return resp.json();
}

// ===================================================
// DASHBOARD LOADERS
// ===================================================
async function loadSessionInfo() {
  const sid = getSessionId();
  if (!sid) {
    window.location.replace("/index.html");
    return;
  }

  const resp = await fetch(`${API}/auth/session`, {
    headers: { "x-session-id": sid },
  });

  if (!resp.ok) {
    clearSession();
    window.location.replace("/index.html");
    return;
  }

  const data = await resp.json();
  document.getElementById("sessionInfo").innerText =
    JSON.stringify(data, null, 2);
}

async function loadDocuments() {
  const docs = await apiGet("/api/doc/list");
  if (!docs) return;

  const list = document.getElementById("docList");
  list.innerHTML = "";

  docs.forEach(doc => {
    const div = document.createElement("div");
    div.className = "doc-item";
    div.innerHTML = `
      <strong>${doc.label || "(no label)"}</strong><br>
      Hash: ${doc.hash_hex}<br>
      Doc ID: ${doc.logical_id}<br>
      Owner: ${doc.owner_wallet || "N/A"}<br>
      <hr>
    `;
    list.appendChild(div);
  });
}

// ===================================================
// DOM BOOTSTRAP (CRITICAL FIX)
// ===================================================
document.addEventListener("DOMContentLoaded", () => {
  console.log("📄 DOM loaded");

  const loginBtn = document.getElementById("login-metamask");
  console.log("Login button:", loginBtn);

  if (loginBtn) {
    loginBtn.addEventListener("click", loginWithMetamask);
  }

  // Dashboard auto-load
  if (document.getElementById("docList")) {
    loadSessionInfo();
    loadDocuments();
  }
});


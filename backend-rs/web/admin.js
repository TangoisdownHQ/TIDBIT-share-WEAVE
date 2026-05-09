const API = window.location.origin.startsWith("http")
  ? window.location.origin
  : "http://127.0.0.1:4100";

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

async function apiGet(path) {
  const resp = await fetch(`${API}${path}`, { headers: authHeaders() });
  if (!resp.ok) {
    const err = new Error(await resp.text());
    err.status = resp.status;
    throw err;
  }
  return resp.json();
}

async function logout() {
  try {
    await fetch(`${API}/auth/logout`, {
      method: "POST",
      headers: authHeaders(),
    });
  } catch (_) {
    // Ignore logout transport errors and still clear the local session.
  }
  clearSession();
  window.location.replace("/index.html");
}

function createElement(tag, options = {}) {
  const el = document.createElement(tag);
  if (options.className) el.className = options.className;
  if (options.text !== undefined) el.textContent = String(options.text);
  if (options.href) el.href = options.href;
  return el;
}

function setContent(root, ...children) {
  root.replaceChildren(...children.filter(Boolean));
  return root;
}

function createMetaLine(label, value) {
  const row = createElement("div", { className: "doc-meta" });
  row.appendChild(createElement("strong", { text: `${label}: ` }));
  row.appendChild(document.createTextNode(String(value ?? "n/a")));
  return row;
}

function createStatCard(value, label, note) {
  const card = createElement("div", { className: "stat-card compact-card" });
  card.appendChild(createElement("strong", { text: value }));
  card.appendChild(createElement("span", { className: "muted", text: label }));
  if (note) {
    card.appendChild(createElement("div", { className: "event-meta", text: note }));
  }
  return card;
}

function createMessageCard(title, message) {
  const card = createElement("div", { className: "event-card neutral-event" });
  card.appendChild(createElement("strong", { text: title }));
  card.appendChild(createElement("div", { className: "event-meta", text: message }));
  return card;
}

function formatDateTime(value) {
  if (!value) return "n/a";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
}

function maskWallet(wallet) {
  const value = String(wallet || "").trim();
  if (!value) return "unknown";
  if (value.length <= 14) return value;
  return `${value.slice(0, 8)}...${value.slice(-6)}`;
}

function formatPercent(part, total) {
  if (!total) return "0%";
  return `${Math.round((part / total) * 100)}%`;
}

function setStatus(message, isError = false) {
  const root = document.getElementById("adminStatus");
  if (!root) return;
  root.className = isError ? "session-card admin-error" : "session-card";
  root.textContent = message;
}

function renderSessionInfo(session, overview) {
  const root = document.getElementById("adminSessionInfo");
  if (!root) return;
  setContent(
    root,
    createMetaLine("Wallet", session.wallet),
    createMetaLine("Chain", session.chain),
    createMetaLine("Session", session.session_id),
    createMetaLine("Created", formatDateTime(new Date(session.created_at * 1000))),
    createMetaLine("Expires", formatDateTime(new Date(session.expires_at * 1000))),
    createMetaLine("Console Path", overview.console_path)
  );
}

function renderTrackingInfo(tracking) {
  const root = document.getElementById("trackingInfo");
  if (!root) return;

  if (!tracking?.total_events) {
    setContent(
      root,
      createMetaLine("Status", "Tracking is active, but the recent event stream is still empty."),
      createMetaLine("Note", "The overview counts still come from source tables right now.")
    );
    return;
  }

  setContent(
    root,
    createMetaLine("Started", formatDateTime(tracking.started_at)),
    createMetaLine("Tracked Events", tracking.total_events),
    createMetaLine("Feed Scope", "Recent activity below comes from the growth event stream.")
  );
}

function renderKpis(overview) {
  const kpis = overview.kpis || {};
  const root = document.getElementById("adminKpis");
  if (!root) return;
  setContent(
    root,
    createStatCard(kpis.total_wallets || 0, "Total wallets"),
    createStatCard(kpis.active_wallets_1d || 0, "DAU"),
    createStatCard(kpis.active_wallets_7d || 0, "WAU"),
    createStatCard(kpis.active_wallets_30d || 0, "MAU"),
    createStatCard(kpis.new_wallets_7d || 0, "New wallets 7d"),
    createStatCard(kpis.new_wallets_30d || 0, "New wallets 30d"),
    createStatCard(kpis.active_sessions_now || 0, "Active sessions now"),
    createStatCard(kpis.active_devices_30d || 0, "Active devices 30d"),
    createStatCard(kpis.total_docs || 0, "Active docs"),
    createStatCard(kpis.total_versions || 0, "Document versions"),
    createStatCard(kpis.total_shares || 0, "All shares"),
    createStatCard(kpis.total_share_anchors || 0, "Arweave share anchors"),
    createStatCard(kpis.total_sign_events || 0, "All sign events")
  );
}

function renderUsage(overview) {
  const usage = overview.usage_window || {};
  const label = `Last ${overview.window_days}d`;
  const root = document.getElementById("adminUsage");
  if (!root) return;
  setContent(
    root,
    createStatCard(usage.uploads || 0, "Uploads", label),
    createStatCard(usage.versions || 0, "Versions", label),
    createStatCard(usage.shares || 0, "Shares", label),
    createStatCard(usage.signs || 0, "Signs", label),
    createStatCard(usage.views || 0, "Views", label),
    createStatCard(usage.downloads || 0, "Downloads", label),
    createStatCard(usage.inbox_actions || 0, "Inbox actions", label),
    createStatCard(usage.public_opens || 0, "Public opens", label),
    createStatCard(usage.public_completions || 0, "Public completions", label),
    createStatCard(usage.share_anchors || 0, "Share anchors", label),
    createStatCard(usage.agents_registered || 0, "Agents registered", label),
    createStatCard(overview.kpis?.wallet_logins_30d || 0, "Wallet logins 30d"),
    createStatCard(overview.kpis?.total_agents || 0, "Active agents")
  );
}

function renderFunnel(overview) {
  const funnel = overview.funnel || {};
  const connected = funnel.connected_wallets || 0;
  const root = document.getElementById("adminFunnel");
  if (!root) return;
  setContent(
    root,
    createStatCard(connected, "Connected wallets", "Top of funnel"),
    createStatCard(funnel.wallets_uploaded || 0, "Uploaded at least once", formatPercent(funnel.wallets_uploaded || 0, connected)),
    createStatCard(funnel.wallets_shared || 0, "Shared at least once", formatPercent(funnel.wallets_shared || 0, connected)),
    createStatCard(funnel.wallets_signed || 0, "Signed at least once", formatPercent(funnel.wallets_signed || 0, connected)),
    createStatCard(funnel.wallets_received || 0, "Received a wallet share", formatPercent(funnel.wallets_received || 0, connected)),
    createStatCard(funnel.wallets_with_agents || 0, "Created agents", formatPercent(funnel.wallets_with_agents || 0, connected))
  );
}

function renderAnonymousAcquisition(overview) {
  const acquisition = overview.anonymous_acquisition || {};
  const summaryRoot = document.getElementById("acquisitionSummary");
  const sourceRoot = document.getElementById("acquisitionSources");
  const referrerRoot = document.getElementById("acquisitionReferrers");
  const uniqueVisitors = acquisition.unique_visitors || 0;
  const convertedVisitors = acquisition.converted_visitors || 0;

  if (summaryRoot) {
    setContent(
      summaryRoot,
      createStatCard(acquisition.page_views || 0, "Anonymous page views", `Last ${overview.window_days}d`),
      createStatCard(uniqueVisitors, "Unique visitors", `Last ${overview.window_days}d`),
      createStatCard(convertedVisitors, "Visitor -> wallet connects", formatPercent(convertedVisitors, uniqueVisitors)),
      createStatCard(acquisition.anonymous_visitors || 0, "Still anonymous", formatPercent(acquisition.anonymous_visitors || 0, uniqueVisitors))
    );
  }

  if (sourceRoot) {
    const items = Array.isArray(acquisition.sources) ? acquisition.sources : [];
    if (!items.length) {
      setContent(sourceRoot, createMessageCard("No acquisition sources yet.", "UTM-tagged traffic will appear here after anonymous visits are tracked."));
    } else {
      setContent(
        sourceRoot,
        ...items.map((item) => {
          const card = createElement("div", { className: "doc-card" });
          card.appendChild(createElement("strong", { text: `${item.source || "direct"} / ${item.medium || "none"}` }));
          card.appendChild(createMetaLine("Campaign", item.campaign || "none"));
          card.appendChild(createMetaLine("Visitors", item.visitors || 0));
          card.appendChild(createMetaLine("Converted", `${item.converted || 0} (${formatPercent(item.converted || 0, item.visitors || 0)})`));
          return card;
        })
      );
    }
  }

  if (referrerRoot) {
    const items = Array.isArray(acquisition.referrers) ? acquisition.referrers : [];
    if (!items.length) {
      setContent(referrerRoot, createMessageCard("No referrer data yet.", "Direct, social, and partner traffic sources will populate here."));
    } else {
      setContent(
        referrerRoot,
        ...items.map((item) => {
          const card = createElement("div", { className: "doc-card" });
          card.appendChild(createElement("strong", { text: item.referrer_host || "direct" }));
          card.appendChild(createMetaLine("Visitors", item.visitors || 0));
          card.appendChild(createMetaLine("Converted", `${item.converted || 0} (${formatPercent(item.converted || 0, item.visitors || 0)})`));
          return card;
        })
      );
    }
  }
}

function renderRetention(overview) {
  const retention = overview.retention || {};
  const summary = retention.summary || {};
  const summaryRoot = document.getElementById("retentionSummary");
  const cohortRoot = document.getElementById("retentionCohorts");

  if (summaryRoot) {
    setContent(
      summaryRoot,
      createStatCard(summary.retained_1d || 0, "D1 retained wallets", `${summary.eligible_1d || 0} eligible · ${formatPercent(summary.retained_1d || 0, summary.eligible_1d || 0)}`),
      createStatCard(summary.retained_7d || 0, "D7 retained wallets", `${summary.eligible_7d || 0} eligible · ${formatPercent(summary.retained_7d || 0, summary.eligible_7d || 0)}`),
      createStatCard(summary.retained_30d || 0, "D30 retained wallets", `${summary.eligible_30d || 0} eligible · ${formatPercent(summary.retained_30d || 0, summary.eligible_30d || 0)}`)
    );
  }

  if (cohortRoot) {
    const items = Array.isArray(retention.cohorts) ? retention.cohorts : [];
    if (!items.length) {
      setContent(cohortRoot, createMessageCard("No wallet cohorts yet.", "Retention cohorts appear after wallets start signing in."));
    } else {
      setContent(
        cohortRoot,
        ...items.map((item) => {
          const row = createElement("div", { className: "event-card neutral-event" });
          const top = createElement("div", { className: "section-head" });
          top.appendChild(createElement("strong", { text: item.cohort_day || "unknown" }));
          top.appendChild(createElement("span", { className: "muted", text: `Cohort size ${item.cohort_size || 0}` }));
          row.appendChild(top);
          row.appendChild(createMetaLine("D1", `${item.retained_1d || 0} / ${item.eligible_1d || 0} (${formatPercent(item.retained_1d || 0, item.eligible_1d || 0)})`));
          row.appendChild(createMetaLine("D7", `${item.retained_7d || 0} / ${item.eligible_7d || 0} (${formatPercent(item.retained_7d || 0, item.eligible_7d || 0)})`));
          row.appendChild(createMetaLine("D30", `${item.retained_30d || 0} / ${item.eligible_30d || 0} (${formatPercent(item.retained_30d || 0, item.eligible_30d || 0)})`));
          return row;
        })
      );
    }
  }
}

function renderShareConversion(overview) {
  const conversion = overview.share_conversion || {};
  const sent = conversion.shares_sent || 0;
  const root = document.getElementById("shareConversion");
  if (!root) return;
  setContent(
    root,
    createStatCard(sent, "Shares sent", `Last ${overview.window_days}d`),
    createStatCard(conversion.shares_opened || 0, "Opened", formatPercent(conversion.shares_opened || 0, sent)),
    createStatCard(conversion.shares_downloaded || 0, "Downloaded", formatPercent(conversion.shares_downloaded || 0, sent)),
    createStatCard(conversion.shares_completed || 0, "Signed / completed", formatPercent(conversion.shares_completed || 0, sent))
  );
}

function renderShareChannels(items) {
  const root = document.getElementById("shareChannels");
  if (!root) return;
  if (!Array.isArray(items) || !items.length) {
    setContent(root, createMessageCard("No share channel data yet.", "Wallet, email, and phone channel performance will appear here."));
    return;
  }

  setContent(
    root,
    ...items.map((item) => {
      const touches = item.share_touches || 0;
      const card = createElement("div", { className: "doc-card" });
      card.appendChild(createElement("strong", { text: String(item.channel || "unknown").toUpperCase() }));
      card.appendChild(createMetaLine("Touches", touches));
      card.appendChild(createMetaLine("Opened", `${item.opened || 0} (${formatPercent(item.opened || 0, touches)})`));
      card.appendChild(createMetaLine("Downloaded", `${item.downloaded || 0} (${formatPercent(item.downloaded || 0, touches)})`));
      card.appendChild(createMetaLine("Completed", `${item.completed || 0} (${formatPercent(item.completed || 0, touches)})`));
      card.appendChild(createMetaLine("Delivered", item.delivered || 0));
      card.appendChild(createMetaLine("Inbox ready", item.inbox_available || 0));
      card.appendChild(createMetaLine("Delivery issues", item.delivery_issues || 0));
      return card;
    })
  );
}

function renderBilling(overview) {
  const billing = overview.billing_conversion || {};
  const summaryRoot = document.getElementById("billingSummary");
  const statusesRoot = document.getElementById("billingStatuses");
  const connectedWallets = billing.connected_wallets || 0;
  const subscriptionRows = billing.subscription_rows || 0;
  const missingRows = Math.max(0, connectedWallets - subscriptionRows);
  const trialBase = (billing.paid_accounts || 0) + (billing.expired_trials || 0);
  const checkoutLive = (billing.stripe_customers || 0) > 0 || (billing.stripe_subscriptions || 0) > 0;

  if (summaryRoot) {
    setContent(
      summaryRoot,
      createStatCard(connectedWallets, "Connected wallets", "Potential billing base"),
      createStatCard(subscriptionRows, "Billing rows", missingRows ? `${missingRows} wallets still need a billing row` : "Coverage looks complete"),
      createStatCard(billing.trialing_accounts || 0, "Trialing", formatPercent(billing.trialing_accounts || 0, subscriptionRows)),
      createStatCard(billing.paid_accounts || 0, "Paid / active", trialBase ? `${formatPercent(billing.paid_accounts || 0, trialBase)} of paid-vs-expired base` : "Waiting on checkout"),
      createStatCard(billing.stripe_customers || 0, "Stripe customers", checkoutLive ? "Checkout linkage detected" : "No Stripe linkage yet"),
      createStatCard(billing.stripe_subscriptions || 0, "Stripe subscriptions", checkoutLive ? "Subscription rows detected" : "Checkout not live yet")
    );
  }

  if (statusesRoot) {
    const items = Array.isArray(billing.statuses) ? billing.statuses : [];
    if (!items.length) {
      setContent(statusesRoot, createMessageCard("No billing rows yet.", "As wallets log in, trial and paid status rows will appear here."));
    } else {
      setContent(
        statusesRoot,
        ...items.map((item) => {
          const card = createElement("div", { className: "doc-card" });
          card.appendChild(createElement("strong", { text: item.status || "unknown" }));
          card.appendChild(createMetaLine("Accounts", item.total || 0));
          card.appendChild(createMetaLine("Share", formatPercent(item.total || 0, subscriptionRows)));
          return card;
        })
      );
    }
  }
}

function renderChainBreakdown(items) {
  const root = document.getElementById("chainBreakdown");
  if (!root) return;
  if (!Array.isArray(items) || !items.length) {
    setContent(root, createMessageCard("No chain data yet.", "Wallet activity will appear here as people use the app."));
    return;
  }

  setContent(
    root,
    ...items.map((item) => {
      const card = createElement("div", { className: "doc-card" });
      card.appendChild(createElement("strong", { text: String(item.chain || "unknown").toUpperCase() }));
      card.appendChild(createMetaLine("Wallets", item.total_wallets || 0));
      card.appendChild(createMetaLine("New 30d", item.new_wallets_30d || 0));
      card.appendChild(createMetaLine("Active 30d", item.active_wallets_30d || 0));
      card.appendChild(createMetaLine("Docs owned", item.docs_owned || 0));
      card.appendChild(createMetaLine("Shares sent", item.shares_sent || 0));
      return card;
    })
  );
}

function renderWalletActivity(items) {
  const root = document.getElementById("walletActivity");
  if (!root) return;
  if (!Array.isArray(items) || !items.length) {
    setContent(root, createMessageCard("No wallet activity yet.", "Wallet-level activity will populate after people sign in."));
    return;
  }

  setContent(
    root,
    ...items.map((item) => {
      const card = createElement("div", { className: "doc-card" });
      const title = createElement("div", { className: "section-head" });
      title.appendChild(createElement("strong", { text: maskWallet(item.wallet) }));
      title.appendChild(createElement("span", { className: "role-badge neutral-role", text: String(item.chain || "unknown").toUpperCase() }));
      card.appendChild(title);
      card.appendChild(createMetaLine("Score", item.score || 0));
      card.appendChild(createMetaLine("Last seen", formatDateTime(item.last_seen_at)));
      card.appendChild(createMetaLine("Logins", item.login_count || 0));
      card.appendChild(createMetaLine("Docs", item.docs_owned || 0));
      card.appendChild(createMetaLine("Shares", item.shares_sent || 0));
      card.appendChild(createMetaLine("Signs", item.sign_count || 0));
      card.appendChild(createMetaLine("Agents", item.agent_count || 0));
      return card;
    })
  );
}

function renderDailySeries(items) {
  const root = document.getElementById("dailySeries");
  if (!root) return;
  if (!Array.isArray(items) || !items.length) {
    setContent(root, createMessageCard("No daily data yet.", "Daily growth rows will appear here."));
    return;
  }

  const maxTotal = Math.max(
    1,
    ...items.map((item) => (item.new_wallets || 0) + (item.uploads || 0) + (item.shares || 0) + (item.signs || 0))
  );

  setContent(
    root,
    ...items.map((item) => {
      const total = (item.new_wallets || 0) + (item.uploads || 0) + (item.shares || 0) + (item.signs || 0);
      const row = createElement("div", { className: "event-card neutral-event" });
      const top = createElement("div", { className: "section-head" });
      top.appendChild(createElement("strong", { text: item.day }));
      top.appendChild(createElement("span", { className: "muted", text: `Tracked total ${total}` }));
      row.appendChild(top);
      row.appendChild(createMetaLine("New wallets", item.new_wallets || 0));
      row.appendChild(createMetaLine("Tracked active wallets", item.active_wallets || 0));
      row.appendChild(createMetaLine("Uploads / versions", `${item.uploads || 0} / ${item.versions || 0}`));
      row.appendChild(createMetaLine("Shares / signs", `${item.shares || 0} / ${item.signs || 0}`));
      row.appendChild(createMetaLine("Agents", item.agents || 0));

      const bar = createElement("div", { className: "admin-bar" });
      const fill = createElement("div", { className: "admin-bar-fill" });
      fill.style.width = `${Math.max(4, Math.round((total / maxTotal) * 100))}%`;
      bar.appendChild(fill);
      row.appendChild(bar);
      return row;
    })
  );
}

function renderRecentEvents(items) {
  const root = document.getElementById("recentEvents");
  if (!root) return;
  if (!Array.isArray(items) || !items.length) {
    setContent(root, createMessageCard("No tracked events yet.", "The feed starts filling as new usage events are recorded."));
    return;
  }

  setContent(
    root,
    ...items.map((item) => {
      const card = createElement("div", { className: "event-card neutral-event" });
      const top = createElement("div", { className: "event-top" });
      top.appendChild(createElement("strong", { text: item.event_type || "UNKNOWN_EVENT" }));
      top.appendChild(createElement("span", { className: "muted", text: formatDateTime(item.occurred_at) }));
      card.appendChild(top);
      card.appendChild(createMetaLine("Actor", item.wallet ? `${maskWallet(item.wallet)} (${item.chain || "unknown"})` : item.actor_kind || "unknown"));
      if (item.doc_id) card.appendChild(createMetaLine("Doc", item.doc_id));
      if (item.envelope_id) card.appendChild(createMetaLine("Envelope", item.envelope_id));
      if (item.agent_id) card.appendChild(createMetaLine("Agent", item.agent_id));
      if (item.properties && Object.keys(item.properties).length) {
        card.appendChild(createElement("pre", { text: JSON.stringify(item.properties, null, 2) }));
      }
      return card;
    })
  );
}

async function loadAdminConsole() {
  const sessionId = getSessionId();
  if (!sessionId) {
    setStatus("Wallet login required. Sign in through /app first, then reopen this console path.", true);
    return;
  }

  try {
    const session = await apiGet("/auth/session");
    const params = new URLSearchParams(window.location.search);
    const days = Number(params.get("days") || "30");
    const overview = await apiGet(`/api/admin/growth/overview?days=${Number.isFinite(days) ? days : 30}`);

    document.getElementById("adminWindowBadge").textContent = `${overview.window_days}d`;
    document.getElementById("adminContent")?.classList.remove("hidden");
    setStatus(`Admin access confirmed for ${maskWallet(session.wallet)} on ${String(session.chain || "").toUpperCase()}.`);
    renderSessionInfo(session, overview);
    renderTrackingInfo(overview.tracking);
    renderKpis(overview);
    renderUsage(overview);
    renderFunnel(overview);
    renderAnonymousAcquisition(overview);
    renderRetention(overview);
    renderShareConversion(overview);
    renderShareChannels(overview.share_channels);
    renderBilling(overview);
    renderChainBreakdown(overview.chain_breakdown);
    renderWalletActivity(overview.wallet_activity);
    renderDailySeries(overview.daily);
    renderRecentEvents(overview.recent_events);
  } catch (error) {
    document.getElementById("adminContent")?.classList.add("hidden");
    if (error.status === 401) {
      clearSession();
      setStatus("This browser session is no longer active. Sign in again through /app, then reopen this console path.", true);
      return;
    }
    if (error.status === 403) {
      setStatus("This wallet is not on the admin allowlist. Set ADMIN_WALLETS for your wallet and redeploy.", true);
      return;
    }
    setStatus(error.message || "Admin console failed to load.", true);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("refreshAdminBtn")?.addEventListener("click", () => loadAdminConsole());
  document.getElementById("logoutAdminBtn")?.addEventListener("click", () => logout());
  loadAdminConsole();
});

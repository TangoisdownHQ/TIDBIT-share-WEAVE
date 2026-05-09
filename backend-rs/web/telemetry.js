const TIDBIT_VISITOR_ID_KEY = "TIDBIT_VISITOR_ID_V1";
const TIDBIT_ATTRIBUTION_FIRST_KEY = "TIDBIT_ATTRIBUTION_FIRST_V1";
const TIDBIT_ATTRIBUTION_LAST_KEY = "TIDBIT_ATTRIBUTION_LAST_V1";

function tidbitApiBase() {
  return window.location.origin.startsWith("http")
    ? window.location.origin
    : "http://127.0.0.1:4100";
}

function readTrackingJson(key) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : null;
  } catch (_) {
    return null;
  }
}

function writeTrackingJson(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch (_) {
    // Ignore storage failures and continue without persistence.
  }
}

function getVisitorId() {
  let visitorId = localStorage.getItem(TIDBIT_VISITOR_ID_KEY);
  if (!visitorId) {
    visitorId =
      typeof crypto?.randomUUID === "function"
        ? crypto.randomUUID()
        : `tidbit-visitor-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    localStorage.setItem(TIDBIT_VISITOR_ID_KEY, visitorId);
  }
  return visitorId;
}

function normalizeText(value) {
  const trimmed = String(value || "").trim();
  return trimmed ? trimmed : null;
}

function currentTrackingSnapshot() {
  const params = new URLSearchParams(window.location.search);
  const referrer = normalizeText(document.referrer);
  let referrerHost = null;
  if (referrer) {
    try {
      referrerHost = normalizeText(new URL(referrer).hostname);
    } catch (_) {
      referrerHost = null;
    }
  }

  return {
    visitor_id: getVisitorId(),
    page_path: normalizeText(window.location.pathname),
    page_title: normalizeText(document.title),
    referrer,
    referrer_host: referrerHost,
    landing_path: normalizeText(window.location.pathname),
    utm_source: normalizeText(params.get("utm_source")),
    utm_medium: normalizeText(params.get("utm_medium")),
    utm_campaign: normalizeText(params.get("utm_campaign")),
    utm_term: normalizeText(params.get("utm_term")),
    utm_content: normalizeText(params.get("utm_content")),
  };
}

function getAttributionSnapshot() {
  const current = currentTrackingSnapshot();
  const first = readTrackingJson(TIDBIT_ATTRIBUTION_FIRST_KEY);
  const initial = first || {
    page_path: current.page_path,
    referrer: current.referrer,
    referrer_host: current.referrer_host,
    utm_source: current.utm_source,
    utm_medium: current.utm_medium,
    utm_campaign: current.utm_campaign,
    utm_term: current.utm_term,
    utm_content: current.utm_content,
    captured_at: new Date().toISOString(),
  };

  writeTrackingJson(TIDBIT_ATTRIBUTION_FIRST_KEY, initial);
  writeTrackingJson(TIDBIT_ATTRIBUTION_LAST_KEY, {
    ...current,
    captured_at: new Date().toISOString(),
  });

  return {
    ...current,
    first_landing_path: initial.page_path || null,
    first_referrer: initial.referrer || null,
    first_referrer_host: initial.referrer_host || null,
    first_utm_source: initial.utm_source || null,
    first_utm_medium: initial.utm_medium || null,
    first_utm_campaign: initial.utm_campaign || null,
    first_utm_term: initial.utm_term || null,
    first_utm_content: initial.utm_content || null,
  };
}

async function trackPageView() {
  const snapshot = getAttributionSnapshot();
  try {
    await fetch(`${tidbitApiBase()}/api/analytics/track`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-visitor-id": snapshot.visitor_id,
      },
      body: JSON.stringify({
        event_type: "PAGE_VIEW",
        visitor_id: snapshot.visitor_id,
        page_path: snapshot.page_path,
        page_title: snapshot.page_title,
        referrer: snapshot.referrer,
        referrer_host: snapshot.referrer_host,
        attribution: snapshot,
      }),
    });
  } catch (_) {
    // Ignore telemetry transport failures.
  }
}

window.TidbitTelemetry = {
  getVisitorId,
  getAttributionSnapshot,
  trackPageView,
};

document.addEventListener("DOMContentLoaded", () => {
  trackPageView();
});

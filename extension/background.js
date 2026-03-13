const BACKEND_CANDIDATES = [
  "https://hack-nocturne-2026-production.up.railway.app",
  "https://hack-nocturne-2026.onrender.com",
];
let activeBackend = BACKEND_CANDIDATES[0];

// Store scam URLs in memory
let scamList = [];

// Fetch all reports on startup
async function loadReports() {
  try {
    let data = null;
    let lastError = null;

    for (const base of [activeBackend, ...BACKEND_CANDIDATES]) {
      const normalizedBase = base.replace(/\/+$/, "");
      const endpoints = [
        `${normalizedBase}/api/reports`,
        `${normalizedBase}/reports`,
      ];

      for (const endpoint of endpoints) {
        try {
          const res = await fetch(endpoint);
          const payload = await res.json();

          if (!res.ok) {
            const message =
              typeof payload?.detail === "string"
                ? payload.detail
                : `HTTP ${res.status} while fetching reports`;
            throw new Error(message);
          }

          data = payload;
          activeBackend = normalizedBase;
          break;
        } catch (err) {
          lastError = err;
        }
      }

      if (data) break;
    }

    if (!data) {
      throw lastError || new Error("Unable to load reports from all endpoints");
    }

    const reportRows = Array.isArray(data)
      ? data
      : Array.isArray(data?.reports)
        ? data.reports
        : [];

    if (!Array.isArray(reportRows)) {
      throw new Error("Invalid reports payload: expected array");
    }

    scamList = reportRows
      .filter((r) => r.url)
      .map((r) => ({
        url: r.url.trim().toLowerCase(),
        txHash: r.txHash || "",
        category: r.category || "Unknown",
        riskScore: r.riskScore || 0,
        reporter: r.reporter || "",
      }));
    console.log(`ScamShield: loaded ${scamList.length} reports`);
  } catch (err) {
    scamList = [];
    console.error("ScamShield: failed to load reports", err);
  }
}

// Refresh every 5 minutes so new reports are picked up
loadReports();
setInterval(loadReports, 5 * 60 * 1000);

// Check URL against scam list
function checkUrl(url) {
  const clean = url.trim().toLowerCase();
  return (
    scamList.find((r) => clean.includes(r.url) || r.url.includes(clean)) || null
  );
}

// Intercept top-level navigations and reroute suspicious pages.
// MV3 no longer allows general-purpose blocking webRequest for normal installs.
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;

  const url = details.url;

  // Skip browser pages, extension pages, and the app's own domain.
  if (
    url.startsWith("chrome") ||
    url.startsWith("moz-extension") ||
    url.startsWith("chrome-extension") ||
    url.includes("hack-nocturne-2026.onrender.com")
  ) {
    return;
  }

  const match = checkUrl(url);
  if (!match) return;

  const params = new URLSearchParams({
    url: url,
    txHash: match.txHash,
    category: match.category,
    riskScore: String(match.riskScore),
    reporter: match.reporter,
  });

  chrome.tabs.update(details.tabId, {
    url: chrome.runtime.getURL(`blocked.html?${params.toString()}`),
  });
});

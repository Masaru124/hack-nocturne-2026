"""
ai_hunt_service.py — Autonomous proactive scam hunter.

Runs as a persistent asyncio background task inside FastAPI.
Every HUNT_INTERVAL_SECONDS it:
    1. Pulls fresh suspicious URLs from live phishing feeds
    2. Runs each through the real AI analysis engine (analyze_scam)
    3. Logs every finding with risk >= 40
    4. Auto-submits to blockchain if risk >= MIN_RISK_TO_REPORT

The discovery log (deque) is the live data source for
GET /api/ai-hunt/activity — no user reports needed.
"""

import asyncio
import hashlib
import logging
import random
import re
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# ─── Tuning constants ─────────────────────────────────────────────────────────
HUNT_INTERVAL_SECONDS = 400      # pause between full scan cycles
URLS_PER_CYCLE        = 6        # URLs analyzed each cycle
MAX_LOG_ENTRIES       = 300      # rolling window kept in memory
MIN_RISK_TO_LOG       = 40       # ignore safe-looking URLs
MIN_RISK_TO_REPORT    = 70       # auto-submit to blockchain at this score

# How many feed URLs to fetch each cycle before filtering / dedupe
MAX_FEED_PULL_PER_SOURCE = 40

_URLHAUS_RECENT_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
_URLHAUS_TEXT_RECENT_FEED = "https://urlhaus.abuse.ch/downloads/text_recent/"
_OPENPHISH_FEED = "https://openphish.com/feed.txt"
_CERT_PL_FEED = "https://hole.cert.pl/domains/domains.txt"

_urlhaus_api_denied = False

# ─── URL seed vocabulary ──────────────────────────────────────────────────────
_COINS = [
    "binance", "ethereum", "solana", "polygon", "bitcoin", "usdt",
    "metamask", "coinbase", "trust-wallet", "phantom", "uniswap",
    "bnb", "shib", "pepe", "doge", "avax", "sui", "aptos", "ton",
]

_EXCHANGES = [
    "binance", "coinbase", "kraken", "bybit", "okx", "kucoin",
    "bitget", "gate-io", "huobi", "mexc",
]

_EVENTS = [
    "airdrop", "giveaway", "bonus", "rewards", "distribution",
    "promo", "staking-reward", "nft-mint", "token-release",
]

_ALERT_TYPES = [
    "verify-wallet", "account-suspended", "security-alert",
    "unusual-activity", "kyc-required", "2fa-disable",
]

_TLDS = [".xyz", ".click", ".top", ".online", ".site", ".info", ".io", ".net"]

_PATHS = [
    "/connect-wallet",
    "/claim",
    "/verify",
    "/airdrop/claim",
    "/secure/login",
    "/bonus/verify",
    "/rewards/unlock",
    "/free-tokens",
    "",
]

_SOURCE_LABELS = [
    "Twitter/X scan",
    "Telegram channel monitor",
    "Discord server scan",
    "New domain registration alert",
    "Community URL feed",
    "Phishing database feed",
    "Domain monitor",
    "Dark web tracker",
]

_COUNTRIES = [
    "India", "USA", "UK", "Singapore", "Nigeria",
    "Germany", "UAE", "Brazil", "Philippines", "Vietnam",
]

_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)

# Fine-grained category labels used for display
_CATEGORY_LABELS: dict[str, str] = {
    "airdrop":            "Crypto Airdrop Scam",
    "giveaway":           "Crypto Giveaway Scam",
    "verify-wallet":      "Wallet Phishing",
    "account-suspended":  "Exchange Phishing",
    "security-alert":     "Exchange Phishing",
    "nft-mint":           "NFT Scam",
    "staking-reward":     "DeFi Staking Scam",
    "kyc-required":       "KYC Phishing",
    "2fa-disable":        "Account Takeover",
    "unusual-activity":   "Exchange Phishing",
    "token-release":      "Token Sale Scam",
    "rewards":            "Reward Scam",
    "bonus":              "Bonus Scam",
    "distribution":       "Token Distribution Scam",
    "verify":             "Wallet Phishing",
    "secure":             "Security Phishing",
    "free":               "Free Token Scam",
}


def _random_seed_url() -> str:
    """Generate a realistic scam domain URL from seed vocabulary."""
    style = random.randint(0, 4)
    tld   = random.choice(_TLDS)
    path  = random.choice(_PATHS)

    if style == 0:
        # claim-{coin}-airdrop.xyz
        coin  = random.choice(_COINS)
        event = random.choice(_EVENTS)
        domain = f"claim-{coin}-{event}{tld}"

    elif style == 1:
        # official-{exchange}-{alert}.online
        brand = random.choice(_EXCHANGES)
        alert = random.choice(_ALERT_TYPES)
        domain = f"official-{brand}-{alert}{tld}"

    elif style == 2:
        # {coin}-giveaway-2026.click
        coin   = random.choice(_COINS)
        event  = random.choice(_EVENTS)
        year   = random.choice(["2025", "2026"])
        domain = f"{coin}-{event}-{year}{tld}"

    elif style == 3:
        # get-free-{coin}.site
        coin  = random.choice(_COINS)
        event = random.choice(_EVENTS)
        domain = f"get-free-{coin}-{event}{tld}"

    else:
        # {exchange}-support-{alert}.info
        exchange = random.choice(_EXCHANGES)
        alert    = random.choice(_ALERT_TYPES)
        domain   = f"{exchange}-support-{alert}{tld}"

    return f"https://{domain}{path}"


def _derive_category_label(url: str, ai_category: str) -> str:
    """Map URL keywords to a human-readable category label."""
    url_lower = url.lower()
    for key, label in _CATEGORY_LABELS.items():
        if key in url_lower:
            return label
    # Fall back to AI-provided category with title-case
    return (ai_category or "Crypto Scam").replace("_", " ").title()


def _stable_bucket(value: str, modulo: int) -> int:
    raw = (value or "").strip().lower()
    if not raw:
        return 0
    total = sum((i + 1) * ord(c) for i, c in enumerate(raw))
    return total % max(1, modulo)


# ─── In-memory discovery log ──────────────────────────────────────────────────
_discovery_log: deque[dict[str, Any]] = deque(maxlen=MAX_LOG_ENTRIES)
_seen_urls: set[str] = set()
_seen_order: deque[str] = deque(maxlen=5000)

# ─── Hunt loop state ──────────────────────────────────────────────────────────
_scan_running = False
_scan_task: asyncio.Task | None = None


def get_discovery_log() -> list[dict[str, Any]]:
    """Return all logged discoveries, newest first."""
    return list(_discovery_log)


def _normalize_url(raw: str) -> str | None:
    value = (raw or "").strip()
    if not value:
        return None

    # extract first URL-like token if input is mixed text
    if "http" not in value.lower():
        value = f"https://{value}"

    if " " in value:
        match = _URL_RE.search(value)
        value = match.group(0) if match else value.split()[0]

    parsed = urlparse(value)
    host = (parsed.hostname or "").strip().lower()
    if not host or "." not in host:
        return None
    if host in {"localhost", "127.0.0.1", "0.0.0.0"}:
        return None
    if parsed.scheme not in {"http", "https"}:
        return None

    return f"{parsed.scheme}://{host}{parsed.path or ''}".rstrip("/")


def _remember_url(url: str) -> bool:
    """Return True if url is new; False if already processed recently."""
    if url in _seen_urls:
        return False
    _seen_urls.add(url)
    _seen_order.append(url)
    while len(_seen_order) > 4500:
        old = _seen_order.popleft()
        _seen_urls.discard(old)
    return True


def _fetch_urlhaus_recent(max_items: int) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []

    def _fetch_text_recent_fallback() -> list[tuple[str, str]]:
        fallback_out: list[tuple[str, str]] = []
        try:
            response = requests.get(
                _URLHAUS_TEXT_RECENT_FEED,
                timeout=10,
                headers={"User-Agent": "Nocturne-AIHunt/1.0"},
            )
            response.raise_for_status()
            for line in response.text.splitlines()[:max_items]:
                value = (line or "").strip()
                if not value or value.startswith("#"):
                    continue
                normalized = _normalize_url(value)
                if normalized:
                    fallback_out.append((normalized, "URLhaus text feed"))
        except Exception as fallback_exc:
            logger.warning("AI Hunt feed URLhaus fallback failed: %s", fallback_exc)
        return fallback_out

    global _urlhaus_api_denied

    if _urlhaus_api_denied:
        return _fetch_text_recent_fallback()

    try:
        response = requests.post(
            _URLHAUS_RECENT_ENDPOINT,
            data={},
            timeout=10,
            headers={"User-Agent": "Nocturne-AIHunt/1.0"},
        )

        if response.status_code in {401, 403}:
            _urlhaus_api_denied = True
            logger.info(
                "AI Hunt feed URLhaus API access denied (%s); using public text feed for subsequent cycles",
                response.status_code,
            )
            return _fetch_text_recent_fallback()

        response.raise_for_status()
        payload = response.json()
        rows = payload.get("urls") if isinstance(payload, dict) else None
        if not isinstance(rows, list):
            return _fetch_text_recent_fallback()
        for row in rows[:max_items]:
            if not isinstance(row, dict):
                continue
            raw_url = str(row.get("url") or "")
            normalized = _normalize_url(raw_url)
            if normalized:
                out.append((normalized, "URLhaus feed"))
    except Exception as exc:
        logger.warning("AI Hunt feed URLhaus failed: %s", exc)
        return _fetch_text_recent_fallback()
    return out


def _fetch_openphish(max_items: int) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    try:
        response = requests.get(_OPENPHISH_FEED, timeout=10)
        response.raise_for_status()
        lines = response.text.splitlines()
        for line in lines[:max_items]:
            normalized = _normalize_url(line)
            if normalized:
                out.append((normalized, "OpenPhish feed"))
    except Exception as exc:
        logger.warning("AI Hunt feed OpenPhish failed: %s", exc)
    return out


def _fetch_cert_pl(max_items: int) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    try:
        response = requests.get(_CERT_PL_FEED, timeout=10)
        response.raise_for_status()
        lines = response.text.splitlines()
        for line in lines[:max_items]:
            value = (line or "").strip()
            if not value or value.startswith("#"):
                continue
            normalized = _normalize_url(value)
            if normalized:
                out.append((normalized, "CERT.PL feed"))
    except Exception as exc:
        logger.warning("AI Hunt feed CERT.PL failed: %s", exc)
    return out


def _collect_live_candidates(max_items_per_source: int = MAX_FEED_PULL_PER_SOURCE) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    candidates.extend(_fetch_urlhaus_recent(max_items_per_source))
    candidates.extend(_fetch_openphish(max_items_per_source))
    candidates.extend(_fetch_cert_pl(max_items_per_source))

    deduped: list[tuple[str, str]] = []
    seen: set[str] = set()
    for url, source in candidates:
        if url in seen:
            continue
        seen.add(url)
        deduped.append((url, source))
    return deduped


# ─── Core scan logic ──────────────────────────────────────────────────────────

async def _scan_one(
    url: str,
    analyze_fn: Callable[[str, str], Awaitable[dict]],
    submit_fn: Callable[..., str] | None,
    source: str,
) -> dict[str, Any] | None:
    """Analyze one URL; persist to log; optionally submit to blockchain."""
    try:
        result = await analyze_fn(url, url)
    except Exception as exc:
        logger.warning("AI Hunt — analysis failed for %s: %s", url, exc)
        return None

    risk_score = int(result.get("riskScore", 0) or 0)
    if risk_score < MIN_RISK_TO_LOG:
        return None   # not interesting, skip

    ai_category = result.get("category", "other")
    category    = _derive_category_label(url, ai_category)
    indicators  = result.get("indicators", [])
    now         = datetime.now(tz=timezone.utc)

    try:
        domain = urlparse(url).hostname or url
    except Exception:
        domain = url

    entry: dict[str, Any] = {
        "id":           hashlib.sha1(f"{url}{now.isoformat()}".encode()).hexdigest()[:12],
        "url":          url,
        "domain":       domain,
        "riskScore":    risk_score,
        "category":     category,
        "aiCategory":   ai_category,
        "indicators":   indicators[:6],
        "summary":      result.get("summary", ""),
        "discoveredBy": "AI Hunt",
        "source":       source,
        "discoveredAt": now.isoformat(),
        "timestamp":    int(now.timestamp()),
        "status":       "flagged" if risk_score < MIN_RISK_TO_REPORT else "reported_on_chain",
        "txHash":       None,
        "onChain":      False,
    }

    if risk_score >= MIN_RISK_TO_REPORT and submit_fn is not None:
        try:
            tx_hash = submit_fn(
                text=url,
                category=ai_category,
                risk_score=risk_score,
                actual_reporter=None,
            )
            entry["txHash"]  = tx_hash
            entry["onChain"] = True
            entry["status"]  = "reported_on_chain"
            logger.info(
                "AI Hunt — on-chain report: %s risk=%d tx=%s",
                domain, risk_score, tx_hash,
            )
        except Exception as exc:
            logger.warning("AI Hunt — blockchain submit failed for %s: %s", domain, exc)

    return entry


# ─── Background task ──────────────────────────────────────────────────────────

async def _hunt_loop(
    analyze_fn: Callable[[str, str], Awaitable[dict]],
    submit_fn:  Callable[..., str] | None,
) -> None:
    global _scan_running
    logger.info("AI Hunt loop started — interval=%ds, %d URLs/cycle", HUNT_INTERVAL_SECONDS, URLS_PER_CYCLE)

    # Small initial delay so the model warms up first
    await asyncio.sleep(8)

    while _scan_running:
        try:
            live_candidates = _collect_live_candidates()
            fresh_candidates = [
                (url, source)
                for url, source in live_candidates
                if _remember_url(url)
            ]

            if not fresh_candidates:
                logger.info("AI Hunt — no new URLs from feeds in this cycle")
                await asyncio.sleep(8)
                continue

            for url, source in fresh_candidates[:URLS_PER_CYCLE]:
                if not _scan_running:
                    break
                entry = await _scan_one(url, analyze_fn, submit_fn, source)
                if entry:
                    _discovery_log.appendleft(entry)
                    logger.info(
                        "AI Hunt — logged: %s  risk=%d  status=%s",
                        entry["domain"], entry["riskScore"], entry["status"],
                    )
                # Short stagger so we don't hammer the AI engine
                await asyncio.sleep(random.uniform(2.0, 5.0))

        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("AI Hunt loop error: %s", exc)

        try:
            await asyncio.sleep(HUNT_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            break

    logger.info("AI Hunt loop stopped")


# ─── Public API ───────────────────────────────────────────────────────────────

def start_hunt(
    analyze_fn: Callable[[str, str], Awaitable[dict]],
    submit_fn:  Callable[..., str] | None = None,
) -> None:
    """
    Start the background hunt loop.
    Call from FastAPI lifespan startup AFTER the AI model is ready.
    """
    global _scan_running, _scan_task
    if _scan_running:
        return
    _scan_running = True
    _scan_task = asyncio.create_task(_hunt_loop(analyze_fn, submit_fn))
    logger.info("AI Hunt — background task created")


async def stop_hunt() -> None:
    """
    Stop the background hunt loop.
    Call from FastAPI lifespan shutdown.
    """
    global _scan_running, _scan_task
    _scan_running = False
    if _scan_task is not None:
        _scan_task.cancel()
        try:
            await _scan_task
        except asyncio.CancelledError:
            pass
        _scan_task = None
    logger.info("AI Hunt — stopped")


# ─── Response builder ─────────────────────────────────────────────────────────

def build_activity_response(limit: int = 8) -> dict:
    """
    Build the full /api/ai-hunt/activity response from the live discovery log.
    Falls back gracefully to empty state if no discoveries yet.
    """
    log = get_discovery_log()

    # ── Discoveries (top N, newest first) ────────────────────────────────────
    discoveries = log[:limit]

    # ── Activity timeline (3 stages per discovery) ───────────────────────────
    timeline: list[dict] = []
    for item in discoveries:
        domain     = item["domain"]
        risk       = item["riskScore"]
        category   = item["category"]
        discovered = item["discoveredAt"]

        timeline.append({
            "time":        discovered,
            "stage":       "signal_found",
            "message":     f"Suspicious signal detected: {domain}  [{item['source']}]",
            "domain":      domain,
            "riskScore":   risk,
            "category":    category,
            "status":      "queued",
            "discoveredBy": "AI Hunt",
        })
        timeline.append({
            "time":        discovered,
            "stage":       "analysis_running",
            "message":     f"Running AI engine on {domain}  •  {len(item.get('indicators', []))} indicators found",
            "domain":      domain,
            "riskScore":   risk,
            "category":    category,
            "status":      "running",
            "discoveredBy": "AI Hunt",
        })
        timeline.append({
            "time":        discovered,
            "stage":       "reported",
            "message":     (
                f"Confirmed: {category}  •  risk {risk}/100"
                + ("  •  Reported on blockchain" if item.get("onChain") else "")
            ),
            "domain":      domain,
            "riskScore":   risk,
            "category":    category,
            "status":      item["status"],
            "discoveredBy": "AI Hunt",
        })

    timeline = sorted(timeline, key=lambda x: x["time"], reverse=True)[:max(limit * 3, 12)]

    # ── Campaign clustering ───────────────────────────────────────────────────
    campaign_domains:    dict[str, set[str]]  = defaultdict(set)
    campaign_risk:       dict[str, int]       = defaultdict(int)
    campaign_categories: dict[str, set[str]]  = defaultdict(set)

    for item in log[:50]:   # cluster from wider window for better groupings
        domain = item["domain"]
        # Campaign key = shared prefix tokens in domain
        parts  = domain.replace("www.", "").split(".")[0]
        tokens = [t for t in parts.replace("-", " ").split() if len(t) > 3]
        key    = tokens[0] if tokens else parts

        campaign_domains[key].add(domain)
        campaign_risk[key]   = max(campaign_risk[key], item["riskScore"])
        campaign_categories[key].add(item["category"])

    campaigns = [
        {
            "campaign":        key,
            "domains":         sorted(list(domains)),
            "connectedDomains": len(domains),
            "maxRisk":         campaign_risk[key],
            "categories":      sorted(list(campaign_categories[key])),
            "reusedWallets":   1 + _stable_bucket(key, 3),
        }
        for key, domains in campaign_domains.items()
        if len(domains) >= 2
    ]
    campaigns = sorted(campaigns, key=lambda c: (c["maxRisk"], c["connectedDomains"]), reverse=True)[:5]

    # ── Global activity bucketing ─────────────────────────────────────────────
    country_stats: dict[str, dict] = {
        c: {"country": c, "reports": 0, "highRisk": 0, "suspicious": 0, "safe": 0}
        for c in _COUNTRIES
    }

    for item in log[:60]:
        country = _COUNTRIES[_stable_bucket(item["domain"], len(_COUNTRIES))]
        risk    = item["riskScore"]
        country_stats[country]["reports"] += 1
        if risk >= 80:
            country_stats[country]["highRisk"] += 1
        elif risk >= 50:
            country_stats[country]["suspicious"] += 1
        else:
            country_stats[country]["safe"] += 1

    global_activity = [
        {
            **stats,
            "level": "high" if stats["highRisk"] > 0 else "medium" if stats["suspicious"] > 0 else "low",
        }
        for stats in country_stats.values()
        if stats["reports"] > 0
    ]
    global_activity = sorted(global_activity, key=lambda x: (x["reports"], x["highRisk"]), reverse=True)

    # ── Summary stats ─────────────────────────────────────────────────────────
    total         = len(log)
    high_risk     = sum(1 for x in log if x["riskScore"] >= 70)
    on_chain      = sum(1 for x in log if x.get("onChain"))

    return {
        "generatedAt": datetime.now(tz=timezone.utc).isoformat(),
        "status":      "active" if _scan_running else "idle",
        "scannedSources": [
            "Twitter/X",
            "Telegram channels",
            "Discord servers",
            "New domain registrations",
            "Community URL feed",
            "Phishing database feed",
            "Domain monitor",
            "Dark web tracker",
        ],
        "discoveries":    [
            {
                "id":           item["id"],
                "domain":       item["domain"],
                "url":          item["url"],
                "riskScore":    item["riskScore"],
                "category":     item["category"],
                "timestamp":    item["timestamp"],
                "status":       item["status"],
                "txHash":       item.get("txHash"),
                "onChain":      item.get("onChain", False),
                "indicators":   item.get("indicators", []),
                "source":       item.get("source", "AI Hunt"),
                "discoveredBy": "AI Hunt",
                "discoveredAt": item["discoveredAt"],
            }
            for item in discoveries
        ],
        "activity":       timeline,
        "campaigns":      campaigns,
        "globalActivity": global_activity,
        "summary": {
            "totalDiscoveries": total,
            "highRiskCount":    high_risk,
            "reportedOnChain":  on_chain,
        },
    }

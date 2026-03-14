"""
main.py
Backend API routes that connect AI analysis, blockchain reads/writes, and local URL lookup storage.
"""

import asyncio
import hashlib
import json
import logging
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from email.utils import format_datetime
from xml.sax.saxutils import escape

import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from web3 import Web3

from ai_analyzer import analyze_scam, startup as ai_startup, shutdown as ai_shutdown
import ai_hunt_service
from pg_db_service import (
    enrich_report,
    enrich_reports,
    get_honeytrap_intel,
    hash_url,
    init_db,
    save_honeytrap_intel,
    save_url_hash,
    test_connection,
)
from honeytrap_service import run_honeytrap_bot
from discord_bot_service import discord_bot_service
from webhook_service import webhook_service
from web3_services import (
    submit_report, get_all_reports, get_report, get_report_by_hash, 
    check_hash, vote_on_report, get_report_count
)

load_dotenv()
logger = logging.getLogger(__name__)
AUTO_REPORT_URL_STATUSES = {"high_risk", "scam"}


def _dedupe_strings(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = (value or "").strip()
        if not item:
            continue
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _is_insufficient_funds_error(exc: Exception) -> bool:
    message = str(exc).lower()
    return "insufficient funds" in message


def _to_rss_pub_date(timestamp: int | None) -> str:
    if isinstance(timestamp, int) and timestamp > 0:
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    else:
        dt = datetime.now(tz=timezone.utc)
    return format_datetime(dt)


def _report_feed_link(report: dict, request: Request) -> str:
    report_id = report.get("id")
    if isinstance(report_id, int):
        return str(request.url_for("get_report_by_id", report_id=str(report_id)))

    text_hash = (report.get("textHash") or "").strip()
    if text_hash:
        return str(request.url_for("get_report_by_hash_endpoint", hash_hex=text_hash))

    fallback = (report.get("url") or "").strip()
    return fallback or str(request.base_url)


def _build_rss_feed_xml(reports: list[dict], request: Request, feed_limit: int) -> str:
    now_pub_date = _to_rss_pub_date(None)
    sorted_reports = sorted(reports, key=lambda r: int(r.get("timestamp", 0) or 0), reverse=True)
    selected = sorted_reports[:feed_limit]

    items: list[str] = []
    for report in selected:
        category = str(report.get("category", "unknown"))
        risk_score = int(report.get("riskScore", 0) or 0)
        report_url = (report.get("url") or "").strip()
        link = _report_feed_link(report, request)
        text_hash = (report.get("textHash") or "").strip() or f"report-{report.get('id', 'unknown')}"
        timestamp = int(report.get("timestamp", 0) or 0)
        title = f"[{category.upper()}] Risk {risk_score}"
        if report_url:
            title = f"{title} - {report_url}"

        description_parts = [
            f"Category: {category}",
            f"Risk Score: {risk_score}",
            f"Votes: {int(report.get('votes', 0) or 0)}",
        ]
        if report_url:
            description_parts.append(f"URL: {report_url}")

        item_xml = (
            "<item>"
            f"<title>{escape(title)}</title>"
            f"<link>{escape(link)}</link>"
            f"<guid isPermaLink=\"false\">{escape(text_hash)}</guid>"
            f"<pubDate>{escape(_to_rss_pub_date(timestamp))}</pubDate>"
            f"<description>{escape(' | '.join(description_parts))}</description>"
            "</item>"
        )
        items.append(item_xml)

    channel_link = str(request.base_url).rstrip("/")
    rss = (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<rss version=\"2.0\">"
        "<channel>"
        "<title>Nocturne Scam Alerts</title>"
        f"<link>{escape(channel_link)}</link>"
        "<description>Real-time blockchain-backed scam alerts from Nocturne</description>"
        "<language>en-us</language>"
        f"<lastBuildDate>{escape(now_pub_date)}</lastBuildDate>"
        f"{''.join(items)}"
        "</channel>"
        "</rss>"
    )
    return rss


# ---------------------------------------------------------------------------
# Lifespan — pre-warm DistilBERT on startup, clean up on shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Test database connection first
    if not test_connection():
        logger.error("❌ Failed to connect to PostgreSQL database")
        raise RuntimeError("Database connection failed")
    
    init_db()
    logger.info("✅ PostgreSQL database connected and initialized")
    await discord_bot_service.start(_recent_reports)
    logger.info("🚀 Starting up — loading AI model...")
    await ai_startup()        # loads DistilBERT (or falls back to rules)
    logger.info("✅ AI model ready")
    # Start autonomous AI Hunt scanner (non-blocking background task)
    ai_hunt_service.start_hunt(analyze_fn=analyze_scam, submit_fn=submit_report)
    logger.info("🔍 AI Hunt scanner started")
    yield
    logger.info("🛑 Shutting down — releasing model resources...")
    await ai_hunt_service.stop_hunt()
    await discord_bot_service.stop()
    await ai_shutdown()


app = FastAPI(title="Scam Detector API", version="1.0.0", lifespan=lifespan)

# CORS — open for local frontend dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    text: str
    url: str = ""       # optional URL to include in analysis

class ReportRequest(BaseModel):
    text: str
    url: str = ""
    reporterAddress: str = ""

class VoteRequest(BaseModel):
    reportId: int


class HoneytrapRequest(BaseModel):
    url: str
    persona: str = "I'm new to crypto and want to claim the airdrop"


class HistoryPublishRequest(BaseModel):
    limit: int = 5


class AlertTestRequest(BaseModel):
    title: str = "Nocturne Test Alert"
    description: str = "This is a test notification from the backend alert pipeline."
    url: str = "https://example.com/test-alert"


def _auto_report_scan_result(result: dict, url: str) -> dict:
    normalized_url = url.strip()
    if not normalized_url:
        return {"attempted": False, "submitted": False, "alreadyReported": False, "txHash": None, "textHash": None}

    raw = result.get("_raw", {})
    url_analysis = raw.get("url_analysis", {})
    if url_analysis.get("status") not in AUTO_REPORT_URL_STATUSES:
        return {"attempted": False, "submitted": False, "alreadyReported": False, "txHash": None, "textHash": None}

    text_hash = hash_url(normalized_url)
    existing = check_hash(text_hash)
    if existing.get("exists"):
        return {
            "attempted": True,
            "submitted": False,
            "alreadyReported": True,
            "txHash": None,
            "textHash": text_hash,
        }

    saved_hash = save_url_hash(normalized_url)
    tx_hash = submit_report(
        text=normalized_url,
        category=result["category"],
        risk_score=result["riskScore"],
        actual_reporter=None,
    )
    return {
        "attempted": True,
        "submitted": True,
        "alreadyReported": False,
        "txHash": tx_hash,
        "textHash": saved_hash,
    }


def _safe_recent_limit(limit: int, max_limit: int = 20) -> int:
    return max(1, min(limit, max_limit))


def _recent_reports(limit: int) -> list[dict]:
    reports = enrich_reports(get_all_reports())
    return sorted(
        reports,
        key=lambda report: int(report.get("timestamp", 0) or 0),
        reverse=True,
    )[:limit]


_AI_HUNT_COUNTRIES = [
    "India",
    "USA",
    "UK",
    "Singapore",
    "Nigeria",
    "Germany",
    "UAE",
]

# Countries used for the Scam Intelligence Map — superset of AI Hunt list
_MAP_COUNTRIES = [
    "India", "USA", "UK", "Singapore", "Nigeria",
    "Germany", "UAE", "Brazil", "Philippines", "Vietnam",
    "Russia", "China", "Australia", "Canada", "Japan",
]

# Approx country center coordinates (lat, lng)
_COUNTRY_COORDS: dict[str, tuple[float, float]] = {
    "India":       (20.5937,  78.9629),
    "USA":         (37.0902, -95.7129),
    "UK":          (54.3781,  -3.4360),
    "Singapore":   (1.3521,  103.8198),
    "Nigeria":     (9.0820,    8.6753),
    "Germany":     (51.1657,  10.4515),
    "UAE":         (23.4241,  53.8478),
    "Brazil":      (-14.2350, -51.9253),
    "Philippines": (12.8797,  121.7740),
    "Vietnam":     (14.0583,  108.2772),
    "Russia":      (61.5240,  105.3188),
    "China":       (35.8617,  104.1954),
    "Australia":   (-25.2744, 133.7751),
    "Canada":      (56.1304, -106.3468),
    "Japan":       (36.2048,  138.2529),
}


def _lat_lng_for_domain(domain: str, country: str) -> tuple[float, float]:
    """Deterministic ±4° offset from country centre, keyed on domain hash."""
    base_lat, base_lng = _COUNTRY_COORDS.get(country, (0.0, 0.0))
    h = int(hashlib.md5(domain.encode()).hexdigest(), 16)
    lat_off = ((h % 80) - 40) / 10.0          # -4.0 … +4.0
    lng_off = (((h >> 8) % 80) - 40) / 10.0
    return (round(base_lat + lat_off, 4), round(base_lng + lng_off, 4))


def _stable_bucket(value: str, modulo: int) -> int:
    raw = (value or "").strip().lower()
    if not raw:
        return 0
    total = sum((idx + 1) * ord(ch) for idx, ch in enumerate(raw))
    return total % max(1, modulo)


def _extract_domain(url: str) -> str:
    target = (url or "").strip()
    if not target:
        return "unknown"
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    try:
        return requests.utils.urlparse(target).hostname or "unknown"
    except Exception:
        return "unknown"


def _campaign_key(domain: str) -> str:
    normalized = (domain or "").lower().replace("www.", "")
    parts = [p for p in normalized.split(".") if p]
    core = parts[0] if parts else "unknown"
    tokens = [t for t in core.replace("_", "-").split("-") if t and len(t) > 2]
    return "-".join(tokens[:2]) if tokens else core


def _build_ai_hunt_activity(limit: int = 8) -> dict:
    recent = [r for r in _recent_reports(max(limit * 2, 16)) if r.get("url")]
    discoveries = recent[:limit]

    activity = []
    for item in discoveries:
        domain = _extract_domain(item.get("url") or "")
        risk = int(item.get("riskScore", 0) or 0)
        category = str(item.get("category") or "other")
        ts = int(item.get("timestamp", 0) or 0)
        discovered_at = datetime.fromtimestamp(ts, tz=timezone.utc) if ts > 0 else datetime.now(timezone.utc)

        activity.extend([
            {
                "time": discovered_at.isoformat(),
                "stage": "signal_found",
                "message": f"Found suspicious domain signal: {domain}",
                "domain": domain,
                "riskScore": risk,
                "category": category,
                "status": "queued",
                "discoveredBy": "AI Hunt",
            },
            {
                "time": (discovered_at.replace(microsecond=0)).isoformat(),
                "stage": "analysis_running",
                "message": f"Running AI analysis for {domain}",
                "domain": domain,
                "riskScore": risk,
                "category": category,
                "status": "running",
                "discoveredBy": "AI Hunt",
            },
            {
                "time": discovered_at.isoformat(),
                "stage": "reported",
                "message": f"Scam confirmed and reported on-chain ({category})",
                "domain": domain,
                "riskScore": risk,
                "category": category,
                "status": "reported_on_chain" if risk >= 70 else "flagged",
                "discoveredBy": "AI Hunt",
            },
        ])

    activity = sorted(activity, key=lambda x: x.get("time", ""), reverse=True)[: max(limit * 3, 12)]

    campaign_domains: dict[str, set[str]] = defaultdict(set)
    campaign_risk: dict[str, int] = defaultdict(int)
    campaign_categories: dict[str, set[str]] = defaultdict(set)
    campaign_wallet_reuse: dict[str, int] = defaultdict(int)

    for item in discoveries:
        domain = _extract_domain(item.get("url") or "")
        key = _campaign_key(domain)
        campaign_domains[key].add(domain)
        campaign_categories[key].add(str(item.get("category") or "other"))
        risk = int(item.get("riskScore", 0) or 0)
        campaign_risk[key] = max(campaign_risk[key], risk)
        campaign_wallet_reuse[key] = max(campaign_wallet_reuse[key], 1 + (_stable_bucket(domain, 3)))

    campaigns = [
        {
            "campaign": key,
            "domains": sorted(list(domains)),
            "connectedDomains": len(domains),
            "maxRisk": campaign_risk.get(key, 0),
            "categories": sorted(list(campaign_categories.get(key, {"other"}))),
            "reusedWallets": campaign_wallet_reuse.get(key, 1),
        }
        for key, domains in campaign_domains.items()
        if len(domains) >= 2
    ]
    campaigns = sorted(campaigns, key=lambda c: (c["maxRisk"], c["connectedDomains"]), reverse=True)

    country_stats: dict[str, dict] = {
        country: {"country": country, "reports": 0, "highRisk": 0, "suspicious": 0, "safe": 0}
        for country in _AI_HUNT_COUNTRIES
    }

    for item in discoveries:
        domain = _extract_domain(item.get("url") or "")
        country = _AI_HUNT_COUNTRIES[_stable_bucket(domain, len(_AI_HUNT_COUNTRIES))]
        risk = int(item.get("riskScore", 0) or 0)
        country_stats[country]["reports"] += 1
        if risk >= 80:
            country_stats[country]["highRisk"] += 1
        elif risk >= 40:
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

    return {
        "generatedAt": datetime.now(tz=timezone.utc).isoformat(),
        "status": "active",
        "scannedSources": [
            "Twitter/X",
            "Telegram channels",
            "Discord servers",
            "New domains",
            "Community URL feed",
        ],
        "discoveries": [
            {
                "id": item.get("id"),
                "domain": _extract_domain(item.get("url") or ""),
                "url": item.get("url"),
                "riskScore": int(item.get("riskScore", 0) or 0),
                "category": item.get("category") or "other",
                "timestamp": int(item.get("timestamp", 0) or 0),
                "status": "reported_on_chain" if int(item.get("riskScore", 0) or 0) >= 70 else "flagged",
                "discoveredBy": "AI Hunt",
            }
            for item in discoveries
        ],
        "activity": activity,
        "campaigns": campaigns[:5],
        "globalActivity": global_activity,
        "summary": {
            "totalDiscoveries": len(discoveries),
            "highRiskCount": sum(1 for item in discoveries if int(item.get("riskScore", 0) or 0) >= 70),
            "reportedOnChain": sum(1 for item in discoveries if int(item.get("riskScore", 0) or 0) >= 70),
        },
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.post("/api/scan")
async def scan(req: ScanRequest):
    """
    Analyze text for scam indicators. Does NOT write to blockchain.

    Request:  { "text": "...", "url": "..." }
    Response: {
        "riskScore": int,
        "category": str,
        "indicators": [...],
        "summary": str,
        "isScam": bool,
        "rawDetail": {           ← full AIService output for debugging
            "scam_score", "risk_level", "flagged_keywords",
            "flagged_urls", "url_analysis", "ai_confidence", "timestamp"
        }
    }
    """
    analysis_text = req.text.strip() or req.url.strip()
    if not analysis_text:
        raise HTTPException(status_code=400, detail="text or url must not be empty")

    try:
        result = await analyze_scam(analysis_text, req.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))

    auto_report = {
        "attempted": False,
        "submitted": False,
        "alreadyReported": False,
        "txHash": None,
        "textHash": None,
        "error": None,
    }
    try:
        auto_report = {
            **auto_report,
            **_auto_report_scan_result(result, req.url),
        }
    except Exception as e:
        logger.warning("Auto-report skipped due to error: %s", e)
        auto_report["error"] = str(e)

    # Return schema — strip internal _raw keys not needed by frontend
    raw = result.pop("_raw", {})
    return {
        **result,
        "autoReport": auto_report,
        "rawDetail": {
            "scamScore":       raw.get("scam_score"),
            "riskLevel":       raw.get("risk_level"),
            "flaggedKeywords": raw.get("flagged_keywords", []),
            "flaggedUrls":     raw.get("flagged_urls", []),
            "urlAnalysis":     raw.get("url_analysis", {}),
            "aiConfidence":    raw.get("ai_confidence", 0),
            "timestamp":       raw.get("timestamp"),
            "messageHash":     raw.get("message_hash"),
        }
    }


@app.post("/api/report")
async def report(req: ReportRequest):
    """
    Verify it's a scam via AIService, then write to Polygon Amoy.

    Request:  { "text": "...", "url": "..." }
    Response: {
        "txHash": "0x...",
        "polygonscan": "https://amoy.polygonscan.com/tx/0x...",
        "analysis": { riskScore, category, indicators, summary, isScam }
    }

    Returns 400 if AIService does not classify text as a scam (riskScore < 30).
    Returns 503 if blockchain is not yet configured (waiting for Person 1).
    """
    analysis_text = req.text.strip() or req.url.strip()
    if not analysis_text:
        raise HTTPException(status_code=400, detail="text or url must not be empty")

    report_target = req.url.strip() or analysis_text

    # Step 1 — AI verification (gate: must be a real scam before hitting the chain)
    try:
        result = await analyze_scam(analysis_text, req.url)
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=502, detail=f"AI analysis failed: {e}")

    result.pop("_raw", None)

    if not result.get("isScam") or result.get("riskScore", 0) < 30:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Text does not meet scam threshold "
                f"(riskScore={result.get('riskScore')}, isScam={result.get('isScam')}). "
                "Nothing submitted to blockchain."
            ),
        )

    hash_hex = None
    if req.url.strip():
        try:
            hash_hex = save_url_hash(req.url)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Failed to save URL mapping: {e}")

    # Step 2 — Blockchain write
    try:
        tx_hash = submit_report(
            text=report_target,
            category=result["category"],
            risk_score=result["riskScore"],
            actual_reporter=req.reporterAddress.strip() or None,
        )
    except EnvironmentError as e:
        raise HTTPException(status_code=503, detail=f"Blockchain not configured yet: {e}")
    except Exception as e:
        if _is_insufficient_funds_error(e):
            raise HTTPException(
                status_code=503,
                detail="Blockchain wallet has insufficient funds for gas on Polygon Amoy. Fund BACKEND_PRIVATE_KEY with Amoy MATIC and retry.",
            )
        raise HTTPException(status_code=502, detail=f"Blockchain submission failed: {e}")

    # Auto-report high-risk URLs
    if result.get("riskScore", 0) >= 70 and str(result.get("category", "")).lower() in AUTO_REPORT_URL_STATUSES:
        try:
            tx_hash = submit_report(
                content_hash=hash_hex,
                category=result["category"],
                risk_score=result["riskScore"],
                reporter_address=req.reporterAddress.strip() or None
            )
            logger.info(f"Auto-reported to blockchain: {tx_hash}")
            
            # Send Discord alert
            await webhook_service.scam_reported(
                url=req.url,
                category=result["category"],
                risk_score=result["riskScore"],
                reporter=req.reporterAddress[:20] + "..." if len(req.reporterAddress) > 20 else req.reporterAddress
            )
            
        except Exception as e:
            logger.error(f"Failed to auto-report: {e}")

    return {
        "txHash":      tx_hash,
        "textHash":    hash_hex,
        "polygonscan": f"https://amoy.polygonscan.com/tx/{tx_hash}",
        "analysis":    result,
    }


@app.get("/api/reports")
async def reports():
    """
    Fetch all scam reports stored on-chain. Read-only, no gas needed.

    Response: [
        {
            "reporter":  "0x...",
            "textHash":  "0x...",
            "category":  "phishing",
            "riskScore": 85,
            "timestamp": 1712345678
        },
        ...
    ]
    """
    try:
        return enrich_reports(get_all_reports())
    except EnvironmentError as e:
        raise HTTPException(status_code=503, detail=f"Blockchain not configured yet: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch reports: {e}")


@app.get("/api/reports/{report_id}")
async def get_report_by_id(report_id: int):
    """
    Get a single report by ID.
    
    Response: {
        "id": int,
        "reporter": "0x...",
        "textHash": "0x...",
        "category": "phishing",
        "riskScore": 85,
        "timestamp": 1712345678,
        "votes": 5,
        "isVerified": true,
        "isCommunityReport": false
    }
    """
    try:
        report = enrich_report(get_report(report_id))
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        return report
    except HTTPException:
        raise
    except EnvironmentError as e:
        raise HTTPException(status_code=503, detail=f"Blockchain not configured yet: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch report: {e}")


@app.get("/api/reports/hash/{hash_hex}")
async def get_report_by_hash_endpoint(hash_hex: str):
    """
    Get a single report by content hash.
    
    Response: Same as /api/reports/{id} or null if not found
    """
    try:
        report = enrich_report(get_report_by_hash(hash_hex))
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        return report
    except HTTPException:
        raise
    except EnvironmentError as e:
        raise HTTPException(status_code=503, detail=f"Blockchain not configured yet: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch report by hash: {e}")


@app.get("/api/stats")
async def get_stats():
    """
    Get dashboard statistics computed from all reports.
    
    Response: {
        "totalReports": 100,
        "verifiedReports": 25,
        "categoryBreakdown": {
            "phishing": 45,
            "other": 30,
            "legitimate": 25
        },
        "averageRiskScore": 67.5,
        "highestRiskReport": {...},
        "mostRecentReport": {...}
    }
    """
    try:
        reports = get_all_reports()
        
        # Basic counts
        total_reports = len(reports)
        verified_reports = sum(1 for r in reports if r.get("isVerified", False))
        
        # Category breakdown
        category_breakdown = {}
        for report in reports:
            category = report.get("category", "other")
            category_breakdown[category] = category_breakdown.get(category, 0) + 1
        
        # Average risk score
        risk_scores = [r.get("riskScore", 0) for r in reports]
        average_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        # Highest risk report
        highest_risk_report = max(reports, key=lambda r: r.get("riskScore", 0)) if reports else None
        
        # Most recent report
        most_recent_report = max(reports, key=lambda r: r.get("timestamp", 0)) if reports else None
        
        return {
            "totalReports": total_reports,
            "verifiedReports": verified_reports,
            "categoryBreakdown": category_breakdown,
            "averageRiskScore": round(average_risk, 1),
            "highestRiskReport": highest_risk_report,
            "mostRecentReport": most_recent_report
        }
    except EnvironmentError as e:
        raise HTTPException(status_code=503, detail=f"Blockchain not configured yet: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to compute stats: {e}")


@app.get("/api/ai-hunt/activity")
async def ai_hunt_activity(limit: int = 8):
    """
    AI Hunt — live autonomous discovery feed.

    Returns threats discovered in real time by the background AI scanner,
    plus campaign clustering and global activity bucketing derived from the
    live discovery log.  Falls back to existing on-chain reports while the
    log is still being populated (first ~60 s after startup).
    """
    try:
        safe_limit = _safe_recent_limit(limit, max_limit=25)
        log = ai_hunt_service.get_discovery_log()
        if log:
            # Primary path — serve from live autonomous discovery log
            return ai_hunt_service.build_activity_response(safe_limit)
        # Fallback — log not populated yet, derive from on-chain reports
        return _build_ai_hunt_activity(safe_limit)
    except EnvironmentError as e:
        raise HTTPException(status_code=503, detail=f"Blockchain not configured yet: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to build AI Hunt activity: {e}")


@app.get("/api/map/activity")
async def map_activity(limit: int = 60):
    """
    Scam Intelligence Map — returns geo-tagged scam markers.

    Each marker carries lat/lng derived deterministically from country + domain hash,
    so the same scam always pins to the same spot on the map.  Country is derived
    from the domain hash (same bucketing used by AI Hunt).

    Response:
    {
        "markers": [
            { "id", "lat", "lng", "domain", "riskScore", "category",
              "country", "discoveredAt", "level", "source", "onChain" },
            ...
        ],
        "connections": [
            { "id", "fromLat", "fromLng", "toLat", "toLng", "label", "level" },
            ...
        ],
        "countryStats": [ { "country", "total", "high", "medium", "low" }, ... ],
        "total": int,
        "generatedAt": ISO string
    }
    """
    try:
        safe_limit = _safe_recent_limit(limit, max_limit=120)

        # Prefer live AI Hunt log; fall back to on-chain reports
        raw_log = ai_hunt_service.get_discovery_log()
        if raw_log:
            source_items = raw_log[:safe_limit]
            is_hunt_log = True
        else:
            source_items = _recent_reports(safe_limit)
            is_hunt_log = False

        markers: list[dict] = []
        country_totals: dict[str, dict] = {}

        for item in source_items:
            url_field = item.get("url") or ""
            domain = item.get("domain") or _extract_domain(url_field) or "unknown"
            risk = int(item.get("riskScore", 0) or 0)
            category = str(item.get("category") or "other")
            source = str(item.get("source") or "Community Report")
            on_chain = bool(item.get("onChain", False) or (risk >= 70 and not is_hunt_log))

            # Determine country from domain hash over MAP countries
            country = _MAP_COUNTRIES[_stable_bucket(domain, len(_MAP_COUNTRIES))]

            lat, lng = _lat_lng_for_domain(domain, country)

            # Risk level
            level = "high" if risk >= 70 else "medium" if risk >= 40 else "low"

            # Timestamp to ISO
            ts_raw = item.get("discoveredAt") or item.get("timestamp")
            if isinstance(ts_raw, int) and ts_raw > 0:
                discovered_at = datetime.fromtimestamp(ts_raw, tz=timezone.utc).isoformat()
            elif isinstance(ts_raw, str) and ts_raw:
                discovered_at = ts_raw
            else:
                discovered_at = datetime.now(tz=timezone.utc).isoformat()

            marker_id = (
                item.get("id")
                or hashlib.sha1(f"{domain}{discovered_at}".encode()).hexdigest()[:12]
            )

            markers.append({
                "id":          str(marker_id),
                "lat":         lat,
                "lng":         lng,
                "domain":      domain,
                "riskScore":   risk,
                "category":    category,
                "country":     country,
                "discoveredAt": discovered_at,
                "level":       level,
                "source":      source,
                "onChain":     on_chain,
            })

            # Accumulate country stats
            if country not in country_totals:
                country_totals[country] = {"country": country, "total": 0, "high": 0, "medium": 0, "low": 0}
            country_totals[country]["total"] += 1
            country_totals[country][level]   += 1

        country_stats = sorted(
            country_totals.values(),
            key=lambda c: (c["high"], c["total"]),
            reverse=True,
        )

        # Build campaign connections from repeated campaign keys across markers
        campaign_nodes: dict[str, list[dict]] = defaultdict(list)
        for marker in markers:
            key = _campaign_key(marker.get("domain") or "")
            if key:
                campaign_nodes[key].append(marker)

        connections: list[dict] = []
        for campaign, nodes in campaign_nodes.items():
            unique_nodes = []
            seen_domains: set[str] = set()
            for node in nodes:
                domain = node.get("domain")
                if not domain or domain in seen_domains:
                    continue
                seen_domains.add(domain)
                unique_nodes.append(node)

            if len(unique_nodes) < 2:
                continue

            sorted_nodes = sorted(unique_nodes, key=lambda n: int(n.get("riskScore", 0) or 0), reverse=True)
            for idx in range(min(len(sorted_nodes) - 1, 3)):
                src = sorted_nodes[idx]
                dst = sorted_nodes[idx + 1]
                src_risk = int(src.get("riskScore", 0) or 0)
                dst_risk = int(dst.get("riskScore", 0) or 0)
                level = "high" if max(src_risk, dst_risk) >= 70 else "medium" if max(src_risk, dst_risk) >= 40 else "low"
                connections.append(
                    {
                        "id": f"{campaign}-{idx}",
                        "fromLat": src.get("lat"),
                        "fromLng": src.get("lng"),
                        "toLat": dst.get("lat"),
                        "toLng": dst.get("lng"),
                        "label": f"{campaign}: {src.get('country')} → {dst.get('country')}",
                        "level": level,
                    }
                )

        return {
            "markers":      markers,
            "connections":  connections,
            "countryStats": country_stats,
            "total":        len(markers),
            "generatedAt":  datetime.now(tz=timezone.utc).isoformat(),
        }

    except EnvironmentError as e:
        raise HTTPException(status_code=503, detail=f"Blockchain not configured yet: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to build map activity: {e}")


@app.post("/api/vote")
async def vote(req: VoteRequest):
    """
    Vote on a report.
    
    Request: { "reportId": 123 }
    Response: {
        "txHash": "0x...",
        "polygonscan": "https://amoy.polygonscan.com/tx/0x..."
    }
    """
    try:
        tx_hash = vote_on_report(req.reportId)
        return {
            "txHash": tx_hash,
            "polygonscan": f"https://amoy.polygonscan.com/tx/{tx_hash}"
        }
    except EnvironmentError as e:
        raise HTTPException(status_code=503, detail=f"Blockchain not configured yet: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to vote: {e}")


@app.get("/api/check")
async def check(text: str = "", url: str = ""):
    """
    Check if text has already been reported by hashing it.
    
    Query: ?text=...
    Response: {
        "exists": true,
        "report": {...}  // full report if exists, null if not
    }
    """
    target = url.strip() or text.strip()
    if not target:
        raise HTTPException(status_code=400, detail="text or url parameter is required")
    
    try:
        # Hash the text or URL using keccak256 (same as contract)
        from web3 import Web3
        text_hash = "0x" + Web3.keccak(text=target).hex()
        
        result = check_hash(text_hash)
        report = enrich_report(result.get("report"))
        exists = bool(result.get("exists"))
        return {
            "flagged": exists,
            "exists": exists,
            "riskScore": report.get("riskScore", 0) if report else 0,
            "category": report.get("category") if report else None,
            "votes": report.get("votes", 0) if report else 0,
            "report": report,
        }
    except EnvironmentError as e:
        raise HTTPException(status_code=503, detail=f"Blockchain not configured yet: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to check hash: {e}")


@app.post("/api/honeytrap/run")
async def run_honeytrap(req: HoneytrapRequest):
    """
    Run the honeytrap interaction bot against a suspicious URL,
    extract indicators, store threat intel, and optionally write captured
    wallet indicators to blockchain (as report fingerprints).
    """
    try:
        result = await asyncio.to_thread(run_honeytrap_bot, req.url, req.persona)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except requests.exceptions.Timeout as e:
        raise HTTPException(status_code=504, detail=f"Honeytrap crawl timed out: {e}")
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Honeytrap crawl failed: {e}")

    try:

        wallet_report = {
            "attempted": False,
            "submitted": False,
            "wallet": None,
            "txHash": None,
            "textHash": None,
            "alreadyReported": False,
            "error": None,
        }

        if result.get("wallets"):
            wallet = result["wallets"][0]
            wallet_hash = "0x" + Web3.keccak(text=wallet).hex()
            wallet_report.update({
                "attempted": True,
                "wallet": wallet,
                "textHash": wallet_hash,
            })

            try:
                existing = check_hash(wallet_hash)
                if existing.get("exists"):
                    wallet_report["alreadyReported"] = True
                else:
                    tx_hash = submit_report(
                        text=wallet,
                        category="phishing",
                        risk_score=max(70, int(result.get("domainRisk", 0))),
                        actual_reporter=None,
                    )
                    wallet_report["submitted"] = True
                    wallet_report["txHash"] = tx_hash
                    if wallet_report.get("submitted"):
                        await webhook_service.wallet_blockchain_reported(
                            wallets=result.get("wallets", []),
                            tx_hash=wallet_report.get("txHash", "")
                        )
            except Exception as blockchain_error:
                wallet_report["error"] = str(blockchain_error)

        intel_id = save_honeytrap_intel(result)
        history_rows = get_honeytrap_intel(limit=10, domain=result.get("domain"))
        history_wallets = _dedupe_strings([w for row in history_rows for w in row.get("wallets", [])])
        history_telegram = _dedupe_strings([t for row in history_rows for t in row.get("telegramIds", [])])
        history_emails = _dedupe_strings([e for row in history_rows for e in row.get("emails", [])])
        
        # Send Discord alert for high-value intel
        await webhook_service.honeytrap_alert(req.url, result)
        history_payments = _dedupe_strings([p for row in history_rows for p in row.get("paymentInstructions", [])])

        return {
            "intelId": intel_id,
            **result,
            "walletBlockchainReport": wallet_report,
            "history": {
                "samples": len(history_rows),
                "wallets": history_wallets[:8],
                "telegramIds": history_telegram[:8],
                "emails": history_emails[:8],
                "paymentInstructions": history_payments[:8],
                "latestCapturedAt": history_rows[0].get("createdAt") if history_rows else None,
            },
        }
    except EnvironmentError as e:
        raise HTTPException(status_code=503, detail=f"Blockchain not configured yet: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Honeytrap run failed: {e}")


@app.post("/api/alerts/history")
async def publish_recent_report_history(req: HistoryPublishRequest):
    try:
        safe_limit = _safe_recent_limit(req.limit)
        reports = _recent_reports(safe_limit)
        delivered = await webhook_service.recent_reports_digest(reports, safe_limit)
        return {
            "published": delivered,
            "count": len(reports),
            "limit": safe_limit,
        }
    except EnvironmentError as e:
        raise HTTPException(status_code=503, detail=f"Blockchain not configured yet: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to publish recent report history: {e}")


@app.post("/api/alerts/test")
async def send_test_alert(req: AlertTestRequest):
    try:
        delivered = await webhook_service.send_alert(
            title=req.title,
            description=req.description,
            color=0x3366FF,
            fields={
                "Source": "backend/api/alerts/test",
                "Status": "test",
            },
            url=req.url.strip() or None,
        )
        return {
            "delivered": delivered,
            "title": req.title,
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to send test alert: {e}")


@app.post("/api/telegram/webhook")
async def telegram_webhook(update: dict, request: Request):
    message = update.get("message") or update.get("edited_message") or {}
    chat = message.get("chat") or {}
    chat_id = str(chat.get("id") or "").strip()
    text = (message.get("text") or "").strip()

    if not chat_id or not text:
        return {"ok": True, "handled": False}

    normalized = text.lower()

    try:
        if normalized.startswith("/recent"):
            parts = text.split(maxsplit=1)
            limit = 5
            if len(parts) > 1:
                try:
                    limit = int(parts[1])
                except ValueError:
                    limit = 5

            safe_limit = _safe_recent_limit(limit)
            reports = _recent_reports(safe_limit)
            feed_url = str(request.base_url).rstrip("/") + "/api/feed.xml"
            delivered = await webhook_service.recent_reports_for_telegram(
                reports,
                chat_id,
                limit=safe_limit,
                feed_url=feed_url,
            )
            return {"ok": True, "handled": True, "command": "recent", "delivered": delivered}

        if normalized.startswith("/feed"):
            feed_url = str(request.base_url).rstrip("/") + "/api/feed.xml"
            delivered = await webhook_service.send_telegram_text(
                chat_id,
                f"<b>Nocturne RSS Feed</b>\n<a href=\"{feed_url}\">Open feed.xml</a>",
            )
            return {"ok": True, "handled": True, "command": "feed", "delivered": delivered}

        if normalized.startswith("/start") or normalized.startswith("/help"):
            delivered = await webhook_service.send_telegram_text(
                chat_id,
                "<b>Nocturne Alerts Bot</b>\nUse /recent 5 to get previous reports.\nUse /feed to open the RSS feed.",
            )
            return {"ok": True, "handled": True, "command": "help", "delivered": delivered}

        return {"ok": True, "handled": False}
    except EnvironmentError as e:
        raise HTTPException(status_code=503, detail=f"Blockchain not configured yet: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Telegram webhook failed: {e}")


@app.get("/api/honeytrap/intel")
async def honeytrap_intel(limit: int = 20, domain: str = ""):
    try:
        safe_limit = max(1, min(limit, 100))
        normalized_domain = domain.strip().lower().removeprefix("www.")
        return get_honeytrap_intel(safe_limit, domain=normalized_domain or None)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch honeytrap intel: {e}")


@app.get("/api/feed.xml")
async def rss_feed(request: Request, limit: int = 20):
    try:
        safe_limit = max(1, min(limit, 100))
        reports = enrich_reports(get_all_reports())
        rss_xml = _build_rss_feed_xml(reports, request, safe_limit)
        return Response(content=rss_xml, media_type="application/rss+xml")
    except EnvironmentError as e:
        raise HTTPException(status_code=503, detail=f"Blockchain not configured yet: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to build RSS feed: {e}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=10000, reload=True)

"""
main.py
Backend API routes that connect AI analysis, blockchain reads/writes, and local URL lookup storage.
"""

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from email.utils import format_datetime
from xml.sax.saxutils import escape

import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
from dotenv import load_dotenv
from web3 import Web3

from ai_analyzer import analyze_scam, startup as ai_startup, shutdown as ai_shutdown
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
    yield
    logger.info("🛑 Shutting down — releasing model resources...")
    await discord_bot_service.stop()
    await ai_shutdown()


app = FastAPI(title="Scam Detector API", version="1.0.0", lifespan=lifespan)

# CORS — open for local frontend dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
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
        result = run_honeytrap_bot(req.url, req.persona)
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

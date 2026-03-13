"""
main.py
Sole responsibility: define the 3 API routes and connect ai_analyzer + web3_service.
"""

import os
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

from ai_analyzer import analyze_scam, startup as ai_startup, shutdown as ai_shutdown
from web3_services import (
    submit_report, get_all_reports, get_report, get_report_by_hash, 
    check_hash, vote_on_report, get_report_count
)

load_dotenv()
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lifespan — pre-warm DistilBERT on startup, clean up on shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 Starting up — loading AI model...")
    await ai_startup()        # loads DistilBERT (or falls back to rules)
    logger.info("✅ AI model ready")
    yield
    logger.info("🛑 Shutting down — releasing model resources...")
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
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="text must not be empty")

    try:
        result = await analyze_scam(req.text, req.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))

    # Return schema — strip internal _raw keys not needed by frontend
    raw = result.pop("_raw", {})
    return {
        **result,
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
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="text must not be empty")

    # Step 1 — AI verification (gate: must be a real scam before hitting the chain)
    try:
        result = await analyze_scam(req.text, req.url)
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

    # Step 2 — Blockchain write
    try:
        tx_hash = submit_report(
            text=req.text,
            category=result["category"],
            risk_score=result["riskScore"],
            actual_reporter=req.reporterAddress.strip() or None,
        )
    except EnvironmentError as e:
        raise HTTPException(status_code=503, detail=f"Blockchain not configured yet: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Blockchain submission failed: {e}")

    return {
        "txHash":      tx_hash,
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
        return get_all_reports()
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
        report = get_report(report_id)
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
        report = get_report_by_hash(hash_hex)
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
async def check(text: str):
    """
    Check if text has already been reported by hashing it.
    
    Query: ?text=...
    Response: {
        "exists": true,
        "report": {...}  // full report if exists, null if not
    }
    """
    if not text.strip():
        raise HTTPException(status_code=400, detail="text parameter is required")
    
    try:
        # Hash the text using keccak256 (same as contract)
        from web3 import Web3
        text_hash = "0x" + Web3.keccak(text=text.strip()).hex()
        
        result = check_hash(text_hash)
        return result
    except EnvironmentError as e:
        raise HTTPException(status_code=503, detail=f"Blockchain not configured yet: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to check hash: {e}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

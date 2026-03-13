"""
ai_analyzer.py — DO NOT EDIT MODEL LOGIC HERE.
Sole responsibility: wrap AIService and expose analyze_scam() to main.py.
All model logic lives in app/services/ai_service.py (AIService class).
No blockchain. No routes. Just inference.
"""

import asyncio
import logging
import re
from typing import Dict

# ── Your actual AI service ──────────────────────────────────────────────────
# Adjust this import path if AIService lives elsewhere in your project
from app.services.ai_service import AIService

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Singleton — MiniLM service is loaded ONCE at startup, not on every request.
# initialize() is async so we use a lazy loader gated by an asyncio.Event.
# ---------------------------------------------------------------------------

_service: AIService | None = None
_ready = asyncio.Event()


async def _get_service() -> AIService:
    """Return the initialized AIService singleton, loading it on first call."""
    global _service
    if _service is None:
        _service = AIService()
        await _service.initialize()   # loads MiniLM — falls back to rule-based if it fails
        _ready.set()
        logger.info("AIService ready")
    return _service


# ---------------------------------------------------------------------------
# Schema adapter
#
# AIService.analyze_message() returns:
#   scam_score      int 0–100
#   risk_level      SAFE | LOW_RISK | SUSPICIOUS | HIGH_RISK | SCAM
#   flagged_keywords  list[str]
#   flagged_urls      list[str]
#   explanation       str  (contains markdown + emoji)
#   message_hash      str
#   url_analysis      dict {status, message}
#   ai_confidence     float
#   timestamp         str
#
# analyze_scam() must return the shared API schema:
#   riskScore   int
#   category    str
#   indicators  list[str]
#   summary     str
#   isScam      bool
# ---------------------------------------------------------------------------

# Maps AIService risk_level → canonical category for the API + blockchain
_RISK_TO_CATEGORY: Dict[str, str] = {
    "SCAM":       "phishing",    # generic fallback; extend if you add category detection
    "HIGH_RISK":  "other",
    "SUSPICIOUS": "other",
    "LOW_RISK":   "legitimate",
    "SAFE":       "legitimate",
}


def _adapt(raw: Dict) -> Dict:
    """Convert AIService result → shared analyze_scam() schema."""
    risk_level = raw.get("risk_level", "SAFE")
    scam_score = raw.get("scam_score", 0)
    is_scam    = scam_score >= 30 and risk_level not in ("SAFE", "LOW_RISK")

    # Build human-readable indicators list
    indicators: list[str] = []
    for kw in raw.get("flagged_keywords", []):
        indicators.append(f"Suspicious keyword: '{kw}'")
    for url in raw.get("flagged_urls", []):
        indicators.append(f"Suspicious URL detected: {url}")
    url_status = raw.get("url_analysis", {}).get("status", "none")
    if url_status in ("scam", "suspicious", "caution"):
        indicators.append(f"URL risk — {raw['url_analysis']['message']}")
    ai_conf = raw.get("ai_confidence", 0)
    ai_conf_pct = ai_conf * 100 if 0 <= ai_conf <= 1 else ai_conf
    if ai_conf > 0:
        indicators.append(f"AI model confidence: {ai_conf_pct:.0f}%")
    if not indicators and is_scam:
        indicators.append("Rule-based pattern match triggered")

    # Clean markdown + emoji from explanation to produce a plain summary
    summary = re.sub(r"[*_`]|[\U00010000-\U0010ffff]|[^\x00-\x7F]", "", raw.get("explanation", "")).strip()
    summary = re.sub(r"\s{2,}", " ", summary)

    return {
        "riskScore":  scam_score,
        "category":   raw.get("category") or _RISK_TO_CATEGORY.get(risk_level, "other"),
        "indicators": indicators,
        "summary":    summary,
        "isScam":     is_scam,
        # Full AIService output passed through for debugging / logging
        "_raw":       raw,
    }


# ---------------------------------------------------------------------------
# Public API — the only function main.py should call
# ---------------------------------------------------------------------------

async def analyze_scam(text: str, url: str = "") -> Dict:
    """
    Analyze `text` (and optional `url`) for scam indicators.

        Delegates to AIService which runs:
            1. MiniLM sentence-embedding similarity scoring (if model loaded)
            2. Keyword / urgency / URL / phishing / impersonation rule scores
            3. Weighted combination → scam_score 0–100

    Returns:
        {
            "riskScore":  int,          # 0–100
            "category":   str,          # phishing | other | legitimate
            "indicators": list[str],    # human-readable flags
            "summary":    str,          # plain-text explanation
            "isScam":     bool,
            "_raw":       dict,         # full AIService output (strip before sending to frontend)
        }

    Raises:
        ValueError   if text is empty
        RuntimeError on model/service failure
    """
    if not text or not text.strip():
        raise ValueError("analyze_scam() requires non-empty text")

    try:
        service = await _get_service()
        raw     = await service.analyze_message(text.strip(), url)
        return _adapt(raw)
    except ValueError:
        raise
    except Exception as e:
        raise RuntimeError(f"AIService.analyze_message() failed: {e}") from e


# ---------------------------------------------------------------------------
# Lifespan hooks — wire these into FastAPI startup/shutdown
# ---------------------------------------------------------------------------

async def startup():
    """Pre-warm the model at server start so the first request isn't slow."""
    await _get_service()


async def shutdown():
    """Release GPU memory and model resources on server shutdown."""
    global _service
    if _service is not None:
        await _service.cleanup()
        _service = None
        _ready.clear()
        logger.info("AIService shut down")


# ---------------------------------------------------------------------------
# Smoke test  →  python ai_analyzer.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json

    samples = [
        (
            "Congratulations! Your PayPal account has been suspended. "
            "Verify immediately at http://paypa1-secure-login.tk or lose access forever!",
            "http://paypa1-secure-login.tk",
        ),
        (
            "Hey, just wanted to confirm our meeting tomorrow at 3pm.",
            "",
        ),
    ]

    async def run():
        for text, url in samples:
            result = await analyze_scam(text, url)
            clean  = {k: v for k, v in result.items() if k != "_raw"}
            print(json.dumps(clean, indent=2))
            print()

    asyncio.run(run())

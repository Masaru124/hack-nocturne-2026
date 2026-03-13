import pytest

import ai_analyzer


def test_adapt_builds_expected_schema():
    raw = {
        "scam_score": 75,
        "risk_level": "HIGH_RISK",
        "flagged_keywords": ["urgent", "wallet"],
        "flagged_urls": ["http://bad.tk"],
        "url_analysis": {"status": "suspicious", "message": "suspicious url"},
        "ai_confidence": 0.63,
        "explanation": "⚠️ **Scam** _likely_",
        "timestamp": "123",
    }

    adapted = ai_analyzer._adapt(raw)

    assert adapted["riskScore"] == 75
    assert adapted["category"] == "other"
    assert adapted["isScam"] is True
    assert any("Suspicious keyword" in item for item in adapted["indicators"])
    assert any("Suspicious URL detected" in item for item in adapted["indicators"])
    assert "Scam likely" in adapted["summary"]
    assert adapted["_raw"] == raw


@pytest.mark.asyncio
async def test_analyze_scam_requires_non_empty_text():
    with pytest.raises(ValueError, match="non-empty"):
        await ai_analyzer.analyze_scam("   ")


@pytest.mark.asyncio
async def test_analyze_scam_wraps_service_failure(monkeypatch):
    class BrokenService:
        async def analyze_message(self, _text, _url):
            raise RuntimeError("backend failure")

    async def _get_service():
        return BrokenService()

    monkeypatch.setattr(ai_analyzer, "_get_service", _get_service)

    with pytest.raises(RuntimeError, match=r"AIService\.analyze_message\(\) failed"):
        await ai_analyzer.analyze_scam("hello", "")


@pytest.mark.asyncio
async def test_startup_and_shutdown(monkeypatch):
    class FakeService:
        def __init__(self):
            self.cleaned = False

        async def initialize(self):
            return None

        async def cleanup(self):
            self.cleaned = True

    created = {"service": None}

    class FakeAIServiceFactory:
        def __call__(self):
            svc = FakeService()
            created["service"] = svc
            return svc

    monkeypatch.setattr(ai_analyzer, "AIService", FakeAIServiceFactory())
    ai_analyzer._service = None
    ai_analyzer._ready.clear()

    await ai_analyzer.startup()
    assert ai_analyzer._service is created["service"]
    assert ai_analyzer._ready.is_set()

    await ai_analyzer.shutdown()
    assert created["service"].cleaned is True
    assert ai_analyzer._service is None
    assert ai_analyzer._ready.is_set() is False

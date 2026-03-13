import numpy as np
import pytest

from app.services.ai_service import AIService


@pytest.mark.asyncio
async def test_analyze_message_rules_only_mode():
    service = AIService()
    service._initialized = True
    service.model_loaded = False

    result = await service.analyze_message(
        "Urgent, verify your account and share your private key now",
        "http://bad.tk",
    )

    assert result["scam_score"] >= 60
    assert result["risk_level"] in {"HIGH_RISK", "SCAM"}
    assert result["ai_confidence"] == 0.55
    assert result["category"] in {
        "phishing",
        "prize_scam",
        "crypto_scam",
        "impersonation",
        "other",
        "legitimate",
    }


@pytest.mark.asyncio
async def test_analyze_message_fuses_ml_and_rules(monkeypatch):
    service = AIService()
    service._initialized = True
    service.model_loaded = True

    monkeypatch.setattr(service, "_run_ml", lambda text: (80.0, "crypto_scam", 0.9))
    monkeypatch.setattr(service, "_run_rules", lambda text, url="": (20.0, {}))

    result = await service.analyze_message("hello", "")

    assert result["scam_score"] == 56
    assert result["risk_level"] == "SUSPICIOUS"
    assert result["category"] == "crypto_scam"
    assert result["ai_confidence"] == 0.9


def test_run_ml_prefers_legitimate_when_legit_similarity_higher():
    class FakeModel:
        @staticmethod
        def encode(_items, convert_to_numpy=True):
            return np.array([[1.0, 0.0]], dtype=float)

    service = AIService()
    service.model = FakeModel()
    service.model_loaded = True
    service._scam_embeddings = {
        "phishing": np.array([0.0, 1.0], dtype=float),
        "crypto_scam": np.array([0.0, 1.0], dtype=float),
    }
    service._legit_embedding = np.array([1.0, 0.0], dtype=float)

    ml_score, category, confidence = service._run_ml("normal meeting reminder")

    assert ml_score == 0.0
    assert category == "legitimate"
    assert confidence == 0.0


def test_cosine_handles_zero_vector():
    score = AIService._cosine(np.array([0.0, 0.0]), np.array([1.0, 2.0]))
    assert score == 0.0


def test_url_risk_score_detects_phishing_like_domain():
    service = AIService()
    score = service._url_risk_score("http://paypa1-secure-login.tk/verify")
    assert score >= 70
    analysis = service._analyze_url("http://paypa1-secure-login.tk/verify")
    assert analysis["status"] == "scam"


def test_url_risk_score_detects_free_hosting_typosquat_domain():
    service = AIService()
    score = service._url_risk_score("https://btttelecommunniccatiion.weeblysite.com/")
    assert score >= 70
    analysis = service._analyze_url("https://btttelecommunniccatiion.weeblysite.com/")
    assert analysis["status"] == "scam"


def test_url_risk_score_keeps_trusted_root_domain_safe():
    service = AIService()
    score = service._url_risk_score("https://www.netflix.com/")
    assert score == 0.0
    analysis = service._analyze_url("https://www.netflix.com/")
    assert analysis["status"] == "safe"


def test_url_model_score_with_phishing_label():
    service = AIService()
    service.url_model_loaded = True
    service.url_classifier = lambda x: [{"label": "phishing", "score": 0.92}]

    score = service._url_model_score("paypa1-secure-login.tk")
    assert score == 92.0


def test_url_model_score_with_benign_label_inverts_confidence():
    service = AIService()
    service.url_model_loaded = True
    service.url_classifier = lambda x: [{"label": "benign", "score": 0.8}]

    score = service._url_model_score("example.com")
    assert round(score, 1) == 20.0


def test_normalize_url_for_model():
    normalized = AIService._normalize_url_for_model("https://PayPal.com/login?x=1")
    assert normalized == "paypal.com/login?x=1"


def test_url_semantic_score_without_external_classifier():
    class FakeModel:
        @staticmethod
        def encode(_items, convert_to_numpy=True):
            return np.array([[1.0, 0.0]], dtype=float)

    service = AIService()
    service.model_loaded = True
    service.url_model_loaded = False
    service.model = FakeModel()
    service._url_phishing_embedding = np.array([1.0, 0.0], dtype=float)
    service._url_legit_embedding = np.array([0.0, 1.0], dtype=float)

    score = service._url_model_score("secure-coinbase-auth-check.info/login")
    assert score >= 90


@pytest.mark.asyncio
async def test_suspicious_url_enforces_minimum_risk(monkeypatch):
    service = AIService()
    service._initialized = True
    service.model_loaded = True

    monkeypatch.setattr(service, "_run_ml", lambda text: (10.0, "legitimate", 0.3))
    monkeypatch.setattr(service, "_run_rules", lambda text, url="": (5.0, {}))
    monkeypatch.setattr(service, "_analyze_url", lambda url: {"status": "scam", "message": "bad"})

    result = await service.analyze_message("please verify", "http://bad.tk")

    assert result["scam_score"] >= 75
    assert result["risk_level"] in {"HIGH_RISK", "SCAM"}
    assert result["category"] == "phishing"


@pytest.mark.asyncio
async def test_url_risk_signal_overrides_low_ml_output(monkeypatch):
    service = AIService()
    service._initialized = True
    service.model_loaded = True

    monkeypatch.setattr(service, "_run_ml", lambda text: (5.0, "romance_scam", 0.25))
    monkeypatch.setattr(service, "_run_rules", lambda text, url="": (15.0, {"url_risk": {"hits": 1, "contribution": 30}}))
    monkeypatch.setattr(service, "_analyze_url", lambda url: {"status": "safe", "message": "No obvious URL red flags"})

    result = await service.analyze_message("check this link", "http://bad-login-example.xyz")

    assert result["scam_score"] >= 70
    assert result["isScam"] if "isScam" in result else True
    assert result["category"] == "phishing"
    assert result["flagged_urls"] == ["http://bad-login-example.xyz"]


@pytest.mark.asyncio
async def test_extracts_url_from_text_when_url_param_empty(monkeypatch):
    service = AIService()
    service._initialized = True
    service.model_loaded = False

    monkeypatch.setattr(service, "_analyze_url", lambda url: {"status": "scam", "message": "bad"})

    result = await service.analyze_message("Click now: http://paypa1-secure-login.tk", "")

    assert result["flagged_urls"] == ["http://paypa1-secure-login.tk"]
    assert result["scam_score"] >= 75


@pytest.mark.asyncio
async def test_extracts_naked_domain_from_text(monkeypatch):
    service = AIService()
    service._initialized = True
    service.model_loaded = False

    monkeypatch.setattr(service, "_analyze_url", lambda url: {"status": "scam", "message": "bad"})

    result = await service.analyze_message("Visit paypa1-secure-login.tk to verify your wallet", "")

    assert result["flagged_urls"][0].startswith("http://")
    assert "paypa1-secure-login.tk" in result["flagged_urls"][0]


@pytest.mark.asyncio
async def test_trusted_https_domain_forces_legitimate_low_risk(monkeypatch):
    service = AIService()
    service._initialized = True
    service.model_loaded = True

    monkeypatch.setattr(service, "_run_ml", lambda text: (32.0, "romance_scam", 0.23))
    monkeypatch.setattr(service, "_run_rules", lambda text, url="": (0.0, {}))
    monkeypatch.setattr(service, "_analyze_url", lambda url: {"status": "safe", "message": "No obvious URL red flags"})

    result = await service.analyze_message("hi", "https://www.netflix.com/")

    assert result["scam_score"] <= 10
    assert result["risk_level"] == "SAFE"
    assert result["category"] == "legitimate"
    assert result["flagged_urls"] == []

import pytest
from fastapi.testclient import TestClient

import main


def _no_lifespan(monkeypatch):
    async def _startup():
        return None

    async def _shutdown():
        return None

    monkeypatch.setattr(main, "ai_startup", _startup)
    monkeypatch.setattr(main, "ai_shutdown", _shutdown)


def test_scan_rejects_empty_text(monkeypatch):
    _no_lifespan(monkeypatch)
    with TestClient(main.app) as client:
        resp = client.post("/api/scan", json={"text": "   ", "url": ""})
    assert resp.status_code == 400
    assert resp.json()["detail"] == "text must not be empty"


def test_scan_success_formats_raw_detail(monkeypatch):
    _no_lifespan(monkeypatch)

    async def _analyze(_text, _url):
        return {
            "riskScore": 88,
            "category": "phishing",
            "indicators": ["k1"],
            "summary": "summary",
            "isScam": True,
            "_raw": {
                "scam_score": 88,
                "risk_level": "SCAM",
                "flagged_keywords": ["urgent"],
                "flagged_urls": ["http://bad.tk"],
                "url_analysis": {"status": "scam", "message": "bad"},
                "ai_confidence": 0.8,
                "timestamp": "123",
                "message_hash": "0xabc",
            },
        }

    monkeypatch.setattr(main, "analyze_scam", _analyze)

    with TestClient(main.app) as client:
        resp = client.post("/api/scan", json={"text": "hello", "url": "http://bad.tk"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["riskScore"] == 88
    assert body["category"] == "phishing"
    assert body["rawDetail"]["scamScore"] == 88
    assert body["rawDetail"]["riskLevel"] == "SCAM"
    assert body["rawDetail"]["messageHash"] == "0xabc"


@pytest.mark.parametrize(
    "exc,expected",
    [(ValueError("bad input"), 400), (RuntimeError("upstream down"), 502)],
)
def test_scan_maps_analyze_errors(monkeypatch, exc, expected):
    _no_lifespan(monkeypatch)

    async def _analyze(_text, _url):
        raise exc

    monkeypatch.setattr(main, "analyze_scam", _analyze)

    with TestClient(main.app) as client:
        resp = client.post("/api/scan", json={"text": "hello", "url": ""})

    assert resp.status_code == expected


def test_report_rejects_non_scam(monkeypatch):
    _no_lifespan(monkeypatch)

    async def _analyze(_text, _url):
        return {
            "riskScore": 10,
            "category": "legitimate",
            "indicators": [],
            "summary": "safe",
            "isScam": False,
            "_raw": {},
        }

    monkeypatch.setattr(main, "analyze_scam", _analyze)

    with TestClient(main.app) as client:
        resp = client.post("/api/report", json={"text": "normal text", "url": ""})

    assert resp.status_code == 400
    assert "does not meet scam threshold" in resp.json()["detail"]


def test_report_success(monkeypatch):
    _no_lifespan(monkeypatch)

    async def _analyze(_text, _url):
        return {
            "riskScore": 70,
            "category": "phishing",
            "indicators": ["kw"],
            "summary": "scam",
            "isScam": True,
            "_raw": {},
        }

    monkeypatch.setattr(main, "analyze_scam", _analyze)
    monkeypatch.setattr(main, "submit_report", lambda text, category, risk_score, actual_reporter=None: "0xtx")

    with TestClient(main.app) as client:
        resp = client.post("/api/report", json={"text": "scam", "url": ""})

    assert resp.status_code == 200
    body = resp.json()
    assert body["txHash"] == "0xtx"
    assert body["polygonscan"].endswith("/0xtx")
    assert body["analysis"]["riskScore"] == 70


def test_report_success_with_user_wallet(monkeypatch):
    _no_lifespan(monkeypatch)

    async def _analyze(_text, _url):
        return {
            "riskScore": 70,
            "category": "phishing",
            "indicators": ["kw"],
            "summary": "scam",
            "isScam": True,
            "_raw": {},
        }

    observed = {"actual_reporter": None}

    def _submit(text, category, risk_score, actual_reporter=None):
        observed["actual_reporter"] = actual_reporter
        return "0xwallettx"

    monkeypatch.setattr(main, "analyze_scam", _analyze)
    monkeypatch.setattr(main, "submit_report", _submit)

    with TestClient(main.app) as client:
        resp = client.post(
            "/api/report",
            json={
                "text": "scam",
                "url": "",
                "reporterAddress": "0x1111111111111111111111111111111111111111",
            },
        )

    assert resp.status_code == 200
    assert observed["actual_reporter"] == "0x1111111111111111111111111111111111111111"
    assert resp.json()["txHash"] == "0xwallettx"


def test_report_maps_ai_and_chain_errors(monkeypatch):
    _no_lifespan(monkeypatch)

    async def _analyze_fail(_text, _url):
        raise RuntimeError("AI unavailable")

    monkeypatch.setattr(main, "analyze_scam", _analyze_fail)

    with TestClient(main.app) as client:
        ai_resp = client.post("/api/report", json={"text": "scam", "url": ""})

    assert ai_resp.status_code == 502
    assert "AI analysis failed" in ai_resp.json()["detail"]

    async def _analyze_ok(_text, _url):
        return {
            "riskScore": 80,
            "category": "phishing",
            "indicators": ["kw"],
            "summary": "scam",
            "isScam": True,
            "_raw": {},
        }

    monkeypatch.setattr(main, "analyze_scam", _analyze_ok)
    monkeypatch.setattr(
        main,
        "submit_report",
        lambda text, category, risk_score, actual_reporter=None: (_ for _ in ()).throw(EnvironmentError("missing env")),
    )

    with TestClient(main.app) as client:
        env_resp = client.post("/api/report", json={"text": "scam", "url": ""})

    assert env_resp.status_code == 503

    monkeypatch.setattr(
        main,
        "submit_report",
        lambda text, category, risk_score, actual_reporter=None: (_ for _ in ()).throw(RuntimeError("tx failed")),
    )

    with TestClient(main.app) as client:
        tx_resp = client.post("/api/report", json={"text": "scam", "url": ""})

    assert tx_resp.status_code == 502
    assert "Blockchain submission failed" in tx_resp.json()["detail"]


def test_reports_maps_chain_errors(monkeypatch):
    _no_lifespan(monkeypatch)

    monkeypatch.setattr(main, "get_all_reports", lambda: [{"reporter": "0x1"}])
    with TestClient(main.app) as client:
        ok = client.get("/api/reports")
    assert ok.status_code == 200
    assert ok.json() == [{"reporter": "0x1"}]

    monkeypatch.setattr(
        main,
        "get_all_reports",
        lambda: (_ for _ in ()).throw(EnvironmentError("missing env")),
    )
    with TestClient(main.app) as client:
        env = client.get("/api/reports")
    assert env.status_code == 503

    monkeypatch.setattr(
        main,
        "get_all_reports",
        lambda: (_ for _ in ()).throw(RuntimeError("rpc down")),
    )
    with TestClient(main.app) as client:
        fail = client.get("/api/reports")
    assert fail.status_code == 502

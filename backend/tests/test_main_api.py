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


def test_get_report_by_id_success_and_not_found(monkeypatch):
    _no_lifespan(monkeypatch)

    monkeypatch.setattr(
        main,
        "get_report",
        lambda report_id: {
            "id": report_id,
            "reporter": "0x1",
            "textHash": "0xabc",
            "category": "phishing",
            "riskScore": 85,
            "timestamp": 123,
            "votes": 2,
            "isVerified": True,
            "isCommunityReport": False,
        },
    )
    with TestClient(main.app) as client:
        ok = client.get("/api/reports/7")
    assert ok.status_code == 200
    assert ok.json()["id"] == 7

    monkeypatch.setattr(main, "get_report", lambda report_id: None)
    with TestClient(main.app) as client:
        missing = client.get("/api/reports/7")
    assert missing.status_code == 404


def test_get_report_by_id_maps_backend_errors(monkeypatch):
    _no_lifespan(monkeypatch)

    monkeypatch.setattr(
        main,
        "get_report",
        lambda report_id: (_ for _ in ()).throw(EnvironmentError("missing env")),
    )
    with TestClient(main.app) as client:
        env = client.get("/api/reports/1")
    assert env.status_code == 503

    monkeypatch.setattr(
        main,
        "get_report",
        lambda report_id: (_ for _ in ()).throw(RuntimeError("bad rpc")),
    )
    with TestClient(main.app) as client:
        fail = client.get("/api/reports/1")
    assert fail.status_code == 502


def test_get_report_by_hash_success_and_not_found(monkeypatch):
    _no_lifespan(monkeypatch)

    monkeypatch.setattr(
        main,
        "get_report_by_hash",
        lambda hash_hex: {
            "id": 3,
            "reporter": "0x1",
            "textHash": hash_hex,
            "category": "phishing",
            "riskScore": 99,
            "timestamp": 456,
            "votes": 5,
            "isVerified": False,
            "isCommunityReport": True,
        },
    )
    with TestClient(main.app) as client:
        ok = client.get("/api/reports/hash/0xabc")
    assert ok.status_code == 200
    assert ok.json()["textHash"] == "0xabc"

    monkeypatch.setattr(main, "get_report_by_hash", lambda hash_hex: None)
    with TestClient(main.app) as client:
        missing = client.get("/api/reports/hash/0xabc")
    assert missing.status_code == 404


def test_get_report_by_hash_maps_backend_errors(monkeypatch):
    _no_lifespan(monkeypatch)

    monkeypatch.setattr(
        main,
        "get_report_by_hash",
        lambda hash_hex: (_ for _ in ()).throw(EnvironmentError("missing env")),
    )
    with TestClient(main.app) as client:
        env = client.get("/api/reports/hash/0xabc")
    assert env.status_code == 503

    monkeypatch.setattr(
        main,
        "get_report_by_hash",
        lambda hash_hex: (_ for _ in ()).throw(RuntimeError("bad rpc")),
    )
    with TestClient(main.app) as client:
        fail = client.get("/api/reports/hash/0xabc")
    assert fail.status_code == 502


def test_stats_computes_summary(monkeypatch):
    _no_lifespan(monkeypatch)
    reports = [
        {"category": "phishing", "riskScore": 80, "timestamp": 10, "isVerified": True},
        {"category": "other", "riskScore": 40, "timestamp": 20, "isVerified": False},
        {"category": "phishing", "riskScore": 100, "timestamp": 15, "isVerified": True},
    ]
    monkeypatch.setattr(main, "get_all_reports", lambda: reports)

    with TestClient(main.app) as client:
        resp = client.get("/api/stats")

    assert resp.status_code == 200
    body = resp.json()
    assert body["totalReports"] == 3
    assert body["verifiedReports"] == 2
    assert body["categoryBreakdown"] == {"phishing": 2, "other": 1}
    assert body["averageRiskScore"] == 73.3
    assert body["highestRiskReport"]["riskScore"] == 100
    assert body["mostRecentReport"]["timestamp"] == 20


def test_stats_empty_and_error_paths(monkeypatch):
    _no_lifespan(monkeypatch)
    monkeypatch.setattr(main, "get_all_reports", lambda: [])
    with TestClient(main.app) as client:
        empty = client.get("/api/stats")
    assert empty.status_code == 200
    assert empty.json()["totalReports"] == 0
    assert empty.json()["averageRiskScore"] == 0

    monkeypatch.setattr(
        main,
        "get_all_reports",
        lambda: (_ for _ in ()).throw(EnvironmentError("missing env")),
    )
    with TestClient(main.app) as client:
        env = client.get("/api/stats")
    assert env.status_code == 503

    monkeypatch.setattr(
        main,
        "get_all_reports",
        lambda: (_ for _ in ()).throw(RuntimeError("bad rpc")),
    )
    with TestClient(main.app) as client:
        fail = client.get("/api/stats")
    assert fail.status_code == 502


def test_vote_success_and_errors(monkeypatch):
    _no_lifespan(monkeypatch)
    monkeypatch.setattr(main, "vote_on_report", lambda report_id: "0xvote")
    with TestClient(main.app) as client:
        ok = client.post("/api/vote", json={"reportId": 5})
    assert ok.status_code == 200
    assert ok.json()["txHash"] == "0xvote"

    monkeypatch.setattr(
        main,
        "vote_on_report",
        lambda report_id: (_ for _ in ()).throw(EnvironmentError("missing env")),
    )
    with TestClient(main.app) as client:
        env = client.post("/api/vote", json={"reportId": 5})
    assert env.status_code == 503

    monkeypatch.setattr(
        main,
        "vote_on_report",
        lambda report_id: (_ for _ in ()).throw(RuntimeError("vote failed")),
    )
    with TestClient(main.app) as client:
        fail = client.post("/api/vote", json={"reportId": 5})
    assert fail.status_code == 502


def test_check_requires_text_and_returns_result(monkeypatch):
    _no_lifespan(monkeypatch)

    with TestClient(main.app) as client:
        missing = client.get("/api/check", params={"text": "   "})
    assert missing.status_code == 400

    observed = {"hash_hex": None}

    def _check_hash(hash_hex):
        observed["hash_hex"] = hash_hex
        return {"exists": True, "report": {"id": 1}}

    monkeypatch.setattr(main, "check_hash", _check_hash)
    with TestClient(main.app) as client:
        ok = client.get("/api/check", params={"text": "hello world"})
    assert ok.status_code == 200
    assert ok.json() == {"exists": True, "report": {"id": 1}}
    assert observed["hash_hex"].startswith("0x")


def test_check_maps_backend_errors(monkeypatch):
    _no_lifespan(monkeypatch)

    monkeypatch.setattr(
        main,
        "check_hash",
        lambda hash_hex: (_ for _ in ()).throw(EnvironmentError("missing env")),
    )
    with TestClient(main.app) as client:
        env = client.get("/api/check", params={"text": "hello"})
    assert env.status_code == 503

    monkeypatch.setattr(
        main,
        "check_hash",
        lambda hash_hex: (_ for _ in ()).throw(RuntimeError("bad rpc")),
    )
    with TestClient(main.app) as client:
        fail = client.get("/api/check", params={"text": "hello"})
    assert fail.status_code == 502

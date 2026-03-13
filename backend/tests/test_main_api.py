import pytest
import requests
from fastapi.testclient import TestClient

import main


def _no_lifespan(monkeypatch):
    async def _startup():
        return None

    async def _shutdown():
        return None

    monkeypatch.setattr(main, "ai_startup", _startup)
    monkeypatch.setattr(main, "ai_shutdown", _shutdown)
    monkeypatch.setattr(main, "init_db", lambda: None)


def test_scan_rejects_empty_text(monkeypatch):
    _no_lifespan(monkeypatch)
    with TestClient(main.app) as client:
        resp = client.post("/api/scan", json={"text": "   ", "url": ""})
    assert resp.status_code == 400
    assert resp.json()["detail"] == "text or url must not be empty"


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
    monkeypatch.setattr(main, "_auto_report_scan_result", lambda result, url: {"attempted": False, "submitted": False, "alreadyReported": False, "txHash": None, "textHash": None})

    with TestClient(main.app) as client:
        resp = client.post("/api/scan", json={"text": "hello", "url": "http://bad.tk"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["riskScore"] == 88
    assert body["category"] == "phishing"
    assert body["autoReport"]["attempted"] is False
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


def test_scan_accepts_url_only_and_auto_reports_flagged_url(monkeypatch):
    _no_lifespan(monkeypatch)

    observed = {"analysis_text": None, "url": None, "submitted": False}

    async def _analyze(text, url):
        observed["analysis_text"] = text
        observed["url"] = url
        return {
            "riskScore": 92,
            "category": "phishing",
            "indicators": ["Suspicious URL detected"],
            "summary": "scam",
            "isScam": True,
            "_raw": {
                "scam_score": 92,
                "risk_level": "SCAM",
                "flagged_keywords": [],
                "flagged_urls": [url],
                "url_analysis": {"status": "scam", "message": "Malicious URL"},
                "ai_confidence": 0.9,
                "timestamp": "123",
                "message_hash": "0xabc",
            },
        }

    def _auto_report(result, url):
        observed["submitted"] = True
        assert result["riskScore"] == 92
        assert url == "https://secure-wallet-verification.weeblysite.com/login"
        return {"attempted": True, "submitted": True, "alreadyReported": False, "txHash": "0xtx", "textHash": "0xhash"}

    monkeypatch.setattr(main, "analyze_scam", _analyze)
    monkeypatch.setattr(main, "_auto_report_scan_result", _auto_report)

    with TestClient(main.app) as client:
        resp = client.post("/api/scan", json={"text": "", "url": "https://secure-wallet-verification.weeblysite.com/login"})

    assert resp.status_code == 200
    body = resp.json()
    assert observed["analysis_text"] == "https://secure-wallet-verification.weeblysite.com/login"
    assert observed["url"] == "https://secure-wallet-verification.weeblysite.com/login"
    assert observed["submitted"] is True
    assert body["autoReport"]["submitted"] is True
    assert body["autoReport"]["txHash"] == "0xtx"


def test_scan_maps_auto_report_errors(monkeypatch):
    _no_lifespan(monkeypatch)

    async def _analyze(text, url):
        return {
            "riskScore": 92,
            "category": "phishing",
            "indicators": [],
            "summary": "scam",
            "isScam": True,
            "_raw": {
                "scam_score": 92,
                "risk_level": "SCAM",
                "flagged_keywords": [],
                "flagged_urls": [url],
                "url_analysis": {"status": "scam", "message": "Malicious URL"},
                "ai_confidence": 0.9,
                "timestamp": "123",
                "message_hash": "0xabc",
            },
        }

    monkeypatch.setattr(main, "analyze_scam", _analyze)
    monkeypatch.setattr(main, "_auto_report_scan_result", lambda result, url: (_ for _ in ()).throw(RuntimeError("tx failed")))

    with TestClient(main.app) as client:
        resp = client.post("/api/scan", json={"text": "", "url": "https://bad.example"})

    assert resp.status_code == 502
    assert "Auto-report failed" in resp.json()["detail"]


def test_auto_report_scan_result_skips_duplicates(monkeypatch):
    monkeypatch.setattr(main, "hash_url", lambda url: "0xhash")
    monkeypatch.setattr(main, "check_hash", lambda hash_hex: {"exists": True, "report": {"id": 1}})

    result = main._auto_report_scan_result(
        {"riskScore": 91, "category": "phishing", "_raw": {"url_analysis": {"status": "scam"}}},
        "https://bad.example",
    )

    assert result == {
        "attempted": True,
        "submitted": False,
        "alreadyReported": True,
        "txHash": None,
        "textHash": "0xhash",
    }


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

    observed = {"saved_url": None, "submitted_text": None}

    monkeypatch.setattr(main, "analyze_scam", _analyze)
    monkeypatch.setattr(main, "save_url_hash", lambda url: observed.__setitem__("saved_url", url) or "0xhash")
    monkeypatch.setattr(
        main,
        "submit_report",
        lambda text, category, risk_score, actual_reporter=None: observed.__setitem__("submitted_text", text) or "0xtx",
    )

    with TestClient(main.app) as client:
        resp = client.post("/api/report", json={"text": "verify this", "url": "https://bad.example"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["txHash"] == "0xtx"
    assert body["textHash"] == "0xhash"
    assert body["polygonscan"].endswith("/0xtx")
    assert body["analysis"]["riskScore"] == 70
    assert observed["saved_url"] == "https://bad.example"
    assert observed["submitted_text"] == "https://bad.example"


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
    monkeypatch.setattr(main, "save_url_hash", lambda url: "0xhash")
    monkeypatch.setattr(main, "submit_report", _submit)

    with TestClient(main.app) as client:
        resp = client.post(
            "/api/report",
            json={
                "text": "scam",
                "url": "https://bad.example",
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
    monkeypatch.setattr(main, "save_url_hash", lambda url: "0xhash")
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
    monkeypatch.setattr(main, "enrich_reports", lambda reports: [{**reports[0], "url": "https://bad.example"}])
    with TestClient(main.app) as client:
        ok = client.get("/api/reports")
    assert ok.status_code == 200
    assert ok.json() == [{"reporter": "0x1", "url": "https://bad.example"}]

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
    monkeypatch.setattr(main, "enrich_report", lambda report: {**report, "url": "https://bad.example"})
    with TestClient(main.app) as client:
        ok = client.get("/api/reports/7")
    assert ok.status_code == 200
    assert ok.json()["id"] == 7
    assert ok.json()["url"] == "https://bad.example"

    monkeypatch.setattr(main, "get_report", lambda report_id: None)
    monkeypatch.setattr(main, "enrich_report", lambda report: report)
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
    monkeypatch.setattr(main, "enrich_report", lambda report: {**report, "url": "https://bad.example"})
    with TestClient(main.app) as client:
        ok = client.get("/api/reports/hash/0xabc")
    assert ok.status_code == 200
    assert ok.json()["textHash"] == "0xabc"
    assert ok.json()["url"] == "https://bad.example"

    monkeypatch.setattr(main, "get_report_by_hash", lambda hash_hex: None)
    monkeypatch.setattr(main, "enrich_report", lambda report: report)
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
        return {"exists": True, "report": {"id": 1, "riskScore": 91, "category": "phishing", "votes": 4}}

    monkeypatch.setattr(main, "check_hash", _check_hash)
    monkeypatch.setattr(main, "enrich_report", lambda report: {**report, "url": "https://bad.example"})
    with TestClient(main.app) as client:
        ok = client.get("/api/check", params={"text": "hello world"})
    assert ok.status_code == 200
    assert ok.json() == {
        "flagged": True,
        "exists": True,
        "riskScore": 91,
        "category": "phishing",
        "votes": 4,
        "report": {"id": 1, "riskScore": 91, "category": "phishing", "votes": 4, "url": "https://bad.example"},
    }
    assert observed["hash_hex"].startswith("0x")


def test_check_accepts_url_param(monkeypatch):
    _no_lifespan(monkeypatch)

    observed = {"hash_hex": None}

    def _check_hash(hash_hex):
        observed["hash_hex"] = hash_hex
        return {"exists": False, "report": None}

    monkeypatch.setattr(main, "check_hash", _check_hash)
    monkeypatch.setattr(main, "enrich_report", lambda report: report)

    with TestClient(main.app) as client:
        ok = client.get("/api/check", params={"url": "https://bad.example"})

    assert ok.status_code == 200
    assert ok.json()["flagged"] is False
    assert ok.json()["exists"] is False
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


def test_honeytrap_run_success_and_wallet_submit(monkeypatch):
    _no_lifespan(monkeypatch)

    monkeypatch.setattr(
        main,
        "run_honeytrap_bot",
        lambda url, persona: {
            "url": url,
            "domain": "fake-airdrop.xyz",
            "domainRisk": 92,
            "scamNetworkRisk": 97,
            "connectedDomains": 3,
            "sharedWallets": 2,
            "activeCampaign": True,
            "wallets": ["0x1234567890abcdef1234567890abcdef12345678"],
            "telegramIds": ["@crypto_airdrop_admin"],
            "emails": ["scam@fake-airdrop.xyz"],
            "paymentInstructions": ["Send 0.2 ETH to verify wallet"],
            "evidence": ["Detected links: 12"],
            "urlAnalysis": {"status": "scam", "score": 92},
        },
    )
    monkeypatch.setattr(main, "check_hash", lambda hash_hex: {"exists": False, "report": None})
    monkeypatch.setattr(main, "submit_report", lambda text, category, risk_score, actual_reporter=None: "0xtx")
    monkeypatch.setattr(main, "save_honeytrap_intel", lambda result: 11)

    with TestClient(main.app) as client:
        resp = client.post(
            "/api/honeytrap/run",
            json={"url": "https://fake-airdrop.xyz", "persona": "test persona"},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["intelId"] == 11
    assert body["walletBlockchainReport"]["attempted"] is True
    assert body["walletBlockchainReport"]["submitted"] is True
    assert body["walletBlockchainReport"]["txHash"] == "0xtx"


def test_honeytrap_run_duplicate_wallet_not_submitted(monkeypatch):
    _no_lifespan(monkeypatch)

    monkeypatch.setattr(
        main,
        "run_honeytrap_bot",
        lambda url, persona: {
            "url": url,
            "domain": "fake-airdrop.xyz",
            "domainRisk": 70,
            "scamNetworkRisk": 75,
            "connectedDomains": 0,
            "sharedWallets": 0,
            "activeCampaign": False,
            "wallets": ["0x1234567890abcdef1234567890abcdef12345678"],
            "telegramIds": [],
            "emails": [],
            "paymentInstructions": [],
            "evidence": [],
            "urlAnalysis": {"status": "high_risk", "score": 70},
        },
    )
    monkeypatch.setattr(main, "check_hash", lambda hash_hex: {"exists": True, "report": {"id": 1}})
    monkeypatch.setattr(main, "save_honeytrap_intel", lambda result: 12)

    with TestClient(main.app) as client:
        resp = client.post("/api/honeytrap/run", json={"url": "https://fake-airdrop.xyz"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["walletBlockchainReport"]["attempted"] is True
    assert body["walletBlockchainReport"]["alreadyReported"] is True
    assert body["walletBlockchainReport"]["submitted"] is False


def test_honeytrap_run_maps_errors(monkeypatch):
    _no_lifespan(monkeypatch)

    monkeypatch.setattr(main, "run_honeytrap_bot", lambda url, persona: (_ for _ in ()).throw(ValueError("url must not be empty")))
    with TestClient(main.app) as client:
        bad = client.post("/api/honeytrap/run", json={"url": ""})
    assert bad.status_code == 400

    monkeypatch.setattr(
        main,
        "run_honeytrap_bot",
        lambda url, persona: {
            "url": url,
            "domain": "x",
            "domainRisk": 88,
            "scamNetworkRisk": 90,
            "connectedDomains": 0,
            "sharedWallets": 0,
            "activeCampaign": False,
            "wallets": ["0x1234567890abcdef1234567890abcdef12345678"],
            "telegramIds": [],
            "emails": [],
            "paymentInstructions": [],
            "evidence": [],
            "urlAnalysis": {"status": "scam", "score": 88},
        },
    )
    monkeypatch.setattr(main, "check_hash", lambda hash_hex: (_ for _ in ()).throw(EnvironmentError("missing env")))
    monkeypatch.setattr(main, "save_honeytrap_intel", lambda result: 13)
    with TestClient(main.app) as client:
        env = client.post("/api/honeytrap/run", json={"url": "https://x.y"})
    assert env.status_code == 200
    assert env.json()["walletBlockchainReport"]["submitted"] is False
    assert "missing env" in env.json()["walletBlockchainReport"]["error"]

    monkeypatch.setattr(main, "check_hash", lambda hash_hex: (_ for _ in ()).throw(RuntimeError("rpc fail")))
    monkeypatch.setattr(main, "save_honeytrap_intel", lambda result: 14)
    with TestClient(main.app) as client:
        fail = client.post("/api/honeytrap/run", json={"url": "https://x.y"})
    assert fail.status_code == 200
    assert fail.json()["walletBlockchainReport"]["submitted"] is False
    assert "rpc fail" in fail.json()["walletBlockchainReport"]["error"]


def test_honeytrap_run_submit_report_insufficient_funds_is_non_fatal(monkeypatch):
    _no_lifespan(monkeypatch)

    monkeypatch.setattr(
        main,
        "run_honeytrap_bot",
        lambda url, persona: {
            "url": url,
            "domain": "x",
            "domainRisk": 88,
            "scamNetworkRisk": 90,
            "connectedDomains": 0,
            "sharedWallets": 0,
            "activeCampaign": False,
            "wallets": ["0x1234567890abcdef1234567890abcdef12345678"],
            "telegramIds": [],
            "emails": [],
            "paymentInstructions": [],
            "evidence": [],
            "urlAnalysis": {"status": "scam", "score": 88},
        },
    )
    monkeypatch.setattr(main, "check_hash", lambda hash_hex: {"exists": False, "report": None})
    monkeypatch.setattr(main, "submit_report", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("INTERNAL_ERROR: insufficient funds")))
    monkeypatch.setattr(main, "save_honeytrap_intel", lambda result: 15)

    with TestClient(main.app) as client:
        resp = client.post("/api/honeytrap/run", json={"url": "https://x.y"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["walletBlockchainReport"]["attempted"] is True
    assert body["walletBlockchainReport"]["submitted"] is False
    assert "insufficient funds" in body["walletBlockchainReport"]["error"]


def test_honeytrap_run_crawl_timeout_not_misclassified(monkeypatch):
    _no_lifespan(monkeypatch)

    monkeypatch.setattr(
        main,
        "run_honeytrap_bot",
        lambda url, persona: (_ for _ in ()).throw(
            requests.exceptions.ConnectTimeout("Connection to target timed out")
        ),
    )

    with TestClient(main.app) as client:
        resp = client.post("/api/honeytrap/run", json={"url": "https://www.pashminaonline.com/pure-pashminas"})

    assert resp.status_code == 504
    assert "Honeytrap crawl timed out" in resp.json()["detail"]


def test_honeytrap_intel_list(monkeypatch):
    _no_lifespan(monkeypatch)
    monkeypatch.setattr(main, "get_honeytrap_intel", lambda limit, domain=None: [{"id": 1, "domain": "fake-airdrop.xyz"}])

    with TestClient(main.app) as client:
        resp = client.get("/api/honeytrap/intel", params={"limit": 10})

    assert resp.status_code == 200
    assert resp.json() == [{"id": 1, "domain": "fake-airdrop.xyz"}]


def test_honeytrap_intel_list_with_domain_filter(monkeypatch):
    _no_lifespan(monkeypatch)

    seen = {"domain": None}

    def _intel(limit, domain=None):
        seen["domain"] = domain
        return [{"id": 2, "domain": domain}]

    monkeypatch.setattr(main, "get_honeytrap_intel", _intel)

    with TestClient(main.app) as client:
        resp = client.get("/api/honeytrap/intel", params={"limit": 5, "domain": "www.fake-airdrop.xyz"})

    assert resp.status_code == 200
    assert seen["domain"] == "fake-airdrop.xyz"
    assert resp.json() == [{"id": 2, "domain": "fake-airdrop.xyz"}]

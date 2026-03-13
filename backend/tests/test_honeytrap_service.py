import honeytrap_service as hs
import requests


def test_honeytrap_uses_url_heuristics_when_crawl_sparse(monkeypatch):
    monkeypatch.setattr(hs, "_crawl_with_playwright", lambda url: (_ for _ in ()).throw(RuntimeError("no browser")))
    monkeypatch.setattr(
        hs,
        "_crawl_with_requests",
        lambda url: {
            "pageText": "",
            "scriptText": "",
            "title": "",
            "links": [],
            "formIntel": [],
            "chatExchanges": [],
            "chatWidgets": [],
            "redirects": [],
            "screenshotInitial": None,
            "screenshotAfter": None,
            "evidence": ["HTTP 404", "Links: 0"],
        },
    )
    monkeypatch.setattr(hs, "analyze_url", lambda url: {"status": "safe", "score": 0, "signals": []})
    monkeypatch.setattr(
        hs,
        "get_honeytrap_network_stats",
        lambda wallets, telegram_ids, domain: {
            "connectedDomains": 0,
            "sharedWallets": 0,
            "activeCampaign": False,
        },
    )

    result = hs.run_honeytrap_bot("https://secure-wallet-verification.weeblysite.com/login?honeytrap=1")

    assert result["domainRisk"] > 0
    assert any("URL signals:" in line for line in result["evidence"])


def test_honeytrap_extracts_indicators_from_url_fallback(monkeypatch):
    monkeypatch.setattr(hs, "_crawl_with_playwright", lambda url: (_ for _ in ()).throw(RuntimeError("no browser")))
    monkeypatch.setattr(
        hs,
        "_crawl_with_requests",
        lambda url: {
            "pageText": "",
            "scriptText": "",
            "title": "",
            "links": [],
            "formIntel": [],
            "chatExchanges": [],
            "chatWidgets": [],
            "redirects": [],
            "screenshotInitial": None,
            "screenshotAfter": None,
            "evidence": ["HTTP 403", "Links: 0"],
        },
    )
    monkeypatch.setattr(hs, "analyze_url", lambda url: {"status": "safe", "score": 0, "signals": []})
    monkeypatch.setattr(
        hs,
        "get_honeytrap_network_stats",
        lambda wallets, telegram_ids, domain: {
            "connectedDomains": 0,
            "sharedWallets": 0,
            "activeCampaign": False,
        },
    )

    url = "https://verify-bonus-claim.xyz/login?contact=@scamadmin&mail=scam%40phish.xyz&wallet=0x1234567890abcdef1234567890abcdef12345678"
    result = hs.run_honeytrap_bot(url)

    assert "0x1234567890abcdef1234567890abcdef12345678" in result["wallets"]
    assert "@scamadmin" in result["telegramIds"]
    assert "scam@phish.xyz" in result["emails"]


def test_honeytrap_handles_total_crawl_timeout_with_url_fallback(monkeypatch):
    monkeypatch.setattr(hs, "_crawl_with_playwright", lambda url: (_ for _ in ()).throw(RuntimeError("browser unavailable")))
    monkeypatch.setattr(
        hs,
        "_crawl_with_requests",
        lambda url: (_ for _ in ()).throw(requests.exceptions.ConnectTimeout("connect timeout=20")),
    )
    monkeypatch.setattr(hs, "analyze_url", lambda url: {"status": "safe", "score": 0, "signals": []})
    monkeypatch.setattr(
        hs,
        "get_honeytrap_network_stats",
        lambda wallets, telegram_ids, domain: {
            "connectedDomains": 0,
            "sharedWallets": 0,
            "activeCampaign": False,
        },
    )

    result = hs.run_honeytrap_bot("https://www.pashminaonline.com/pure-pashminas")

    assert result["url"] == "https://www.pashminaonline.com/pure-pashminas"
    assert result["domain"] == "pashminaonline.com"
    assert result["domainRisk"] >= 20
    assert any("Requests failed" in line for line in result["evidence"])
    assert any("Crawler: url_fallback" == line for line in result["evidence"])
    assert any("unreachable-target baseline" in line for line in result["evidence"])


def test_honeytrap_uses_external_domains_when_no_onchain_network(monkeypatch):
    monkeypatch.setattr(hs, "_crawl_with_playwright", lambda url, persona: (_ for _ in ()).throw(RuntimeError("no browser")))
    monkeypatch.setattr(
        hs,
        "_crawl_with_requests",
        lambda url: {
            "pageText": "verify your account",
            "scriptText": "",
            "title": "",
            "links": [
                "https://pay-gateway.example/checkout",
                "https://cdn-captcha.example/widget.js",
            ],
            "formIntel": [{"action": "https://collector.evil.tld/submit", "suspicious": True}],
            "chatExchanges": [],
            "chatWidgets": [],
            "redirects": ["https://jump.evil.tld/redirect"],
            "screenshotInitial": None,
            "screenshotAfter": None,
            "evidence": ["HTTP 200"],
        },
    )
    monkeypatch.setattr(hs, "analyze_url", lambda url: {"status": "safe", "score": 0, "signals": []})
    monkeypatch.setattr(
        hs,
        "get_honeytrap_network_stats",
        lambda wallets, telegram_ids, domain: {
            "connectedDomains": 0,
            "sharedWallets": 0,
            "activeCampaign": False,
        },
    )

    result = hs.run_honeytrap_bot("https://target.example/login")

    assert result["connectedDomains"] >= 1
    assert result["activeCampaign"] is True
    assert any("External domains observed:" in line for line in result["evidence"])


def test_honeytrap_crawl_diagnostics_for_playwright_and_dns_failures(monkeypatch):
    monkeypatch.setattr(
        hs,
        "_crawl_with_playwright",
        lambda url, persona: (_ for _ in ()).throw(ModuleNotFoundError("No module named 'playwright'")),
    )
    monkeypatch.setattr(
        hs,
        "_crawl_with_requests",
        lambda url: (_ for _ in ()).throw(RuntimeError("NameResolutionError: Failed to resolve target")),
    )
    monkeypatch.setattr(hs, "analyze_url", lambda url: {"status": "safe", "score": 0, "signals": []})
    monkeypatch.setattr(
        hs,
        "get_honeytrap_network_stats",
        lambda wallets, telegram_ids, domain: {
            "connectedDomains": 0,
            "sharedWallets": 0,
            "activeCampaign": False,
        },
    )

    result = hs.run_honeytrap_bot("https://www.pagarcelsia.st/")
    diagnostics = result["crawlDiagnostics"]

    assert diagnostics["unreachable"] is True
    assert diagnostics["playwrightMissing"] is True
    assert diagnostics["dnsFailure"] is True
    assert diagnostics["likelyCause"] == "playwright_missing_and_dns_failure"
    assert diagnostics["recommendations"]


def test_url_candidates_include_scheme_and_www_variants():
    variants = hs._url_candidates("https://target.example/login")

    assert "https://target.example/login" in variants
    assert "https://www.target.example/login" in variants
    assert "http://target.example/login" in variants

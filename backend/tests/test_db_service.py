from pathlib import Path

import db_service


def test_save_lookup_and_enrich_reports(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(db_service, "DB_PATH", tmp_path / "reports.db")

    db_service.init_db()
    hash_hex = db_service.save_url_hash("https://bad.example")

    assert db_service.lookup_url(hash_hex) == "https://bad.example"
    assert db_service.enrich_report({"textHash": hash_hex, "riskScore": 90}) == {
        "textHash": hash_hex,
        "riskScore": 90,
        "url": "https://bad.example",
    }


def test_enrich_reports_handles_missing_urls(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(db_service, "DB_PATH", tmp_path / "reports.db")

    db_service.init_db()
    first_hash = db_service.save_url_hash("https://bad.example")

    reports = db_service.enrich_reports(
        [
            {"textHash": first_hash, "riskScore": 99},
            {"textHash": "0xmissing", "riskScore": 1},
        ]
    )

    assert reports == [
        {"textHash": first_hash, "riskScore": 99, "url": "https://bad.example"},
        {"textHash": "0xmissing", "riskScore": 1, "url": None},
    ]


def test_save_and_load_honeytrap_intel(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(db_service, "DB_PATH", tmp_path / "reports.db")

    db_service.init_db()
    intel_id = db_service.save_honeytrap_intel(
        {
            "url": "https://fake-airdrop.xyz",
            "domain": "fake-airdrop.xyz",
            "domainRisk": 92,
            "scamNetworkRisk": 96,
            "connectedDomains": 3,
            "sharedWallets": 2,
            "activeCampaign": True,
            "wallets": ["0x1234567890abcdef1234567890abcdef12345678"],
            "telegramIds": ["@crypto_airdrop_admin"],
            "emails": ["scam@fake-airdrop.xyz"],
            "paymentInstructions": ["Send 0.2 ETH to verify wallet"],
            "evidence": ["Detected links: 12"],
        }
    )

    intel = db_service.get_honeytrap_intel(limit=5)
    assert intel_id == 1
    assert intel[0]["id"] == 1
    assert intel[0]["domain"] == "fake-airdrop.xyz"
    assert intel[0]["wallets"] == ["0x1234567890abcdef1234567890abcdef12345678"]
    assert intel[0]["activeCampaign"] is True


def test_honeytrap_network_stats_detects_links(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(db_service, "DB_PATH", tmp_path / "reports.db")
    db_service.init_db()

    db_service.save_honeytrap_intel(
        {
            "url": "https://first-scam.xyz",
            "domain": "first-scam.xyz",
            "domainRisk": 91,
            "scamNetworkRisk": 94,
            "connectedDomains": 0,
            "sharedWallets": 0,
            "activeCampaign": False,
            "wallets": ["0x1234567890abcdef1234567890abcdef12345678"],
            "telegramIds": ["@same_operator"],
            "emails": [],
            "paymentInstructions": [],
            "evidence": [],
        }
    )
    db_service.save_honeytrap_intel(
        {
            "url": "https://second-scam.xyz",
            "domain": "second-scam.xyz",
            "domainRisk": 89,
            "scamNetworkRisk": 91,
            "connectedDomains": 0,
            "sharedWallets": 0,
            "activeCampaign": False,
            "wallets": ["0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"],
            "telegramIds": ["@same_operator"],
            "emails": [],
            "paymentInstructions": [],
            "evidence": [],
        }
    )

    stats = db_service.get_honeytrap_network_stats(
        ["0x1234567890abcdef1234567890abcdef12345678"],
        ["@same_operator"],
        "new-scam.xyz",
    )

    assert stats["activeCampaign"] is True
    assert stats["connectedDomains"] >= 1
    assert stats["sharedWallets"] >= 1
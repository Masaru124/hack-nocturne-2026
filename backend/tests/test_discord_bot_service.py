import discord_bot_service as svc


def test_format_recent_reports_includes_feed_url(monkeypatch):
    service = svc.DiscordHistoryBotService()
    service.public_base_url = "https://demo.example"

    content = service._format_recent_reports(
        [
            {"id": 1, "timestamp": 100, "riskScore": 91, "category": "phishing", "url": "https://bad.example"},
            {"id": 2, "timestamp": 90, "riskScore": 55, "category": "other", "textHash": "0xabc"},
        ],
        5,
    )

    assert "Recent scam reports:" in content
    assert "[phishing] risk 91 - https://bad.example" in content
    assert "RSS: https://demo.example/api/feed.xml" in content


def test_format_recent_reports_empty():
    service = svc.DiscordHistoryBotService()
    assert service._format_recent_reports([], 5) == "No scam reports found yet."
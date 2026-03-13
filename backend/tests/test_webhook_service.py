import asyncio

import webhook_service as ws


class _Response:
    def raise_for_status(self):
        return None


class _AsyncClientStub:
    requests = []

    def __init__(self, *args, **kwargs):
        return None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, json):
        self.requests.append({"url": url, "json": json})
        return _Response()


def test_send_alert_posts_to_telegram(monkeypatch):
    monkeypatch.setattr(ws.httpx, "AsyncClient", _AsyncClientStub)

    service = ws.DiscordWebhookService()
    service.webhook_url = None
    service.discord_enabled = False
    service.telegram_bot_token = "test-token"
    service.telegram_chat_ids = ["12345"]
    service.telegram_enabled = True
    service.enabled = True

    _AsyncClientStub.requests.clear()

    result = asyncio.run(
        service.send_alert(
            title="Scam detected",
            description="Suspicious wallet drain flow found",
            fields={"Risk Score": "91/100"},
            url="https://example.com/scam",
        )
    )

    assert result is True
    assert len(_AsyncClientStub.requests) == 1
    payload = _AsyncClientStub.requests[0]
    assert payload["url"] == "https://api.telegram.org/bottest-token/sendMessage"
    assert payload["json"]["chat_id"] == "12345"
    assert payload["json"]["parse_mode"] == "HTML"
    assert "Scam detected" in payload["json"]["text"]


def test_send_alert_without_chat_id_skips_telegram(monkeypatch):
    monkeypatch.setattr(ws.httpx, "AsyncClient", _AsyncClientStub)

    service = ws.DiscordWebhookService()
    service.webhook_url = None
    service.discord_enabled = False
    service.telegram_bot_token = "test-token"
    service.telegram_chat_ids = []
    service.telegram_enabled = False
    service.enabled = True

    _AsyncClientStub.requests.clear()

    result = asyncio.run(service.send_alert(title="Test", description="Hello"))

    assert result is False
    assert _AsyncClientStub.requests == []
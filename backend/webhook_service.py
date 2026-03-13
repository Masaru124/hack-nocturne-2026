import os
import json
import logging
import html
import httpx
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class DiscordWebhookService:
    def __init__(self):
        self.webhook_url = os.getenv("webhook_url")
        self.telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN") or os.getenv("telegram_api")
        self.telegram_chat_ids = self._parse_telegram_chat_ids(
            os.getenv("TELEGRAM_CHAT_ID") or os.getenv("telegram_chat_id") or ""
        )
        self.discord_enabled = bool(self.webhook_url)
        self.telegram_enabled = bool(self.telegram_bot_token and self.telegram_chat_ids)
        self.enabled = self.discord_enabled or self.telegram_enabled

    def _parse_telegram_chat_ids(self, raw_value: str) -> list[str]:
        return [item.strip() for item in raw_value.split(",") if item.strip()]

    def _format_telegram_message(
        self,
        title: str,
        description: str,
        fields: Optional[Dict[str, Any]] = None,
        url: Optional[str] = None,
    ) -> str:
        lines = [f"<b>{html.escape(title)}</b>", html.escape(description)]

        if fields:
            for key, value in fields.items():
                lines.append(f"<b>{html.escape(str(key))}:</b> {html.escape(str(value))}")

        if url:
            safe_url = html.escape(url, quote=True)
            lines.append(f"<a href=\"{safe_url}\">Open link</a>")

        return "\n".join(lines)[:4000]

    def _recent_report_lines(self, reports: list[dict], limit: int) -> list[str]:
        selected = sorted(
            reports,
            key=lambda report: int(report.get("timestamp", 0) or 0),
            reverse=True,
        )[:limit]

        lines: list[str] = []
        for index, report in enumerate(selected, start=1):
            category = str(report.get("category", "unknown"))
            risk_score = int(report.get("riskScore", 0) or 0)
            report_url = (report.get("url") or "").strip()
            reference = report_url or (report.get("textHash") or f"id:{report.get('id', '?')}")
            lines.append(f"{index}. [{category}] risk {risk_score} - {reference}")
        return lines

    async def _send_telegram_message(self, message: str, chat_ids: Optional[list[str]] = None) -> bool:
        if not self.telegram_bot_token:
            return False

        target_chat_ids = chat_ids or self.telegram_chat_ids
        if not target_chat_ids:
            logger.warning("Telegram bot token configured but TELEGRAM_CHAT_ID is missing")
            return False

        endpoint = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
        delivered = False

        async with httpx.AsyncClient(timeout=10.0) as client:
            for chat_id in target_chat_ids:
                response = await client.post(
                    endpoint,
                    json={
                        "chat_id": chat_id,
                        "text": message[:4000],
                        "parse_mode": "HTML",
                        "disable_web_page_preview": False,
                    },
                )
                response.raise_for_status()
                delivered = True

        return delivered

    async def _send_discord_alert(
        self,
        title: str,
        description: str,
        color: int = 0xFF0000,
        fields: Optional[Dict[str, Any]] = None,
        url: Optional[str] = None,
    ) -> bool:
        if not self.discord_enabled:
            return False

        embed = {
            "title": title,
            "description": description,
            "color": color,
            "timestamp": datetime.utcnow().isoformat(),
            "footer": {
                "text": "ScamShield Real-time Alert"
            }
        }

        if fields:
            embed["fields"] = [
                {"name": k, "value": str(v), "inline": True}
                for k, v in fields.items()
            ]

        if url:
            embed["url"] = url

        payload = {
            "embeds": [embed],
            "username": "ScamShield Bot",
            "avatar_url": "https://i.imgur.com/3Z4j2rM.png"
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(self.webhook_url, json=payload)
            response.raise_for_status()

        logger.info("Discord alert sent: %s", title)
        return True

    async def _send_telegram_alert(
        self,
        title: str,
        description: str,
        fields: Optional[Dict[str, Any]] = None,
        url: Optional[str] = None,
    ) -> bool:
        if not self.telegram_bot_token:
            return False

        message = self._format_telegram_message(title, description, fields=fields, url=url)
        delivered = await self._send_telegram_message(message, self.telegram_chat_ids)

        if delivered:
            logger.info("Telegram alert sent: %s", title)
        return delivered

    async def send_telegram_text(self, chat_id: str, message: str) -> bool:
        return await self._send_telegram_message(message, [chat_id])

    async def recent_reports_digest(self, reports: list[dict], limit: int = 5) -> bool:
        lines = self._recent_report_lines(reports, limit)
        return await self.send_alert(
            title="Recent Scam Reports",
            description="Previously reported scam alerts from Nocturne",
            color=0x3366FF,
            fields={
                "Reports": "\n".join(lines) if lines else "No reports found",
                "Count": str(len(lines)),
            },
        )

    async def recent_reports_for_telegram(
        self,
        reports: list[dict],
        chat_id: str,
        limit: int = 5,
        feed_url: Optional[str] = None,
    ) -> bool:
        lines = self._recent_report_lines(reports, limit)
        body_lines = [
            "<b>Recent Scam Reports</b>",
            f"Showing the latest {len(lines)} reports.",
        ]

        if lines:
            body_lines.extend(html.escape(line) for line in lines)
        else:
            body_lines.append("No reports found.")

        if feed_url:
            safe_feed_url = html.escape(feed_url, quote=True)
            body_lines.append(f"<a href=\"{safe_feed_url}\">Open RSS feed</a>")

        return await self.send_telegram_text(chat_id, "\n".join(body_lines))
        
    async def send_alert(self, 
                    title: str, 
                    description: str, 
                    color: int = 0xFF0000,
                    fields: Optional[Dict[str, Any]] = None,
                    url: Optional[str] = None):
        """Send alert to every configured notification channel."""
        
        if not self.enabled:
            logger.warning("No alert channels configured")
            return False
            
        delivered = False

        try:
            delivered = await self._send_discord_alert(
                title,
                description,
                color=color,
                fields=fields,
                url=url,
            ) or delivered
        except Exception as e:
            logger.error("Failed to send Discord alert: %s", e)

        try:
            delivered = await self._send_telegram_alert(
                title,
                description,
                fields=fields,
                url=url,
            ) or delivered
        except Exception as e:
            logger.error("Failed to send Telegram alert: %s", e)

        return delivered
    
    async def scam_reported(self, url: str, category: str, risk_score: int, reporter: str = "System"):
        """Alert when new scam is reported"""
        
        color = self._risk_color(risk_score)
        
        return await self.send_alert(
            title="🚨 New Scam Reported",
            description=f"A new suspicious URL has been detected and reported",
            color=color,
            fields={
                "URL": url[:100] + "..." if len(url) > 100 else url,
                "Category": category,
                "Risk Score": f"{risk_score}/100",
                "Reporter": reporter
            },
            url=url
        )
    
    async def honeytrap_alert(self, url: str, intel: Dict[str, Any]):
        """Alert when honeytrap finds high-value intel"""
        
        wallets = intel.get("wallets", [])
        telegram = intel.get("telegramIds", [])
        emails = intel.get("emails", [])
        
        if not (wallets or telegram or emails):
            return False
            
        return await self.send_alert(
            title="🕵️ Honeytrap Intel Captured",
            description=f"High-value intelligence extracted from scam page",
            color=0x00FF00,
            fields={
                "URL": url[:80] + "..." if len(url) > 80 else url,
                "Wallets": f"{len(wallets)} found" if wallets else "None",
                "Telegram": f"{len(telegram)} found" if telegram else "None", 
                "Emails": f"{len(emails)} found" if emails else "None",
                "Domain Risk": f"{intel.get('domainRisk', 0)}/100",
                "Network Risk": f"{intel.get('scamNetworkRisk', 0)}/100"
            },
            url=url
        )
    
    async def ai_analysis_alert(self, url: str, attack_type: str, risk_score: int, confidence: int, indicators: list):
        """Alert when AI detects high-risk scam"""
        
        if risk_score < 70:
            return False  # Only alert for high-risk detections
            
        return await self.send_alert(
            title="⚡ AI High-Risk Detection",
            description=f"AI-powered analysis detected a dangerous scam",
            color=self._risk_color(risk_score),
            fields={
                "URL": url[:80] + "..." if len(url) > 80 else url,
                "Attack Type": attack_type,
                "Risk Score": f"{risk_score}/100",
                "Confidence": f"{confidence}%",
                "Indicators": "\n".join(indicators[:3])  # First 3 indicators
            },
            url=url
        )
    
    async def wallet_blockchain_reported(self, wallets: list, tx_hash: str):
        """Alert when scam wallets are reported to blockchain"""
        
        return await self.send_alert(
            title="⛓️ Wallets Reported to Blockchain",
            description=f"Scam wallet addresses have been submitted to blockchain",
            color=0xFF6600,
            fields={
                "Wallets Reported": str(len(wallets)),
                "Transaction": tx_hash[:20] + "..." if len(tx_hash) > 20 else tx_hash,
                "Network": "Polygon Amoy"
            },
            url=f"https://amoy.polygonscan.com/tx/{tx_hash}"
        )
    
    def _risk_color(self, risk_score: int) -> int:
        """Get Discord embed color based on risk score"""
        if risk_score >= 80:
            return 0xFF0000  # Red
        elif risk_score >= 60:
            return 0xFF6600  # Orange  
        elif risk_score >= 40:
            return 0xFFFF00  # Yellow
        else:
            return 0x00FF00  # Green

# Global webhook service instance
webhook_service = DiscordWebhookService()

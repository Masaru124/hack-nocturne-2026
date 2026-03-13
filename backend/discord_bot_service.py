import asyncio
import logging
import os
from typing import Callable, Optional

logger = logging.getLogger(__name__)

try:
    import discord
    from discord import app_commands
except ImportError:
    discord = None
    app_commands = None


class DiscordHistoryBotService:
    def __init__(self):
        self.bot_token = os.getenv("DISCORD_BOT_TOKEN") or os.getenv("discord_bot_token")
        self.guild_id = self._parse_guild_id(os.getenv("DISCORD_GUILD_ID") or os.getenv("discord_guild_id"))
        self.public_base_url = (os.getenv("PUBLIC_BASE_URL") or "").strip().rstrip("/")
        self.client = None
        self.tree = None
        self._task: Optional[asyncio.Task] = None
        self._fetch_recent_reports: Optional[Callable[[int], list[dict]]] = None

    def _parse_guild_id(self, raw_value: str | None) -> Optional[int]:
        if not raw_value:
            return None
        try:
            return int(raw_value)
        except ValueError:
            logger.warning("Invalid DISCORD_GUILD_ID value: %s", raw_value)
            return None

    @property
    def enabled(self) -> bool:
        return bool(self.bot_token and discord is not None)

    def _feed_url(self) -> str:
        if not self.public_base_url:
            return ""
        return f"{self.public_base_url}/api/feed.xml"

    def _format_recent_reports(self, reports: list[dict], limit: int) -> str:
        selected = sorted(
            reports,
            key=lambda report: int(report.get("timestamp", 0) or 0),
            reverse=True,
        )[:limit]

        if not selected:
            return "No scam reports found yet."

        lines = ["Recent scam reports:"]
        for index, report in enumerate(selected, start=1):
            category = str(report.get("category", "unknown"))
            risk_score = int(report.get("riskScore", 0) or 0)
            report_url = (report.get("url") or "").strip()
            target = report_url or (report.get("textHash") or f"id:{report.get('id', '?')}")
            lines.append(f"{index}. [{category}] risk {risk_score} - {target}")

        feed_url = self._feed_url()
        if feed_url:
            lines.append("")
            lines.append(f"RSS: {feed_url}")

        return "\n".join(lines)[:1900]

    async def _handle_history(self, interaction, limit: int):
        safe_limit = max(1, min(limit, 10))
        reports = self._fetch_recent_reports(safe_limit) if self._fetch_recent_reports else []
        content = self._format_recent_reports(reports, safe_limit)
        await interaction.response.send_message(content)

    async def _handle_feed(self, interaction):
        feed_url = self._feed_url()
        if not feed_url:
            await interaction.response.send_message("RSS feed URL is not configured yet. Set PUBLIC_BASE_URL first.", ephemeral=True)
            return
        await interaction.response.send_message(f"Nocturne RSS feed: {feed_url}")

    async def start(self, fetch_recent_reports: Callable[[int], list[dict]]):
        self._fetch_recent_reports = fetch_recent_reports

        if not self.bot_token:
            logger.info("Discord bot not configured; skipping startup")
            return
        if discord is None:
            logger.warning("discord.py is not installed; Discord bot commands are disabled")
            return
        if self._task and not self._task.done():
            return

        intents = discord.Intents.none()
        self.client = discord.Client(intents=intents)
        self.tree = app_commands.CommandTree(self.client)
        guild_object = discord.Object(id=self.guild_id) if self.guild_id else None

        @self.tree.command(name="history", description="Show recent scam reports", guild=guild_object)
        @app_commands.describe(limit="How many recent reports to show")
        async def history(interaction: discord.Interaction, limit: int = 5):
            await self._handle_history(interaction, limit)

        @self.tree.command(name="feed", description="Get the RSS feed URL", guild=guild_object)
        async def feed(interaction: discord.Interaction):
            await self._handle_feed(interaction)

        @self.client.event
        async def on_ready():
            logger.info("Discord history bot connected as %s", self.client.user)

        async def setup_hook():
            if guild_object:
                await self.tree.sync(guild=guild_object)
                logger.info("Discord slash commands synced to guild %s", self.guild_id)
            else:
                await self.tree.sync()
                logger.info("Discord global slash commands synced")

        self.client.setup_hook = setup_hook
        self._task = asyncio.create_task(self.client.start(self.bot_token))

    async def stop(self):
        if self.client is not None:
            await self.client.close()

        if self._task is not None:
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                logger.warning("Discord bot shutdown completed with error: %s", exc)
            finally:
                self._task = None
                self.client = None
                self.tree = None


discord_bot_service = DiscordHistoryBotService()
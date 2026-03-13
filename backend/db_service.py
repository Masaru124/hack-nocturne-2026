import os
import json
import sqlite3
from pathlib import Path

from web3 import Web3


DB_PATH = Path(os.getenv("SCAMSHIELD_DB_PATH") or Path(__file__).with_name("scam_reports.db"))


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with _connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS url_hashes (
                hash TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS honeytrap_intel (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                domain_risk INTEGER NOT NULL,
                scam_network_risk INTEGER NOT NULL,
                connected_domains INTEGER NOT NULL,
                shared_wallets INTEGER NOT NULL,
                active_campaign INTEGER NOT NULL,
                wallets_json TEXT NOT NULL,
                telegram_json TEXT NOT NULL,
                emails_json TEXT NOT NULL,
                payment_json TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


def hash_url(url: str) -> str:
    normalized = url.strip()
    if not normalized:
        raise ValueError("url must not be empty")
    return "0x" + Web3.keccak(text=normalized).hex()


def save_url_hash(url: str) -> str:
    normalized = url.strip()
    hash_hex = hash_url(normalized)

    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO url_hashes(hash, url)
            VALUES(?, ?)
            ON CONFLICT(hash) DO UPDATE SET url = excluded.url
            """,
            (hash_hex, normalized),
        )

    return hash_hex


def lookup_url(hash_hex: str) -> str | None:
    with _connect() as connection:
        row = connection.execute(
            "SELECT url FROM url_hashes WHERE hash = ?",
            (hash_hex,),
        ).fetchone()

    return row["url"] if row else None


def enrich_report(report: dict | None) -> dict | None:
    if not report:
        return report

    enriched = dict(report)
    enriched["url"] = lookup_url(report.get("textHash", ""))
    return enriched


def enrich_reports(reports: list[dict]) -> list[dict]:
    if not reports:
        return []

    hashes = [report.get("textHash") for report in reports if report.get("textHash")]
    if not hashes:
        return [dict(report, url=None) for report in reports]

    placeholders = ",".join("?" for _ in hashes)
    with _connect() as connection:
        rows = connection.execute(
            f"SELECT hash, url FROM url_hashes WHERE hash IN ({placeholders})",
            hashes,
        ).fetchall()

    urls_by_hash = {row["hash"]: row["url"] for row in rows}
    return [dict(report, url=urls_by_hash.get(report.get("textHash"))) for report in reports]


def _json_loads(value: str) -> list[str]:
    try:
        parsed = json.loads(value)
    except Exception:
        return []
    return parsed if isinstance(parsed, list) else []


def _normalize_domain(domain: str) -> str:
    return domain.strip().lower().removeprefix("www.")


def get_honeytrap_intel(limit: int = 30, domain: str | None = None) -> list[dict]:
    normalized_domain = _normalize_domain(domain) if domain else ""

    with _connect() as connection:
        if normalized_domain:
            rows = connection.execute(
                """
                SELECT id, url, domain, domain_risk, scam_network_risk,
                       connected_domains, shared_wallets, active_campaign,
                       wallets_json, telegram_json, emails_json, payment_json,
                       evidence_json, created_at
                FROM honeytrap_intel
                WHERE domain = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (normalized_domain, limit),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT id, url, domain, domain_risk, scam_network_risk,
                       connected_domains, shared_wallets, active_campaign,
                       wallets_json, telegram_json, emails_json, payment_json,
                       evidence_json, created_at
                FROM honeytrap_intel
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

    return [
        {
            "id": row["id"],
            "url": row["url"],
            "domain": row["domain"],
            "domainRisk": row["domain_risk"],
            "scamNetworkRisk": row["scam_network_risk"],
            "connectedDomains": row["connected_domains"],
            "sharedWallets": row["shared_wallets"],
            "activeCampaign": bool(row["active_campaign"]),
            "wallets": _json_loads(row["wallets_json"]),
            "telegramIds": _json_loads(row["telegram_json"]),
            "emails": _json_loads(row["emails_json"]),
            "paymentInstructions": _json_loads(row["payment_json"]),
            "evidence": _json_loads(row["evidence_json"]),
            "createdAt": row["created_at"],
        }
        for row in rows
    ]


def save_honeytrap_intel(result: dict) -> int:
    with _connect() as connection:
        cursor = connection.execute(
            """
            INSERT INTO honeytrap_intel (
                url, domain, domain_risk, scam_network_risk,
                connected_domains, shared_wallets, active_campaign,
                wallets_json, telegram_json, emails_json, payment_json,
                evidence_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.get("url", ""),
                result.get("domain", ""),
                int(result.get("domainRisk", 0)),
                int(result.get("scamNetworkRisk", 0)),
                int(result.get("connectedDomains", 0)),
                int(result.get("sharedWallets", 0)),
                1 if result.get("activeCampaign") else 0,
                json.dumps(result.get("wallets", [])),
                json.dumps(result.get("telegramIds", [])),
                json.dumps(result.get("emails", [])),
                json.dumps(result.get("paymentInstructions", [])),
                json.dumps(result.get("evidence", [])),
            ),
        )
        return int(cursor.lastrowid)


def get_honeytrap_network_stats(wallets: list[str], telegram_ids: list[str], domain: str) -> dict:
    intel = get_honeytrap_intel(limit=500)

    wallet_set = {w.lower() for w in wallets}
    tg_set = {t.lower() for t in telegram_ids}
    connected_domain_set: set[str] = set()
    shared_wallets = 0
    active_campaign = False

    for item in intel:
        item_wallets = {w.lower() for w in item.get("wallets", [])}
        item_tgs = {t.lower() for t in item.get("telegramIds", [])}

        wallet_overlap = wallet_set.intersection(item_wallets)
        tg_overlap = tg_set.intersection(item_tgs)

        if wallet_overlap or tg_overlap:
            active_campaign = True
            shared_wallets += len(wallet_overlap)
            if item.get("domain") and item.get("domain") != domain:
                connected_domain_set.add(item["domain"])

    return {
        "connectedDomains": len(connected_domain_set),
        "sharedWallets": shared_wallets,
        "activeCampaign": active_campaign,
    }
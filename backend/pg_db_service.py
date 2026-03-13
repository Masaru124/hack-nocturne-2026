import os
import json
from typing import List, Dict, Optional
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError
from dotenv import load_dotenv
from pathlib import Path

from web3 import Web3

load_dotenv(dotenv_path=Path(__file__).with_name(".env"))

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise EnvironmentError("DATABASE_URL is not set in .env")

# SQLAlchemy engine and session
# pool_pre_ping detects stale/dropped connections before use
# pool_recycle prevents long-lived SSL connections from going stale
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Initialize PostgreSQL database tables"""
    with engine.connect() as connection:
        # Create url_hashes table
        connection.execute(text("""
            CREATE TABLE IF NOT EXISTS url_hashes (
                hash TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))
        
        # Create honeytrap_intel table
        connection.execute(text("""
            CREATE TABLE IF NOT EXISTS honeytrap_intel (
                id SERIAL PRIMARY KEY,
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
        """))
        
        connection.commit()


def hash_url(url: str) -> str:
    """Hash URL using keccak256"""
    normalized = url.strip()
    if not normalized:
        raise ValueError("url must not be empty")
    return "0x" + Web3.keccak(text=normalized).hex()


def save_url_hash(url: str) -> str:
    """Save URL hash to PostgreSQL"""
    normalized = url.strip()
    hash_hex = hash_url(normalized)

    with engine.connect() as connection:
        connection.execute(text("""
            INSERT INTO url_hashes(hash, url)
            VALUES(:hash, :url)
            ON CONFLICT (hash) DO UPDATE SET url = excluded.url
        """), {"hash": hash_hex, "url": normalized})
        connection.commit()

    return hash_hex


def lookup_url(hash_hex: str) -> Optional[str]:
    """Lookup URL by hash from PostgreSQL"""
    with engine.connect() as connection:
        result = connection.execute(text("""
            SELECT url FROM url_hashes WHERE hash = :hash
        """), {"hash": hash_hex}).fetchone()
        
    return result[0] if result else None


def enrich_report(report: Optional[Dict]) -> Optional[Dict]:
    """Enrich a single report with URL information"""
    if not report:
        return report

    enriched = dict(report)
    enriched["url"] = lookup_url(report.get("textHash", ""))
    return enriched


def enrich_reports(reports: List[Dict]) -> List[Dict]:
    """Enrich multiple reports with URL information"""
    if not reports:
        return []

    hashes = [report.get("textHash") for report in reports if report.get("textHash")]
    if not hashes:
        return [dict(report, url=None) for report in reports]

    placeholders = ",".join(f":hash_{i}" for i in range(len(hashes)))
    params = {f"hash_{i}": hash_val for i, hash_val in enumerate(hashes)}
    
    with engine.connect() as connection:
        rows = connection.execute(text(f"""
            SELECT hash, url FROM url_hashes WHERE hash IN ({placeholders})
        """), params).fetchall()

    urls_by_hash = {row[0]: row[1] for row in rows}
    return [dict(report, url=urls_by_hash.get(report.get("textHash"))) for report in reports]


def _json_loads(value: str) -> List[str]:
    """Safely load JSON string"""
    try:
        parsed = json.loads(value)
    except Exception:
        return []
    return parsed if isinstance(parsed, list) else []


def _normalize_domain(domain: str) -> str:
    """Normalize domain name"""
    return domain.strip().lower().removeprefix("www.")


def get_honeytrap_intel(limit: int = 30, domain: Optional[str] = None) -> List[Dict]:
    """Get honeytrap intelligence from PostgreSQL"""
    normalized_domain = _normalize_domain(domain) if domain else ""

    with engine.connect() as connection:
        if normalized_domain:
            rows = connection.execute(text("""
                SELECT id, url, domain, domain_risk, scam_network_risk,
                       connected_domains, shared_wallets, active_campaign,
                       wallets_json, telegram_json, emails_json, payment_json,
                       evidence_json, created_at
                FROM honeytrap_intel
                WHERE domain = :domain
                ORDER BY id DESC
                LIMIT :limit
            """), {"domain": normalized_domain, "limit": limit}).fetchall()
        else:
            rows = connection.execute(text("""
                SELECT id, url, domain, domain_risk, scam_network_risk,
                       connected_domains, shared_wallets, active_campaign,
                       wallets_json, telegram_json, emails_json, payment_json,
                       evidence_json, created_at
                FROM honeytrap_intel
                ORDER BY id DESC
                LIMIT :limit
            """), {"limit": limit}).fetchall()

    return [
        {
            "id": row[0],
            "url": row[1],
            "domain": row[2],
            "domainRisk": row[3],
            "scamNetworkRisk": row[4],
            "connectedDomains": row[5],
            "sharedWallets": row[6],
            "activeCampaign": bool(row[7]),
            "wallets": _json_loads(row[8]),
            "telegramIds": _json_loads(row[9]),
            "emails": _json_loads(row[10]),
            "paymentInstructions": _json_loads(row[11]),
            "evidence": _json_loads(row[12]),
            "createdAt": row[13],
        }
        for row in rows
    ]


def save_honeytrap_intel(result: Dict) -> int:
    """Save honeytrap intelligence to PostgreSQL"""
    with engine.connect() as connection:
        cursor = connection.execute(text("""
            INSERT INTO honeytrap_intel (
                url, domain, domain_risk, scam_network_risk,
                connected_domains, shared_wallets, active_campaign,
                wallets_json, telegram_json, emails_json, payment_json,
                evidence_json
            ) VALUES (:url, :domain, :domain_risk, :scam_network_risk,
                     :connected_domains, :shared_wallets, :active_campaign,
                     :wallets_json, :telegram_json, :emails_json, :payment_json,
                     :evidence_json)
            RETURNING id
        """), {
            "url": result.get("url", ""),
            "domain": result.get("domain", ""),
            "domain_risk": int(result.get("domainRisk", 0)),
            "scam_network_risk": int(result.get("scamNetworkRisk", 0)),
            "connected_domains": int(result.get("connectedDomains", 0)),
            "shared_wallets": int(result.get("sharedWallets", 0)),
            "active_campaign": 1 if result.get("activeCampaign") else 0,
            "wallets_json": json.dumps(result.get("wallets", [])),
            "telegram_json": json.dumps(result.get("telegramIds", [])),
            "emails_json": json.dumps(result.get("emails", [])),
            "payment_json": json.dumps(result.get("paymentInstructions", [])),
            "evidence_json": json.dumps(result.get("evidence", [])),
        })
        connection.commit()
        return int(cursor.fetchone()[0])


def get_honeytrap_network_stats(wallets: List[str], telegram_ids: List[str], domain: str) -> Dict:
    """Get network statistics from PostgreSQL"""
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


def test_connection() -> bool:
    """Test PostgreSQL connection"""
    try:
        with engine.connect() as connection:
            result = connection.execute(text("SELECT 1")).fetchone()
            return result[0] == 1
    except SQLAlchemyError as e:
        print(f"Database connection error: {e}")
        return False


if __name__ == "__main__":
    # Test database connection
    print("Testing PostgreSQL connection...")
    if test_connection():
        print("✅ Connection successful!")
        
        # Initialize tables
        print("Initializing tables...")
        init_db()
        print("✅ Tables initialized!")
    else:
        print("❌ Connection failed!")

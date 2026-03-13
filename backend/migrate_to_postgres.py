#!/usr/bin/env python3
"""
Migration script to transfer data from SQLite to PostgreSQL (Neon)
"""

import sqlite3
import sys
from pathlib import Path
from pg_db_service import init_db, save_url_hash, save_honeytrap_intel
from dotenv import load_dotenv

load_dotenv()

def migrate_sqlite_to_postgres():
    """Migrate data from SQLite to PostgreSQL"""
    
    # SQLite connection
    sqlite_path = Path(__file__).with_name("scam_reports.db")
    if not sqlite_path.exists():
        print("❌ SQLite database not found. No data to migrate.")
        return
    
    print("🔄 Starting migration from SQLite to PostgreSQL...")
    
    try:
        # Initialize PostgreSQL tables
        init_db()
        print("✅ PostgreSQL tables initialized")
        
        # Connect to SQLite
        sqlite_conn = sqlite3.connect(sqlite_path)
        sqlite_conn.row_factory = sqlite3.Row
        
        # Migrate url_hashes
        print("📦 Migrating URL hashes...")
        cursor = sqlite_conn.execute("SELECT hash, url FROM url_hashes")
        url_count = 0
        
        for row in cursor.fetchall():
            try:
                # Use the PostgreSQL save function which handles duplicates
                save_url_hash(row['url'])
                url_count += 1
            except Exception as e:
                print(f"⚠️  Error migrating URL hash {row['hash']}: {e}")
        
        print(f"✅ Migrated {url_count} URL hashes")
        
        # Migrate honeytrap_intel
        print("📦 Migrating honeytrap intelligence...")
        cursor = sqlite_conn.execute("""
            SELECT url, domain, domain_risk, scam_network_risk,
                   connected_domains, shared_wallets, active_campaign,
                   wallets_json, telegram_json, emails_json, payment_json,
                   evidence_json, created_at
            FROM honeytrap_intel
        """)
        intel_count = 0
        
        for row in cursor.fetchall():
            try:
                intel_data = {
                    "url": row['url'],
                    "domain": row['domain'],
                    "domainRisk": row['domain_risk'],
                    "scamNetworkRisk": row['scam_network_risk'],
                    "connectedDomains": row['connected_domains'],
                    "sharedWallets": row['shared_wallets'],
                    "activeCampaign": bool(row['active_campaign']),
                    "wallets": eval(row['wallets_json']) if row['wallets_json'] else [],
                    "telegramIds": eval(row['telegram_json']) if row['telegram_json'] else [],
                    "emails": eval(row['emails_json']) if row['emails_json'] else [],
                    "paymentInstructions": eval(row['payment_json']) if row['payment_json'] else [],
                    "evidence": eval(row['evidence_json']) if row['evidence_json'] else [],
                }
                save_honeytrap_intel(intel_data)
                intel_count += 1
            except Exception as e:
                print(f"⚠️  Error migrating intel for {row['domain']}: {e}")
        
        print(f"✅ Migrated {intel_count} honeytrap intelligence records")
        
        sqlite_conn.close()
        print("🎉 Migration completed successfully!")
        
        # Optional: backup SQLite file
        backup_path = sqlite_path.with_suffix('.db.backup')
        sqlite_path.rename(backup_path)
        print(f"💾 SQLite database backed up to: {backup_path}")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    migrate_sqlite_to_postgres()

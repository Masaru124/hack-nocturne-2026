"""
web3_service.py
Sole responsibility: talk to the Polygon Amoy blockchain.
No AI logic. No routes. Just Web3.
Requires CONTRACT_ADDRESS and ABI from Person 1 before testing.
"""

import os
import json
import time
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Connection setup
# ---------------------------------------------------------------------------

ALCHEMY_URL       = os.getenv("ALCHEMY_AMOY_URL")
CONTRACT_ADDRESS  = os.getenv("CONTRACT_ADDRESS")
PRIVATE_KEY       = os.getenv("BACKEND_PRIVATE_KEY")

# Placeholder ABI — replace with the real ABI JSON from Person 1.
# Must include at minimum: communityReport() and getAllReports()
CONTRACT_ABI = json.loads(os.getenv("CONTRACT_ABI", "[]"))


def _to_hex(value):
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    return value


def _to_text(value):
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return "0x" + bytes(value).hex()
    return value

def _get_web3() -> Web3:
    if not ALCHEMY_URL:
        raise EnvironmentError("ALCHEMY_AMOY_URL is not set in .env")
    w3 = Web3(Web3.HTTPProvider(ALCHEMY_URL))
    # Polygon PoA chain requires this middleware
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    if not w3.is_connected():
        raise ConnectionError("Cannot connect to Polygon Amoy. Check ALCHEMY_AMOY_URL.")
    return w3

def _get_contract(w3: Web3):
    if not CONTRACT_ADDRESS:
        raise EnvironmentError("CONTRACT_ADDRESS is not set in .env — waiting for Person 1.")
    if not CONTRACT_ABI:
        raise EnvironmentError("CONTRACT_ABI is not set in .env — waiting for Person 1.")
    return w3.eth.contract(
        address=Web3.to_checksum_address(CONTRACT_ADDRESS),
        abi=CONTRACT_ABI,
    )

def _get_wallet(w3: Web3):
    if not PRIVATE_KEY:
        raise EnvironmentError("BACKEND_PRIVATE_KEY is not set in .env")
    return w3.eth.account.from_key(PRIVATE_KEY)


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

def submit_report(text: str, category: str, risk_score: int, actual_reporter: str | None = None) -> str:
    """
    Hash `text` with keccak256, then call communityReport() on the contract.

    Args:
        text:       The original suspicious message
        category:   Scam category string from ai_analyzer
        risk_score: 0–100 integer from ai_analyzer

    Returns:
        txHash as a hex string (0x...)

    Raises:
        EnvironmentError if env vars are missing
        Exception on transaction failure
    """
    w3       = _get_web3()
    contract = _get_contract(w3)
    wallet   = _get_wallet(w3)

    # Hash the text — stores a fingerprint, not the raw message
    text_hash = w3.keccak(text=text)

    # Build transaction
    nonce = w3.eth.get_transaction_count(wallet.address)

    if actual_reporter:
        reporter = Web3.to_checksum_address(actual_reporter)
        tx_call = contract.functions.communityReport(
            text_hash,
            category,
            risk_score,
            reporter,
        )
    else:
        if hasattr(contract.functions, "reportScam"):
            tx_call = contract.functions.reportScam(
                text_hash,
                category,
                risk_score,
            )
        else:
            tx_call = contract.functions.communityReport(
                text_hash,
                category,
                risk_score,
            )

    tx = tx_call.build_transaction({
        "from":     wallet.address,
        "nonce":    nonce,
        "gas":      300_000,
        "gasPrice": w3.eth.gas_price,
        "chainId":  80002,   # Polygon Amoy chain ID
    })

    # Sign and send
    signed   = w3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
    tx_hash  = w3.eth.send_raw_transaction(signed.raw_transaction)

    # Wait for confirmation (up to 60 s)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    if receipt.status != 1:
        raise RuntimeError(f"Transaction reverted. Receipt: {receipt}")

    return tx_hash.hex()


def get_all_reports() -> list[dict]:
    """
    Call getAllReports() on the contract and return a cleaned list.

    Returns:
        [
            {
                "reporter":   "0x...",
                "textHash":   "0x...",
                "category":   "phishing",
                "riskScore":  85,
                "timestamp":  1712345678,
            },
            ...
        ]
    """
    w3       = _get_web3()
    contract = _get_contract(w3)

    raw_reports = contract.functions.getAllReports().call()

    formatted = []
    for r in raw_reports:
        # New struct layout (ScamRegistry):
        # (id, reporter, contentHash, category, riskScore, timestamp, votes, isVerified, isCommunityReport)
        if len(r) >= 6 and isinstance(r[0], int):
            reporter = r[1]
            text_hash = r[2]
            category = r[3]
            risk_score = r[4]
            timestamp = r[5]
        else:
            # Legacy layout:
            # (reporter, textHash, category, riskScore, timestamp)
            reporter = r[0]
            text_hash = r[1]
            category = r[2]
            risk_score = r[3]
            timestamp = r[4]

        formatted.append({
            "reporter":  _to_text(reporter),
            "textHash":  _to_hex(text_hash),
            "category":  _to_text(category),
            "riskScore": int(risk_score),
            "timestamp": int(timestamp),
        })

    return formatted


def get_report(report_id: int) -> dict:
    """
    Call getReport(id) on the contract and return a single report.
    """
    w3 = _get_web3()
    contract = _get_contract(w3)
    
    try:
        report = contract.functions.getReport(report_id).call()
        (
            id,
            reporter,
            text_hash,
            category,
            risk_score,
            timestamp,
            votes,
            is_verified,
            is_community_report
        ) = report
        
        return {
            "id": int(id),
            "reporter": _to_text(reporter),
            "textHash": _to_hex(text_hash),
            "category": _to_text(category),
            "riskScore": int(risk_score),
            "timestamp": int(timestamp),
            "votes": int(votes),
            "isVerified": bool(is_verified),
            "isCommunityReport": bool(is_community_report),
        }
    except Exception as e:
        raise RuntimeError(f"Failed to get report {report_id}: {e}")


def get_report_by_hash(hash_hex: str) -> dict:
    """
    Call getReportByHash(hash) on the contract and return a single report.
    """
    w3 = _get_web3()
    contract = _get_contract(w3)
    
    try:
        # Convert hex string to bytes32
        hash_bytes = Web3.to_bytes(hexstr=hash_hex)
        report = contract.functions.getReportByHash(hash_bytes).call()
        
        if not report:
            return None
            
        (
            id,
            reporter,
            text_hash,
            category,
            risk_score,
            timestamp,
            votes,
            is_verified,
            is_community_report
        ) = report
        
        return {
            "id": int(id),
            "reporter": _to_text(reporter),
            "textHash": _to_hex(text_hash),
            "category": _to_text(category),
            "riskScore": int(risk_score),
            "timestamp": int(timestamp),
            "votes": int(votes),
            "isVerified": bool(is_verified),
            "isCommunityReport": bool(is_community_report),
        }
    except Exception as e:
        raise RuntimeError(f"Failed to get report by hash {hash_hex}: {e}")


def check_hash(hash_hex: str) -> dict:
    """
    Call checkHash(hash) on the contract to check if hash exists.
    """
    w3 = _get_web3()
    contract = _get_contract(w3)
    
    try:
        # Convert hex string to bytes32
        hash_bytes = Web3.to_bytes(hexstr=hash_hex)
        exists = contract.functions.checkHash(hash_bytes).call()
        
        if exists:
            # If exists, get the full report
            report = get_report_by_hash(hash_hex)
            return {
                "exists": True,
                "report": report
            }
        else:
            return {
                "exists": False,
                "report": None
            }
    except Exception as e:
        raise RuntimeError(f"Failed to check hash {hash_hex}: {e}")


def vote_on_report(report_id: int) -> str:
    """
    Call voteOnReport(id) on the contract.
    """
    w3 = _get_web3()
    contract = _get_contract(w3)
    wallet = _get_wallet(w3)
    
    try:
        # Build transaction
        tx = contract.functions.voteOnReport(report_id).build_transaction({
            "from": wallet.address,
            "nonce": w3.eth.get_transaction_count(wallet.address),
        })
        
        # Sign and send transaction
        signed_tx = w3.eth.account.sign_transaction(tx, wallet.key)
        raw_transaction = getattr(signed_tx, "raw_transaction", None)
        if raw_transaction is None:
            raw_transaction = signed_tx.rawTransaction
        tx_hash = w3.eth.send_raw_transaction(raw_transaction)
        
        # Wait for confirmation
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        if receipt.status == 1:
            return tx_hash.hex()
        else:
            raise RuntimeError(f"Transaction failed: {tx_hash.hex()}")
    except Exception as e:
        raise RuntimeError(f"Failed to vote on report {report_id}: {e}")


def get_report_count() -> int:
    """
    Call reportCount() on the contract to get total number of reports.
    """
    w3 = _get_web3()
    contract = _get_contract(w3)
    
    try:
        count = contract.functions.reportCount().call()
        return int(count)
    except Exception as e:
        raise RuntimeError(f"Failed to get report count: {e}")


# ---------------------------------------------------------------------------
# Quick smoke-test  →  python web3_service.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("Testing get_all_reports() — read-only, no gas needed...")
    reports = get_all_reports()
    print(f"Found {len(reports)} report(s):")
    print(json.dumps(reports, indent=2))

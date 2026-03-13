import pytest

import web3_services
from web3.exceptions import ContractLogicError


def test_get_web3_requires_alchemy_url(monkeypatch):
    monkeypatch.setattr(web3_services, "ALCHEMY_URL", None)
    with pytest.raises(EnvironmentError, match="ALCHEMY_AMOY_URL"):
        web3_services._get_web3()


def test_get_contract_requires_config(monkeypatch):
    class W3:
        class Eth:
            @staticmethod
            def contract(**_kwargs):
                return object()

        eth = Eth()

    monkeypatch.setattr(web3_services, "CONTRACT_ADDRESS", None)
    with pytest.raises(EnvironmentError, match="CONTRACT_ADDRESS"):
        web3_services._get_contract(W3())

    monkeypatch.setattr(web3_services, "CONTRACT_ADDRESS", "0x0000000000000000000000000000000000000001")
    monkeypatch.setattr(web3_services, "CONTRACT_ABI", [])
    with pytest.raises(EnvironmentError, match="CONTRACT_ABI"):
        web3_services._get_contract(W3())


def test_get_wallet_requires_private_key(monkeypatch):
    class W3:
        class Eth:
            class Account:
                @staticmethod
                def from_key(_key):
                    return object()

            account = Account()

        eth = Eth()

    monkeypatch.setattr(web3_services, "PRIVATE_KEY", None)
    with pytest.raises(EnvironmentError, match="BACKEND_PRIVATE_KEY"):
        web3_services._get_wallet(W3())


def test_submit_report_success(monkeypatch):
    class FakeTxHash:
        def hex(self):
            return "0xabc"

    class FakeReceipt:
        status = 1

    class FakeSigned:
        raw_transaction = b"raw"

    class FakeCallBuilder:
        def build_transaction(self, tx):
            assert tx["chainId"] == 80002
            assert tx["gas"] == 300_000
            return {"built": True}

    class FakeFunctions:
        def reportScam(self, text_hash, category, risk_score):
            assert text_hash == b"hash"
            assert category == "phishing"
            assert risk_score == 90
            return FakeCallBuilder()

    class FakeContract:
        functions = FakeFunctions()

    class FakeAccountOps:
        @staticmethod
        def sign_transaction(tx, private_key):
            assert tx == {"built": True}
            assert private_key == "pk"
            return FakeSigned()

    class FakeEth:
        gas_price = 123
        account = FakeAccountOps()

        @staticmethod
        def get_transaction_count(_address):
            return 7

        @staticmethod
        def send_raw_transaction(_raw):
            return FakeTxHash()

        @staticmethod
        def wait_for_transaction_receipt(_tx_hash, timeout):
            assert timeout == 60
            return FakeReceipt()

    class FakeW3:
        eth = FakeEth()

        @staticmethod
        def keccak(text):
            assert text == "scam text"
            return b"hash"

    class FakeWallet:
        address = "0xwallet"

    monkeypatch.setattr(web3_services, "_get_web3", lambda: FakeW3())
    monkeypatch.setattr(web3_services, "_get_contract", lambda _w3: FakeContract())
    monkeypatch.setattr(web3_services, "_get_wallet", lambda _w3: FakeWallet())
    monkeypatch.setattr(web3_services, "PRIVATE_KEY", "pk")

    tx_hash = web3_services.submit_report("scam text", "phishing", 90)
    assert tx_hash == "0xabc"


def test_submit_report_with_actual_reporter_uses_community_report(monkeypatch):
    class FakeTxHash:
        def hex(self):
            return "0xabc"

    class FakeReceipt:
        status = 1

    class FakeSigned:
        raw_transaction = b"raw"

    class FakeCallBuilder:
        def build_transaction(self, tx):
            assert tx["chainId"] == 80002
            return {"built": True}

    class FakeFunctions:
        def communityReport(self, text_hash, category, risk_score, actual_reporter):
            assert text_hash == b"hash"
            assert category == "phishing"
            assert risk_score == 90
            assert actual_reporter == "CHECKSUM:0x1111111111111111111111111111111111111111"
            return FakeCallBuilder()

    class FakeContract:
        functions = FakeFunctions()

    class FakeAccountOps:
        @staticmethod
        def sign_transaction(tx, private_key):
            assert tx == {"built": True}
            assert private_key == "pk"
            return FakeSigned()

    class FakeEth:
        gas_price = 123
        account = FakeAccountOps()

        @staticmethod
        def get_transaction_count(_address):
            return 7

        @staticmethod
        def send_raw_transaction(_raw):
            return FakeTxHash()

        @staticmethod
        def wait_for_transaction_receipt(_tx_hash, timeout):
            assert timeout == 60
            return FakeReceipt()

    class FakeW3:
        eth = FakeEth()

        @staticmethod
        def keccak(text):
            assert text == "scam text"
            return b"hash"

    class FakeWallet:
        address = "0xwallet"

    monkeypatch.setattr(web3_services, "_get_web3", lambda: FakeW3())
    monkeypatch.setattr(web3_services, "_get_contract", lambda _w3: FakeContract())
    monkeypatch.setattr(web3_services, "_get_wallet", lambda _w3: FakeWallet())
    monkeypatch.setattr(web3_services, "PRIVATE_KEY", "pk")
    monkeypatch.setattr(web3_services.Web3, "to_checksum_address", lambda addr: f"CHECKSUM:{addr}")

    tx_hash = web3_services.submit_report(
        "scam text",
        "phishing",
        90,
        actual_reporter="0x1111111111111111111111111111111111111111",
    )
    assert tx_hash == "0xabc"


def test_submit_report_reverted_transaction(monkeypatch):
    class FakeTxHash:
        def hex(self):
            return "0xabc"

    class FakeReceipt:
        status = 0

    class FakeSigned:
        raw_transaction = b"raw"

    class FakeCallBuilder:
        def build_transaction(self, _tx):
            return {"built": True}

    class FakeFunctions:
        def reportScam(self, *_args):
            return FakeCallBuilder()

    class FakeContract:
        functions = FakeFunctions()

    class FakeAccountOps:
        @staticmethod
        def sign_transaction(_tx, private_key):
            assert private_key == "pk"
            return FakeSigned()

    class FakeEth:
        gas_price = 123
        account = FakeAccountOps()

        @staticmethod
        def get_transaction_count(_address):
            return 7

        @staticmethod
        def send_raw_transaction(_raw):
            return FakeTxHash()

        @staticmethod
        def wait_for_transaction_receipt(_tx_hash, timeout):
            assert timeout == 60
            return FakeReceipt()

    class FakeW3:
        eth = FakeEth()

        @staticmethod
        def keccak(text):
            return b"hash"

    class FakeWallet:
        address = "0xwallet"

    monkeypatch.setattr(web3_services, "_get_web3", lambda: FakeW3())
    monkeypatch.setattr(web3_services, "_get_contract", lambda _w3: FakeContract())
    monkeypatch.setattr(web3_services, "_get_wallet", lambda _w3: FakeWallet())
    monkeypatch.setattr(web3_services, "PRIVATE_KEY", "pk")

    with pytest.raises(RuntimeError, match="Transaction reverted"):
        web3_services.submit_report("scam text", "phishing", 90)


def test_get_all_reports_formats_bytes_hash(monkeypatch):
    class FakeCall:
        @staticmethod
        def call():
            return [
                ("0x1", b"\xaa", "phishing", 85, 1712345678),
                ("0x2", "0xbb", "other", 45, 1712345679),
            ]

    class FakeFunctions:
        @staticmethod
        def getAllReports():
            return FakeCall()

    class FakeContract:
        functions = FakeFunctions()

    class FakeW3:
        pass

    monkeypatch.setattr(web3_services, "_get_web3", lambda: FakeW3())
    monkeypatch.setattr(web3_services, "_get_contract", lambda _w3: FakeContract())

    reports = web3_services.get_all_reports()

    assert reports == [
        {
            "reporter": "0x1",
            "textHash": "0xaa",
            "category": "phishing",
            "riskScore": 85,
            "timestamp": 1712345678,
        },
        {
            "reporter": "0x2",
            "textHash": "0xbb",
            "category": "other",
            "riskScore": 45,
            "timestamp": 1712345679,
        },
    ]


def test_get_all_reports_parses_new_registry_struct_layout(monkeypatch):
    class FakeCall:
        @staticmethod
        def call():
            return [
                (
                    1,
                    "0x92580dd57DAC544222BD68Aa2Ece34ce4D098a9c",
                    b"\x7d\x01",
                    "phishing",
                    100,
                    1712345680,
                    0,
                    False,
                    True,
                )
            ]

    class FakeFunctions:
        @staticmethod
        def getAllReports():
            return FakeCall()

    class FakeContract:
        functions = FakeFunctions()

    class FakeW3:
        pass

    monkeypatch.setattr(web3_services, "_get_web3", lambda: FakeW3())
    monkeypatch.setattr(web3_services, "_get_contract", lambda _w3: FakeContract())

    reports = web3_services.get_all_reports()

    assert reports == [
        {
            "reporter": "0x92580dd57DAC544222BD68Aa2Ece34ce4D098a9c",
            "textHash": "0x7d01",
            "category": "phishing",
            "riskScore": 100,
            "timestamp": 1712345680,
        }
    ]


def test_get_report_formats_registry_tuple(monkeypatch):
    class FakeCall:
        @staticmethod
        def call():
            return (7, "0xabc", b"\x01\x02", "phishing", 88, 999, 4, True, False)

    class FakeFunctions:
        @staticmethod
        def getReport(report_id):
            assert report_id == 7
            return FakeCall()

    class FakeContract:
        functions = FakeFunctions()

    monkeypatch.setattr(web3_services, "_get_web3", lambda: object())
    monkeypatch.setattr(web3_services, "_get_contract", lambda _w3: FakeContract())

    report = web3_services.get_report(7)
    assert report == {
        "id": 7,
        "reporter": "0xabc",
        "textHash": "0x0102",
        "category": "phishing",
        "riskScore": 88,
        "timestamp": 999,
        "votes": 4,
        "isVerified": True,
        "isCommunityReport": False,
    }


def test_get_report_by_hash_converts_hash_and_formats_result(monkeypatch):
    class FakeCall:
        @staticmethod
        def call():
            return (3, "0xabc", b"\xaa", "other", 45, 111, 1, False, True)

    class FakeFunctions:
        @staticmethod
        def getReportByHash(hash_bytes):
            assert hash_bytes == b"decoded"
            return FakeCall()

    class FakeContract:
        functions = FakeFunctions()

    monkeypatch.setattr(web3_services, "_get_web3", lambda: object())
    monkeypatch.setattr(web3_services, "_get_contract", lambda _w3: FakeContract())
    monkeypatch.setattr(web3_services.Web3, "to_bytes", lambda hexstr: b"decoded")

    report = web3_services.get_report_by_hash("0xhash")
    assert report["id"] == 3
    assert report["textHash"] == "0xaa"
    assert report["category"] == "other"
    assert report["isCommunityReport"] is True


def test_get_report_by_hash_returns_none(monkeypatch):
    class FakeCall:
        @staticmethod
        def call():
            return None

    class FakeFunctions:
        @staticmethod
        def getReportByHash(hash_bytes):
            return FakeCall()

    class FakeContract:
        functions = FakeFunctions()

    monkeypatch.setattr(web3_services, "_get_web3", lambda: object())
    monkeypatch.setattr(web3_services, "_get_contract", lambda _w3: FakeContract())
    monkeypatch.setattr(web3_services.Web3, "to_bytes", lambda hexstr: b"decoded")

    assert web3_services.get_report_by_hash("0xhash") is None


def test_get_report_by_hash_contract_not_found_revert_returns_none(monkeypatch):
    class FakeCall:
        @staticmethod
        def call():
            raise ContractLogicError("execution reverted: Not found")

    class FakeFunctions:
        @staticmethod
        def getReportByHash(hash_bytes):
            return FakeCall()

    class FakeContract:
        functions = FakeFunctions()

    monkeypatch.setattr(web3_services, "_get_web3", lambda: object())
    monkeypatch.setattr(web3_services, "_get_contract", lambda _w3: FakeContract())
    monkeypatch.setattr(web3_services.Web3, "to_bytes", lambda hexstr: b"decoded")

    assert web3_services.get_report_by_hash("0xhash") is None


def test_check_hash_returns_exists_and_report(monkeypatch):
    class FakeCall:
        @staticmethod
        def call():
            return True

    class FakeFunctions:
        @staticmethod
        def checkHash(hash_bytes):
            assert hash_bytes == b"decoded"
            return FakeCall()

    class FakeContract:
        functions = FakeFunctions()

    monkeypatch.setattr(web3_services, "_get_web3", lambda: object())
    monkeypatch.setattr(web3_services, "_get_contract", lambda _w3: FakeContract())
    monkeypatch.setattr(web3_services.Web3, "to_bytes", lambda hexstr: b"decoded")
    monkeypatch.setattr(web3_services, "get_report_by_hash", lambda hash_hex: {"id": 1})

    result = web3_services.check_hash("0xhash")
    assert result == {"exists": True, "report": {"id": 1}}


def test_check_hash_returns_false_when_missing(monkeypatch):
    class FakeCall:
        @staticmethod
        def call():
            return False

    class FakeFunctions:
        @staticmethod
        def checkHash(hash_bytes):
            return FakeCall()

    class FakeContract:
        functions = FakeFunctions()

    monkeypatch.setattr(web3_services, "_get_web3", lambda: object())
    monkeypatch.setattr(web3_services, "_get_contract", lambda _w3: FakeContract())
    monkeypatch.setattr(web3_services.Web3, "to_bytes", lambda hexstr: b"decoded")

    result = web3_services.check_hash("0xhash")
    assert result == {"exists": False, "report": None}


def test_vote_on_report_success(monkeypatch):
    class FakeTxHash:
        def hex(self):
            return "0xvote"

    class FakeReceipt:
        status = 1

    class FakeSigned:
        raw_transaction = b"raw"

    class FakeCallBuilder:
        def build_transaction(self, tx):
            assert tx["from"] == "0xwallet"
            assert tx["nonce"] == 4
            return {"built": True}

    class FakeFunctions:
        @staticmethod
        def voteOnReport(report_id):
            assert report_id == 9
            return FakeCallBuilder()

    class FakeContract:
        functions = FakeFunctions()

    class FakeAccountOps:
        @staticmethod
        def sign_transaction(tx, key):
            assert tx == {"built": True}
            assert key == b"wallet-key"
            return FakeSigned()

    class FakeEth:
        account = FakeAccountOps()

        @staticmethod
        def get_transaction_count(_address):
            return 4

        @staticmethod
        def send_raw_transaction(raw_transaction):
            assert raw_transaction == b"raw"
            return FakeTxHash()

        @staticmethod
        def wait_for_transaction_receipt(tx_hash):
            return FakeReceipt()

    class FakeW3:
        eth = FakeEth()

    class FakeWallet:
        address = "0xwallet"
        key = b"wallet-key"

    monkeypatch.setattr(web3_services, "_get_web3", lambda: FakeW3())
    monkeypatch.setattr(web3_services, "_get_contract", lambda _w3: FakeContract())
    monkeypatch.setattr(web3_services, "_get_wallet", lambda _w3: FakeWallet())

    assert web3_services.vote_on_report(9) == "0xvote"


def test_vote_on_report_failure(monkeypatch):
    class FakeReceipt:
        status = 0

    class FakeTxHash:
        def hex(self):
            return "0xvote"

    class FakeSigned:
        rawTransaction = b"legacy"

    class FakeCallBuilder:
        def build_transaction(self, tx):
            return {"built": True}

    class FakeFunctions:
        @staticmethod
        def voteOnReport(report_id):
            return FakeCallBuilder()

    class FakeContract:
        functions = FakeFunctions()

    class FakeAccountOps:
        @staticmethod
        def sign_transaction(tx, key):
            return FakeSigned()

    class FakeEth:
        account = FakeAccountOps()

        @staticmethod
        def get_transaction_count(_address):
            return 4

        @staticmethod
        def send_raw_transaction(raw_transaction):
            assert raw_transaction == b"legacy"
            return FakeTxHash()

        @staticmethod
        def wait_for_transaction_receipt(tx_hash):
            return FakeReceipt()

    class FakeW3:
        eth = FakeEth()

    class FakeWallet:
        address = "0xwallet"
        key = b"wallet-key"

    monkeypatch.setattr(web3_services, "_get_web3", lambda: FakeW3())
    monkeypatch.setattr(web3_services, "_get_contract", lambda _w3: FakeContract())
    monkeypatch.setattr(web3_services, "_get_wallet", lambda _w3: FakeWallet())

    with pytest.raises(RuntimeError, match="Failed to vote on report 9"):
        web3_services.vote_on_report(9)


def test_get_report_count(monkeypatch):
    class FakeCall:
        @staticmethod
        def call():
            return 12

    class FakeFunctions:
        @staticmethod
        def reportCount():
            return FakeCall()

    class FakeContract:
        functions = FakeFunctions()

    monkeypatch.setattr(web3_services, "_get_web3", lambda: object())
    monkeypatch.setattr(web3_services, "_get_contract", lambda _w3: FakeContract())

    assert web3_services.get_report_count() == 12

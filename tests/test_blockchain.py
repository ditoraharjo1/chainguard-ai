"""Tests for the blockchain audit trail."""

from src.blockchain.chain import AuditChain, AuditRecord


def _make_record(name: str = "TestContract", vulns: int = 3) -> AuditRecord:
    return AuditRecord(
        contract_name=name,
        source_hash="abc123" * 10 + "abcd",
        risk_grade="C",
        risk_score=55.0,
        num_vulnerabilities=vulns,
    )


def test_genesis_block_created() -> None:
    chain = AuditChain(difficulty=1)
    assert len(chain.chain) == 1
    assert chain.chain[0].index == 0
    assert chain.chain[0].audit_record.contract_name == "Genesis"


def test_add_audit_block() -> None:
    chain = AuditChain(difficulty=1)
    record = _make_record()
    block = chain.add_audit(record)
    assert block.index == 1
    assert len(chain.chain) == 2
    assert block.audit_record.contract_name == "TestContract"


def test_chain_integrity() -> None:
    chain = AuditChain(difficulty=1)
    chain.add_audit(_make_record("A"))
    chain.add_audit(_make_record("B"))
    chain.add_audit(_make_record("C"))
    assert chain.verify_chain() is True


def test_tampered_chain_fails_verification() -> None:
    chain = AuditChain(difficulty=1)
    chain.add_audit(_make_record("A"))
    chain.add_audit(_make_record("B"))

    # Tamper with a block
    chain.chain[1].audit_record.contract_name = "HACKED"
    assert chain.verify_chain() is False


def test_proof_of_work() -> None:
    chain = AuditChain(difficulty=3)
    block = chain.add_audit(_make_record())
    assert block.hash.startswith("000")


def test_get_chain_data() -> None:
    chain = AuditChain(difficulty=1)
    chain.add_audit(_make_record())
    data = chain.get_chain_data()
    assert len(data) == 2
    assert "hash" in data[0]
    assert "audit" in data[1]


def test_get_block_by_hash() -> None:
    chain = AuditChain(difficulty=1)
    block = chain.add_audit(_make_record())
    found = chain.get_block_by_hash(block.hash)
    assert found is not None
    assert found.index == block.index


def test_get_block_by_hash_not_found() -> None:
    chain = AuditChain(difficulty=1)
    assert chain.get_block_by_hash("nonexistent") is None


def test_block_links() -> None:
    chain = AuditChain(difficulty=1)
    chain.add_audit(_make_record("A"))
    chain.add_audit(_make_record("B"))
    assert chain.chain[2].previous_hash == chain.chain[1].hash
    assert chain.chain[1].previous_hash == chain.chain[0].hash

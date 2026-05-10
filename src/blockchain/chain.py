"""Lightweight blockchain for immutable audit trail storage.

This module implements a minimal proof-of-work blockchain where each block
stores a smart-contract audit hash.  It is intentionally simple — the goal
is to demonstrate how audit results can be anchored to a tamper-evident
ledger, not to compete with production chains.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from threading import Lock


@dataclass
class AuditRecord:
    contract_name: str
    source_hash: str
    risk_grade: str
    risk_score: float
    num_vulnerabilities: int
    analyzer_version: str = "1.0.0"


@dataclass
class Block:
    index: int
    timestamp: float
    audit_record: AuditRecord
    previous_hash: str
    nonce: int = 0
    hash: str = ""

    def compute_hash(self) -> str:
        block_data = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "audit": {
                    "contract_name": self.audit_record.contract_name,
                    "source_hash": self.audit_record.source_hash,
                    "risk_grade": self.audit_record.risk_grade,
                    "risk_score": self.audit_record.risk_score,
                    "num_vulnerabilities": self.audit_record.num_vulnerabilities,
                    "analyzer_version": self.audit_record.analyzer_version,
                },
                "previous_hash": self.previous_hash,
                "nonce": self.nonce,
            },
            sort_keys=True,
        )
        return hashlib.sha256(block_data.encode()).hexdigest()


@dataclass
class AuditChain:
    """A minimal blockchain storing audit records with proof-of-work."""

    difficulty: int = 2
    chain: list[Block] = field(default_factory=list)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def __post_init__(self) -> None:
        if not self.chain:
            self._create_genesis_block()

    def _create_genesis_block(self) -> None:
        genesis_record = AuditRecord(
            contract_name="Genesis",
            source_hash="0" * 64,
            risk_grade="N/A",
            risk_score=0.0,
            num_vulnerabilities=0,
        )
        genesis = Block(
            index=0,
            timestamp=time.time(),
            audit_record=genesis_record,
            previous_hash="0" * 64,
        )
        genesis.hash = self._mine_block(genesis)
        self.chain.append(genesis)

    def _mine_block(self, block: Block) -> str:
        """Simple proof-of-work: find a hash with `difficulty` leading zeros."""
        target = "0" * self.difficulty
        while True:
            candidate = block.compute_hash()
            if candidate.startswith(target):
                return candidate
            block.nonce += 1

    @property
    def latest_block(self) -> Block:
        return self.chain[-1]

    def add_audit(self, record: AuditRecord) -> Block:
        """Mine a new block containing the given audit record."""
        with self._lock:
            new_block = Block(
                index=len(self.chain),
                timestamp=time.time(),
                audit_record=record,
                previous_hash=self.latest_block.hash,
            )
            new_block.hash = self._mine_block(new_block)
            self.chain.append(new_block)
            return new_block

    def verify_chain(self) -> bool:
        """Validate the entire chain integrity."""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            if current.hash != current.compute_hash():
                return False
            if current.previous_hash != previous.hash:
                return False
            if not current.hash.startswith("0" * self.difficulty):
                return False

        return True

    def get_chain_data(self) -> list[dict]:
        """Serialize the chain for API responses."""
        result = []
        for block in self.chain:
            result.append(
                {
                    "index": block.index,
                    "timestamp": block.timestamp,
                    "hash": block.hash,
                    "previous_hash": block.previous_hash,
                    "nonce": block.nonce,
                    "audit": {
                        "contract_name": block.audit_record.contract_name,
                        "source_hash": block.audit_record.source_hash,
                        "risk_grade": block.audit_record.risk_grade,
                        "risk_score": block.audit_record.risk_score,
                        "num_vulnerabilities": block.audit_record.num_vulnerabilities,
                    },
                }
            )
        return result

    def get_block_by_hash(self, block_hash: str) -> Block | None:
        for block in self.chain:
            if block.hash == block_hash:
                return block
        return None


# Global singleton
audit_chain = AuditChain(difficulty=2)

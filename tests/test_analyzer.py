"""Tests for the vulnerability analysis engine."""

from src.analyzer.engine import analyze_contract
from src.models.vulnerability import VulnerabilityType

VULNERABLE_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vulnerable {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = tx.origin;
    }

    function withdraw(uint256 _amount) public {
        require(balances[msg.sender] >= _amount);
        (bool sent, ) = msg.sender.call{value: _amount}("");
        require(sent);
        balances[msg.sender] -= _amount;
    }

    function destroy() public {
        selfdestruct(payable(owner));
    }

    function changeOwner(address _newOwner) public {
        require(tx.origin == owner, "Not owner");
        owner = _newOwner;
    }

    function isLocked() public view returns (bool) {
        return block.timestamp < 1700000000;
    }
}
"""

SECURE_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Secure is ReentrancyGuard {
    mapping(address => uint256) public balances;
    address public immutable owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function withdraw(uint256 _amount) external nonReentrant {
        require(balances[msg.sender] >= _amount, "Insufficient");
        balances[msg.sender] -= _amount;
        (bool sent, ) = payable(msg.sender).call{value: _amount}("");
        require(sent, "Failed");
    }
}
"""


def test_detects_reentrancy() -> None:
    result = analyze_contract(VULNERABLE_CONTRACT, "Vulnerable")
    types = {v.vuln_type for v in result.vulnerabilities}
    assert VulnerabilityType.REENTRANCY in types


def test_detects_selfdestruct() -> None:
    result = analyze_contract(VULNERABLE_CONTRACT, "Vulnerable")
    types = {v.vuln_type for v in result.vulnerabilities}
    assert VulnerabilityType.SELFDESTRUCT in types


def test_detects_tx_origin() -> None:
    result = analyze_contract(VULNERABLE_CONTRACT, "Vulnerable")
    types = {v.vuln_type for v in result.vulnerabilities}
    assert VulnerabilityType.TX_ORIGIN in types


def test_detects_timestamp_dependency() -> None:
    result = analyze_contract(VULNERABLE_CONTRACT, "Vulnerable")
    types = {v.vuln_type for v in result.vulnerabilities}
    assert VulnerabilityType.TIMESTAMP_DEPENDENCY in types


def test_detects_floating_pragma() -> None:
    result = analyze_contract(VULNERABLE_CONTRACT, "Vulnerable")
    types = {v.vuln_type for v in result.vulnerabilities}
    assert VulnerabilityType.FLOATING_PRAGMA in types


def test_risk_score_vulnerable() -> None:
    result = analyze_contract(VULNERABLE_CONTRACT, "Vulnerable")
    assert result.risk_score.overall > 30
    assert result.risk_score.grade in ("C", "D", "F")


def test_risk_score_secure_is_lower() -> None:
    vuln_result = analyze_contract(VULNERABLE_CONTRACT, "Vulnerable")
    secure_result = analyze_contract(SECURE_CONTRACT, "Secure")
    assert secure_result.risk_score.overall < vuln_result.risk_score.overall


def test_secure_has_fewer_vulns() -> None:
    vuln_result = analyze_contract(VULNERABLE_CONTRACT, "Vulnerable")
    secure_result = analyze_contract(SECURE_CONTRACT, "Secure")
    assert len(secure_result.vulnerabilities) < len(vuln_result.vulnerabilities)


def test_ai_summary_generated() -> None:
    result = analyze_contract(VULNERABLE_CONTRACT, "Vulnerable")
    assert len(result.ai_summary) > 50
    assert "Vulnerable" in result.ai_summary


def test_metadata_extracted() -> None:
    result = analyze_contract(VULNERABLE_CONTRACT, "Vulnerable")
    assert result.metadata.num_functions > 0
    assert result.metadata.total_lines > 0


def test_source_hash_consistent() -> None:
    r1 = analyze_contract(VULNERABLE_CONTRACT, "Test")
    r2 = analyze_contract(VULNERABLE_CONTRACT, "Test")
    assert r1.source_hash == r2.source_hash


def test_empty_contract_no_crash() -> None:
    result = analyze_contract("// empty", "Empty")
    assert result.risk_score.grade == "A"
    assert len(result.vulnerabilities) == 0

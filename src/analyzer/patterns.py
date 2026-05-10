"""Vulnerability detection patterns for Solidity smart contracts.

Each pattern defines a regex, associated vulnerability type, severity,
and remediation guidance. The AI engine scores matches using contextual
analysis to reduce false positives.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from src.models.vulnerability import Severity, VulnerabilityType


@dataclass
class VulnPattern:
    name: str
    vuln_type: VulnerabilityType
    severity: Severity
    pattern: re.Pattern[str]
    description: str
    recommendation: str
    confidence_base: float = 0.7
    cwe_id: str | None = None
    context_boost_patterns: list[re.Pattern[str]] = field(default_factory=list)
    context_reduce_patterns: list[re.Pattern[str]] = field(default_factory=list)


VULNERABILITY_PATTERNS: list[VulnPattern] = [
    # --- Critical ---
    VulnPattern(
        name="Reentrancy via external call before state update",
        vuln_type=VulnerabilityType.REENTRANCY,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"\.call\{.*?value\s*:.*?\}\s*\(.*?\).*?;"
            r"(?:(?!\.call\{).)*?"
            r"(?:balances|balance|amounts?|deposits?)\s*\[",
            re.DOTALL,
        ),
        description=(
            "State variable is modified after an external call. An attacker can "
            "re-enter the function before the state is updated, draining funds."
        ),
        recommendation=(
            "Apply the Checks-Effects-Interactions pattern: update state variables "
            "before making external calls. Consider using OpenZeppelin's "
            "ReentrancyGuard."
        ),
        confidence_base=0.85,
        cwe_id="CWE-841",
        context_boost_patterns=[
            re.compile(r"msg\.value"),
            re.compile(r"withdraw|deposit|transfer"),
        ],
        context_reduce_patterns=[
            re.compile(r"nonReentrant|reentrancyGuard|ReentrancyGuard"),
        ],
    ),
    VulnPattern(
        name="Reentrancy (simple call pattern)",
        vuln_type=VulnerabilityType.REENTRANCY,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"\.call\s*\{.*?value\s*:",
            re.DOTALL,
        ),
        description=(
            "External call with value transfer detected. If state is not updated "
            "before this call, reentrancy attacks may be possible."
        ),
        recommendation=(
            "Ensure all state changes occur before external calls. Use "
            "ReentrancyGuard from OpenZeppelin for critical functions."
        ),
        confidence_base=0.60,
        cwe_id="CWE-841",
        context_reduce_patterns=[
            re.compile(r"nonReentrant|ReentrancyGuard"),
        ],
    ),
    # --- High ---
    VulnPattern(
        name="Unchecked external call return value",
        vuln_type=VulnerabilityType.UNCHECKED_CALL,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"(?:address\s*\(.*?\)|msg\.sender|[\w.]+)\s*\.call\s*\{[^}]*\}\s*\([^)]*\)\s*;",
        ),
        description=(
            "The return value of a low-level .call() is not checked. If the call "
            "fails silently, contract state may become inconsistent."
        ),
        recommendation=(
            "Always check the boolean return value: "
            '`(bool success, ) = addr.call{...}(""); require(success);`'
        ),
        confidence_base=0.80,
        cwe_id="CWE-252",
    ),
    VulnPattern(
        name="tx.origin used for authorization",
        vuln_type=VulnerabilityType.TX_ORIGIN,
        severity=Severity.HIGH,
        pattern=re.compile(r"require\s*\(\s*tx\.origin\s*=="),
        description=(
            "tx.origin is used for authorization. A phishing contract can trick "
            "the owner into calling it, passing the tx.origin check."
        ),
        recommendation="Replace tx.origin with msg.sender for authentication.",
        confidence_base=0.90,
        cwe_id="CWE-284",
    ),
    VulnPattern(
        name="Unprotected selfdestruct",
        vuln_type=VulnerabilityType.SELFDESTRUCT,
        severity=Severity.CRITICAL,
        pattern=re.compile(r"selfdestruct\s*\("),
        description=(
            "selfdestruct is present. If not properly access-controlled, anyone "
            "can destroy the contract and steal remaining Ether."
        ),
        recommendation=(
            "Protect selfdestruct with strict access control (onlyOwner). "
            "Consider removing it entirely — it is deprecated in newer EVM versions."
        ),
        confidence_base=0.70,
        cwe_id="CWE-284",
        context_reduce_patterns=[
            re.compile(r"onlyOwner|require\s*\(\s*msg\.sender\s*==\s*owner"),
        ],
    ),
    VulnPattern(
        name="Dangerous delegatecall",
        vuln_type=VulnerabilityType.DELEGATECALL,
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\.delegatecall\s*\("),
        description=(
            "delegatecall executes code in the context of the calling contract. "
            "If the target is user-controlled, storage can be corrupted or funds stolen."
        ),
        recommendation=(
            "Only delegatecall to trusted, immutable implementation contracts. "
            "Never allow user-supplied addresses for delegatecall targets."
        ),
        confidence_base=0.75,
        cwe_id="CWE-829",
    ),
    # --- Medium ---
    VulnPattern(
        name="Timestamp dependency",
        vuln_type=VulnerabilityType.TIMESTAMP_DEPENDENCY,
        severity=Severity.MEDIUM,
        pattern=re.compile(r"block\.timestamp\s*[<>=!]+|now\s*[<>=!]+"),
        description=(
            "Contract logic depends on block.timestamp, which miners can "
            "manipulate by ~15 seconds."
        ),
        recommendation=(
            "Avoid using block.timestamp for critical logic. If timing is needed, "
            "use block numbers or an oracle."
        ),
        confidence_base=0.65,
        cwe_id="CWE-829",
    ),
    VulnPattern(
        name="Integer overflow / underflow (pre-0.8.0)",
        vuln_type=VulnerabilityType.INTEGER_OVERFLOW,
        severity=Severity.HIGH,
        pattern=re.compile(r"pragma\s+solidity\s+[\^~]?0\.[0-7]\.\d+"),
        description=(
            "Contract uses Solidity < 0.8.0 which does not have built-in overflow "
            "checks. Arithmetic operations may silently wrap."
        ),
        recommendation=(
            "Upgrade to Solidity >= 0.8.0 for built-in overflow protection, "
            "or use OpenZeppelin's SafeMath library."
        ),
        confidence_base=0.85,
        cwe_id="CWE-190",
    ),
    VulnPattern(
        name="Unchecked math block",
        vuln_type=VulnerabilityType.UNCHECKED_MATH,
        severity=Severity.MEDIUM,
        pattern=re.compile(r"unchecked\s*\{"),
        description=(
            "An unchecked block disables overflow/underflow checks. This is "
            "valid for gas optimization but dangerous if assumptions are wrong."
        ),
        recommendation=(
            "Ensure unchecked blocks only wrap operations proven safe via "
            "require() pre-conditions or known value bounds."
        ),
        confidence_base=0.50,
        cwe_id="CWE-190",
    ),
    # --- Low / Info ---
    VulnPattern(
        name="Floating pragma",
        vuln_type=VulnerabilityType.FLOATING_PRAGMA,
        severity=Severity.LOW,
        pattern=re.compile(r"pragma\s+solidity\s+\^"),
        description=(
            "The pragma directive uses ^, allowing compilation with future "
            "minor versions that may introduce breaking changes."
        ),
        recommendation=(
            "Pin the compiler version, e.g. `pragma solidity 0.8.20;` "
            "to ensure consistent behavior."
        ),
        confidence_base=0.90,
        cwe_id="CWE-1104",
    ),
    VulnPattern(
        name="Access control missing on state-changing function",
        vuln_type=VulnerabilityType.ACCESS_CONTROL,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"function\s+\w+\s*\([^)]*\)\s+(?:public|external)\s+(?!view|pure)"
            r"(?:(?!onlyOwner|onlyRole|require\s*\(\s*msg\.sender).)*?\{",
            re.DOTALL,
        ),
        description=(
            "A public/external state-changing function lacks visible access "
            "control. Anyone can call it, potentially modifying critical state."
        ),
        recommendation=(
            "Add appropriate access modifiers (onlyOwner, role-based) or "
            "require(msg.sender == ...) checks."
        ),
        confidence_base=0.45,
        cwe_id="CWE-284",
        context_reduce_patterns=[
            re.compile(r"onlyOwner|onlyRole|_onlyOwner|Ownable|AccessControl"),
        ],
    ),
    VulnPattern(
        name="Potential front-running via public mempool",
        vuln_type=VulnerabilityType.FRONT_RUNNING,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"function\s+(?:swap|buy|sell|bid|claim|mint)\s*\(",
        ),
        description=(
            "Functions with financial naming (swap, buy, sell, bid) may be "
            "susceptible to front-running by MEV bots."
        ),
        recommendation=(
            "Use commit-reveal schemes, Flashbots Protect, or private mempools "
            "to mitigate front-running risks."
        ),
        confidence_base=0.40,
        cwe_id="CWE-362",
    ),
    VulnPattern(
        name="Potential DoS with gas limit",
        vuln_type=VulnerabilityType.DOS,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"for\s*\([^)]*;\s*\w+\s*<\s*\w+\.length\s*;",
        ),
        description=(
            "A loop iterates over a dynamic array. If the array grows large, "
            "the function may exceed the block gas limit and become uncallable."
        ),
        recommendation=(
            "Use pagination, limit array sizes, or implement a pull-over-push "
            "pattern to avoid unbounded gas consumption."
        ),
        confidence_base=0.55,
        cwe_id="CWE-400",
    ),
]

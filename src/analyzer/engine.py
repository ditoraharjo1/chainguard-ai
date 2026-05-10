"""Core analysis engine — scans Solidity source code for vulnerabilities.

The engine applies regex-based pattern matching with context-aware confidence
scoring.  Each match is boosted or reduced based on surrounding code (e.g. a
ReentrancyGuard import lowers reentrancy confidence).  An AI summary is
generated from the aggregated findings.
"""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from datetime import datetime, timezone

from src.analyzer.patterns import VULNERABILITY_PATTERNS, VulnPattern
from src.models.vulnerability import (
    AnalysisResult,
    ContractMetadata,
    RiskScore,
    Severity,
    Vulnerability,
)


def _compute_confidence(pattern: VulnPattern, source: str, match_text: str) -> float:
    """Adjust base confidence using contextual boost / reduce patterns."""
    confidence = pattern.confidence_base

    for bp in pattern.context_boost_patterns:
        if bp.search(source):
            confidence = min(1.0, confidence + 0.10)

    for rp in pattern.context_reduce_patterns:
        if rp.search(source):
            confidence = max(0.05, confidence - 0.30)

    return round(confidence, 2)


def _find_line_number(source: str, match_start: int) -> int:
    return source[:match_start].count("\n") + 1


def _extract_snippet(source: str, line: int, context: int = 2) -> str:
    lines = source.splitlines()
    start = max(0, line - 1 - context)
    end = min(len(lines), line + context)
    numbered = [
        f"{'>' if i == line - 1 else ' '} {i + 1:4d} | {lines[i]}"
        for i in range(start, end)
    ]
    return "\n".join(numbered)


def _extract_metadata(source: str) -> ContractMetadata:
    contract_match = re.search(r"contract\s+(\w+)", source)
    name = contract_match.group(1) if contract_match else "Unknown"

    pragma_match = re.search(r"pragma\s+solidity\s+([\^~>=<\s\d.]+);", source)
    compiler = pragma_match.group(1).strip() if pragma_match else None

    return ContractMetadata(
        name=name,
        compiler_version=compiler,
        num_functions=len(re.findall(r"\bfunction\s+\w+", source)),
        num_modifiers=len(re.findall(r"\bmodifier\s+\w+", source)),
        num_events=len(re.findall(r"\bevent\s+\w+", source)),
        num_state_variables=len(
            re.findall(r"^\s+(?:uint|int|address|bool|string|bytes|mapping)\b", source, re.M)
        ),
        has_fallback=bool(re.search(r"\bfallback\s*\(", source)),
        has_receive=bool(re.search(r"\breceive\s*\(", source)),
        uses_assembly=bool(re.search(r"\bassembly\s*\{", source)),
        total_lines=source.count("\n") + 1,
    )


_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 1,
}


def _compute_risk_score(vulns: list[Vulnerability], metadata: ContractMetadata) -> RiskScore:
    if not vulns:
        return RiskScore(overall=5.0, security=5.0, code_quality=10.0, complexity=10.0, grade="A")

    penalty = sum(_SEVERITY_WEIGHT[v.severity] * v.confidence for v in vulns)
    security = min(100.0, round(penalty, 1))
    code_quality = min(100.0, round(penalty * 0.6, 1))
    complexity = min(100.0, round(metadata.total_lines / 10 + metadata.num_functions * 2, 1))
    overall = round(security * 0.6 + code_quality * 0.25 + complexity * 0.15, 1)
    overall = min(100.0, overall)

    if overall <= 20:
        grade = "A"
    elif overall <= 40:
        grade = "B"
    elif overall <= 60:
        grade = "C"
    elif overall <= 80:
        grade = "D"
    else:
        grade = "F"

    return RiskScore(
        overall=overall,
        security=security,
        code_quality=code_quality,
        complexity=complexity,
        grade=grade,
    )


def _generate_ai_summary(
    vulns: list[Vulnerability],
    metadata: ContractMetadata,
    risk: RiskScore,
) -> str:
    if not vulns:
        return (
            f"Contract **{metadata.name}** ({metadata.total_lines} lines, "
            f"{metadata.num_functions} functions) passed all automated checks. "
            f"Risk grade: **{risk.grade}**. No known vulnerability patterns detected. "
            "A manual audit is still recommended before mainnet deployment."
        )

    crit = sum(1 for v in vulns if v.severity == Severity.CRITICAL)
    high = sum(1 for v in vulns if v.severity == Severity.HIGH)
    med = sum(1 for v in vulns if v.severity == Severity.MEDIUM)
    low = sum(1 for v in vulns if v.severity in (Severity.LOW, Severity.INFO))

    severity_parts: list[str] = []
    if crit:
        severity_parts.append(f"**{crit} critical**")
    if high:
        severity_parts.append(f"**{high} high**")
    if med:
        severity_parts.append(f"{med} medium")
    if low:
        severity_parts.append(f"{low} low/info")

    top_issues = ", ".join(
        v.title for v in sorted(vulns, key=lambda x: _SEVERITY_WEIGHT[x.severity], reverse=True)[:3]
    )

    return (
        f"## AI Security Summary for `{metadata.name}`\n\n"
        f"Analyzed **{metadata.total_lines}** lines across "
        f"**{metadata.num_functions}** functions. "
        f"Detected **{len(vulns)}** potential issues: "
        f"{', '.join(severity_parts)}.\n\n"
        f"**Risk Grade: {risk.grade}** (score {risk.overall}/100)\n\n"
        f"Top concerns: {top_issues}.\n\n"
        + (
            "**Immediate action required** — critical vulnerabilities found. "
            "Do NOT deploy without remediation."
            if crit
            else "Review the findings and apply recommended fixes before deployment."
        )
    )


def analyze_contract(source_code: str, contract_name: str | None = None) -> AnalysisResult:
    """Run the full analysis pipeline on a Solidity source string."""
    start = time.monotonic()

    source_hash = hashlib.sha256(source_code.encode()).hexdigest()
    metadata = _extract_metadata(source_code)
    if contract_name:
        metadata.name = contract_name

    vulns: list[Vulnerability] = []
    seen: set[tuple[str, int | None]] = set()

    for vp in VULNERABILITY_PATTERNS:
        for match in vp.pattern.finditer(source_code):
            line = _find_line_number(source_code, match.start())
            key = (vp.vuln_type.value, line)
            if key in seen:
                continue
            seen.add(key)

            confidence = _compute_confidence(vp, source_code, match.group())

            vulns.append(
                Vulnerability(
                    vuln_type=vp.vuln_type,
                    severity=vp.severity,
                    title=vp.name,
                    description=vp.description,
                    line_number=line,
                    code_snippet=_extract_snippet(source_code, line),
                    recommendation=vp.recommendation,
                    confidence=confidence,
                    cwe_id=vp.cwe_id,
                )
            )

    vulns.sort(key=lambda v: (_SEVERITY_WEIGHT[v.severity], v.confidence), reverse=True)
    risk = _compute_risk_score(vulns, metadata)
    summary = _generate_ai_summary(vulns, metadata, risk)
    duration = int((time.monotonic() - start) * 1000)

    return AnalysisResult(
        contract_id=uuid.uuid4().hex[:16],
        contract_name=metadata.name,
        source_hash=source_hash,
        vulnerabilities=vulns,
        risk_score=risk,
        metadata=metadata,
        ai_summary=summary,
        timestamp=datetime.now(timezone.utc),
        analysis_duration_ms=duration,
    )

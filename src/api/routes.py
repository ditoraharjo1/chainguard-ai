"""FastAPI routes for the ChainGuard AI REST API."""

from __future__ import annotations

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from src.analyzer.engine import analyze_contract
from src.blockchain.chain import AuditRecord, audit_chain
from src.models.vulnerability import AnalysisRequest, AnalysisResult

router = APIRouter(prefix="/api/v1", tags=["analysis"])


@router.post("/analyze", response_model=AnalysisResult)
async def analyze(request: AnalysisRequest) -> AnalysisResult:
    """Analyze a Solidity smart contract for vulnerabilities."""
    if not request.source_code.strip():
        raise HTTPException(status_code=400, detail="Source code cannot be empty.")

    result = analyze_contract(request.source_code, request.contract_name)

    record = AuditRecord(
        contract_name=result.contract_name,
        source_hash=result.source_hash,
        risk_grade=result.risk_score.grade,
        risk_score=result.risk_score.overall,
        num_vulnerabilities=len(result.vulnerabilities),
    )
    block = audit_chain.add_audit(record)
    result.blockchain_tx_hash = block.hash

    return result


@router.post("/analyze/upload", response_model=AnalysisResult)
async def analyze_upload(
    file: UploadFile = File(...),
    contract_name: str = Form(default="Unknown"),
) -> AnalysisResult:
    """Upload a .sol file for analysis."""
    if not file.filename or not file.filename.endswith(".sol"):
        raise HTTPException(status_code=400, detail="Only .sol files are accepted.")

    content = await file.read()
    source_code = content.decode("utf-8", errors="replace")

    result = analyze_contract(source_code, contract_name or file.filename.replace(".sol", ""))

    record = AuditRecord(
        contract_name=result.contract_name,
        source_hash=result.source_hash,
        risk_grade=result.risk_score.grade,
        risk_score=result.risk_score.overall,
        num_vulnerabilities=len(result.vulnerabilities),
    )
    block = audit_chain.add_audit(record)
    result.blockchain_tx_hash = block.hash

    return result


# ── Blockchain endpoints ──────────────────────────────────────────────


chain_router = APIRouter(prefix="/api/v1/chain", tags=["blockchain"])


@chain_router.get("/blocks")
async def get_chain():
    """Return the full audit blockchain."""
    return {
        "length": len(audit_chain.chain),
        "valid": audit_chain.verify_chain(),
        "blocks": audit_chain.get_chain_data(),
    }


@chain_router.get("/blocks/{block_hash}")
async def get_block(block_hash: str):
    """Look up a single block by its hash."""
    block = audit_chain.get_block_by_hash(block_hash)
    if not block:
        raise HTTPException(status_code=404, detail="Block not found.")
    return {
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


@chain_router.get("/verify")
async def verify_chain():
    """Verify the integrity of the entire audit chain."""
    return {
        "valid": audit_chain.verify_chain(),
        "length": len(audit_chain.chain),
    }


# ── Health ────────────────────────────────────────────────────────────


health_router = APIRouter(tags=["health"])


@health_router.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0", "chain_length": len(audit_chain.chain)}

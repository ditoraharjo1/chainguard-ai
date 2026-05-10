"""Tests for the FastAPI endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient

from src.api.app import create_app

app = create_app()


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_health(client: AsyncClient) -> None:
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "chain_length" in data


@pytest.mark.asyncio
async def test_analyze_endpoint(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/v1/analyze",
        json={
            "source_code": "pragma solidity ^0.8.0; contract Test { }",
            "contract_name": "Test",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "vulnerabilities" in data
    assert "risk_score" in data
    assert "blockchain_tx_hash" in data
    assert data["blockchain_tx_hash"] is not None


@pytest.mark.asyncio
async def test_analyze_empty_code(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/v1/analyze",
        json={"source_code": "   ", "contract_name": "Empty"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_chain_blocks(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/chain/blocks")
    assert resp.status_code == 200
    data = resp.json()
    assert "blocks" in data
    assert data["valid"] is True


@pytest.mark.asyncio
async def test_chain_verify(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/chain/verify")
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True


@pytest.mark.asyncio
async def test_block_not_found(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/chain/blocks/nonexistent")
    assert resp.status_code == 404

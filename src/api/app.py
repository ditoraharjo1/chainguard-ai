"""FastAPI application factory for ChainGuard AI."""

from __future__ import annotations

import pathlib

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.api.routes import chain_router, health_router, router

DESCRIPTION = """
# ChainGuard AI 🛡️

**AI-Powered Smart Contract Security Analyzer with Blockchain Audit Trail**

ChainGuard AI combines pattern-based static analysis with AI-driven risk
scoring to detect vulnerabilities in Solidity smart contracts.  Every audit
result is anchored to a lightweight proof-of-work blockchain, creating an
immutable, verifiable record of all scans.

## Features

- 🔍 **15+ vulnerability patterns** — reentrancy, overflow, access control, and more
- 🤖 **AI risk scoring** — weighted confidence model with context-aware adjustments
- ⛓️ **Blockchain audit trail** — each scan is mined into a tamper-proof block
- 📊 **Rich dashboard** — upload contracts and view results in real time
- 🔌 **REST API** — integrate into CI/CD pipelines
"""


def create_app() -> FastAPI:
    app = FastAPI(
        title="ChainGuard AI",
        description=DESCRIPTION,
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health_router)
    app.include_router(router)
    app.include_router(chain_router)

    # Static files & templates
    base = pathlib.Path(__file__).resolve().parent.parent.parent
    static_dir = base / "frontend" / "static"
    templates_dir = base / "frontend" / "templates"

    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    if templates_dir.exists():
        templates = Jinja2Templates(directory=str(templates_dir))

        @app.get("/", response_class=HTMLResponse)
        async def index(request: Request):
            return templates.TemplateResponse(request, "index.html")

    return app


app = create_app()

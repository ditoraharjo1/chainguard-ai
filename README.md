<div align="center">

# 🛡️ ChainGuard AI

### AI-Powered Smart Contract Security Analyzer with Blockchain Audit Trail

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104%2B-009688.svg)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

**Detect vulnerabilities in Solidity smart contracts using AI pattern analysis,
with every audit result anchored to a tamper-proof blockchain.**

[Features](#-features) · [Quick Start](#-quick-start) · [Architecture](#-architecture) · [API](#-api-reference) · [Contributing](#-contributing)

</div>

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **15+ Vulnerability Patterns** | Reentrancy, integer overflow, unchecked calls, tx.origin auth, unprotected selfdestruct, dangerous delegatecall, front-running, DoS, and more |
| 🤖 **AI Risk Scoring** | Weighted confidence model with context-aware adjustments — boosts severity when risky patterns co-occur, reduces false positives when mitigations are present |
| ⛓️ **Blockchain Audit Trail** | Every scan is mined into a proof-of-work blockchain block, creating an immutable, verifiable history of all audits |
| 📊 **Web Dashboard** | Modern dark-theme UI to upload contracts, view vulnerabilities, explore the blockchain, and read AI-generated security summaries |
| 🔌 **REST API** | Full-featured API with Swagger/ReDoc docs — integrate into CI/CD pipelines |
| 🖥️ **CLI Tool** | Analyze contracts from your terminal with rich formatted output |
| 🐳 **Docker Ready** | One-command deployment with the included Dockerfile |

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        ChainGuard AI                             │
├──────────────┬───────────────┬──────────────┬───────────────────┤
│  Frontend    │   REST API    │  AI Engine   │  Blockchain       │
│  Dashboard   │   (FastAPI)   │  (Analyzer)  │  (Audit Chain)    │
├──────────────┼───────────────┼──────────────┼───────────────────┤
│ HTML/CSS/JS  │ /api/v1/*     │ Pattern      │ Proof-of-Work     │
│ Dark Theme   │ Upload .sol   │ Matching     │ SHA-256 Hashing   │
│ Drag & Drop  │ JSON API      │ Context      │ Chain Validation  │
│ Real-time    │ Swagger Docs  │ Scoring      │ Immutable Blocks  │
│ Charts       │ CORS Ready    │ AI Summary   │ Block Explorer    │
└──────────────┴───────────────┴──────────────┴───────────────────┘
```

### Project Structure

```
chainguard-ai/
├── src/
│   ├── analyzer/          # Vulnerability detection engine
│   │   ├── engine.py      # Core analysis pipeline
│   │   └── patterns.py    # 15+ vulnerability pattern definitions
│   ├── blockchain/        # Blockchain audit trail
│   │   └── chain.py       # Proof-of-work chain implementation
│   ├── api/               # FastAPI application
│   │   ├── app.py         # App factory & middleware
│   │   └── routes.py      # API endpoints
│   ├── models/            # Pydantic data models
│   │   └── vulnerability.py
│   └── cli.py             # Command-line interface
├── frontend/
│   ├── templates/
│   │   └── index.html     # Dashboard SPA
│   └── static/
│       ├── style.css      # Dark theme styles
│       └── app.js         # Frontend logic
├── contracts/
│   └── examples/
│       ├── VulnerableVault.sol  # Insecure demo contract
│       └── SecureVault.sol      # Best-practices contract
├── tests/
│   ├── test_analyzer.py   # Analyzer unit tests
│   ├── test_blockchain.py # Blockchain unit tests
│   └── test_api.py        # API integration tests
├── pyproject.toml
├── Dockerfile
└── README.md
```

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- pip or uv

### Installation

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/chainguard-ai.git
cd chainguard-ai

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install dependencies
pip install -e ".[dev]"
```

### Run the Web Dashboard

```bash
# Start the server
python -m uvicorn src.api.app:app --reload --port 8000

# Open http://localhost:8000 in your browser
```

### CLI Usage

```bash
# Analyze a contract file
python -m src.cli analyze contracts/examples/VulnerableVault.sol

# JSON output (for CI/CD integration)
python -m src.cli analyze contracts/examples/VulnerableVault.sol --json

# Start the web server
python -m src.cli serve --port 8000
```

### Docker

```bash
docker build -t chainguard-ai .
docker run -p 8000:8000 chainguard-ai
```

## 🔍 Vulnerability Detection

ChainGuard AI detects the following vulnerability patterns:

| # | Vulnerability | Severity | CWE |
|---|--------------|----------|-----|
| 1 | Reentrancy (call before state update) | 🔴 Critical | CWE-841 |
| 2 | Unprotected selfdestruct | 🔴 Critical | CWE-284 |
| 3 | Dangerous delegatecall | 🔴 Critical | CWE-829 |
| 4 | tx.origin authentication | 🟠 High | CWE-284 |
| 5 | Unchecked external call | 🟠 High | CWE-252 |
| 6 | Integer overflow (pre-0.8.0) | 🟠 High | CWE-190 |
| 7 | Missing access control | 🟠 High | CWE-284 |
| 8 | Timestamp dependency | 🟡 Medium | CWE-829 |
| 9 | Front-running susceptibility | 🟡 Medium | CWE-362 |
| 10 | Denial of Service (gas limit) | 🟡 Medium | CWE-400 |
| 11 | Unchecked math block | 🟡 Medium | CWE-190 |
| 12 | Floating pragma | 🔵 Low | CWE-1104 |

### AI Confidence Scoring

Each finding has a **confidence score** (0-100%) that adjusts based on context:

- **Boosted** when risky patterns co-occur (e.g., `msg.value` near `.call{}`)
- **Reduced** when mitigations are detected (e.g., `ReentrancyGuard`, `onlyOwner`)
- **Risk Grade** (A–F) aggregates all findings into a single score

## ⛓️ Blockchain Audit Trail

Every analysis result is stored in a proof-of-work blockchain:

1. **Mining** — Each audit is hashed into a block with a SHA-256 proof-of-work
2. **Linking** — Blocks reference the previous block's hash, forming a chain
3. **Verification** — The entire chain can be validated for tamper detection
4. **Explorer** — View blocks, hashes, and audit records in the web dashboard

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Block #0   │───▶│  Block #1   │───▶│  Block #2   │
│  (Genesis)  │    │  Audit: A   │    │  Audit: B   │
│  Hash: 00.. │    │  Hash: 00.. │    │  Hash: 00.. │
└─────────────┘    └─────────────┘    └─────────────┘
```

## 🔌 API Reference

### Analyze Contract

```http
POST /api/v1/analyze
Content-Type: application/json

{
  "source_code": "pragma solidity ^0.8.0; contract Test { ... }",
  "contract_name": "MyContract"
}
```

### Upload .sol File

```http
POST /api/v1/analyze/upload
Content-Type: multipart/form-data

file: @MyContract.sol
contract_name: MyContract
```

### Get Blockchain

```http
GET /api/v1/chain/blocks
```

### Verify Chain

```http
GET /api/v1/chain/verify
```

### Health Check

```http
GET /health
```

Full interactive docs available at `/docs` (Swagger) and `/redoc`.

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_analyzer.py

# Lint
ruff check src/ tests/
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built with ❤️ for the blockchain security community**

[Report Bug](../../issues) · [Request Feature](../../issues)

</div>

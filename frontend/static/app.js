/* ── ChainGuard AI — Frontend Application ─────────────────────────── */

const API = "/api/v1";

/* ── DOM refs ────────────────────────────────────────────────────── */
const codeEditor     = document.getElementById("code-editor");
const analyzeBtn     = document.getElementById("btn-analyze");
const fileInput      = document.getElementById("file-input");
const uploadZone     = document.getElementById("upload-zone");
const resultsSection = document.getElementById("results");

/* ── Tab system ──────────────────────────────────────────────────── */
document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
        document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
        document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
        btn.classList.add("active");
        document.getElementById(btn.dataset.tab).classList.add("active");
    });
});

/* ── Upload zone ─────────────────────────────────────────────────── */
uploadZone.addEventListener("click", () => fileInput.click());

uploadZone.addEventListener("dragover", e => {
    e.preventDefault();
    uploadZone.classList.add("dragover");
});

uploadZone.addEventListener("dragleave", () => uploadZone.classList.remove("dragover"));

uploadZone.addEventListener("drop", e => {
    e.preventDefault();
    uploadZone.classList.remove("dragover");
    const file = e.dataTransfer.files[0];
    if (file) loadFile(file);
});

fileInput.addEventListener("change", () => {
    if (fileInput.files[0]) loadFile(fileInput.files[0]);
});

function loadFile(file) {
    const reader = new FileReader();
    reader.onload = e => {
        codeEditor.value = e.target.result;
        // switch to editor tab
        document.querySelector('[data-tab="tab-editor"]').click();
    };
    reader.readAsText(file);
}

/* ── Sample contracts ────────────────────────────────────────────── */
const SAMPLE_VULNERABLE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = tx.origin; // Vulnerable: tx.origin auth
    }

    // Reentrancy: call before state update
    function withdraw(uint256 _amount) public {
        require(balances[msg.sender] >= _amount);

        (bool sent, ) = msg.sender.call{value: _amount}("");
        require(sent);

        balances[msg.sender] -= _amount;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // No access control
    function emergencyDrain(address payable _to) external {
        _to.call{value: address(this).balance}("");
    }

    // Unprotected selfdestruct
    function destroy() public {
        selfdestruct(payable(owner));
    }

    // DoS: unbounded loop
    address[] public depositors;
    function distributeRewards(uint256 _reward) public {
        for (uint256 i = 0; i < depositors.length; i++) {
            balances[depositors[i]] += _reward;
        }
    }

    // Timestamp dependency
    function isLocked() public view returns (bool) {
        return block.timestamp < 1700000000;
    }
}`;

const SAMPLE_SECURE = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureVault is ReentrancyGuard {
    mapping(address => uint256) public balances;
    address public immutable owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        require(msg.value > 0, "Must send ETH");
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 _amount) external nonReentrant {
        require(balances[msg.sender] >= _amount, "Insufficient");
        balances[msg.sender] -= _amount;
        (bool sent, ) = payable(msg.sender).call{value: _amount}("");
        require(sent, "Transfer failed");
    }

    function emergencyDrain(address payable _to) external onlyOwner {
        (bool sent, ) = _to.call{value: address(this).balance}("");
        require(sent);
    }
}`;

document.getElementById("load-vulnerable").addEventListener("click", () => {
    codeEditor.value = SAMPLE_VULNERABLE;
    document.querySelector('[data-tab="tab-editor"]').click();
});

document.getElementById("load-secure").addEventListener("click", () => {
    codeEditor.value = SAMPLE_SECURE;
    document.querySelector('[data-tab="tab-editor"]').click();
});

/* ── Analyze ─────────────────────────────────────────────────────── */
analyzeBtn.addEventListener("click", analyze);

async function analyze() {
    const code = codeEditor.value.trim();
    if (!code) return alert("Please enter Solidity source code.");

    analyzeBtn.classList.add("loading");
    analyzeBtn.disabled = true;

    try {
        const res = await fetch(`${API}/analyze`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ source_code: code, contract_name: "UserContract" }),
        });

        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || "Analysis failed");
        }

        const data = await res.json();
        renderResults(data);
        loadChain();
    } catch (e) {
        alert("Error: " + e.message);
    } finally {
        analyzeBtn.classList.remove("loading");
        analyzeBtn.disabled = false;
    }
}

/* ── Render results ──────────────────────────────────────────────── */
function renderResults(data) {
    resultsSection.classList.add("visible");

    // Stats
    document.getElementById("stat-vulns").textContent    = data.vulnerabilities.length;
    document.getElementById("stat-score").textContent     = data.risk_score.overall;
    document.getElementById("stat-grade").textContent     = data.risk_score.grade;
    document.getElementById("stat-time").textContent      = data.analysis_duration_ms + "ms";
    document.getElementById("stat-functions").textContent = data.metadata.num_functions;
    document.getElementById("stat-lines").textContent     = data.metadata.total_lines;

    // Risk badge
    const badge = document.getElementById("risk-badge");
    badge.textContent = data.risk_score.grade;
    badge.className = `risk-badge grade-${data.risk_score.grade}`;

    // Score bars
    renderScoreBar("bar-security",   data.risk_score.security);
    renderScoreBar("bar-quality",    data.risk_score.code_quality);
    renderScoreBar("bar-complexity", data.risk_score.complexity);

    // AI Summary
    document.getElementById("ai-summary").textContent = data.ai_summary;

    // Vulnerabilities
    const vulnList = document.getElementById("vuln-list");
    vulnList.innerHTML = "";

    if (data.vulnerabilities.length === 0) {
        vulnList.innerHTML = `
            <div style="text-align:center;padding:2rem;color:var(--success);">
                <div style="font-size:3rem;margin-bottom:0.5rem;">&#x2714;</div>
                <p>No vulnerabilities detected!</p>
            </div>`;
        return;
    }

    data.vulnerabilities.forEach(v => {
        const li = document.createElement("li");
        li.className = "vuln-item";
        li.innerHTML = `
            <div class="vuln-header">
                <span class="severity-tag severity-${v.severity}">${v.severity}</span>
                <span class="vuln-title">${escHtml(v.title)}</span>
                <span class="vuln-confidence">${(v.confidence * 100).toFixed(0)}% conf.</span>
            </div>
            <div class="vuln-details">
                <p>${escHtml(v.description)}</p>
                ${v.code_snippet ? `<pre class="vuln-snippet">${escHtml(v.code_snippet)}</pre>` : ""}
                <div class="vuln-fix"><strong>Fix:</strong> ${escHtml(v.recommendation)}</div>
                ${v.line_number ? `<p style="margin-top:0.5rem;color:var(--text-muted);font-size:0.8rem;">Line ${v.line_number} ${v.cwe_id ? "| " + v.cwe_id : ""}</p>` : ""}
            </div>`;
        li.addEventListener("click", () => li.classList.toggle("expanded"));
        vulnList.appendChild(li);
    });

    // Blockchain tx hash
    if (data.blockchain_tx_hash) {
        document.getElementById("tx-hash").textContent = data.blockchain_tx_hash;
        document.getElementById("tx-hash-section").style.display = "block";
    }

    // Scroll to results
    resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderScoreBar(id, value) {
    const bar = document.getElementById(id);
    bar.style.width = `${Math.min(100, value)}%`;
    const color = value <= 30 ? "var(--success)" : value <= 60 ? "var(--warning)" : "var(--danger)";
    bar.style.background = color;
    bar.parentElement.nextElementSibling.querySelector(".score-val").textContent = value.toFixed(1);
}

/* ── Blockchain ──────────────────────────────────────────────────── */
async function loadChain() {
    try {
        const res = await fetch(`${API}/chain/blocks`);
        const data = await res.json();

        document.getElementById("chain-length").textContent = data.length;
        document.getElementById("chain-valid").textContent = data.valid ? "Valid" : "INVALID";
        document.getElementById("chain-valid").style.color = data.valid ? "var(--success)" : "var(--danger)";

        const container = document.getElementById("chain-blocks");
        container.innerHTML = "";

        // Show last 10 blocks (newest first)
        const blocks = data.blocks.slice(-10).reverse();
        blocks.forEach((block, i) => {
            if (i > 0) {
                const connector = document.createElement("div");
                connector.className = "chain-connector";
                connector.textContent = "\u2B07";
                container.appendChild(connector);
            }

            const div = document.createElement("div");
            div.className = "chain-block";
            div.innerHTML = `
                <span class="label">Block</span><span class="value">#${block.index}</span>
                <span class="label">Hash</span><span class="value hash">${block.hash.slice(0, 24)}...</span>
                <span class="label">Contract</span><span class="value">${escHtml(block.audit.contract_name)}</span>
                <span class="label">Grade</span><span class="value">${block.audit.risk_grade} (${block.audit.risk_score})</span>
                <span class="label">Issues</span><span class="value">${block.audit.num_vulnerabilities}</span>
                <span class="label">Nonce</span><span class="value">${block.nonce}</span>`;
            container.appendChild(div);
        });
    } catch (e) {
        console.error("Failed to load chain:", e);
    }
}

/* ── Helpers ──────────────────────────────────────────────────────── */
function escHtml(s) {
    const div = document.createElement("div");
    div.textContent = s;
    return div.innerHTML;
}

/* ── Init ─────────────────────────────────────────────────────────── */
loadChain();

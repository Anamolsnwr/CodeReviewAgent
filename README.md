# CodeReviewAgent 🛡️

A production-grade, AI-powered code review and automated remediation platform. CodeReviewAgent combines deterministic static analysis (AST inspection, security pattern detection, complexity scoring) with large language model review to find bugs, security vulnerabilities, and code quality issues, validate AI-generated fixes across 7 verification gates, and generate auditable PDF and JSON reports.

---

## 🚀 Key Features

### 1. GitHub Pull Request Reviews
- **Repository Connection**: Connect public or private GitHub repositories by owner, repo name, and pull request number.
- **Diff Parsing & Line Mapping**: Maps git unified diff hunks to head line numbers.
- **Priority Line Analysis**: Prioritizes newly introduced vulnerabilities in changed lines while retaining surrounding code context.
- **Deduplicated & Authorized Review Comments**: Validates comment positions against active diff hunks before submission, checks for existing comments to prevent duplicates, and **strictly requires explicit user confirmation** before posting to GitHub. Never auto-approves or modifies PRs.

### 2. AI-Powered Fixes with 7-Step Validation
- **Structured Fix Proposals**: Formulates root causes, technical explanations, unified diffs, and compatibility risk disclosures.
- **Rigorous 7-Step Validation Pipeline**:
  1. **Match Verification**: Verifies target file exists and exact snippet matches.
  2. **Unambiguity Check**: Rejects ambiguous, out-of-range, or stale patches.
  3. **Scope Guard**: Ensures the patch is strictly confined to targeted code without touching unrelated logic.
  4. **Syntax / AST Parse**: Confirms the patch produces valid Python AST syntax without compilation errors.
  5. **Isolated Test Execution**: Executes unit and targeted regression tests in a restricted subprocess with timeouts (8s) and zero shell execution.
  6. **Security Property Verification**: Re-scans patched code to guarantee the original vulnerability rule is actually eliminated.
  7. **Regression Detection**: Compares before-and-after findings to ensure no new critical or high severity defects were introduced.
- **Safe Application & Rollback**: Creates automatic timestamped `.bak` backups before applying fixes to disk and allows one-click rollback.

### 3. Persistent Scan History & Deep Comparisons
- **SQLite Database (`scans.db`)**: Lightweight, zero-configuration local persistence with schema migration tracking.
- **Stable Finding Fingerprints**: Computes stable SHA-256 hashes (`rule_id` + normalized code + file) so findings remain stably identified even when line numbers shift across commits.
- **Deep Scan Comparisons**: Compare any two scans to identify:
  - 🚨 Newly introduced findings
  - ✅ Resolved findings
  - 🔄 Unchanged findings
  - 📊 Risk score delta
- **Data Retention**: Built-in 30-day retention cleanup.

### 4. Professional Report Generation
- **Executive PDF Reports**: Formatted using `fpdf2` with color-coded severity badges, risk score cards, detailed findings, AI remediation results, and safe typography escaping.
- **Structured JSON Reports**: Machine-readable JSON output with automated credential and token redaction.

---

## 🏗️ Architecture

```
CodeReviewAgent/
├── app.py                         # Streamlit interactive Web Dashboard
├── code_reviewer.py               # Backward-compatible CLI / Tkinter entry point
├── scans.db                       # Persistent SQLite database (auto-created)
├── requirements.txt               # Pinned dependencies
├── .env.example                   # Configuration template
├── codereview/                    # Core modular engine
│   ├── models.py                  # Domain models (Finding, FixProposal, ScanResult, etc.)
│   ├── github/                    # GitHub API integration & diff parsing
│   │   ├── client.py              # REST API client with timeouts & pagination
│   │   ├── diff_parser.py         # Unified diff parser & line mapper
│   │   └── review_poster.py       # Deduplicated PR reviewer & position validator
│   ├── providers/                 # AI provider abstraction layer
│   │   ├── base.py                # BaseAIProvider interface
│   │   ├── groq_provider.py       # Groq LLM provider (openai/gpt-oss-120b)
│   │   └── mock_provider.py       # Deterministic mock provider for tests
│   ├── remediation/               # AI patch generator & 7-step validation engine
│   │   ├── patcher.py             # Diff creator, patch applier, backup & rollback
│   │   └── validator.py           # 7-step safety validation pipeline
│   ├── reports/                   # PDF & JSON report generation
│   │   ├── pdf_exporter.py        # Styled PDF report generator (fpdf2)
│   │   └── json_exporter.py       # Redacted JSON report exporter
│   ├── scanners/                  # Deterministic static analyzers
│   │   ├── ast_scanner.py         # Python AST syntax & security scanner
│   │   ├── complexity_scanner.py  # Radon cyclomatic complexity & maintainability
│   │   ├── engine.py              # Unified ReviewEngine orchestrator
│   │   └── security_scanner.py    # Regex vulnerability & secrets detector
│   ├── scoring/                   # Risk score calculation
│   │   └── calculator.py          # 0-100 weighted risk score & level evaluator
│   ├── storage/                   # Persistent storage layer
│   │   └── db.py                  # SQLite database engine with migrations
│   └── utils/                     # Security & helper utilities
│       └── security.py            # Credential redaction, path safety, prompt boundary
└── tests/                         # Comprehensive automated test suite
    ├── test_diff_parser.py        # Diff parsing & hunk tests
    ├── test_github.py             # GitHub client & review comment tests
    ├── test_remediation.py        # Patch validation & rollback tests
    ├── test_reports.py            # PDF & JSON report export tests
    ├── test_scanners_and_engine.py# Static scanner & risk score tests
    ├── test_security.py           # Credential redaction & prompt injection tests
    └── test_storage.py            # SQLite persistence & fingerprint comparison tests
```

---

## 🛠️ Installation & Setup

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.13)
- Git

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy `.env.example` to `.env` and fill in your API credentials:
```bash
cp .env.example .env
```
Contents of `.env`:
```ini
GROQ_API_KEY=gsk_your_groq_api_key_here
GROQ_MODEL=openai/gpt-oss-120b
GITHUB_TOKEN=ghp_your_github_token_here
```

#### GitHub Token Permissions
- **Public repositories**: `public_repo` scope.
- **Private repositories**: `repo` scope.
- For pull request reviews: Ensure the token has `pull_requests: write` or `repo` permissions to publish comments upon authorization.

---

## 💻 Usage

### Option A: Interactive Web Dashboard (Recommended)
Launch the Streamlit web dashboard:
```bash
streamlit run app.py
```
Open your browser to `http://localhost:8501`. The dashboard includes:
- **📁 Local Review**: Upload Python files or paste snippets to review.
- **🐙 GitHub PR Reviews**: Connect GitHub PRs, inspect changed hunks, review findings, and publish authorized reviews.
- **🛠️ AI Fix & Validation Studio**: Inspect diffs, execute the 7-step validation pipeline, apply patches with backups, and rollback.
- **📜 Scan History & Comparisons**: View past audits and compare two scans to see new vs resolved issues.
- **📥 Reports & Exports**: Download complete audit reports in PDF and JSON formats.

### Option B: CLI / Tkinter Entry Point
You can still run the backward-compatible entry point:
```bash
# Interactive file dialog:
python code_reviewer.py

# Direct command-line file argument:
python code_reviewer.py path/to/your_file.py
```

---

## 🧪 Testing

Run the automated test suite with pytest:
```bash
python -m pytest tests -v
```

All 35 unit, integration, and security tests run offline using mocked GitHub API endpoints and mock AI providers, with zero paid API usage.

---

## 🔒 Security & Safe Operation Principles

1. **Prompt Injection Defense**: Untrusted source code and pull request diffs are wrapped in strict security boundaries (`<UNTRUSTED_SOURCE_CODE_DATA>`) with explicit instructions forbidding the LLM from executing or following instructions embedded inside source code.
2. **Credential Redaction**: Tokens (`ghp_*`, `gsk_*`, `sk-*`, `AKIA*`, private keys, passwords) are automatically redacted in error messages, logs, diffs, and report exports.
3. **Mandatory Explicit Confirmation**: No changes to disk (patches) and no remote API calls (publishing GitHub reviews) will ever occur without explicit user confirmation.
4. **Isolated Workloads**: Compilation and test runs are executed in isolated temporary directories with strict timeouts (8s) and `shell=False`.
5. **No Auto-Merge**: The system never merges, closes, or approves pull requests automatically.

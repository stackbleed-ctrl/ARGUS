# 🔍 Argus v2

**AI-powered open source vulnerability scanner. Built for defenders.**
**Nefarious actors, look away. 👁**

[![PyPI](https://img.shields.io/pypi/v/argus-scanner)](https://pypi.org/project/argus-scanner/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)

Argus v2 combines **four detection layers** to find what everything else misses:

| Layer | Method | Cost |
|---|---|---|
| 1 | 60+ regex patterns across 18 vuln categories | Free |
| 2 | Shannon entropy scan — finds embedded secrets even without keyword context | Free |
| 3 | Claude semantic analysis — taint tracing, logic flaws, auth bypasses | API key |
| 4 | Dependency audit via OSV.dev — CVEs in your packages | Free |

No cloud upload of your code. No SaaS. No vendor lock-in. Just a CLI you run yourself.

---

## Install

```bash
pip install argus-scanner

# Full install (watch mode + YAML config)
pip install "argus-scanner[full]"
```

Set your API key (optional — pattern + entropy mode works without it):
```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Commands

### `argus scan` — Scan a directory or file

```bash
# Full scan (AI + patterns + entropy + dep audit)
argus scan ./myproject

# Generate AI fix patches for CRITICAL/HIGH findings
argus scan ./myproject --fix

# Pattern + entropy only (no API key needed, instant)
argus scan ./myproject --no-ai

# Save reports
argus scan ./myproject -o report.json --sarif results.sarif

# Only show HIGH and above
argus scan ./myproject --severity HIGH

# Verbose: descriptions, code snippets, fix recommendations
argus scan ./myproject --verbose

# Baseline comparison (CI regression detection)
argus scan ./myproject --baseline report-v1.json -o report-v2.json
```

### `argus audit` — Interactive triage

```bash
argus audit report.json
```

Arrow-key through findings. Per-finding actions:

| Key | Action |
|---|---|
| `↑↓` | Navigate |
| `a` | Accept (mark as confirmed vulnerability) |
| `d` | Dismiss (suppress — adds to `.argus-ignore`) |
| `s` | Snooze (skip for this session) |
| `p` | View AI-generated patch diff |
| `e` | Export as GitHub Issue body |
| `q` | Save & quit |

### `argus watch` — Live guard mode

```bash
argus watch ./src
```

Watches for file saves, rescans instantly. Catches vulnerabilities before you even commit.
Requires: `pip install "argus-scanner[watch]"`

### `argus init` — Project setup

```bash
argus init
```

Creates `.argus.yml` and `.argus-ignore` in the current directory.

---

## Output

```
  ▄████████████████████████████████████▄
  █  ARGUS v2  —  Defensive AI Scanner  █
  █    👁  Watching. Always watching.    █
  ▀████████████████████████████████████▀

──────────────────────────────────────────────────────────────
  ARGUS SCAN COMPLETE
──────────────────────────────────────────────────────────────
  Target:    /home/user/myproject
  Scan ID:   a3f9c12b8e4d
  Files:     847  |  Lines: 142,391
  Duration:  23.4s
  Mode:      AI + Pattern + Entropy
──────────────────────────────────────────────────────────────
  CRITICAL   ████ 2
  HIGH       ████████████████ 8
  MEDIUM     ██████████████████████████████ 15
  LOW        ████████ 4

  Total findings: 29
  Dep advisories: 6  3 CRITICAL  2 HIGH
──────────────────────────────────────────────────────────────
```

Each finding includes: severity, CWE, file + line, code snippet, actionable fix recommendation, confidence, detection method, and a stable **fingerprint** for baseline tracking.

---

## Configuration (`.argus.yml`)

```yaml
# Which severity levels fail CI
fail_on:
  - CRITICAL
  - HIGH

# Paths to skip
ignore_paths:
  - tests/
  - fixtures/
  - vendor/

# Dependency audit via OSV.dev (free, no key needed)
dep_audit: true

# Auto-generate AI fix patches for CRITICAL/HIGH
fix_mode: false

# Concurrency
concurrency: 5
```

## Suppression (`.argus-ignore`)

Use `argus audit` to interactively dismiss findings. Dismissed findings are added to `.argus-ignore` by fingerprint — they won't resurface in future scans or CI runs.

```
# .argus-ignore — one fingerprint per line
a1b2c3d4e5f6g7h8
```

---

## What Argus v2 Finds

### Code Vulnerabilities (Pattern + AI)

| Category | CWE | Detection |
|---|---|---|
| SQL Injection | CWE-89 | Pattern + AI |
| Command Injection | CWE-78 | Pattern + AI |
| Path Traversal | CWE-22 | Pattern + AI |
| Hardcoded Secrets | CWE-798 | Pattern + Entropy + AI |
| High-Entropy Strings | CWE-798 | Entropy |
| Insecure Deserialization | CWE-502 | Pattern + AI |
| SSRF / XXE | CWE-918 | Pattern + AI |
| XSS | CWE-79 | Pattern + AI |
| Open Redirect | CWE-601 | Pattern + AI |
| Auth/JWT Bypasses | CWE-287 | Pattern + AI |
| Weak Cryptography | CWE-327 | Pattern + AI |
| IDOR / Mass Assignment | CWE-639 | Pattern + AI |
| Prototype Pollution | CWE-1321 | Pattern + AI |
| Debug Mode Enabled | CWE-489 | Pattern |
| Weak Password Hashing | CWE-916 | Pattern + AI |
| Insecure File Upload | CWE-434 | Pattern + AI |
| GraphQL Misconfig | CWE-200 | Pattern |
| IaC Misconfigurations | CWE-732 | Pattern |
| Race Conditions | CWE-362 | AI |
| Business Logic Flaws | — | AI |
| Memory Safety (C/C++) | CWE-119 | AI |
| Second-Order Injection | CWE-89 | AI |
| JWT Algorithm Confusion | CWE-327 | Pattern + AI |
| Dependency Confusion | CWE-1104 | Pattern |

### Dependency Vulnerabilities (OSV.dev — free, no key)

- Python (`requirements.txt`, `pyproject.toml`, `Pipfile`)
- JavaScript (`package.json`, `yarn.lock`)
- Go (`go.mod`)
- Ruby (`Gemfile.lock`)
- Rust (`Cargo.toml`)
- Java (`pom.xml`) *(via AI)*

---

## Architecture

```
argus scan ./target
     │
     ├─ collect_files()              # Walk, respect excludes + .argus.yml
     │
     ├─ PatternScanner               # 60+ regex patterns, 18 categories
     │   └─ EntropyScanner           # Shannon entropy on all string literals
     │
     ├─ AIAnalyzer (async)           # Claude semantic / taint analysis
     │   ├─ Chunked file reading     # Handles large files gracefully
     │   ├─ Hint injection           # Pattern hints inform AI context
     │   ├─ Deduplication            # AI doesn't re-report pattern hits
     │   └─ Fix generation           # Unified diff patches (--fix mode)
     │
     ├─ DependencyAuditor            # Parse manifests → OSV.dev batch API
     │   ├─ requirements.txt / pyproject.toml
     │   ├─ package.json
     │   ├─ go.mod
     │   ├─ Gemfile.lock
     │   └─ Cargo.toml
     │
     └─ Reporter
         ├─ Console (colored, severity bars)
         ├─ JSON (fingerprinted, baseline-diffable)
         ├─ SARIF (GitHub Code Scanning)
         └─ .patch files (--fix mode)
```

---

## GitHub Actions Integration

```yaml
# .github/workflows/argus.yml
name: Argus Security Scan

on: [push, pull_request]

jobs:
  argus:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install Argus
        run: pip install argus-scanner

      - name: Run Argus
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          argus scan . \
            -o argus-report.json \
            --sarif argus-results.sarif \
            --severity LOW

      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: argus-results.sarif

      - name: Upload report artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: argus-report
          path: argus-report.json
```

### PR Regression Mode (only fail on NEW findings)

```yaml
      - name: Download baseline
        uses: dawidd6/action-download-artifact@v3
        with:
          name: argus-report
          path: baseline/
        continue-on-error: true

      - name: Run Argus with baseline
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          argus scan . \
            --baseline baseline/argus-report.json \
            -o argus-report.json \
            --sarif argus-results.sarif
```

---

## Supported Languages

Python · JavaScript · TypeScript · Go · Rust · C · C++ · Java · Kotlin · Scala · PHP · Ruby · Shell · YAML · TOML · Terraform (HCL) · C# · Swift · Lua · SQL · HTML/Jinja · XML

---

## Responsible Use

Argus is a **defensive** tool. If you find vulnerabilities in other projects:

1. Contact the maintainer privately (security@ or GitHub Security Advisories)
2. Give them reasonable time to patch (90 days is standard)
3. Only publish after a fix is available

Do not use Argus to scan systems you don't own or have explicit permission to test.

---

## Contributing

High-value contributions:

- New pattern checks (`argus/patterns/scanner.py`)
- Language-specific parser improvements
- Benchmark suite against DVWA, WebGoat, Juice Shop
- Integration tests
- GitHub Issue / Jira export connectors in triage mode

```bash
git clone https://github.com/stackbleed-ctrl/ARGUS
cd ARGUS
pip install -e ".[full]"
pytest
```

---

## License

MIT — use it, fork it, ship it.

---

*Built with Claude. Threat actors not welcome. 👁*

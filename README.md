# 🔍 Argus

**AI-powered open source vulnerability scanner. Built for defenders.**

[![PyPI](https://img.shields.io/pypi/v/argus-scanner)](https://pypi.org/project/argus-scanner/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)

Argus combines **fast regex pattern matching** with **Claude's semantic reasoning** to find vulnerabilities that automated tools miss — logic flaws, auth bypasses, subtle injection vectors, and cryptographic weaknesses.

No cloud upload of your code. No SaaS. Just a CLI you run yourself.

---

## Why Argus?

Most SAST tools match patterns. They find the obvious stuff. What they miss:

- Business logic flaws requiring cross-file reasoning
- Auth bypasses that depend on execution context
- Subtle type confusion vulnerabilities
- Cryptographic misuse that isn't syntactically wrong
- Race conditions and TOCTOU issues

Argus uses Claude to *read* your code the way a security researcher does — understanding what it does, not just what it looks like.

---

## Install

```bash
pip install argus-scanner
```

Set your API key:
```bash
export ANTHROPIC_API_KEY=your_key_here
```

---

## Usage

```bash
# Scan a directory (AI + pattern mode)
argus scan ./myproject

# Pattern-only mode (no API key needed, fast)
argus scan ./myproject --no-ai

# Save reports
argus scan ./myproject -o report.json --sarif results.sarif

# Only show HIGH and above
argus scan ./myproject --severity HIGH

# Verbose output with code snippets and fix recommendations
argus scan ./myproject --verbose

# High concurrency for large repos
argus scan ./myproject --concurrency 10
```

---

## Output

```
  ▄████████████████████████████████▄
  █  ARGUS — Defensive AI Code Audit █
  ▀████████████████████████████████▀

────────────────────────────────────────────────────────────
  ARGUS SCAN COMPLETE
────────────────────────────────────────────────────────────
  Target:   /home/user/myproject
  Scan ID:  a3f9c12b8e4d
  Files:    847  |  Lines: 142,391
  Duration: 23.4s
  Mode:     AI + Pattern
────────────────────────────────────────────────────────────
  CRITICAL   ██ 2
  HIGH       ████████ 8
  MEDIUM     ███████████████ 15
  LOW        ████ 4

  Total findings: 29
```

Each finding includes:
- **Severity** (CRITICAL / HIGH / MEDIUM / LOW)
- **CWE identifier**
- **Exact file and line number**
- **Code snippet**
- **Specific, actionable fix recommendation**
- **Confidence level** and detection method (AI vs pattern)

---

## GitHub Actions Integration

Drop this in `.github/workflows/argus.yml` and findings appear natively in the **Security** tab:

```yaml
- name: Run Argus
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: argus scan . --sarif results.sarif

- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

See [`.github/workflows/argus-scan.yml`](.github/workflows/argus-scan.yml) for the full workflow with PR comments.

---

## What Argus Finds

| Category | CWE | Detection |
|----------|-----|-----------|
| SQL Injection | CWE-89 | Pattern + AI |
| Command Injection | CWE-78 | Pattern + AI |
| Path Traversal | CWE-22 | Pattern + AI |
| Hardcoded Secrets | CWE-798 | Pattern + AI |
| Insecure Deserialization | CWE-502 | Pattern + AI |
| SSRF / XXE | CWE-611 | Pattern + AI |
| Auth/Authz Bypasses | CWE-285 | AI |
| Cryptographic Weaknesses | CWE-327 | AI |
| Race Conditions | CWE-362 | AI |
| Business Logic Flaws | — | AI |
| Memory Safety (C/C++) | CWE-119 | AI |

---

## Supported Languages

Python · JavaScript · TypeScript · Go · Rust · C · C++ · Java · PHP · Ruby · Shell · YAML · Terraform

---

## Architecture

```
argus scan ./target
     │
     ├─ collect_files()          # Walk directory, respect excludes
     │
     ├─ PatternScanner           # Fast regex, zero API cost
     │   └─ QUICK_PATTERN_CHECKS # 18 patterns across 6 categories
     │
     ├─ AIAnalyzer (async)       # Claude semantic analysis
     │   ├─ Chunked file reading  # Handles large files gracefully
     │   ├─ Hint injection        # Pattern findings inform AI context
     │   └─ Deduplication         # AI doesn't re-report pattern hits
     │
     └─ Reporter
         ├─ Console summary + colored findings
         ├─ JSON report
         └─ SARIF (GitHub Code Scanning compatible)
```

**Privacy**: Your code is sent to the Anthropic API for analysis. Review [Anthropic's privacy policy](https://anthropic.com/privacy) before scanning proprietary code. Use `--no-ai` for air-gapped or sensitive environments.

---

## Responsible Disclosure

If Argus finds vulnerabilities in **other people's software**, please follow coordinated disclosure:

1. Contact the maintainer privately (security@ email, GitHub Security Advisories)
2. Give them reasonable time to patch (90 days is standard)
3. Only publish after a fix is available

Do not use Argus to scan systems you don't own or have explicit permission to test.

---

## Contributing

PRs welcome. High-value contributions:

- New pattern checks (`argus/patterns/`)
- Language-specific analyzers
- Better deduplication logic
- Benchmark suite against known-vulnerable repos (DVWA, WebGoat, etc.)
- Integration tests

```bash
git clone https://github.com/yourusername/argus
cd argus
pip install -e ".[dev]"
pytest
```

---

## License

MIT — use it, fork it, ship it. Attribution appreciated but not required.

---

*Built with Claude. Not affiliated with Anthropic.*

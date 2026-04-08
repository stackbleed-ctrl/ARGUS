"""
Argus - AI-Powered Open Source Vulnerability Scanner
Core scanning engine using Claude for deep semantic analysis.
"""

import os
import ast
import json
import hashlib
import asyncio
import aiohttp
import argparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional
import re

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-sonnet-4-20250514"

# ─── Severity & Finding Types ────────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[31m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[34m",
    "INFO":     "\033[36m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs",
    ".c", ".cpp", ".h", ".java", ".php", ".rb", ".sh",
    ".yaml", ".yml", ".json", ".toml", ".env", ".tf",
}

QUICK_PATTERN_CHECKS = {
    "hardcoded_secret": [
        r'(?i)(password|passwd|secret|api_?key|token|auth)\s*=\s*["\'][^"\']{8,}["\']',
        r'(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*["\'][A-Z0-9/+]{20,}["\']',
        r'(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}',
    ],
    "sql_injection": [
        r'(?i)(execute|cursor\.execute|query)\s*\(\s*["\'].*%[s|d].*["\'].*%',
        r'(?i)f["\'].*SELECT.*\{',
        r'(?i)\+\s*["\']?\s*(WHERE|AND|OR|SELECT|INSERT|UPDATE|DELETE)',
    ],
    "command_injection": [
        r'(?i)(os\.system|subprocess\.call|subprocess\.run|shell=True)\s*\(.*\+',
        r'(?i)exec\s*\(\s*.*\+',
        r'(?i)`.*\$[{(]',
    ],
    "path_traversal": [
        r'(?i)open\s*\(\s*.*\+',
        r'\.\./|\.\.',
        r'(?i)(readfile|include|require)\s*\(\s*.*\$',
    ],
    "insecure_deserialize": [
        r'(?i)(pickle\.loads|yaml\.load\s*\([^,)]*\)(?!\s*,\s*Loader))',
        r'(?i)unserialize\s*\(',
        r'(?i)eval\s*\(.*request',
    ],
    "xxe_ssrf": [
        r'(?i)(requests\.get|urllib\.request)\s*\(.*\+',
        r'(?i)lxml.*resolve_entities\s*=\s*True',
        r'(?i)etree\.parse\s*\(',
    ],
}


@dataclass
class Finding:
    id: str
    severity: str
    category: str
    title: str
    description: str
    file: str
    line_start: int
    line_end: int
    code_snippet: str
    recommendation: str
    cwe: Optional[str] = None
    cvss_score: Optional[float] = None
    confidence: str = "MEDIUM"
    detected_by: str = "pattern"

    def to_dict(self):
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    scan_id: str
    timestamp: str
    files_scanned: int = 0
    lines_scanned: int = 0
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    duration_seconds: float = 0.0
    model_used: str = MODEL

    @property
    def critical_count(self): return sum(1 for f in self.findings if f.severity == "CRITICAL")
    @property
    def high_count(self): return sum(1 for f in self.findings if f.severity == "HIGH")
    @property
    def medium_count(self): return sum(1 for f in self.findings if f.severity == "MEDIUM")
    @property
    def low_count(self): return sum(1 for f in self.findings if f.severity == "LOW")


# ─── Pattern Scanner ──────────────────────────────────────────────────────────

class PatternScanner:
    def scan_file(self, path: Path, content: str) -> list[Finding]:
        findings = []
        lines = content.splitlines()

        for category, patterns in QUICK_PATTERN_CHECKS.items():
            for pattern in patterns:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line):
                        fid = hashlib.md5(f"{path}{i}{category}".encode()).hexdigest()[:8]
                        findings.append(Finding(
                            id=f"PAT-{fid}",
                            severity=self._severity_for_category(category),
                            category=category,
                            title=f"Potential {category.replace('_', ' ').title()}",
                            description=f"Pattern match for {category} at line {i}",
                            file=str(path),
                            line_start=i,
                            line_end=i,
                            code_snippet=line.strip()[:200],
                            recommendation=self._recommendation(category),
                            cwe=self._cwe_for_category(category),
                            confidence="MEDIUM",
                            detected_by="pattern"
                        ))
        return findings

    def _severity_for_category(self, cat):
        mapping = {
            "hardcoded_secret": "HIGH",
            "sql_injection": "HIGH",
            "command_injection": "CRITICAL",
            "path_traversal": "MEDIUM",
            "insecure_deserialize": "HIGH",
            "xxe_ssrf": "HIGH",
        }
        return mapping.get(cat, "MEDIUM")

    def _cwe_for_category(self, cat):
        mapping = {
            "hardcoded_secret": "CWE-798",
            "sql_injection": "CWE-89",
            "command_injection": "CWE-78",
            "path_traversal": "CWE-22",
            "insecure_deserialize": "CWE-502",
            "xxe_ssrf": "CWE-611",
        }
        return mapping.get(cat)

    def _recommendation(self, cat):
        mapping = {
            "hardcoded_secret": "Use environment variables or a secrets manager. Never commit credentials.",
            "sql_injection": "Use parameterized queries or an ORM. Never concatenate user input into SQL.",
            "command_injection": "Avoid shell=True. Use subprocess with argument lists. Sanitize all inputs.",
            "path_traversal": "Validate and sanitize file paths. Use os.path.realpath and check against allowed dirs.",
            "insecure_deserialize": "Use safe deserializers. For YAML, use yaml.safe_load. Avoid pickle with untrusted data.",
            "xxe_ssrf": "Disable external entity resolution. Validate and allowlist URLs before fetching.",
        }
        return mapping.get(cat, "Review and sanitize this code.")


# ─── Claude AI Deep Analyzer ──────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a world-class application security researcher performing a defensive code audit.

Your job: find real, exploitable security vulnerabilities. Be precise, not paranoid.

For each vulnerability found, respond ONLY with a valid JSON array of objects:
[
  {
    "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "category": "e.g. sql_injection, xss, buffer_overflow, ...",
    "title": "short title",
    "description": "precise technical description of the vulnerability",
    "line_start": <int>,
    "line_end": <int>,
    "code_snippet": "the vulnerable code",
    "recommendation": "specific, actionable fix",
    "cwe": "CWE-XXX or null",
    "cvss_score": <float 0-10 or null>,
    "confidence": "HIGH|MEDIUM|LOW"
  }
]

If no vulnerabilities found, return: []

Focus on:
- Logic flaws that automated scanners miss
- Authentication/authorization bypasses
- Cryptographic weaknesses
- Race conditions
- Memory safety issues
- Business logic vulnerabilities

Do NOT report: style issues, theoretical issues without exploitability, or issues already caught by linters.
Return ONLY the JSON array, no prose."""


class AIAnalyzer:
    def __init__(self, api_key: str, max_file_lines: int = 300):
        self.api_key = api_key
        self.max_file_lines = max_file_lines

    async def analyze_file(self, path: Path, content: str,
                           pattern_findings: list[Finding]) -> list[Finding]:
        lines = content.splitlines()
        if len(lines) > self.max_file_lines:
            # Chunk large files
            chunks = [lines[i:i+self.max_file_lines]
                      for i in range(0, len(lines), self.max_file_lines)]
        else:
            chunks = [lines]

        findings = []
        for chunk_idx, chunk in enumerate(chunks):
            offset = chunk_idx * self.max_file_lines
            chunk_findings = await self._analyze_chunk(
                path, "\n".join(chunk), offset, pattern_findings
            )
            findings.extend(chunk_findings)
        return findings

    async def _analyze_chunk(self, path: Path, content: str,
                              line_offset: int, hints: list[Finding]) -> list[Finding]:
        hint_summary = ""
        if hints:
            hint_summary = "\n\nPattern scanner already found these (don't re-report, but use as context):\n"
            for h in hints[:5]:
                hint_summary += f"- Line {h.line_start}: {h.title}\n"

        user_msg = f"""Audit this {path.suffix} file for security vulnerabilities:

File: {path.name}
Line offset: {line_offset}
{hint_summary}

```
{content}
```"""

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    ANTHROPIC_API_URL,
                    headers={
                        "x-api-key": self.api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": MODEL,
                        "max_tokens": 2000,
                        "system": SYSTEM_PROMPT,
                        "messages": [{"role": "user", "content": user_msg}],
                    },
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json()
                    raw = data["content"][0]["text"].strip()
                    raw = re.sub(r'^```json\s*', '', raw)
                    raw = re.sub(r'```$', '', raw).strip()
                    items = json.loads(raw)
                    findings = []
                    for item in items:
                        fid = hashlib.md5(
                            f"{path}{item.get('line_start',0)}{item.get('title','')}".encode()
                        ).hexdigest()[:8]
                        findings.append(Finding(
                            id=f"AI-{fid}",
                            severity=item.get("severity", "MEDIUM"),
                            category=item.get("category", "unknown"),
                            title=item.get("title", "Unnamed finding"),
                            description=item.get("description", ""),
                            file=str(path),
                            line_start=item.get("line_start", 0) + line_offset,
                            line_end=item.get("line_end", 0) + line_offset,
                            code_snippet=item.get("code_snippet", "")[:300],
                            recommendation=item.get("recommendation", ""),
                            cwe=item.get("cwe"),
                            cvss_score=item.get("cvss_score"),
                            confidence=item.get("confidence", "MEDIUM"),
                            detected_by="ai"
                        ))
                    return findings
        except Exception:
            return []


# ─── Main Scanner Orchestrator ────────────────────────────────────────────────

class ArgusScanner:
    def __init__(self, api_key: Optional[str] = None,
                 ai_mode: bool = True,
                 max_concurrent: int = 5,
                 exclude_dirs: list[str] = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.ai_mode = ai_mode and bool(self.api_key)
        self.max_concurrent = max_concurrent
        self.exclude_dirs = set(exclude_dirs or [
            ".git", "node_modules", "__pycache__", ".venv",
            "venv", "dist", "build", ".tox", "vendor"
        ])
        self.pattern_scanner = PatternScanner()
        self.ai_analyzer = AIAnalyzer(self.api_key) if self.ai_mode else None
        self._semaphore = asyncio.Semaphore(max_concurrent)

    def collect_files(self, target: Path) -> list[Path]:
        if target.is_file():
            return [target]
        files = []
        for f in target.rglob("*"):
            if any(exc in f.parts for exc in self.exclude_dirs):
                continue
            if f.is_file() and f.suffix in SUPPORTED_EXTENSIONS:
                files.append(f)
        return sorted(files)

    async def scan_file(self, path: Path) -> tuple[list[Finding], list[str], int]:
        async with self._semaphore:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                return [], [f"Read error {path}: {e}"], 0

            lines = len(content.splitlines())
            pattern_findings = self.pattern_scanner.scan_file(path, content)

            if self.ai_mode and self.ai_analyzer:
                ai_findings = await self.ai_analyzer.analyze_file(
                    path, content, pattern_findings
                )
                # Deduplicate: skip AI findings that overlap with pattern findings
                deduped = []
                for af in ai_findings:
                    overlap = any(
                        abs(af.line_start - pf.line_start) <= 2 and
                        af.category == pf.category
                        for pf in pattern_findings
                    )
                    if not overlap:
                        deduped.append(af)
                all_findings = pattern_findings + deduped
            else:
                all_findings = pattern_findings

            return all_findings, [], lines

    async def scan(self, target: str) -> ScanResult:
        t = Path(target)
        scan_id = hashlib.md5(f"{target}{datetime.utcnow()}".encode()).hexdigest()[:12]
        result = ScanResult(
            target=str(t.resolve()),
            scan_id=scan_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
        )

        files = self.collect_files(t)
        start = asyncio.get_event_loop().time()

        tasks = [self.scan_file(f) for f in files]
        results = await asyncio.gather(*tasks)

        for findings, errors, lines in results:
            result.findings.extend(findings)
            result.errors.extend(errors)
            result.lines_scanned += lines

        result.files_scanned = len(files)
        result.duration_seconds = round(asyncio.get_event_loop().time() - start, 2)

        # Sort by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        result.findings.sort(key=lambda f: sev_order.get(f.severity, 5))

        return result


# ─── Reporter ─────────────────────────────────────────────────────────────────

class Reporter:
    def print_summary(self, result: ScanResult):
        print(f"\n{BOLD}{'─'*60}{RESET}")
        print(f"{BOLD}  ARGUS SCAN COMPLETE{RESET}")
        print(f"{'─'*60}")
        print(f"  Target:   {result.target}")
        print(f"  Scan ID:  {result.scan_id}")
        print(f"  Files:    {result.files_scanned:,}  |  Lines: {result.lines_scanned:,}")
        print(f"  Duration: {result.duration_seconds}s")
        print(f"  Mode:     {'AI + Pattern' if result.model_used else 'Pattern only'}")
        print(f"{'─'*60}")

        counts = {
            "CRITICAL": result.critical_count,
            "HIGH":     result.high_count,
            "MEDIUM":   result.medium_count,
            "LOW":      result.low_count,
        }
        for sev, count in counts.items():
            if count:
                color = SEVERITY_COLORS[sev]
                bar = "█" * min(count, 40)
                print(f"  {color}{sev:<10}{RESET} {bar} {count}")

        total = len(result.findings)
        print(f"\n  Total findings: {BOLD}{total}{RESET}")

    def print_findings(self, result: ScanResult, verbose: bool = False):
        for f in result.findings:
            color = SEVERITY_COLORS.get(f.severity, "")
            print(f"\n{color}{BOLD}[{f.severity}] {f.title}{RESET}")
            print(f"  File:   {f.file}:{f.line_start}")
            print(f"  CWE:    {f.cwe or 'N/A'}  |  Confidence: {f.confidence}  |  By: {f.detected_by}")
            if verbose:
                print(f"  Desc:   {f.description}")
                print(f"  Code:   {f.code_snippet[:120]}")
                print(f"  Fix:    {f.recommendation}")

    def save_json(self, result: ScanResult, output: Path):
        data = {
            "scan_id": result.scan_id,
            "target": result.target,
            "timestamp": result.timestamp,
            "summary": {
                "files_scanned": result.files_scanned,
                "lines_scanned": result.lines_scanned,
                "duration_seconds": result.duration_seconds,
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
                "total": len(result.findings),
            },
            "findings": [f.to_dict() for f in result.findings],
            "errors": result.errors,
        }
        output.write_text(json.dumps(data, indent=2))
        print(f"\n  📄 Report saved: {output}")

    def save_sarif(self, result: ScanResult, output: Path):
        """GitHub-compatible SARIF format for security alerts integration."""
        rules = {}
        for f in result.findings:
            rid = f.category
            if rid not in rules:
                rules[rid] = {
                    "id": rid,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe.replace('CWE-','')}.html" if f.cwe else "",
                    "properties": {"tags": ["security"]},
                }

        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Argus",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/yourusername/argus",
                        "rules": list(rules.values()),
                    }
                },
                "results": [
                    {
                        "ruleId": f.category,
                        "level": {"CRITICAL": "error", "HIGH": "error",
                                  "MEDIUM": "warning", "LOW": "note"}.get(f.severity, "note"),
                        "message": {"text": f.description},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.file},
                                "region": {
                                    "startLine": f.line_start,
                                    "endLine": f.line_end,
                                    "snippet": {"text": f.code_snippet},
                                }
                            }
                        }]
                    }
                    for f in result.findings
                ]
            }]
        }
        output.write_text(json.dumps(sarif, indent=2))
        print(f"  📊 SARIF saved: {output}")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Argus — AI-Powered Open Source Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  argus scan ./myproject
  argus scan ./myproject --no-ai
  argus scan ./myproject -o report.json --sarif report.sarif
  argus scan ./myproject --severity HIGH --verbose
        """
    )
    sub = parser.add_subparsers(dest="command")
    scan_p = sub.add_parser("scan", help="Scan a directory or file")
    scan_p.add_argument("target", help="Path to scan")
    scan_p.add_argument("--no-ai", action="store_true", help="Pattern-only mode (no API key needed)")
    scan_p.add_argument("-o", "--output", help="Save JSON report to file")
    scan_p.add_argument("--sarif", help="Save SARIF report (GitHub Code Scanning)")
    scan_p.add_argument("--severity", default="LOW",
                        choices=["CRITICAL","HIGH","MEDIUM","LOW","INFO"],
                        help="Minimum severity to display")
    scan_p.add_argument("--verbose", "-v", action="store_true")
    scan_p.add_argument("--concurrency", type=int, default=5)

    args = parser.parse_args()

    if args.command == "scan":
        print(f"""
{BOLD}  ▄████████████████████████████████▄
  █  ARGUS — Defensive AI Code Audit █
  ▀████████████████████████████████▀{RESET}
        """)

        scanner = ArgusScanner(
            ai_mode=not args.no_ai,
            max_concurrent=args.concurrency,
        )
        reporter = Reporter()

        result = asyncio.run(scanner.scan(args.target))

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        min_sev = sev_order[args.severity]
        result.findings = [
            f for f in result.findings
            if sev_order.get(f.severity, 4) <= min_sev
        ]

        reporter.print_summary(result)
        reporter.print_findings(result, verbose=args.verbose)

        if args.output:
            reporter.save_json(result, Path(args.output))
        if args.sarif:
            reporter.save_sarif(result, Path(args.sarif))

        # Exit code for CI pipelines
        if result.critical_count > 0:
            exit(2)
        elif result.high_count > 0:
            exit(1)
        exit(0)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

"""
Argus v2 — Core types, dataclasses, and constants.
"""
from __future__ import annotations
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime

# ─── ANSI Colors ─────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[31m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[34m",
    "INFO":     "\033[36m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
GREEN = "\033[32m"
CYAN  = "\033[36m"

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# ─── Supported file types ─────────────────────────────────────────────────────

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".go", ".rs", ".c", ".cpp", ".h", ".hpp",
    ".java", ".kt", ".scala",
    ".php", ".rb", ".pl",
    ".sh", ".bash", ".zsh", ".fish",
    ".yaml", ".yml", ".json", ".toml", ".env",
    ".tf", ".tfvars", ".hcl",
    ".cs", ".vb",
    ".swift", ".m",
    ".lua", ".r",
    ".sql",
    ".html", ".htm", ".ejs", ".jinja", ".j2",
    ".xml",
}

DEPENDENCY_FILES = {
    "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
    "Pipfile", "Pipfile.lock",
    "pyproject.toml", "setup.py", "setup.cfg",
    "package.json", "package-lock.json", "yarn.lock",
    "go.mod", "go.sum",
    "Gemfile", "Gemfile.lock",
    "Cargo.toml", "Cargo.lock",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "composer.json", "composer.lock",
}

# ─── Finding dataclass ────────────────────────────────────────────────────────

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
    cwe: Optional[str]            = None
    cvss_score: Optional[float]   = None
    confidence: str               = "MEDIUM"
    detected_by: str              = "pattern"
    fix_diff: Optional[str]       = None   # populated by --fix mode
    fingerprint: Optional[str]    = None   # for baseline diffing
    suppressed: bool              = False  # for .argus-ignore

    def __post_init__(self):
        if not self.fingerprint:
            raw = f"{self.file}:{self.category}:{self.line_start}:{self.code_snippet[:80]}"
            self.fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Finding":
        return Finding(**{k: v for k, v in d.items() if k in Finding.__dataclass_fields__})

# ─── ScanResult dataclass ─────────────────────────────────────────────────────

@dataclass
class ScanResult:
    target:          str
    scan_id:         str
    timestamp:       str
    files_scanned:   int   = 0
    lines_scanned:   int   = 0
    findings:        list  = field(default_factory=list)
    errors:          list  = field(default_factory=list)
    duration_seconds: float = 0.0
    model_used:      str   = ""
    dep_advisories:  list  = field(default_factory=list)  # OSV results

    @property
    def critical_count(self): return sum(1 for f in self.findings if f.severity == "CRITICAL" and not f.suppressed)
    @property
    def high_count(self):     return sum(1 for f in self.findings if f.severity == "HIGH"     and not f.suppressed)
    @property
    def medium_count(self):   return sum(1 for f in self.findings if f.severity == "MEDIUM"   and not f.suppressed)
    @property
    def low_count(self):      return sum(1 for f in self.findings if f.severity == "LOW"      and not f.suppressed)

    def active_findings(self):
        return [f for f in self.findings if not f.suppressed]

# ─── Baseline diff result ─────────────────────────────────────────────────────

@dataclass
class BaselineDiff:
    new_findings:      list  # regressions — these fail CI
    resolved_findings: list  # wins
    unchanged_findings: list
    new_critical: int = 0
    new_high: int     = 0

    def __post_init__(self):
        self.new_critical = sum(1 for f in self.new_findings if f.severity == "CRITICAL")
        self.new_high     = sum(1 for f in self.new_findings if f.severity == "HIGH")

# ─── Dependency advisory ──────────────────────────────────────────────────────

@dataclass
class DepAdvisory:
    package:    str
    version:    str
    ecosystem:  str
    vuln_id:    str
    severity:   str
    summary:    str
    details:    str
    fixed_in:   Optional[str] = None
    cvss_score: Optional[float] = None
    aliases:    list = field(default_factory=list)

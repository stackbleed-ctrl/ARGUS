"""
Argus v2 — Main scanner orchestrator.
Coordinates pattern scan, entropy scan, AI analysis, dep audit, and baseline diff.
"""
from __future__ import annotations

import os
import json
import hashlib
import asyncio
from pathlib import Path
from typing import Optional
from datetime import datetime

from argus.core.types import (
    Finding, ScanResult, BaselineDiff, DepAdvisory,
    SUPPORTED_EXTENSIONS, DEPENDENCY_FILES, SEV_ORDER,
)
from argus.patterns.scanner import PatternScanner
from argus.core.ai import AIAnalyzer, MODEL
from argus.core.deps import audit_dependencies
from argus.core.config import ArgusConfig

EXCLUDE_DIRS_DEFAULT = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox", "vendor", ".next", "coverage",
    ".pytest_cache", "htmlcov", "target", "out",
}


class ArgusScanner:

    def __init__(
        self,
        config: Optional[ArgusConfig] = None,
        api_key: Optional[str] = None,
        ai_mode: bool = True,
        fix_mode: bool = False,
        max_concurrent: int = 5,
        dep_audit: bool = True,
    ):
        self.config      = config or ArgusConfig()
        self.api_key     = api_key or os.getenv("ANTHROPIC_API_KEY") or self.config.api_key
        self.ai_mode     = ai_mode and bool(self.api_key)
        self.fix_mode    = fix_mode
        self.dep_audit   = dep_audit
        self.max_concurrent = max_concurrent

        self.exclude_dirs = EXCLUDE_DIRS_DEFAULT | set(self.config.ignore_paths)

        self.pattern_scanner = PatternScanner()
        self.ai_analyzer     = (
            AIAnalyzer(self.api_key, fix_mode=fix_mode)
            if self.ai_mode else None
        )
        self._semaphore = asyncio.Semaphore(max_concurrent)

    # ── File collection ────────────────────────────────────────────────────

    def collect_files(self, target: Path) -> list[Path]:
        if target.is_file():
            return [target]

        files = []
        for f in target.rglob("*"):
            if any(exc in f.parts for exc in self.exclude_dirs):
                continue
            if f.is_file() and (
                f.suffix in SUPPORTED_EXTENSIONS or
                f.name in DEPENDENCY_FILES
            ):
                files.append(f)
        return sorted(files)

    # ── Single file scan ───────────────────────────────────────────────────

    async def scan_file(
        self, path: Path
    ) -> tuple[list[Finding], list[str], int]:
        async with self._semaphore:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                return [], [f"Read error {path}: {e}"], 0

            lines = len(content.splitlines())

            # Pattern + entropy pass
            pattern_findings = self.pattern_scanner.scan_file(path, content)

            if self.ai_mode and self.ai_analyzer:
                ai_findings = await self.ai_analyzer.analyze_file(
                    path, content, pattern_findings
                )
                # Deduplicate: drop AI findings that overlap with pattern findings
                deduped_ai = []
                for af in ai_findings:
                    overlap = any(
                        abs(af.line_start - pf.line_start) <= 3 and
                        af.category == pf.category
                        for pf in pattern_findings
                    )
                    if not overlap:
                        deduped_ai.append(af)
                all_findings = pattern_findings + deduped_ai
            else:
                all_findings = pattern_findings

            # Apply suppression list from config / .argus-ignore
            all_findings = self._apply_suppressions(all_findings)

            return all_findings, [], lines

    # ── Suppression ────────────────────────────────────────────────────────

    def _apply_suppressions(self, findings: list[Finding]) -> list[Finding]:
        if not self.config.suppressed_fingerprints:
            return findings
        for f in findings:
            if f.fingerprint in self.config.suppressed_fingerprints:
                f.suppressed = True
        return findings

    # ── Full scan ──────────────────────────────────────────────────────────

    async def scan(self, target: str, watch_mode: bool = False) -> ScanResult:
        t = Path(target)
        scan_id = hashlib.md5(
            f"{target}{datetime.utcnow().isoformat()}".encode()
        ).hexdigest()[:12]

        result = ScanResult(
            target=str(t.resolve()),
            scan_id=scan_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
            model_used=MODEL if self.ai_mode else "",
        )

        files = self.collect_files(t)
        start = asyncio.get_event_loop().time()

        # Run all file scans concurrently (bounded by semaphore)
        tasks = [self.scan_file(f) for f in files]
        scan_results = await asyncio.gather(*tasks)

        for findings, errors, lines in scan_results:
            result.findings.extend(findings)
            result.errors.extend(errors)
            result.lines_scanned += lines
        result.files_scanned = len(files)

        # Dependency audit
        if self.dep_audit:
            result.dep_advisories = await audit_dependencies(t)

        result.duration_seconds = round(asyncio.get_event_loop().time() - start, 2)

        # Sort by severity
        result.findings.sort(key=lambda f: SEV_ORDER.get(f.severity, 5))

        return result

    # ── Baseline comparison ────────────────────────────────────────────────

    @staticmethod
    def diff_baseline(current: ScanResult, baseline: ScanResult) -> BaselineDiff:
        """
        Compare current scan against a previous baseline.
        Returns new findings (regressions), resolved findings, and unchanged.
        """
        baseline_fps: set[str] = {
            f.fingerprint for f in baseline.findings if f.fingerprint
        }
        current_fps: set[str] = {
            f.fingerprint for f in current.findings if f.fingerprint
        }

        new_findings = [
            f for f in current.findings
            if f.fingerprint not in baseline_fps
        ]
        resolved_findings = [
            f for f in baseline.findings
            if f.fingerprint not in current_fps
        ]
        unchanged_findings = [
            f for f in current.findings
            if f.fingerprint in baseline_fps
        ]

        return BaselineDiff(
            new_findings=sorted(new_findings, key=lambda f: SEV_ORDER.get(f.severity, 5)),
            resolved_findings=resolved_findings,
            unchanged_findings=unchanged_findings,
        )

    # ── Incremental (watch mode) ───────────────────────────────────────────

    async def scan_single_file(self, path: Path) -> list[Finding]:
        """Rescan a single file — used by watch mode."""
        findings, _, _ = await self.scan_file(path)
        return findings

"""
Argus v2 — Reporter.
Console (rich colored), JSON, SARIF, and baseline diff output.
"""
from __future__ import annotations

import json
from pathlib import Path
from argus.core.types import (
    Finding, ScanResult, BaselineDiff, DepAdvisory,
    SEVERITY_COLORS, RESET, BOLD, DIM, GREEN, CYAN, SEV_ORDER,
)

# ─── Console ─────────────────────────────────────────────────────────────────

BANNER = f"""\
{BOLD}
  ▄████████████████████████████████████▄
  █  ARGUS v2  —  Defensive AI Scanner  █
  █    👁  Watching. Always watching.    █
  ▀████████████████████████████████████▀{RESET}
"""

class Reporter:

    # ── Scan summary ──────────────────────────────────────────────────────

    def print_banner(self):
        print(BANNER)

    def print_summary(self, result: ScanResult, diff: BaselineDiff = None):
        sep = "─" * 62
        print(f"\n{BOLD}{sep}{RESET}")
        print(f"{BOLD}  ARGUS SCAN COMPLETE{RESET}")
        print(sep)
        print(f"  Target:    {result.target}")
        print(f"  Scan ID:   {result.scan_id}")
        print(f"  Timestamp: {result.timestamp}")
        print(f"  Files:     {result.files_scanned:,}  |  Lines: {result.lines_scanned:,}")
        print(f"  Duration:  {result.duration_seconds}s")
        print(f"  Mode:      {'AI + Pattern + Entropy' if result.model_used else 'Pattern + Entropy (no AI)'}")
        if result.model_used:
            print(f"  Model:     {result.model_used}")
        print(sep)

        active = result.active_findings()
        counts = {
            "CRITICAL": result.critical_count,
            "HIGH":     result.high_count,
            "MEDIUM":   result.medium_count,
            "LOW":      result.low_count,
        }
        for sev, count in counts.items():
            if count:
                color = SEVERITY_COLORS[sev]
                bar   = "█" * min(count * 2, 50)
                print(f"  {color}{sev:<10}{RESET} {bar} {count}")

        suppressed = len([f for f in result.findings if f.suppressed])
        total_active = len(active)
        print(f"\n  Total findings: {BOLD}{total_active}{RESET}", end="")
        if suppressed:
            print(f"  {DIM}({suppressed} suppressed){RESET}", end="")
        print()

        # Dep advisory summary
        if result.dep_advisories:
            dep_crits = sum(1 for d in result.dep_advisories if d.severity == "CRITICAL")
            dep_high  = sum(1 for d in result.dep_advisories if d.severity == "HIGH")
            print(f"\n  Dep advisories: {BOLD}{len(result.dep_advisories)}{RESET}", end="")
            if dep_crits:
                print(f"  {SEVERITY_COLORS['CRITICAL']}{dep_crits} CRITICAL{RESET}", end="")
            if dep_high:
                print(f"  {SEVERITY_COLORS['HIGH']}{dep_high} HIGH{RESET}", end="")
            print()

        # Baseline diff summary
        if diff:
            print(f"\n  {BOLD}Baseline diff:{RESET}")
            if diff.new_findings:
                new_crits = sum(1 for f in diff.new_findings if f.severity == "CRITICAL")
                print(f"    {SEVERITY_COLORS['CRITICAL']}▲ {len(diff.new_findings)} NEW{RESET}", end="")
                if new_crits:
                    print(f" ({new_crits} CRITICAL)", end="")
                print()
            if diff.resolved_findings:
                print(f"    {GREEN}▼ {len(diff.resolved_findings)} RESOLVED{RESET}")
            if diff.unchanged_findings:
                print(f"    {DIM}= {len(diff.unchanged_findings)} unchanged{RESET}")

        print(sep)

    # ── Finding detail ────────────────────────────────────────────────────

    def print_findings(self, result: ScanResult, verbose: bool = False, min_severity: str = "LOW"):
        min_sev = SEV_ORDER.get(min_severity, 4)
        active  = [
            f for f in result.active_findings()
            if SEV_ORDER.get(f.severity, 4) <= min_sev
        ]

        if not active:
            print(f"\n  {GREEN}✓ No active findings at or above {min_severity}{RESET}\n")
            return

        print(f"\n{BOLD}  FINDINGS{RESET}\n")
        for f in active:
            color = SEVERITY_COLORS.get(f.severity, "")
            badge = f"[{f.severity}]"
            print(f"{color}{BOLD}{badge}{RESET} {f.title}")
            print(f"  {DIM}File:{RESET} {f.file}:{f.line_start}")
            print(f"  {DIM}CWE:{RESET}  {f.cwe or 'N/A'}  │  "
                  f"{DIM}Confidence:{RESET} {f.confidence}  │  "
                  f"{DIM}Detected by:{RESET} {f.detected_by}  │  "
                  f"{DIM}ID:{RESET} {f.id}")
            if verbose:
                print(f"  {DIM}Desc:{RESET} {f.description}")
                if f.code_snippet:
                    snippet = f.code_snippet.strip()[:160]
                    print(f"  {DIM}Code:{RESET} {snippet}")
                print(f"  {DIM}Fix: {RESET} {f.recommendation}")
                if f.fix_diff:
                    print(f"\n{DIM}  --- patch ---{RESET}")
                    for line in f.fix_diff.splitlines()[:30]:
                        if line.startswith("+"):
                            print(f"  {GREEN}{line}{RESET}")
                        elif line.startswith("-"):
                            print(f"  {SEVERITY_COLORS['HIGH']}{line}{RESET}")
                        else:
                            print(f"  {line}")
                    print()
            print()

    def print_dep_advisories(self, result: ScanResult, verbose: bool = False):
        if not result.dep_advisories:
            return
        print(f"\n{BOLD}  DEPENDENCY ADVISORIES{RESET}\n")
        for adv in result.dep_advisories:
            color = SEVERITY_COLORS.get(adv.severity, "")
            cvss_str = f" (CVSS {adv.cvss_score})" if adv.cvss_score else ""
            aliases  = f" [{', '.join(adv.aliases[:3])}]" if adv.aliases else ""
            print(f"{color}{BOLD}[{adv.severity}]{RESET} {adv.package} {adv.version} — {adv.vuln_id}{aliases}{cvss_str}")
            print(f"  {DIM}Ecosystem:{RESET} {adv.ecosystem}")
            print(f"  {DIM}Summary:{RESET}   {adv.summary}")
            if adv.fixed_in:
                print(f"  {GREEN}Fixed in:  {adv.fixed_in}{RESET}")
            if verbose and adv.details:
                print(f"  {DIM}Details:{RESET}   {adv.details[:200]}")
            print()

    def print_baseline_diff(self, diff: BaselineDiff, verbose: bool = False):
        if diff.new_findings:
            print(f"\n{BOLD}{SEVERITY_COLORS['CRITICAL']}  ▲ NEW FINDINGS (REGRESSIONS){RESET}\n")
            mock_result = type("R", (), {"active_findings": lambda self: diff.new_findings,
                                          "findings": diff.new_findings,
                                          "critical_count": diff.new_critical,
                                          "high_count": diff.new_high,
                                          "medium_count": 0,
                                          "low_count": 0})()
            self.print_findings(mock_result, verbose=verbose)

        if diff.resolved_findings:
            print(f"\n{BOLD}{GREEN}  ▼ RESOLVED FINDINGS{RESET}\n")
            for f in diff.resolved_findings:
                print(f"  {GREEN}✓{RESET} [{f.severity}] {f.title}  {DIM}({f.file}:{f.line_start}){RESET}")
            print()

    # ── JSON report ───────────────────────────────────────────────────────

    def save_json(self, result: ScanResult, output: Path, diff: BaselineDiff = None):
        data = {
            "schema_version": "2.0",
            "scan_id":   result.scan_id,
            "target":    result.target,
            "timestamp": result.timestamp,
            "model":     result.model_used,
            "summary": {
                "files_scanned":   result.files_scanned,
                "lines_scanned":   result.lines_scanned,
                "duration_seconds":result.duration_seconds,
                "critical": result.critical_count,
                "high":     result.high_count,
                "medium":   result.medium_count,
                "low":      result.low_count,
                "total":    len(result.active_findings()),
                "suppressed": len([f for f in result.findings if f.suppressed]),
            },
            "findings": [f.to_dict() for f in result.findings],
            "dep_advisories": [
                {
                    "package":    a.package,
                    "version":    a.version,
                    "ecosystem":  a.ecosystem,
                    "vuln_id":    a.vuln_id,
                    "severity":   a.severity,
                    "summary":    a.summary,
                    "fixed_in":   a.fixed_in,
                    "cvss_score": a.cvss_score,
                    "aliases":    a.aliases,
                }
                for a in result.dep_advisories
            ],
            "errors": result.errors,
        }
        if diff:
            data["baseline_diff"] = {
                "new_count":      len(diff.new_findings),
                "resolved_count": len(diff.resolved_findings),
                "unchanged_count":len(diff.unchanged_findings),
                "new_critical":   diff.new_critical,
                "new_high":       diff.new_high,
                "new_findings":   [f.to_dict() for f in diff.new_findings],
                "resolved_fingerprints": [f.fingerprint for f in diff.resolved_findings],
            }
        output.write_text(json.dumps(data, indent=2, default=str))
        print(f"\n  📄 JSON report: {output}")

    # ── SARIF report ──────────────────────────────────────────────────────

    def save_sarif(self, result: ScanResult, output: Path):
        """GitHub Code Scanning compatible SARIF 2.1.0."""
        rules_seen: dict[str, dict] = {}
        for f in result.active_findings():
            rid = f.category
            if rid not in rules_seen:
                cwe_url = ""
                if f.cwe:
                    cwe_num = f.cwe.replace("CWE-", "")
                    cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
                rules_seen[rid] = {
                    "id": rid,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription":  {"text": f.description},
                    "helpUri": cwe_url,
                    "properties": {"tags": ["security"], "precision": f.confidence.lower()},
                    "defaultConfiguration": {
                        "level": self._sarif_level(f.severity)
                    },
                }

        results = []
        for f in result.active_findings():
            r = {
                "ruleId": f.category,
                "level":  self._sarif_level(f.severity),
                "message": {"text": f"{f.description} — {f.recommendation}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"},
                        "region": {
                            "startLine": max(1, f.line_start),
                            "endLine":   max(1, f.line_end),
                            "snippet":   {"text": f.code_snippet},
                        }
                    }
                }],
                "fingerprints": {"argusV1": f.fingerprint or ""},
            }
            if f.cvss_score is not None:
                r["properties"] = {"cvss": f.cvss_score}
            results.append(r)

        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Argus",
                        "version": "2.0.0",
                        "semanticVersion": "2.0.0",
                        "informationUri": "https://github.com/stackbleed-ctrl/ARGUS",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
                "automationDetails": {
                    "id": f"argus/{result.scan_id}",
                    "description": {"text": f"Argus scan of {result.target}"},
                },
            }]
        }
        output.write_text(json.dumps(sarif, indent=2))
        print(f"  📊 SARIF:        {output}")

    @staticmethod
    def _sarif_level(severity: str) -> str:
        return {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning"}.get(severity, "note")

    # ── Fix patches ───────────────────────────────────────────────────────

    def save_patches(self, result: ScanResult, output_dir: Path):
        """Write .patch files for all findings that have a generated fix."""
        output_dir.mkdir(parents=True, exist_ok=True)
        saved = 0
        for f in result.active_findings():
            if f.fix_diff:
                patch_file = output_dir / f"argus-fix-{f.id}.patch"
                patch_file.write_text(f.fix_diff)
                saved += 1
        if saved:
            print(f"  🔧 {saved} patch(es) saved to: {output_dir}/")
        else:
            print(f"  🔧 No auto-fix patches generated.")

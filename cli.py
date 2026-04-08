"""
Argus v2 — CLI entry point.
Commands: scan, audit (triage), watch, init
"""
from __future__ import annotations

import os
import sys
import json
import asyncio
import argparse
from pathlib import Path

from argus.core.types import BOLD, RESET, DIM, SEV_ORDER, SEVERITY_COLORS, GREEN
from argus.core.config import ArgusConfig
from argus.core.scanner import ArgusScanner
from argus.reports.reporter import Reporter, BANNER


# ─── scan ─────────────────────────────────────────────────────────────────────

def cmd_scan(args, config: ArgusConfig):
    scanner = ArgusScanner(
        config=config,
        api_key=args.api_key or os.getenv("ANTHROPIC_API_KEY"),
        ai_mode=not args.no_ai,
        fix_mode=args.fix,
        max_concurrent=args.concurrency or config.concurrency,
        dep_audit=not args.no_deps,
    )
    reporter = Reporter()
    reporter.print_banner()

    result = asyncio.run(scanner.scan(args.target))

    # Baseline diff
    diff = None
    if args.baseline and Path(args.baseline).exists():
        try:
            baseline_data = json.loads(Path(args.baseline).read_text())
            from argus.core.types import ScanResult, Finding
            baseline_findings = [Finding.from_dict(f) for f in baseline_data.get("findings", [])]
            baseline_result = ScanResult(
                target    = baseline_data.get("target", ""),
                scan_id   = baseline_data.get("scan_id", ""),
                timestamp = baseline_data.get("timestamp", ""),
                findings  = baseline_findings,
            )
            diff = ArgusScanner.diff_baseline(result, baseline_result)
        except Exception as e:
            print(f"  {DIM}Warning: could not load baseline: {e}{RESET}")

    # Filter by severity for display
    reporter.print_summary(result, diff=diff)
    reporter.print_findings(result, verbose=args.verbose, min_severity=args.severity)
    reporter.print_dep_advisories(result, verbose=args.verbose)

    if diff:
        reporter.print_baseline_diff(diff, verbose=args.verbose)

    # Save outputs
    if args.output:
        reporter.save_json(result, Path(args.output), diff=diff)

    if args.sarif:
        reporter.save_sarif(result, Path(args.sarif))

    if args.fix and args.patches:
        reporter.save_patches(result, Path(args.patches))
    elif args.fix:
        reporter.save_patches(result, Path("argus-patches"))

    # Exit codes for CI
    if diff:
        # Baseline mode: fail only on NEW criticals/highs
        fail_sevs = set(config.fail_on)
        if diff.new_critical > 0 and "CRITICAL" in fail_sevs:
            sys.exit(2)
        if diff.new_high > 0 and "HIGH" in fail_sevs:
            sys.exit(1)
    else:
        fail_sevs = set(config.fail_on)
        if result.critical_count > 0 and "CRITICAL" in fail_sevs:
            sys.exit(2)
        if result.high_count > 0 and "HIGH" in fail_sevs:
            sys.exit(1)

    sys.exit(0)


# ─── audit (triage) ───────────────────────────────────────────────────────────

def cmd_audit(args, config: ArgusConfig):
    from argus.commands.triage import run_triage
    report_path = Path(args.report)
    sys.exit(run_triage(report_path, config))


# ─── watch ────────────────────────────────────────────────────────────────────

def cmd_watch(args, config: ArgusConfig):
    from argus.commands.watch import run_watch
    scanner = ArgusScanner(
        config=config,
        api_key=args.api_key or os.getenv("ANTHROPIC_API_KEY"),
        ai_mode=not args.no_ai,
        max_concurrent=2,
        dep_audit=False,  # too slow for watch mode
    )
    sys.exit(run_watch(args.target, scanner, config))


# ─── init ─────────────────────────────────────────────────────────────────────

def cmd_init(args, config: ArgusConfig):
    target = Path(args.target if hasattr(args, 'target') and args.target else ".")
    config_file = target / ".argus.yml"
    if config_file.exists():
        print(f"  .argus.yml already exists at {config_file}")
        return

    config_file.write_text("""\
# Argus v2 configuration
# https://github.com/stackbleed-ctrl/ARGUS

# Severity levels that cause CI to fail (exit code 1 or 2)
fail_on:
  - CRITICAL
  - HIGH

# Minimum severity to report (CRITICAL / HIGH / MEDIUM / LOW / INFO)
# min_severity: LOW

# Paths to ignore (relative to this file)
ignore_paths:
  - tests/
  - fixtures/
  - vendor/

# Minimum confidence to report (HIGH / MEDIUM / LOW)
min_confidence: LOW

# Max concurrent file scans
concurrency: 5

# Audit dependencies against OSV.dev
dep_audit: true

# Generate AI fix patches for CRITICAL/HIGH findings
fix_mode: false
""")
    print(f"  {GREEN}✓ Created .argus.yml{RESET}")

    ignore_file = target / ".argus-ignore"
    if not ignore_file.exists():
        ignore_file.write_text(
            "# Argus suppressed findings — add fingerprints here to suppress\n"
            "# Use `argus audit report.json` to interactively dismiss findings\n"
        )
        print(f"  {GREEN}✓ Created .argus-ignore{RESET}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="argus",
        description="Argus v2 — AI-Powered Vulnerability Scanner. Built for defenders.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{BOLD}Commands:{RESET}
  scan     Scan a directory or file for vulnerabilities
  audit    Interactively triage a saved scan report
  watch    Watch a directory and scan on file save
  init     Create .argus.yml config in target directory

{BOLD}Examples:{RESET}
  argus scan ./myapp
  argus scan ./myapp --no-ai --severity HIGH
  argus scan ./myapp -o report.json --sarif results.sarif
  argus scan ./myapp --fix --patches ./patches
  argus scan ./myapp --baseline report-v1.json
  argus audit report.json
  argus watch ./src
  argus init
""",
    )
    parser.add_argument("--version", action="version", version="argus 2.0.0")

    subs = parser.add_subparsers(dest="command")

    # ── scan ──
    sp = subs.add_parser("scan", help="Scan a directory or file")
    sp.add_argument("target", help="Path to scan")
    sp.add_argument("--no-ai",     action="store_true", help="Pattern + entropy only (no Claude API)")
    sp.add_argument("--no-deps",   action="store_true", help="Skip dependency audit")
    sp.add_argument("--fix",       action="store_true", help="Generate AI fix patches for CRITICAL/HIGH")
    sp.add_argument("--patches",   help="Directory to save .patch files (default: ./argus-patches)")
    sp.add_argument("-o", "--output", help="Save JSON report")
    sp.add_argument("--sarif",     help="Save SARIF report (for GitHub Code Scanning)")
    sp.add_argument("--baseline",  help="JSON report to compare against (shows regressions only)")
    sp.add_argument("--severity",  default="LOW",
                    choices=["CRITICAL","HIGH","MEDIUM","LOW","INFO"],
                    help="Minimum severity to display (default: LOW)")
    sp.add_argument("--verbose", "-v", action="store_true", help="Show descriptions, code snippets, and fixes")
    sp.add_argument("--concurrency", type=int, help="Concurrent file scans (overrides config)")
    sp.add_argument("--api-key", help="Anthropic API key (or set ANTHROPIC_API_KEY env var)")
    sp.add_argument("--config",  help="Path to .argus.yml (default: auto-discover)")

    # ── audit ──
    ap = subs.add_parser("audit", help="Interactively triage a scan report")
    ap.add_argument("report", help="Path to JSON report from `argus scan`")
    ap.add_argument("--config", help="Path to .argus.yml")

    # ── watch ──
    wp = subs.add_parser("watch", help="Watch directory, scan on file save")
    wp.add_argument("target", help="Directory to watch")
    wp.add_argument("--no-ai",    action="store_true")
    wp.add_argument("--api-key",  help="Anthropic API key")
    wp.add_argument("--config",   help="Path to .argus.yml")

    # ── init ──
    ip = subs.add_parser("init", help="Create .argus.yml config file")
    ip.add_argument("target", nargs="?", default=".", help="Directory (default: .)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Load config
    config_path = getattr(args, 'config', None)
    if config_path:
        config = ArgusConfig.load(Path(config_path))
    else:
        target = getattr(args, 'target', '.')
        config = ArgusConfig.load(Path(target))

    dispatch = {
        "scan":  cmd_scan,
        "audit": cmd_audit,
        "watch": cmd_watch,
        "init":  cmd_init,
    }
    dispatch[args.command](args, config)


if __name__ == "__main__":
    main()

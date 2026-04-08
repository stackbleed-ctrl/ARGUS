"""
Argus v2 — Interactive triage mode.
`argus audit report.json` — arrow-key through findings, accept/dismiss/snooze/export.
Works in any terminal without curses dependency.
"""
from __future__ import annotations

import sys
import json
import tty
import termios
import os
from pathlib import Path
from typing import Optional
from argus.core.types import (
    Finding, ScanResult, SEVERITY_COLORS, RESET, BOLD, DIM, GREEN, CYAN, SEV_ORDER
)
from argus.core.config import ArgusConfig

# ── Terminal helpers ──────────────────────────────────────────────────────────

def _getch() -> str:
    """Read a single keypress without echo."""
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        # Handle escape sequences (arrow keys)
        if ch == '\x1b':
            ch2 = sys.stdin.read(1)
            if ch2 == '[':
                ch3 = sys.stdin.read(1)
                return {'A': 'UP', 'B': 'DOWN', 'C': 'RIGHT', 'D': 'LEFT'}.get(ch3, '')
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

def _clear():
    os.system('clear' if os.name == 'posix' else 'cls')

def _term_width() -> int:
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 80

# ── Triage session ────────────────────────────────────────────────────────────

class TriageSession:

    ACTIONS = {
        'a': ('ACCEPT',   GREEN,                    'Mark as confirmed vulnerability'),
        'd': ('DISMISS',  '\033[90m',               'Suppress (add to .argus-ignore)'),
        's': ('SNOOZE',   '\033[35m',               'Snooze (skip for this session)'),
        'e': ('EXPORT',   CYAN,                     'Export to GitHub Issue / Jira'),
        'p': ('PATCH',    '\033[34m',               'View generated patch diff'),
        '?': ('HELP',     '',                       'Show keybindings'),
        'q': ('QUIT',     SEVERITY_COLORS['HIGH'],  'Save & quit'),
    }

    def __init__(self, result: ScanResult, config: ArgusConfig):
        self.result   = result
        self.config   = config
        self.findings = result.active_findings()
        self.idx      = 0
        self.accepted:  list[Finding] = []
        self.snoozed:   set[str]      = set()
        self.running    = True

    def run(self):
        if not self.findings:
            print("No active findings to triage.")
            return

        _clear()
        self._print_header()
        print(f"  {len(self.findings)} findings to triage.\n")
        print(f"  Controls: {BOLD}↑↓{RESET} navigate  {BOLD}a{RESET}ccept  {BOLD}d{RESET}ismiss  "
              f"{BOLD}s{RESET}nooze  {BOLD}p{RESET}atch  {BOLD}e{RESET}xport  {BOLD}q{RESET}uit\n")
        print("  Press any key to start...")
        _getch()

        while self.running and self.idx < len(self.findings):
            self._render()
            key = _getch()
            self._handle_key(key)

        self._print_session_summary()

    def _render(self):
        _clear()
        width = _term_width()
        f = self.findings[self.idx]
        color = SEVERITY_COLORS.get(f.severity, "")

        # Progress bar
        done = self.idx + 1
        total = len(self.findings)
        pct = done / total
        bar_width = min(40, width - 30)
        filled = int(bar_width * pct)
        bar = "█" * filled + "░" * (bar_width - filled)
        print(f"\n  [{bar}] {done}/{total}  {DIM}(a)ccept (d)ismiss (s)nooze (p)atch (q)uit{RESET}\n")

        # Finding card
        sev_badge = f"{color}{BOLD} {f.severity} {RESET}"
        print(f"  {sev_badge}  {BOLD}{f.title}{RESET}")
        print(f"  {'─' * (width - 4)}")
        print(f"  {DIM}File:{RESET}       {f.file}:{f.line_start}")
        print(f"  {DIM}CWE:{RESET}        {f.cwe or 'N/A'}")
        print(f"  {DIM}Confidence:{RESET} {f.confidence}  │  {DIM}Detected by:{RESET} {f.detected_by}")
        print(f"  {DIM}ID:{RESET}         {f.id}  │  {DIM}Fingerprint:{RESET} {f.fingerprint}")
        print()
        print(f"  {BOLD}Description:{RESET}")
        self._wrapped_print(f.description, width, indent=4)
        print()
        if f.code_snippet:
            print(f"  {BOLD}Code:{RESET}")
            for line in f.code_snippet.strip().splitlines()[:6]:
                print(f"    {DIM}{line}{RESET}")
            print()
        print(f"  {BOLD}Recommendation:{RESET}")
        self._wrapped_print(f.recommendation, width, indent=4)

        # Status badges
        statuses = []
        if f.fingerprint in self.snoozed:
            statuses.append(f"{DIM}[SNOOZED]{RESET}")
        if f in self.accepted:
            statuses.append(f"{GREEN}[ACCEPTED]{RESET}")
        if f.fingerprint in self.config.suppressed_fingerprints:
            statuses.append(f"{DIM}[SUPPRESSED]{RESET}")
        if f.fix_diff:
            statuses.append(f"\033[34m[PATCH AVAILABLE]{RESET}")
        if statuses:
            print(f"\n  Status: {' '.join(statuses)}")

        print(f"\n  {'─' * (width - 4)}")
        print(f"  {DIM}Keys: ↑↓ navigate  [a]ccept  [d]ismiss  [s]nooze  [p]atch diff  [e]export  [q]uit{RESET}")

    def _handle_key(self, key: str):
        f = self.findings[self.idx]

        if key in ('DOWN', 'j', '\r', '\n', ' '):
            self.idx = min(self.idx + 1, len(self.findings) - 1)

        elif key in ('UP', 'k'):
            self.idx = max(self.idx - 1, 0)

        elif key == 'a':
            if f not in self.accepted:
                self.accepted.append(f)
            self.idx = min(self.idx + 1, len(self.findings) - 1)

        elif key == 'd':
            self.config.save_suppression(f.fingerprint)
            f.suppressed = True
            self.idx = min(self.idx + 1, len(self.findings) - 1)

        elif key == 's':
            self.snoozed.add(f.fingerprint)
            self.idx = min(self.idx + 1, len(self.findings) - 1)

        elif key == 'p':
            self._show_patch(f)

        elif key == 'e':
            self._export_finding(f)

        elif key in ('q', '\x03', '\x04'):
            self.running = False

    def _show_patch(self, f: Finding):
        _clear()
        if not f.fix_diff:
            print(f"\n  {DIM}No patch available for this finding.{RESET}\n")
        else:
            print(f"\n  {BOLD}Patch for: {f.title}{RESET}\n")
            for line in f.fix_diff.splitlines():
                if line.startswith("+"):
                    print(f"  {GREEN}{line}{RESET}")
                elif line.startswith("-"):
                    print(f"  {SEVERITY_COLORS['HIGH']}{line}{RESET}")
                else:
                    print(f"  {line}")
        print(f"\n  {DIM}Press any key to continue...{RESET}")
        _getch()

    def _export_finding(self, f: Finding):
        """Export finding as a GitHub issue body (copied to stdout)."""
        _clear()
        issue_body = f"""## Security Finding: {f.title}

**Severity:** {f.severity}
**CWE:** {f.cwe or 'N/A'}
**File:** `{f.file}:{f.line_start}`
**Detected by:** Argus v2 ({f.detected_by})
**Confidence:** {f.confidence}

### Description
{f.description}

### Vulnerable Code
```
{f.code_snippet}
```

### Recommendation
{f.recommendation}

### References
- {f.cwe and f'https://cwe.mitre.org/data/definitions/{f.cwe.replace("CWE-","")}.html' or 'N/A'}
- Argus finding ID: `{f.id}`
- Fingerprint: `{f.fingerprint}`

---
*Found by [Argus](https://github.com/stackbleed-ctrl/ARGUS) — AI-powered vulnerability scanner*
"""
        print(f"\n  {BOLD}GitHub Issue body (copy below):{RESET}\n")
        print(issue_body)
        print(f"\n  {DIM}Press any key to continue...{RESET}")
        _getch()

    def _print_session_summary(self):
        _clear()
        self._print_header()
        print(f"\n  {BOLD}Triage complete.{RESET}\n")
        print(f"  {GREEN}✓ Accepted:    {len(self.accepted)}{RESET}")
        dismissed = len([f for f in self.findings if f.fingerprint in self.config.suppressed_fingerprints])
        print(f"  {DIM}✗ Dismissed:   {dismissed}{RESET}")
        print(f"  {DIM}~ Snoozed:     {len(self.snoozed)}{RESET}")
        remaining = len(self.findings) - len(self.accepted) - dismissed - len(self.snoozed)
        print(f"\n  Remaining:     {remaining}")
        if self.accepted:
            print(f"\n  {BOLD}Accepted findings (confirmed vulnerabilities):{RESET}")
            for f in self.accepted:
                color = SEVERITY_COLORS.get(f.severity, "")
                print(f"    {color}[{f.severity}]{RESET} {f.title}  {DIM}({f.file}:{f.line_start}){RESET}")
        print()

    def _print_header(self):
        print(f"\n  {BOLD}ARGUS v2 — Interactive Triage{RESET}\n")

    @staticmethod
    def _wrapped_print(text: str, width: int, indent: int = 2):
        prefix = " " * indent
        words = text.split()
        line = prefix
        for word in words:
            if len(line) + len(word) + 1 > width - 2:
                print(line)
                line = prefix + word + " "
            else:
                line += word + " "
        if line.strip():
            print(line)


# ── Entry point ───────────────────────────────────────────────────────────────

def run_triage(report_path: Path, config: ArgusConfig):
    """Load a report JSON and start an interactive triage session."""
    if not report_path.exists():
        print(f"Report not found: {report_path}")
        return 1

    try:
        data = json.loads(report_path.read_text())
    except json.JSONDecodeError as e:
        print(f"Failed to parse report: {e}")
        return 1

    # Reconstruct ScanResult
    findings = [Finding.from_dict(f) for f in data.get("findings", [])]
    result = ScanResult(
        target    = data.get("target", ""),
        scan_id   = data.get("scan_id", ""),
        timestamp = data.get("timestamp", ""),
        findings  = findings,
        model_used= data.get("model", ""),
    )
    result.files_scanned = data.get("summary", {}).get("files_scanned", 0)
    result.lines_scanned = data.get("summary", {}).get("lines_scanned", 0)

    session = TriageSession(result, config)
    session.run()
    return 0

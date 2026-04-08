"""
Argus v2 — Watch mode.
`argus watch ./src` — re-scans changed files on save.
Requires: watchdog (pip install watchdog)
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path
from datetime import datetime
from argus.core.types import Finding, SEVERITY_COLORS, RESET, BOLD, DIM, GREEN
from argus.core.scanner import ArgusScanner
from argus.core.config import ArgusConfig

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False


class _ArgusWatchHandler(FileSystemEventHandler):

    COOLDOWN = 0.5  # seconds between rescans of same file

    def __init__(self, scanner: ArgusScanner, loop: asyncio.AbstractEventLoop):
        self.scanner   = scanner
        self.loop      = loop
        self._last_scan: dict[str, float] = {}

    def _should_scan(self, path_str: str) -> bool:
        now = time.monotonic()
        last = self._last_scan.get(path_str, 0)
        if now - last < self.COOLDOWN:
            return False
        self._last_scan[path_str] = now
        return True

    def on_modified(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        if path.suffix in self.scanner.pattern_scanner.__class__.__module__ and not path.is_file():
            return
        if self._should_scan(str(path)):
            asyncio.run_coroutine_threadsafe(self._rescan(path), self.loop)

    on_created = on_modified

    async def _rescan(self, path: Path):
        from argus.core.types import SUPPORTED_EXTENSIONS
        if path.suffix not in SUPPORTED_EXTENSIONS:
            return
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n  {DIM}[{ts}] File changed: {path.name}{RESET}")

        findings = await self.scanner.scan_single_file(path)
        active = [f for f in findings if not f.suppressed]

        if not active:
            print(f"  {GREEN}✓ No new findings in {path.name}{RESET}")
            return

        # Sort by severity
        from argus.core.types import SEV_ORDER
        active.sort(key=lambda f: SEV_ORDER.get(f.severity, 5))

        print(f"\n  {BOLD}⚠ {len(active)} finding(s) in {path.name}{RESET}")
        for f in active:
            color = SEVERITY_COLORS.get(f.severity, "")
            print(f"    {color}[{f.severity}]{RESET} {f.title}  {DIM}line {f.line_start}{RESET}")

        # Flash CRITICAL
        crits = [f for f in active if f.severity == "CRITICAL"]
        if crits:
            print(f"\n  {SEVERITY_COLORS['CRITICAL']}{BOLD}⛔ CRITICAL finding — fix before committing!{RESET}")
        print()


def run_watch(target: str, scanner: ArgusScanner, config: ArgusConfig):
    """Start file watcher on target directory."""
    if not HAS_WATCHDOG:
        print(
            "  watchdog is required for watch mode.\n"
            "  Install: pip install watchdog"
        )
        return 1

    path = Path(target).resolve()
    if not path.exists():
        print(f"  Target not found: {path}")
        return 1

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    handler  = _ArgusWatchHandler(scanner, loop)
    observer = Observer()
    observer.schedule(handler, str(path), recursive=True)
    observer.start()

    print(f"\n  {BOLD}ARGUS — Watch Mode{RESET}")
    print(f"  Watching: {path}")
    print(f"  Mode:     {'AI + Pattern' if scanner.ai_mode else 'Pattern only'}")
    print(f"  {DIM}Save any supported file to trigger a scan.{RESET}")
    print(f"  {DIM}Ctrl+C to stop.{RESET}\n")

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print(f"\n  {DIM}Watch mode stopped.{RESET}\n")
    finally:
        observer.stop()
        observer.join()
        loop.close()
    return 0

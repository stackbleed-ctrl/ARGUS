"""
Argus v2 — Configuration loader.
Reads .argus.yml from the scan target directory.
Manages .argus-ignore suppression fingerprints.
"""
from __future__ import annotations

import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

ARGUS_IGNORE_FILE = ".argus-ignore"
ARGUS_CONFIG_FILE = ".argus.yml"

DEFAULT_CONFIG = {
    "fail_on": ["CRITICAL", "HIGH"],
    "max_findings": None,
    "ignore_paths": [],
    "min_confidence": "LOW",
    "concurrency": 5,
    "dep_audit": True,
    "fix_mode": False,
    "api_key": None,
}


@dataclass
class ArgusConfig:
    fail_on:                 list  = field(default_factory=lambda: ["CRITICAL", "HIGH"])
    max_findings:            Optional[int] = None
    ignore_paths:            list  = field(default_factory=list)
    min_confidence:          str   = "LOW"
    concurrency:             int   = 5
    dep_audit:               bool  = True
    fix_mode:                bool  = False
    api_key:                 Optional[str] = None
    suppressed_fingerprints: set   = field(default_factory=set)
    source_path:             Optional[Path] = None

    @classmethod
    def load(cls, target: Path) -> "ArgusConfig":
        """
        Load config from .argus.yml in target directory (or parents).
        Load suppressions from .argus-ignore.
        """
        search = target if target.is_dir() else target.parent
        config_data = dict(DEFAULT_CONFIG)

        # Walk up looking for .argus.yml
        for parent in [search] + list(search.parents):
            config_file = parent / ARGUS_CONFIG_FILE
            if config_file.exists():
                try:
                    if HAS_YAML:
                        import yaml
                        data = yaml.safe_load(config_file.read_text()) or {}
                    else:
                        # Fallback: very basic key: value parser
                        data = {}
                        for line in config_file.read_text().splitlines():
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue
                            if ":" in line:
                                k, v = line.split(":", 1)
                                data[k.strip()] = v.strip()
                    config_data.update({k: v for k, v in data.items() if k in DEFAULT_CONFIG})
                except Exception:
                    pass
                break

        # Load suppressed fingerprints from .argus-ignore
        suppressed: set[str] = set()
        for parent in [search] + list(search.parents):
            ignore_file = parent / ARGUS_IGNORE_FILE
            if ignore_file.exists():
                try:
                    for line in ignore_file.read_text().splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            suppressed.add(line)
                except Exception:
                    pass
                break

        cfg = cls(
            fail_on=config_data.get("fail_on", ["CRITICAL", "HIGH"]),
            max_findings=config_data.get("max_findings"),
            ignore_paths=config_data.get("ignore_paths", []),
            min_confidence=config_data.get("min_confidence", "LOW"),
            concurrency=int(config_data.get("concurrency", 5)),
            dep_audit=config_data.get("dep_audit", True) not in (False, "false", "False"),
            fix_mode=config_data.get("fix_mode", False) not in (False, "false", "False"),
            api_key=config_data.get("api_key"),
            suppressed_fingerprints=suppressed,
            source_path=search,
        )
        return cfg

    def save_suppression(self, fingerprint: str):
        """Add a fingerprint to .argus-ignore."""
        if not self.source_path:
            return
        ignore_file = self.source_path / ARGUS_IGNORE_FILE
        existing = set()
        if ignore_file.exists():
            for line in ignore_file.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    existing.add(line)
        existing.add(fingerprint)
        ignore_file.write_text(
            "# Argus suppressed findings — one fingerprint per line\n" +
            "\n".join(sorted(existing)) + "\n"
        )
        self.suppressed_fingerprints.add(fingerprint)

    def remove_suppression(self, fingerprint: str):
        """Remove a fingerprint from .argus-ignore."""
        if not self.source_path:
            return
        ignore_file = self.source_path / ARGUS_IGNORE_FILE
        if not ignore_file.exists():
            return
        lines = [
            l.strip() for l in ignore_file.read_text().splitlines()
            if l.strip() and l.strip() != fingerprint
        ]
        ignore_file.write_text("\n".join(lines) + "\n")
        self.suppressed_fingerprints.discard(fingerprint)

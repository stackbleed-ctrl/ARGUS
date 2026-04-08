"""
Argus v2 — Dependency Auditor.
Parses requirements.txt, package.json, go.mod, Gemfile, Cargo.toml etc.
Checks packages against OSV.dev (open source, free, no API key needed).
"""
from __future__ import annotations

import re
import json
import asyncio
import aiohttp
from pathlib import Path
from typing import Optional
from argus.core.types import DepAdvisory

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# ─── Parsers ──────────────────────────────────────────────────────────────────

def parse_requirements_txt(content: str) -> list[tuple[str, str, str]]:
    """Returns list of (package, version, ecosystem)."""
    pkgs = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-r", "--", "git+")):
            continue
        # Handle: package==1.2.3, package>=1.0, package~=2.0, package[extras]==1.0
        m = re.match(r'^([A-Za-z0-9_\-\[\]\.]+)\s*[=><~!]+\s*([^\s;]+)', line)
        if m:
            name = re.sub(r'\[.*?\]', '', m.group(1)).strip()
            ver  = re.split(r'[,;]', m.group(2))[0].strip()
            pkgs.append((name, ver, "PyPI"))
        else:
            # Bare package name, no version
            name = re.sub(r'\[.*?\]', '', line.split()[0]).strip()
            if name:
                pkgs.append((name, "", "PyPI"))
    return pkgs


def parse_package_json(content: str) -> list[tuple[str, str, str]]:
    pkgs = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return pkgs
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, version in data.get(section, {}).items():
            # Strip semver range prefix: ^1.2.3 → 1.2.3
            clean_ver = re.sub(r'^[\^~>=<]+ *', '', str(version)).strip()
            pkgs.append((name, clean_ver, "npm"))
    return pkgs


def parse_go_mod(content: str) -> list[tuple[str, str, str]]:
    pkgs = []
    in_require = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if in_require or line.startswith("require "):
            parts = line.replace("require ", "").split()
            if len(parts) >= 2:
                name = parts[0]
                ver  = parts[1].lstrip("v")
                pkgs.append((name, ver, "Go"))
    return pkgs


def parse_gemfile_lock(content: str) -> list[tuple[str, str, str]]:
    pkgs = []
    in_specs = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "specs:":
            in_specs = True
            continue
        if in_specs:
            # Gem entries are indented with exactly 4 spaces: "    gem_name (version)"
            m = re.match(r'^    ([a-zA-Z0-9_\-\.]+)\s+\(([^)]+)\)', line)
            if m:
                pkgs.append((m.group(1), m.group(2).split("-")[0], "RubyGems"))
            elif line.strip() and not line.startswith("    "):
                in_specs = False
    return pkgs


def parse_cargo_toml(content: str) -> list[tuple[str, str, str]]:
    pkgs = []
    in_deps = False
    for line in content.splitlines():
        line = line.strip()
        if line in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]"):
            in_deps = True
            continue
        if in_deps:
            if line.startswith("["):
                in_deps = False
                continue
            m = re.match(r'^([a-zA-Z0-9_\-]+)\s*=\s*["\']?([0-9][^"\']*)["\']?', line)
            if m:
                pkgs.append((m.group(1), m.group(2).strip(), "crates.io"))
    return pkgs


def parse_pyproject_toml(content: str) -> list[tuple[str, str, str]]:
    pkgs = []
    in_deps = False
    for line in content.splitlines():
        s = line.strip()
        if s in ('dependencies = [', 'requires = ['):
            in_deps = True
            continue
        if in_deps:
            if s == ']':
                in_deps = False
                continue
            m = re.match(r'["\']?([A-Za-z0-9_\-\[\]\.]+)[>=<~!]+([^\s"\']+)', s)
            if m:
                name = re.sub(r'\[.*?\]', '', m.group(1)).strip()
                pkgs.append((name, m.group(2).strip(), "PyPI"))
    return pkgs


PARSERS: dict[str, callable] = {
    "requirements.txt":     parse_requirements_txt,
    "requirements-dev.txt": parse_requirements_txt,
    "requirements-test.txt":parse_requirements_txt,
    "package.json":         parse_package_json,
    "go.mod":               parse_go_mod,
    "Gemfile.lock":         parse_gemfile_lock,
    "Cargo.toml":           parse_cargo_toml,
    "pyproject.toml":       parse_pyproject_toml,
}

ECOSYSTEM_MAP = {
    "PyPI":      "PyPI",
    "npm":       "npm",
    "Go":        "Go",
    "RubyGems":  "RubyGems",
    "crates.io": "crates.io",
}


# ─── OSV.dev Checker ──────────────────────────────────────────────────────────

async def _check_osv_batch(
    packages: list[tuple[str, str, str]],
    timeout: int = 30,
) -> list[DepAdvisory]:
    """
    Query OSV.dev batch API for a list of (name, version, ecosystem) tuples.
    Returns list of DepAdvisory for any packages with known vulnerabilities.
    """
    if not packages:
        return []

    queries = []
    for name, version, ecosystem in packages:
        q: dict = {"package": {"name": name, "ecosystem": ECOSYSTEM_MAP.get(ecosystem, ecosystem)}}
        if version:
            q["version"] = version
        queries.append(q)

    advisories: list[DepAdvisory] = []

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                OSV_BATCH_URL,
                json={"queries": queries},
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"Content-Type": "application/json"},
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()

        results = data.get("results", [])
        for i, result in enumerate(results):
            vulns = result.get("vulns", [])
            if not vulns:
                continue
            name, version, ecosystem = packages[i]
            for vuln in vulns:
                # Extract severity
                severity = "MEDIUM"
                cvss = None
                for sev in vuln.get("severity", []):
                    if sev.get("type") == "CVSS_V3":
                        try:
                            cvss = float(sev.get("score", 0))
                            if cvss >= 9.0:   severity = "CRITICAL"
                            elif cvss >= 7.0: severity = "HIGH"
                            elif cvss >= 4.0: severity = "MEDIUM"
                            else:             severity = "LOW"
                        except (ValueError, TypeError):
                            pass

                # Find fixed version
                fixed_in = None
                for affected in vuln.get("affected", []):
                    for rng in affected.get("ranges", []):
                        for evt in rng.get("events", []):
                            if "fixed" in evt:
                                fixed_in = evt["fixed"]
                                break

                advisories.append(DepAdvisory(
                    package=name,
                    version=version,
                    ecosystem=ecosystem,
                    vuln_id=vuln.get("id", "UNKNOWN"),
                    severity=severity,
                    summary=vuln.get("summary", "No summary available."),
                    details=vuln.get("details", "")[:500],
                    fixed_in=fixed_in,
                    cvss_score=cvss,
                    aliases=vuln.get("aliases", []),
                ))

    except Exception:
        return []

    return advisories


# ─── Main entry point ─────────────────────────────────────────────────────────

async def audit_dependencies(target: Path) -> list[DepAdvisory]:
    """
    Walk target directory, find all dependency manifests,
    parse them, and check against OSV.dev.
    Returns flat list of DepAdvisory.
    """
    if target.is_file():
        search_root = target.parent
    else:
        search_root = target

    all_packages: list[tuple[str, str, str]] = []

    for filename, parser in PARSERS.items():
        for manifest in search_root.rglob(filename):
            # Skip node_modules, vendor, etc.
            parts = manifest.parts
            if any(p in parts for p in (".git", "node_modules", "vendor", "__pycache__", ".venv", "venv")):
                continue
            try:
                content = manifest.read_text(encoding="utf-8", errors="replace")
                pkgs = parser(content)
                all_packages.extend(pkgs)
            except Exception:
                continue

    # Deduplicate (name, version, ecosystem)
    seen: set[tuple] = set()
    unique_pkgs = []
    for p in all_packages:
        key = (p[0].lower(), p[1], p[2])
        if key not in seen:
            seen.add(key)
            unique_pkgs.append(p)

    # OSV batch in chunks of 100 (API limit)
    chunk_size = 100
    advisories: list[DepAdvisory] = []
    for i in range(0, len(unique_pkgs), chunk_size):
        chunk = unique_pkgs[i:i + chunk_size]
        chunk_results = await _check_osv_batch(chunk)
        advisories.extend(chunk_results)

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    advisories.sort(key=lambda a: sev_order.get(a.severity, 4))
    return advisories

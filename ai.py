"""
Argus v2 — Claude AI Analyzer.
Deep semantic analysis: taint tracing, logic flaw detection, fix generation.
"""
from __future__ import annotations

import re
import json
import hashlib
import asyncio
import aiohttp
from pathlib import Path
from typing import Optional
from argus.core.types import Finding

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL             = "claude-sonnet-4-20250514"

# ─── System Prompts ───────────────────────────────────────────────────────────

AUDIT_SYSTEM_PROMPT = """You are a world-class application security researcher performing a defensive security audit.
Your mission: find real, exploitable vulnerabilities that automated pattern matchers miss.

TAINT ANALYSIS APPROACH:
1. Identify all entry points: HTTP params, headers, cookies, file uploads, env vars, CLI args, IPC
2. Trace data flow from entry points to dangerous sinks: SQL execution, shell commands, file I/O, network calls, HTML rendering, deserialization
3. Flag every path where user-controlled data reaches a sink WITHOUT adequate sanitization, validation, or parameterization

FOCUS ON THESE HIGH-VALUE TARGETS:
- Authentication/authorization bypasses (JWT alg confusion, broken session logic, missing ownership checks)
- Business logic flaws (race conditions, integer overflow in pricing/inventory, state machine violations)
- Second-order injection (data stored then later executed — stored XSS, stored SQLi)
- Trust boundary violations (SSRF, request forgery, confused deputy)
- Cryptographic failures (weak algorithms, broken key management, nonce reuse, ECB mode)
- Memory safety issues in C/C++ (buffer overflows, UAF, format string)
- Insecure defaults and misconfigurations that would be exploitable in production

DO NOT REPORT:
- Style issues or code smells
- Purely theoretical issues with no realistic attack path
- Issues already flagged by the pattern hints below

Respond ONLY with a valid JSON array. Each object:
{
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "category": "e.g. sql_injection, auth_bypass, race_condition, ...",
  "title": "concise title (under 80 chars)",
  "description": "precise technical description — what is vulnerable and WHY it's exploitable",
  "line_start": <int>,
  "line_end": <int>,
  "code_snippet": "the vulnerable code (under 300 chars)",
  "recommendation": "specific, actionable fix — show corrected code where possible",
  "cwe": "CWE-XXX or null",
  "cvss_score": <float 0-10 or null>,
  "confidence": "HIGH|MEDIUM|LOW"
}

If no new vulnerabilities found: return []
Return ONLY the JSON array — no prose, no markdown fences."""


FIX_SYSTEM_PROMPT = """You are a senior security engineer generating patches for known vulnerabilities.

Given a vulnerability finding and its surrounding code, produce a unified diff that fixes the issue.
The fix must:
1. Address the root cause, not just the symptom
2. Follow language idioms and not break surrounding code
3. Be minimal — change only what's necessary
4. Include a brief inline comment explaining the security fix

Respond ONLY with a unified diff in this exact format:
--- a/{filename}
+++ b/{filename}
@@ ... @@
 (context)
-(vulnerable line)
+(fixed line)
 (context)

If you cannot produce a safe fix, respond with: NO_FIX"""

CALLGRAPH_SYSTEM_PROMPT = """You are a security-focused code analyst.
Given a function that contains a vulnerability and its callers,
identify whether the vulnerability is reachable from an untrusted entry point.

Respond with JSON:
{
  "reachable_from_untrusted": true|false,
  "entry_points": ["list of entry point function names"],
  "attack_path": "brief description of the call chain",
  "exploitability_boost": "CRITICAL|HIGH|MEDIUM|LOW|NONE"
}"""


# ─── AI Analyzer ──────────────────────────────────────────────────────────────

class AIAnalyzer:

    def __init__(self, api_key: str, max_file_lines: int = 400, fix_mode: bool = False):
        self.api_key       = api_key
        self.max_file_lines = max_file_lines
        self.fix_mode      = fix_mode

    async def _call_api(
        self,
        system: str,
        user_msg: str,
        max_tokens: int = 2500,
        timeout: int = 90,
    ) -> Optional[str]:
        """Raw API call. Returns text content or None on error."""
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
                        "max_tokens": max_tokens,
                        "system": system,
                        "messages": [{"role": "user", "content": user_msg}],
                    },
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
                    return data["content"][0]["text"].strip()
        except Exception:
            return None

    def _parse_json_findings(self, raw: str, path: Path, line_offset: int) -> list[Finding]:
        """Parse Claude's JSON array response into Finding objects."""
        if not raw:
            return []
        # Strip any accidental markdown fences
        cleaned = re.sub(r'^```(?:json)?\s*', '', raw)
        cleaned = re.sub(r'```\s*$', '', cleaned).strip()
        try:
            items = json.loads(cleaned)
        except json.JSONDecodeError:
            return []
        if not isinstance(items, list):
            return []

        findings = []
        for item in items:
            try:
                fid = hashlib.md5(
                    f"{path}{item.get('line_start', 0)}{item.get('title', '')}".encode()
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
                    detected_by="ai",
                ))
            except Exception:
                continue
        return findings

    async def analyze_file(
        self,
        path: Path,
        content: str,
        pattern_findings: list[Finding],
    ) -> list[Finding]:
        """Analyze a full file, chunking if needed."""
        lines = content.splitlines()

        chunks = []
        for i in range(0, len(lines), self.max_file_lines):
            chunks.append((i, lines[i:i + self.max_file_lines]))

        all_findings: list[Finding] = []
        for offset, chunk_lines in chunks:
            chunk_findings = await self._analyze_chunk(
                path, "\n".join(chunk_lines), offset, pattern_findings
            )
            all_findings.extend(chunk_findings)

        # If fix mode, generate diffs for CRITICAL + HIGH AI findings
        if self.fix_mode:
            for finding in all_findings:
                if finding.severity in ("CRITICAL", "HIGH"):
                    diff = await self._generate_fix(path, content, finding)
                    if diff:
                        finding.fix_diff = diff

        return all_findings

    async def _analyze_chunk(
        self,
        path: Path,
        content: str,
        line_offset: int,
        hints: list[Finding],
    ) -> list[Finding]:
        hint_block = ""
        if hints:
            hint_block = "\n\nPattern scanner already flagged these (do NOT re-report, use as taint context):\n"
            for h in hints[:8]:
                hint_block += f"  • Line {h.line_start}: [{h.severity}] {h.title} ({h.cwe or 'no CWE'})\n"

        user_msg = (
            f"Security audit this {path.suffix or 'file'}:\n\n"
            f"**File:** `{path.name}`\n"
            f"**Line offset:** {line_offset}\n"
            f"{hint_block}\n"
            f"```\n{content}\n```"
        )

        raw = await self._call_api(AUDIT_SYSTEM_PROMPT, user_msg)
        return self._parse_json_findings(raw or "[]", path, line_offset)

    async def _generate_fix(
        self,
        path: Path,
        full_content: str,
        finding: Finding,
    ) -> Optional[str]:
        """Generate a unified diff patch for a finding."""
        lines = full_content.splitlines()
        # Grab context window around the finding
        start = max(0, finding.line_start - 5)
        end   = min(len(lines), finding.line_end + 5)
        context = "\n".join(
            f"{i+start+1}: {line}"
            for i, line in enumerate(lines[start:end])
        )

        user_msg = (
            f"**File:** `{path.name}`\n"
            f"**Vulnerability:** [{finding.severity}] {finding.title}\n"
            f"**Description:** {finding.description}\n"
            f"**CWE:** {finding.cwe or 'N/A'}\n\n"
            f"**Surrounding code (lines {start+1}–{end}):**\n```\n{context}\n```\n\n"
            f"Generate a unified diff to fix this vulnerability."
        )

        raw = await self._call_api(FIX_SYSTEM_PROMPT, user_msg, max_tokens=1000)
        if not raw or raw.strip() == "NO_FIX":
            return None
        return raw.strip()

    async def analyze_callgraph(
        self,
        vuln_function: str,
        callers: list[str],
    ) -> Optional[dict]:
        """Check if a vulnerable function is reachable from untrusted input."""
        user_msg = (
            f"**Vulnerable function:**\n```\n{vuln_function}\n```\n\n"
            f"**Callers:**\n" +
            "\n\n".join(f"```\n{c}\n```" for c in callers[:5])
        )
        raw = await self._call_api(CALLGRAPH_SYSTEM_PROMPT, user_msg, max_tokens=500)
        if not raw:
            return None
        try:
            cleaned = re.sub(r'^```(?:json)?\s*', '', raw)
            cleaned = re.sub(r'```\s*$', '', cleaned).strip()
            return json.loads(cleaned)
        except Exception:
            return None

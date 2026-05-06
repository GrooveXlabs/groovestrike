"""Vulnerability discovery — static and dynamic."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests


@dataclass
class DiscoveryResult:
    title: str
    severity: str
    category: str
    description: str
    evidence: str | None = None
    cvss_score: float | None = None


def _cvss_from_severity(severity: str) -> float:
    mapping = {"critical": 9.5, "high": 7.5, "medium": 5.5, "low": 3.5, "info": 0.0}
    return mapping.get(severity.lower(), 5.0)


def static_scan_repo(repo_path: Path) -> list[DiscoveryResult]:
    """Run basic static analysis on a repository."""
    findings = []
    if not repo_path.exists():
        return findings

    for file_path in repo_path.rglob("*"):
        if not file_path.is_file():
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        # Hardcoded secrets
        secret_patterns = [
            (r'api[_-]?key\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "API Key"),
            (r'secret\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "Secret Token"),
            (r'password\s*[:=]\s*["\']([^"\']{6,})["\']', "Hardcoded Password"),
            (r'token\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "Access Token"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
        ]
        for pattern, label in secret_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                findings.append(DiscoveryResult(
                    title=f"Hardcoded {label}",
                    severity="high",
                    category="secret",
                    description=f"Found potential {label} in {file_path.name}",
                    evidence=f"Line: {content[:match.start()].count(chr(10)) + 1}",
                    cvss_score=7.5,
                ))

        # Dangerous eval/exec
        if re.search(r'\beval\s*\(|\bexec\s*\(|\bFunction\s*\(', content):
            findings.append(DiscoveryResult(
                title="Dangerous eval/exec Usage",
                severity="critical",
                category="cmdi",
                description=f"Code execution via eval/exec found in {file_path.name}",
                evidence=file_path.name,
                cvss_score=9.0,
            ))

        # SSRF patterns
        if re.search(r'\b(fetch|request|curl)\s*\([^)]*\b(url|uri|href)\b', content, re.IGNORECASE):
            findings.append(DiscoveryResult(
                title="Potential SSRF Vector",
                severity="high",
                category="ssrf",
                description=f"Possible SSRF in {file_path.name}",
                evidence=file_path.name,
                cvss_score=7.5,
            ))

        # SQL injection
        if re.search(r'\.query\s*\(\s*[`"\'].*\$', content) or re.search(r'execute\s*\(\s*["\'].*%s', content):
            findings.append(DiscoveryResult(
                title="Potential SQL Injection",
                severity="high",
                category="sqli",
                description=f"Possible SQL injection in {file_path.name}",
                evidence=file_path.name,
                cvss_score=7.5,
            ))

    # Deduplicate by title
    seen = set()
    unique = []
    for f in findings:
        key = f.title + f.category
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def dynamic_probe_ssrf(url: str) -> DiscoveryResult | None:
    """Probe for SSRF vulnerability safely."""
    try:
        payload = {"url": "http://127.0.0.1:1/"}
        r = requests.post(url, json=payload, timeout=10, allow_redirects=False)
        if r.status_code in [200, 500]:
            return DiscoveryResult(
                title="SSRF Vulnerability Confirmed",
                severity="high",
                category="ssrf",
                description=f"Target accepted internal URL parameter at {url}",
                evidence=f"Status: {r.status_code}, Length: {len(r.content)}",
                cvss_score=7.5,
            )
    except Exception:
        pass
    return None


def dynamic_probe_cmdi(url: str, param: str = "cmd") -> DiscoveryResult | None:
    """Probe for command injection safely."""
    try:
        payload = {param: "echo GROOVESTRIKE_TEST"}
        r = requests.post(url, json=payload, timeout=10)
        if "GROOVESTRIKE_TEST" in r.text:
            return DiscoveryResult(
                title="Command Injection Confirmed",
                severity="critical",
                category="cmdi",
                description=f"Target executed command at {url}",
                evidence="Reflected command output detected",
                cvss_score=9.0,
            )
    except Exception:
        pass
    return None


def dynamic_probe_pathtraversal(url: str) -> DiscoveryResult | None:
    """Probe for path traversal safely."""
    try:
        payload = {"file": "../../../etc/passwd"}
        r = requests.get(url, params=payload, timeout=10)
        if "root:" in r.text:
            return DiscoveryResult(
                title="Path Traversal Confirmed",
                severity="high",
                category="pathtraversal",
                description=f"Target vulnerable to path traversal at {url}",
                evidence="/etc/passwd pattern detected in response",
                cvss_score=7.5,
            )
    except Exception:
        pass
    return None


def dynamic_probe_sqli(url: str) -> DiscoveryResult | None:
    """Probe for SQL injection safely using time-based detection."""
    import time
    try:
        start = time.time()
        payload = {"id": "1 AND SLEEP(0)"}
        requests.get(url, params=payload, timeout=10)
        baseline = time.time() - start

        start = time.time()
        payload = {"id": "1 AND SLEEP(2)"}
        requests.get(url, params=payload, timeout=10)
        delay = time.time() - start

        if delay > baseline + 1.5:
            return DiscoveryResult(
                title="SQL Injection (Time-Based) Confirmed",
                severity="critical",
                category="sqli",
                description=f"Time-based SQL injection at {url}",
                evidence=f"Baseline: {baseline:.2f}s, Delay: {delay:.2f}s",
                cvss_score=9.0,
            )
    except Exception:
        pass
    return None


def discover_web_vulns(base_url: str) -> list[DiscoveryResult]:
    """Run all dynamic probes against a web target."""
    findings = []

    # Normalize URL
    if not base_url.startswith(("http://", "https://")):
        base_url = f"https://{base_url}"

    probes = [
        dynamic_probe_ssrf,
        dynamic_probe_cmdi,
        dynamic_probe_pathtraversal,
        dynamic_probe_sqli,
    ]

    for probe in probes:
        try:
            result = probe(base_url)
            if result:
                findings.append(result)
        except Exception:
            continue

    return findings

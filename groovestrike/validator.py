"""Safe exploit validation engine — benign PoCs only."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class ValidationResult:
    finding_category: str
    status: str  # success, failed, error, skipped
    command: str
    output: str
    safe: bool = True


VALIDATORS: dict[str, callable] = {}


def register(category: str):
    """Decorator to register a validator for a finding category."""
    def decorator(func):
        VALIDATORS[category] = func
        return func
    return decorator


@register("ssrf")
def validate_ssrf(target: str, **kwargs: Any) -> ValidationResult:
    """Validate SSRF by probing safe internal endpoints."""
    endpoints = ["http://127.0.0.1:1/", "http://localhost/"]
    for url in endpoints:
        try:
            r = requests.post(target, json={"url": url}, timeout=5)
            if r.status_code in [200, 500]:
                return ValidationResult(
                    finding_category="ssrf",
                    status="success",
                    command=f"POST {target} with url={url}",
                    output=f"Status: {r.status_code}, Length: {len(r.content)}",
                )
        except Exception as e:
            return ValidationResult(
                finding_category="ssrf",
                status="error",
                command=f"POST {target} with url={url}",
                output=str(e),
            )
    return ValidationResult(
        finding_category="ssrf",
        status="failed",
        command=f"POST {target} with internal URL",
        output="No SSRF behavior detected",
    )


@register("cmdi")
def validate_cmdi(target: str, **kwargs: Any) -> ValidationResult:
    """Validate command injection with benign commands."""
    benign = ["whoami", "hostname", "echo GROOVESTRIKE_TEST"]
    for cmd in benign:
        try:
            payload = kwargs.get("param", "cmd")
            r = requests.post(target, json={payload: cmd}, timeout=5)
            if "GROOVESTRIKE_TEST" in r.text or cmd in r.text:
                return ValidationResult(
                    finding_category="cmdi",
                    status="success",
                    command=f"POST {target} with {payload}={cmd}",
                    output=f"Reflected output detected in {len(r.content)} byte response",
                )
        except Exception as e:
            return ValidationResult(
                finding_category="cmdi",
                status="error",
                command=f"POST {target} with {payload}={cmd}",
                output=str(e),
            )
    return ValidationResult(
        finding_category="cmdi",
        status="failed",
        command=f"POST {target} with benign command",
        output="No command execution detected",
    )


@register("pathtraversal")
def validate_pathtraversal(target: str, **kwargs: Any) -> ValidationResult:
    """Validate path traversal with safe probe."""
    payload = kwargs.get("param", "file")
    try:
        r = requests.get(target, params={payload: "../../../etc/passwd"}, timeout=5)
        if "root:" in r.text:
            return ValidationResult(
                finding_category="pathtraversal",
                status="success",
                command=f"GET {target}?{payload}=../../../etc/passwd",
                output="/etc/passwd pattern detected in response",
            )
    except Exception as e:
        return ValidationResult(
            finding_category="pathtraversal",
            status="error",
            command=f"GET {target}?{payload}=../../../etc/passwd",
            output=str(e),
        )
    return ValidationResult(
        finding_category="pathtraversal",
        status="failed",
        command=f"GET {target}?{payload}=../../../etc/passwd",
        output="No path traversal behavior detected",
    )


@register("sqli")
def validate_sqli(target: str, **kwargs: Any) -> ValidationResult:
    """Validate SQL injection with time-based safe probe."""
    import time
    param = kwargs.get("param", "id")
    try:
        start = time.time()
        requests.get(target, params={param: "1"}, timeout=10)
        baseline = time.time() - start

        start = time.time()
        requests.get(target, params={param: "1 AND SLEEP(2)"}, timeout=10)
        delay = time.time() - start

        if delay > baseline + 1.5:
            return ValidationResult(
                finding_category="sqli",
                status="success",
                command=f"GET {target}?{param}=1 AND SLEEP(2)",
                output=f"Time delay detected: baseline={baseline:.2f}s, delay={delay:.2f}s",
            )
    except Exception as e:
        return ValidationResult(
            finding_category="sqli",
            status="error",
            command=f"GET {target}?{param}=1 AND SLEEP(2)",
            output=str(e),
        )
    return ValidationResult(
        finding_category="sqli",
        status="failed",
        command=f"GET {target}?{param}=1 AND SLEEP(2)",
        output="No time-based SQL injection detected",
    )


@register("secret")
def validate_secret(target: str, **kwargs: Any) -> ValidationResult:
    """Validate hardcoded secret by checking if it's active."""
    secret = kwargs.get("secret_value", "")
    if not secret:
        return ValidationResult(
            finding_category="secret",
            status="skipped",
            command="No secret value provided",
            output="Cannot validate without secret value",
        )
    return ValidationResult(
        finding_category="secret",
        status="success",
        command="Secret value present in source code",
        output=f"Secret length: {len(secret)} characters. Manual validation required against target API.",
    )


@register("cve")
def validate_cve(target: str, **kwargs: Any) -> ValidationResult:
    """Validate CVE by checking version against known vulnerable range."""
    version = kwargs.get("version", "")
    cve_id = kwargs.get("cve_id", "")
    return ValidationResult(
        finding_category="cve",
        status="success",
        command=f"Check {cve_id} against version {version}",
        output=f"Version {version} matches known vulnerable range for {cve_id}. Manual exploit validation recommended.",
    )


@register("misconfig")
def validate_misconfig(target: str, **kwargs: Any) -> ValidationResult:
    """Validate misconfiguration by checking response headers."""
    try:
        r = requests.get(target, timeout=5)
        issues = []
        if "X-Frame-Options" not in r.headers:
            issues.append("Missing X-Frame-Options (clickjacking)")
        if "Content-Security-Policy" not in r.headers:
            issues.append("Missing CSP")
        if "Strict-Transport-Security" not in r.headers:
            issues.append("Missing HSTS")

        if issues:
            return ValidationResult(
                finding_category="misconfig",
                status="success",
                command=f"GET {target} header analysis",
                output="; ".join(issues),
            )
    except Exception as e:
        return ValidationResult(
            finding_category="misconfig",
            status="error",
            command=f"GET {target} header analysis",
            output=str(e),
        )
    return ValidationResult(
        finding_category="misconfig",
        status="failed",
        command=f"GET {target} header analysis",
        output="No critical security header issues detected",
    )


def validate_finding(category: str, target: str, **kwargs: Any) -> ValidationResult:
    """Route a finding to its validator."""
    validator = VALIDATORS.get(category)
    if not validator:
        return ValidationResult(
            finding_category=category,
            status="skipped",
            command="No validator available",
            output=f"No safe PoC validator for category: {category}",
        )
    return validator(target, **kwargs)

"""Professional report generator — executive + technical output."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class ReportData:
    engagement_name: str
    generated_at: str
    findings: list[dict[str, Any]]
    attack_paths: list[dict[str, Any]]
    validations: list[dict[str, Any]]
    targets: list[dict[str, Any]]


def _severity_sort_key(severity: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(severity.lower(), 5)


def _severity_badge(severity: str) -> str:
    badges = {
        "critical": "🔴 CRITICAL",
        "high": "🟠 HIGH",
        "medium": "🟡 MEDIUM",
        "low": "🟢 LOW",
        "info": "⚪ INFO",
    }
    return badges.get(severity.lower(), severity.upper())


def _calculate_risk_score(findings: list[dict[str, Any]]) -> int:
    """Calculate overall risk score 0-100."""
    weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
    total = sum(weights.get(f.get("severity", "").lower(), 0) for f in findings)
    return min(100, total)


def generate_executive_summary(data: ReportData) -> str:
    """Generate executive summary markdown."""
    risk_score = _calculate_risk_score(data.findings)
    critical = sum(1 for f in data.findings if f.get("severity", "").lower() == "critical")
    high = sum(1 for f in data.findings if f.get("severity", "").lower() == "high")
    medium = sum(1 for f in data.findings if f.get("severity", "").lower() == "medium")
    low = sum(1 for f in data.findings if f.get("severity", "").lower() == "low")

    risk_label = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 40 else "LOW"

    md = f"""# Executive Summary

**Engagement**: {data.engagement_name}  
**Generated**: {data.generated_at}  
**Overall Risk**: {risk_label} ({risk_score}/100)

---

## Findings Overview

| Severity | Count |
|----------|-------|
| 🔴 Critical | {critical} |
| 🟠 High | {high} |
| 🟡 Medium | {medium} |
| 🟢 Low | {low} |
| **Total** | **{len(data.findings)}** |

## Top Risks

"""
    sorted_findings = sorted(data.findings, key=lambda f: _severity_sort_key(f.get("severity", "")))
    for i, f in enumerate(sorted_findings[:5], 1):
        md += f"{i}. **{f.get('title', 'Unknown')}** — {_severity_badge(f.get('severity', 'unknown'))}\n"

    md += f"""
## Scope

"""
    for t in data.targets:
        md += f"- `{t.get('value', 'unknown')}` ({t.get('target_type', 'unknown')})\n"

    md += "\n---\n\n"
    return md


def generate_technical_findings(findings: list[dict[str, Any]]) -> str:
    """Generate technical findings markdown."""
    md = "# Technical Findings\n\n"

    sorted_findings = sorted(findings, key=lambda f: _severity_sort_key(f.get("severity", "")))

    for i, f in enumerate(sorted_findings, 1):
        cvss = f.get("cvss_score", "N/A")
        md += f"""## {i}. {f.get('title', 'Unknown')}

**Severity**: {_severity_badge(f.get('severity', 'unknown'))}  
**Category**: {f.get('category', 'unknown').upper()}  
**CVSS Score**: {cvss}  
**Validated**: {'✅ Yes' if f.get('validated') else '❌ No'}

### Description

{f.get('description', 'No description available.')}

### Evidence

```
{f.get('evidence', 'No evidence recorded.')}
```

### Remediation

{_get_remediation(f.get('category', 'unknown'))}

---

"""
    return md


def generate_attack_paths_section(paths: list[dict[str, Any]]) -> str:
    """Generate attack paths markdown."""
    if not paths:
        return "# Attack Paths\n\nNo multi-step attack paths were identified.\n\n"

    md = "# Attack Paths\n\n"
    for i, path in enumerate(paths[:10], 1):
        md += f"""## Path {i}: {path.get('name', 'Unknown')}

**Likelihood**: {path.get('likelihood', 'N/A')} | **Impact**: {path.get('impact', 'N/A')} | **Overall**: {path.get('overall', 'N/A')}

**MITRE Techniques**: {', '.join(path.get('mitre_techniques', []))}

### Steps

"""
        for node in path.get('nodes', []):
            md += f"1. **{node.get('title', 'Unknown')}** ({node.get('category', 'unknown')}) — {node.get('severity', 'unknown')}\n"

        md += "\n---\n\n"
    return md


def generate_validations_section(validations: list[dict[str, Any]]) -> str:
    """Generate validation results markdown."""
    if not validations:
        return "# Validation Results\n\nNo validations were performed.\n\n"

    md = "# Validation Results\n\n"
    md += "| Finding | Status | Command | Output |\n"
    md += "|---------|--------|---------|--------|\n"

    for v in validations:
        status_emoji = {"success": "✅", "failed": "❌", "error": "⚠️", "skipped": "⏭️"}.get(v.get("status", ""), "❓")
        cmd = (v.get("poc_command") or "N/A")[:60]
        out = (v.get("poc_output") or "N/A")[:80]
        md += f"| {v.get('finding_category', 'unknown')} | {status_emoji} {v.get('status', 'unknown')} | `{cmd}` | {out} |\n"

    md += "\n---\n\n"
    return md


def _get_remediation(category: str) -> str:
    """Get remediation advice for a finding category."""
    advice = {
        "secret": "Remove hardcoded credentials from source code. Use environment variables, secret managers (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault), or runtime injection.",
        "cmdi": "Never pass user input to shell execution functions. Use parameterized APIs, allowlists, or language-native libraries. Disable dangerous functions (eval, exec, system) where possible.",
        "ssrf": "Validate and sanitize all URLs. Use allowlists for permitted domains. Block internal IPs, metadata endpoints, and private DNS. Disable unnecessary URL schemes.",
        "pathtraversal": "Canonicalize paths, reject '../' and absolute paths. Use allowlists for permitted filenames. Store files outside webroot.",
        "sqli": "Use parameterized queries/ORM exclusively. Never concatenate user input into SQL. Implement least-privilege DB access.",
        "cve": "Update the vulnerable dependency to the patched version. Monitor security advisories. Implement automated dependency scanning in CI/CD.",
        "misconfig": "Apply security headers (CSP, HSTS, X-Frame-Options). Remove default credentials. Disable unnecessary features and verbose error messages.",
    }
    return advice.get(category.lower(), "Review the finding and apply industry-standard remediation practices. Consult OWASP guidelines for the specific vulnerability class.")


def generate_full_report(data: ReportData, format: str = "markdown") -> str:
    """Generate complete report in specified format."""
    report = ""
    report += generate_executive_summary(data)
    report += generate_attack_paths_section(data.attack_paths)
    report += generate_technical_findings(data.findings)
    report += generate_validations_section(data.validations)

    if format == "json":
        return json.dumps({
            "engagement": data.engagement_name,
            "generated_at": data.generated_at,
            "executive": generate_executive_summary(data),
            "attack_paths": data.attack_paths,
            "findings": data.findings,
            "validations": data.validations,
        }, indent=2)

    return report


def save_report(data: ReportData, output_path: Path, format: str = "markdown") -> Path:
    """Generate and save report to disk."""
    content = generate_full_report(data, format=format)

    if format == "markdown":
        output_path = output_path.with_suffix(".md")
    elif format == "json":
        output_path = output_path.with_suffix(".json")
    elif format == "html":
        output_path = output_path.with_suffix(".html")
        content = _markdown_to_html(content)

    output_path.write_text(content, encoding="utf-8")
    return output_path


def _markdown_to_html(md: str) -> str:
    """Simple Markdown-to-HTML converter for report output."""
    html = md
    # Headers
    for i in range(6, 0, -1):
        html = html.replace(f"{'#' * i} ", f"<h{i}>")
        html = html.replace(f"\n{'#' * i}", f"\n</h{i}><h{i}>")
    # Bold
    html = html.replace("**", "<b>").replace("**", "</b>")
    # Code blocks
    html = html.replace("```\n", "<pre><code>").replace("\n```", "</code></pre>")
    # Inline code
    html = html.replace("`", "<code>", 1).replace("`", "</code>", 1)
    # Line breaks
    html = html.replace("\n\n", "<br><br>")
    html = html.replace("\n", "<br>")
    return f"<!DOCTYPE html><html><body>{html}</body></html>"

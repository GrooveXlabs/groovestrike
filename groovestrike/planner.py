"""Attack path planner — graph-based vulnerability chaining."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


MITRE_MAP: dict[str, dict[str, Any]] = {
    "secret": {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"},
    "cmdi": {"id": "T1059.004", "name": "Command Shell", "tactic": "Execution"},
    "ssrf": {"id": "T1021.001", "name": "Remote Services", "tactic": "Lateral Movement"},
    "pathtraversal": {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
    "sqli": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "cve": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "misconfig": {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
}

SEVERITY_SCORES = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3, "info": 0.1}

CHAIN_LOGIC: dict[str, list[str]] = {
    "secret": ["ssrf", "cmdi", "sqli"],
    "ssrf": ["secret", "cmdi"],
    "cmdi": ["secret", "pathtraversal"],
    "pathtraversal": ["secret", "cmdi"],
    "sqli": ["cmdi", "secret"],
    "cve": ["cmdi", "sqli", "ssrf"],
    "misconfig": ["cmdi", "secret"],
}


@dataclass
class PathNode:
    finding_id: int
    title: str
    category: str
    severity: str
    mitre: dict[str, str] = field(default_factory=dict)


@dataclass
class AttackPathPlan:
    name: str
    nodes: list[PathNode]
    likelihood: float
    impact: float
    overall: float
    mitre_techniques: list[str] = field(default_factory=list)


def map_mitre(category: str) -> dict[str, str]:
    """Map a finding category to MITRE ATT&CK."""
    return MITRE_MAP.get(category, {"id": "T1595", "name": "Unknown", "tactic": "Unknown"})


def score_finding(severity: str) -> float:
    """Convert severity string to numeric score."""
    return SEVERITY_SCORES.get(severity.lower(), 0.5)


def build_attack_paths(findings: list[dict[str, Any]]) -> list[AttackPathPlan]:
    """Build attack paths from findings using chain logic."""
    if not findings:
        return []

    # Build nodes
    nodes = []
    for i, f in enumerate(findings):
        category = f.get("category", "unknown")
        mitre = map_mitre(category)
        nodes.append(PathNode(
            finding_id=i,
            title=f.get("title", "Unknown"),
            category=category,
            severity=f.get("severity", "medium"),
            mitre=mitre,
        ))

    # Group by category
    by_category: dict[str, list[PathNode]] = {}
    for node in nodes:
        by_category.setdefault(node.category, []).append(node)

    paths = []
    seen = set()

    # Build chains from each category
    for start_cat, start_nodes in by_category.items():
        next_cats = CHAIN_LOGIC.get(start_cat, [])
        for next_cat in next_cats:
            if next_cat not in by_category:
                continue

            for start_node in start_nodes:
                for next_node in by_category[next_cat]:
                    if start_node.finding_id == next_node.finding_id:
                        continue

                    path_key = (start_node.finding_id, next_node.finding_id)
                    if path_key in seen:
                        continue
                    seen.add(path_key)

                    likelihood = score_finding(start_node.severity) * score_finding(next_node.severity)
                    impact = max(score_finding(start_node.severity), score_finding(next_node.severity))
                    overall = likelihood * impact

                    mitre_ids = list({start_node.mitre["id"], next_node.mitre["id"]})

                    paths.append(AttackPathPlan(
                        name=f"{start_node.title} → {next_node.title}",
                        nodes=[start_node, next_node],
                        likelihood=round(likelihood, 2),
                        impact=round(impact, 2),
                        overall=round(overall, 2),
                        mitre_techniques=mitre_ids,
                    ))

    # Sort by overall score descending
    paths.sort(key=lambda p: p.overall, reverse=True)
    return paths[:20]  # Top 20 paths


def generate_attack_paths_for_engagement(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generate serializable attack paths for an engagement."""
    plans = build_attack_paths(findings)
    return [
        {
            "name": plan.name,
            "steps": [node.finding_id for node in plan.nodes],
            "likelihood": plan.likelihood,
            "impact": plan.impact,
            "overall": plan.overall,
            "mitre_techniques": plan.mitre_techniques,
            "nodes": [
                {
                    "finding_id": node.finding_id,
                    "title": node.title,
                    "category": node.category,
                    "severity": node.severity,
                    "mitre": node.mitre,
                }
                for node in plan.nodes
            ],
        }
        for plan in plans
    ]

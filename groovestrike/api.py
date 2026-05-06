"""FastAPI REST API for GrooveStrike."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session

from groovestrike.db import get_session
from groovestrike.engine import EngagementEngine, ScopeItem
from groovestrike.models import Engagement, Finding, AttackPath, Validation, Report

app = FastAPI(
    title="GrooveStrike API",
    description="Autonomous Penetration Testing Framework",
    version="0.1.0",
)


def _engagement_to_dict(e: Engagement) -> dict[str, Any]:
    return {
        "id": e.id,
        "name": e.name,
        "description": e.description,
        "status": e.status,
        "created_at": e.created_at.isoformat() if e.created_at else None,
        "updated_at": e.updated_at.isoformat() if e.updated_at else None,
        "target_count": len([t for t in e.targets if not t.excluded]),
        "finding_count": len(e.findings),
    }


@app.get("/")
def root() -> dict[str, str]:
    return {"name": "GrooveStrike", "version": "0.1.0"}


@app.post("/engagements")
def create_engagement(
    name: str,
    description: str = "",
    targets: list[str] | None = None,
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Create a new pentest engagement."""
    engine = EngagementEngine(session)
    scope_items = []
    if targets:
        for t in targets:
            if ":" in t:
                item_type, value = t.split(":", 1)
                scope_items.append(ScopeItem(item_type, value))
    engagement = engine.create_engagement(name, description, scope_items)
    return _engagement_to_dict(engagement)


@app.get("/engagements")
def list_engagements(
    limit: int = 50,
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    """List all engagements."""
    engine = EngagementEngine(session)
    return [_engagement_to_dict(e) for e in engine.list_engagements(limit)]


@app.get("/engagements/{engagement_id}")
def get_engagement(
    engagement_id: int,
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Get engagement details."""
    engine = EngagementEngine(session)
    engagement = engine.get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return _engagement_to_dict(engagement)


@app.delete("/engagements/{engagement_id}")
def delete_engagement(
    engagement_id: int,
    session: Session = Depends(get_session),
) -> dict[str, bool]:
    """Delete an engagement."""
    engine = EngagementEngine(session)
    success = engine.delete_engagement(engagement_id)
    if not success:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return {"deleted": True}


@app.get("/engagements/{engagement_id}/findings")
def get_findings(
    engagement_id: int,
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    """List findings for an engagement."""
    engine = EngagementEngine(session)
    engagement = engine.get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "category": f.category,
            "description": f.description,
            "evidence": f.evidence,
            "cvss_score": f.cvss_score,
            "validated": f.validated,
        }
        for f in engagement.findings
    ]


@app.get("/engagements/{engagement_id}/paths")
def get_attack_paths(
    engagement_id: int,
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    """List attack paths for an engagement."""
    engine = EngagementEngine(session)
    engagement = engine.get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return [
        {
            "id": p.id,
            "name": p.name,
            "steps": p.steps,
            "mitre_techniques": p.mitre_techniques,
            "likelihood": p.likelihood_score,
            "impact": p.impact_score,
            "overall": p.overall_score,
        }
        for p in engagement.attack_paths
    ]


@app.get("/engagements/{engagement_id}/report")
def get_report(
    engagement_id: int,
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Get latest report for an engagement."""
    engine = EngagementEngine(session)
    engagement = engine.get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    if not engagement.reports:
        raise HTTPException(status_code=404, detail="No report generated yet")
    latest = max(engagement.reports, key=lambda r: r.generated_at)
    return {
        "format": latest.format,
        "generated_at": latest.generated_at.isoformat() if latest.generated_at else None,
        "content": latest.content,
    }


@app.post("/export/sigma")
def export_sigma(
    engagement_id: int,
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Export Sigma rules for an engagement."""
    from groovestrike.bridge import export_sigma_rules

    engine = EngagementEngine(session)
    engagement = engine.get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")

    findings = [
        {"title": f.title, "severity": f.severity, "category": f.category}
        for f in engagement.findings
    ]
    rules = export_sigma_rules(findings)
    return {"engagement": engagement.name, "rules": rules}


@app.post("/export/atomic")
def export_atomic(
    engagement_id: int,
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Export atomic tests for an engagement."""
    from groovestrike.bridge import export_atomic_tests

    engine = EngagementEngine(session)
    engagement = engine.get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")

    findings = [
        {"title": f.title, "severity": f.severity, "category": f.category}
        for f in engagement.findings
    ]
    tests = export_atomic_tests(findings)
    return {"engagement": engagement.name, "tests": tests}

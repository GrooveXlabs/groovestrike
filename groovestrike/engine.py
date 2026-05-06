"""Core engagement orchestration engine."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from groovestrike.models import Engagement, Target, Finding, AttackPath, Validation, Report
from groovestrike.db import get_session


class ScopeItem:
    """Represents a single scope item."""

    def __init__(self, item_type: str, value: str, excluded: bool = False) -> None:
        self.type = item_type
        self.value = value
        self.excluded = excluded

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "value": self.value, "excluded": self.excluded}


class EngagementEngine:
    """Central orchestrator for pentest engagements."""

    def __init__(self, session: Session | None = None) -> None:
        self._session = session
        self._owns_session = session is None

    def _get_session(self) -> Session:
        if self._session is None:
            self._session = next(get_session())
        return self._session

    def create_engagement(
        self,
        name: str,
        description: str | None = None,
        scope_items: list[ScopeItem] | None = None,
    ) -> Engagement:
        """Create a new pentest engagement."""
        session = self._get_session()
        engagement = Engagement(name=name, description=description, status="created")
        session.add(engagement)
        session.flush()

        if scope_items:
            for item in scope_items:
                target = Target(
                    engagement_id=engagement.id,
                    target_type=item.type,
                    value=item.value,
                    excluded=item.excluded,
                )
                session.add(target)

        session.commit()
        session.refresh(engagement)
        return engagement

    def get_engagement(self, engagement_id: int) -> Engagement | None:
        """Retrieve an engagement by ID."""
        session = self._get_session()
        return session.get(Engagement, engagement_id)

    def list_engagements(self, limit: int = 50) -> list[Engagement]:
        """List all engagements."""
        session = self._get_session()
        return session.query(Engagement).order_by(Engagement.created_at.desc()).limit(limit).all()

    def update_status(self, engagement_id: int, status: str) -> Engagement | None:
        """Update engagement status."""
        session = self._get_session()
        engagement = session.get(Engagement, engagement_id)
        if engagement:
            engagement.status = status
            engagement.updated_at = datetime.now(timezone.utc)
            session.commit()
            session.refresh(engagement)
        return engagement

    def delete_engagement(self, engagement_id: int) -> bool:
        """Delete an engagement and all related data."""
        session = self._get_session()
        engagement = session.get(Engagement, engagement_id)
        if engagement:
            session.delete(engagement)
            session.commit()
            return True
        return False

    def get_findings(self, engagement_id: int) -> list[Finding]:
        """Get all findings for an engagement."""
        session = self._get_session()
        engagement = session.get(Engagement, engagement_id)
        return engagement.findings if engagement else []

    def get_attack_paths(self, engagement_id: int) -> list[AttackPath]:
        """Get all attack paths for an engagement."""
        session = self._get_session()
        engagement = session.get(Engagement, engagement_id)
        return engagement.attack_paths if engagement else []

    def get_validations(self, engagement_id: int) -> list[Validation]:
        """Get all validations for an engagement."""
        session = self._get_session()
        engagement = session.get(Engagement, engagement_id)
        return engagement.validations if engagement else []

    def add_finding(
        self,
        engagement_id: int,
        title: str,
        severity: str,
        category: str,
        description: str,
        evidence: str | None = None,
        cvss_score: float | None = None,
        target_id: int | None = None,
    ) -> Finding:
        """Add a finding to an engagement."""
        session = self._get_session()
        finding = Finding(
            engagement_id=engagement_id,
            target_id=target_id,
            title=title,
            severity=severity,
            category=category,
            description=description,
            evidence=evidence,
            cvss_score=cvss_score,
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)
        return finding

    def add_attack_path(
        self,
        engagement_id: int,
        name: str,
        steps: list[int],
        mitre_techniques: list[str] | None = None,
        likelihood: float | None = None,
        impact: float | None = None,
    ) -> AttackPath:
        """Add an attack path to an engagement."""
        session = self._get_session()
        overall = (likelihood * impact) if (likelihood and impact) else None
        path = AttackPath(
            engagement_id=engagement_id,
            name=name,
            steps_json=str(steps).replace("'", '"'),
            mitre_techniques_json=str(mitre_techniques or []).replace("'", '"'),
            likelihood_score=likelihood,
            impact_score=impact,
            overall_score=overall,
        )
        session.add(path)
        session.commit()
        session.refresh(path)
        return path

    def add_validation(
        self,
        engagement_id: int,
        finding_id: int | None,
        status: str,
        poc_command: str | None = None,
        poc_output: str | None = None,
    ) -> Validation:
        """Add a validation result."""
        session = self._get_session()
        validation = Validation(
            engagement_id=engagement_id,
            finding_id=finding_id,
            status=status,
            poc_command=poc_command,
            poc_output=poc_output,
            executed_at=datetime.now(timezone.utc) if status != "pending" else None,
        )
        session.add(validation)
        session.commit()
        session.refresh(validation)
        return validation

    def add_report(
        self,
        engagement_id: int,
        format: str,
        content: str,
        file_path: str | None = None,
    ) -> Report:
        """Add a generated report."""
        session = self._get_session()
        report = Report(
            engagement_id=engagement_id,
            format=format,
            content=content,
            file_path=file_path,
        )
        session.add(report)
        session.commit()
        session.refresh(report)
        return report

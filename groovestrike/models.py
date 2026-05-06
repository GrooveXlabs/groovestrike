"""SQLAlchemy ORM models for GrooveStrike engagements."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List

from sqlalchemy import ForeignKey, Integer, String, DateTime, Float, Boolean, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Engagement(Base):
    __tablename__ = "engagements"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="created")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc)
    )

    targets: Mapped[List["Target"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan", lazy="selectin"
    )
    findings: Mapped[List["Finding"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan", lazy="selectin"
    )
    attack_paths: Mapped[List["AttackPath"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan", lazy="selectin"
    )
    validations: Mapped[List["Validation"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan", lazy="selectin"
    )
    reports: Mapped[List["Report"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan", lazy="selectin"
    )


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    target_type: Mapped[str] = mapped_column(String(20))  # ip, domain, url, cidr, repo
    value: Mapped[str] = mapped_column(String(500))
    excluded: Mapped[bool] = mapped_column(Boolean, default=False)
    target_metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    engagement: Mapped["Engagement"] = relationship(back_populates="targets")

    @property
    def target_metadata(self) -> dict:
        return json.loads(self.target_metadata_json) if self.target_metadata_json else {}

    @target_metadata.setter
    def target_metadata(self, value: dict) -> None:
        self.target_metadata_json = json.dumps(value)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(500))
    severity: Mapped[str] = mapped_column(String(10), default="medium")
    category: Mapped[str] = mapped_column(String(50))  # ssrf, cmdi, pathtraversal, sqli, secret, cve, misconfig
    description: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(50), nullable=True)
    validated: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )

    engagement: Mapped["Engagement"] = relationship(back_populates="findings")


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    name: Mapped[str] = mapped_column(String(200))
    steps_json: Mapped[str] = mapped_column(Text)  # JSON array of finding IDs
    mitre_techniques_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    likelihood_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    impact_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    overall_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    engagement: Mapped["Engagement"] = relationship(back_populates="attack_paths")

    @property
    def steps(self) -> list[int]:
        return json.loads(self.steps_json) if self.steps_json else []

    @steps.setter
    def steps(self, value: list[int]) -> None:
        self.steps_json = json.dumps(value)

    @property
    def mitre_techniques(self) -> list[str]:
        return json.loads(self.mitre_techniques_json) if self.mitre_techniques_json else []

    @mitre_techniques.setter
    def mitre_techniques(self, value: list[str]) -> None:
        self.mitre_techniques_json = json.dumps(value)


class Validation(Base):
    __tablename__ = "validations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # success, failed, error, skipped
    poc_command: Mapped[str | None] = mapped_column(Text, nullable=True)
    poc_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    safe: Mapped[bool] = mapped_column(Boolean, default=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    engagement: Mapped["Engagement"] = relationship(back_populates="validations")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    format: Mapped[str] = mapped_column(String(20))  # pdf, markdown, json
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )

    engagement: Mapped["Engagement"] = relationship(back_populates="reports")

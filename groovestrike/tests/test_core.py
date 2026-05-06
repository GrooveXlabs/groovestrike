"""Core tests for GrooveStrike."""

from __future__ import annotations

from groovestrike.db import init_db, get_session
from groovestrike.engine import EngagementEngine, ScopeItem
from groovestrike.models import Engagement, Target, Finding, AttackPath
from groovestrike.planner import build_attack_paths, map_mitre
from groovestrike.validator import validate_finding
from groovestrike.reporter import ReportData, generate_full_report, _calculate_risk_score
from groovestrike.bridge import export_sigma_rules, export_atomic_tests


class TestEngine:
    def test_create_engagement(self) -> None:
        init_db(":memory:")
        with next(get_session()) as session:
            engine = EngagementEngine(session)
            engagement = engine.create_engagement(
                "Test Engagement",
                "Description",
                [ScopeItem("ip", "10.0.0.1"), ScopeItem("domain", "example.com")],
            )
            assert engagement.id is not None
            assert engagement.name == "Test Engagement"
            assert len(engagement.targets) == 2

    def test_get_engagement(self) -> None:
        init_db(":memory:")
        with next(get_session()) as session:
            engine = EngagementEngine(session)
            created = engine.create_engagement("Test", scope_items=[ScopeItem("ip", "10.0.0.1")])
            fetched = engine.get_engagement(created.id)
            assert fetched is not None
            assert fetched.name == "Test"

    def test_add_finding(self) -> None:
        init_db(":memory:")
        with next(get_session()) as session:
            engine = EngagementEngine(session)
            engagement = engine.create_engagement("Test")
            finding = engine.add_finding(
                engagement.id,
                title="SQL Injection",
                severity="critical",
                category="sqli",
                description="Found in login form",
                cvss_score=9.0,
            )
            assert finding.id is not None
            assert finding.severity == "critical"

    def test_add_attack_path(self) -> None:
        init_db(":memory:")
        with next(get_session()) as session:
            engine = EngagementEngine(session)
            engagement = engine.create_engagement("Test")
            path = engine.add_attack_path(
                engagement.id,
                "Path A",
                steps=[1, 2],
                mitre_techniques=["T1190"],
                likelihood=0.8,
                impact=0.9,
            )
            assert round(path.overall_score, 2) == 0.72
            assert path.steps == [1, 2]


class TestPlanner:
    def test_map_mitre(self) -> None:
        assert map_mitre("cmdi")["id"] == "T1059.004"
        assert map_mitre("ssrf")["id"] == "T1021.001"
        assert map_mitre("unknown")["id"] == "T1595"

    def test_build_attack_paths(self) -> None:
        findings = [
            {"title": "Secret", "category": "secret", "severity": "high"},
            {"title": "SSRF", "category": "ssrf", "severity": "high"},
            {"title": "CMDi", "category": "cmdi", "severity": "critical"},
        ]
        paths = build_attack_paths(findings)
        assert len(paths) > 0
        assert paths[0].overall > 0
        assert len(paths[0].nodes) == 2

    def test_build_attack_paths_empty(self) -> None:
        assert build_attack_paths([]) == []


class TestValidator:
    def test_validate_unknown_category(self) -> None:
        result = validate_finding("unknown_category", "http://example.com")
        assert result.status == "skipped"

    def test_validate_misconfig(self) -> None:
        result = validate_finding("misconfig", "https://httpbin.org/get")
        assert result.status in ["success", "failed", "error"]
        assert result.safe is True


class TestReporter:
    def test_calculate_risk_score(self) -> None:
        findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
        ]
        score = _calculate_risk_score(findings)
        assert 0 <= score <= 100

    def test_generate_full_report(self) -> None:
        data = ReportData(
            engagement_name="Test",
            generated_at="2026-05-07",
            findings=[{"title": "XSS", "severity": "high", "category": "cmdi", "description": "Found XSS"}],
            attack_paths=[],
            validations=[],
            targets=[{"target_type": "url", "value": "https://example.com"}],
        )
        report = generate_full_report(data)
        assert "Executive Summary" in report
        assert "XSS" in report
        assert "Technical Findings" in report

    def test_generate_json_report(self) -> None:
        data = ReportData(
            engagement_name="Test",
            generated_at="2026-05-07",
            findings=[],
            attack_paths=[],
            validations=[],
            targets=[],
        )
        report = generate_full_report(data, format="json")
        assert "engagement" in report


class TestBridge:
    def test_export_sigma_rules(self) -> None:
        findings = [
            {"title": "Cmdi", "severity": "critical", "category": "cmdi"},
            {"title": "SSRF", "severity": "high", "category": "ssrf"},
        ]
        rules = export_sigma_rules(findings)
        assert len(rules) == 2
        assert rules[0]["filename"].endswith(".yml")
        assert "title:" in rules[0]["content"]

    def test_export_atomic_tests(self) -> None:
        findings = [{"title": "Cmdi", "severity": "critical", "category": "cmdi"}]
        tests = export_atomic_tests(findings)
        assert len(tests) == 1
        assert tests[0]["filename"].endswith(".ps1")


class TestAPIModels:
    @classmethod
    def setup_class(cls) -> None:
        init_db(":memory:")
        cls.client = __import__("fastapi.testclient", fromlist=["TestClient"]).TestClient(
            __import__("groovestrike.api", fromlist=["app"]).app
        )

    def test_root(self) -> None:
        response = self.client.get("/")
        assert response.status_code == 200
        assert response.json()["name"] == "GrooveStrike"

    def test_list_empty_engagements(self) -> None:
        response = self.client.get("/engagements")
        assert response.status_code == 200
        assert response.json() == []

    def test_get_nonexistent_engagement(self) -> None:
        response = self.client.get("/engagements/999")
        assert response.status_code == 404

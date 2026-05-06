"""Click CLI for GrooveStrike."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from groovestrike.db import init_db, get_session
from groovestrike.engine import EngagementEngine, ScopeItem
from groovestrike.recon import port_scan, enum_subdomains, fingerprint_web, discover_api_endpoints
from groovestrike.discovery import static_scan_repo, discover_web_vulns
from groovestrike.planner import generate_attack_paths_for_engagement
from groovestrike.validator import validate_finding
from groovestrike.reporter import ReportData, save_report
from groovestrike.bridge import export_sigma_rules, export_atomic_tests, export_to_groovehub_format

console = Console()


def _engagement_table(engagements: list) -> Table:
    table = Table(title="Engagements")
    table.add_column("ID", style="cyan", justify="right")
    table.add_column("Name", style="magenta")
    table.add_column("Status", style="yellow")
    table.add_column("Targets", style="green", justify="right")
    table.add_column("Findings", style="red", justify="right")
    table.add_column("Created", style="white")
    for e in engagements:
        table.add_row(
            str(e.id),
            e.name,
            e.status,
            str(len(e.targets)),
            str(len(e.findings)),
            e.created_at.strftime("%Y-%m-%d") if e.created_at else "—",
        )
    return table


@click.group()
@click.version_option(version="0.1.0", prog_name="groovestrike")
def main() -> None:
    """GrooveStrike — Autonomous Penetration Testing Framework."""
    init_db()


@main.command()
@click.argument("name")
@click.option("--description", default="", help="Engagement description")
@click.option("--target", "-t", multiple=True, required=True, help="Target (ip:10.0.0.1, domain:example.com, url:https://example.com)")
@click.option("--exclude", "-x", multiple=True, help="Excluded scope item")
def engage(name: str, description: str, target: tuple[str, ...], exclude: tuple[str, ...]) -> None:
    """Create a new pentest engagement."""
    scope_items = []
    exclusions = set(exclude)

    for t in target:
        if ":" not in t:
            console.print(f"[red]Invalid target format: {t}. Use type:value (e.g., ip:10.0.0.1)[/red]")
            sys.exit(1)
        item_type, value = t.split(":", 1)
        scope_items.append(ScopeItem(item_type, value, excluded=value in exclusions))

    with next(get_session()) as session:
        engine = EngagementEngine(session)
        engagement = engine.create_engagement(name, description, scope_items)

    console.print(f"[green]Created engagement #{engagement.id}: {engagement.name}[/green]")
    console.print(f"  Targets: {len([t for t in engagement.targets if not t.excluded])}")


@main.command()
@click.argument("engagement_id", type=int)
def recon(engagement_id: int) -> None:
    """Run reconnaissance on an engagement."""
    with next(get_session()) as session:
        engine = EngagementEngine(session)
        engagement = engine.get_engagement(engagement_id)
        if not engagement:
            console.print(f"[red]Engagement {engagement_id} not found[/red]")
            sys.exit(1)

        targets = [t for t in engagement.targets if not t.excluded]
        if not targets:
            console.print("[yellow]No targets in scope[/yellow]")
            return

        engine.update_status(engagement_id, "recon")
        results = []

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as progress:
            for target in targets:
                if target.target_type == "ip":
                    task = progress.add_task(f"Scanning {target.value}...", total=None)
                    scan_results = port_scan([target.value], threads=50)
                    results.extend(scan_results)
                    for r in scan_results:
                        console.print(f"  [green]{r.host}:{r.port}[/green] open ({r.service or 'unknown'})")

                elif target.target_type == "domain":
                    task = progress.add_task(f"Enumerating {target.value}...", total=None)
                    subs = enum_subdomains(target.value)
                    console.print(f"  [green]Found {len(subs)} subdomains for {target.value}[/green]")
                    for s in subs[:10]:
                        console.print(f"    - {s}")

                elif target.target_type == "url":
                    task = progress.add_task(f"Fingerprinting {target.value}...", total=None)
                    info = fingerprint_web(target.value)
                    console.print(f"  [green]{target.value}[/green] → {info.status_code}")
                    if info.technologies:
                        console.print(f"    Tech: {', '.join(info.technologies)}")
                    if info.title:
                        console.print(f"    Title: {info.title}")

                    progress.update(task, description=f"Discovering API endpoints on {target.value}...")
                    endpoints = discover_api_endpoints(target.value)
                    if endpoints:
                        console.print(f"    Endpoints: {len(endpoints)}")

        engine.update_status(engagement_id, "discovery")
        console.print(f"\n[green]Reconnaissance complete. Found {len(results)} open ports/services.[/green]")


@main.command()
@click.argument("engagement_id", type=int)
@click.option("--repo", help="Local repo path for static analysis")
def scan(engagement_id: int, repo: str | None) -> None:
    """Run vulnerability discovery on an engagement."""
    with next(get_session()) as session:
        engine = EngagementEngine(session)
        engagement = engine.get_engagement(engagement_id)
        if not engagement:
            console.print(f"[red]Engagement {engagement_id} not found[/red]")
            sys.exit(1)

        engine.update_status(engagement_id, "discovery")
        targets = [t for t in engagement.targets if not t.excluded]

        # Static scan
        if repo:
            console.print(f"[cyan]Running static analysis on {repo}...[/cyan]")
            static_findings = static_scan_repo(Path(repo))
            for f in static_findings:
                engine.add_finding(
                    engagement_id=engagement_id,
                    title=f.title,
                    severity=f.severity,
                    category=f.category,
                    description=f.description,
                    evidence=f.evidence,
                    cvss_score=f.cvss_score,
                )
            console.print(f"  [green]{len(static_findings)} static findings[/green]")

        # Dynamic scan
        for target in targets:
            if target.target_type == "url":
                console.print(f"[cyan]Probing {target.value}...[/cyan]")
                dynamic_findings = discover_web_vulns(target.value)
                for f in dynamic_findings:
                    engine.add_finding(
                        engagement_id=engagement_id,
                        title=f.title,
                        severity=f.severity,
                        category=f.category,
                        description=f.description,
                        evidence=f.evidence,
                        cvss_score=f.cvss_score,
                    )
                console.print(f"  [green]{len(dynamic_findings)} dynamic findings[/green]")

        engine.update_status(engagement_id, "exploitation")
        console.print(f"\n[green]Discovery complete. Total findings: {len(engagement.findings)}[/green]")


@main.command()
@click.argument("engagement_id", type=int)
def plan(engagement_id: int) -> None:
    """Build attack paths from findings."""
    with next(get_session()) as session:
        engine = EngagementEngine(session)
        engagement = engine.get_engagement(engagement_id)
        if not engagement:
            console.print(f"[red]Engagement {engagement_id} not found[/red]")
            sys.exit(1)

        findings = [
            {"title": f.title, "category": f.category, "severity": f.severity}
            for f in engagement.findings
        ]

        paths = generate_attack_paths_for_engagement(findings)
        for p in paths:
            engine.add_attack_path(
                engagement_id=engagement_id,
                name=p["name"],
                steps=p["steps"],
                mitre_techniques=p["mitre_techniques"],
                likelihood=p["likelihood"],
                impact=p["impact"],
            )

        console.print(f"[green]Generated {len(paths)} attack paths[/green]")
        for p in paths[:5]:
            console.print(f"  [yellow]{p['name']}[/yellow] (score: {p['overall']})")


@main.command()
@click.argument("engagement_id", type=int)
def validate(engagement_id: int) -> None:
    """Run safe exploit validation on findings."""
    with next(get_session()) as session:
        engine = EngagementEngine(session)
        engagement = engine.get_engagement(engagement_id)
        if not engagement:
            console.print(f"[red]Engagement {engagement_id} not found[/red]")
            sys.exit(1)

        targets = [t for t in engagement.targets if not t.excluded and t.target_type == "url"]
        if not targets:
            console.print("[yellow]No URL targets to validate against[/yellow]")
            return

        target_url = targets[0].value

        for finding in engagement.findings:
            result = validate_finding(finding.category, target_url)
            engine.add_validation(
                engagement_id=engagement_id,
                finding_id=finding.id,
                status=result.status,
                poc_command=result.command,
                poc_output=result.output,
            )
            status_color = {"success": "green", "failed": "yellow", "error": "red", "skipped": "gray"}.get(result.status, "white")
            console.print(f"  [{status_color}]{finding.category}: {result.status}[/{status_color}]")

        console.print(f"\n[green]Validation complete[/green]")


@main.command()
@click.argument("engagement_id", type=int)
@click.option("--format", "output_format", default="markdown", type=click.Choice(["markdown", "json", "html"]))
@click.option("--output", "-o", help="Output file path")
def report(engagement_id: int, output_format: str, output: str | None) -> None:
    """Generate professional pentest report."""
    with next(get_session()) as session:
        engine = EngagementEngine(session)
        engagement = engine.get_engagement(engagement_id)
        if not engagement:
            console.print(f"[red]Engagement {engagement_id} not found[/red]")
            sys.exit(1)

        data = ReportData(
            engagement_name=engagement.name,
            generated_at=datetime.now(timezone.utc).isoformat(),
            findings=[
                {"title": f.title, "severity": f.severity, "category": f.category,
                 "description": f.description, "evidence": f.evidence, "cvss_score": f.cvss_score,
                 "validated": f.validated}
                for f in engagement.findings
            ],
            attack_paths=[
                {"name": p.name, "steps": p.steps, "mitre_techniques": p.mitre_techniques,
                 "likelihood": p.likelihood_score, "impact": p.impact_score, "overall": p.overall_score}
                for p in engagement.attack_paths
            ],
            validations=[
                {"finding_category": "unknown", "status": v.status,
                 "poc_command": v.poc_command, "poc_output": v.poc_output}
                for v in engagement.validations
            ],
            targets=[{"target_type": t.target_type, "value": t.value} for t in engagement.targets],
        )

        if output:
            out_path = Path(output)
        else:
            out_path = Path(f"groovestrike_report_{engagement_id}")

        saved = save_report(data, out_path, format=output_format)
        engine.add_report(engagement_id, output_format, saved.read_text(encoding="utf-8"), str(saved))
        engine.update_status(engagement_id, "completed")

        console.print(f"[green]Report saved to {saved}[/green]")
        console.print(Panel(saved.read_text(encoding="utf-8")[:800] + "...", title="Preview"))


@main.command()
def list() -> None:
    """List all engagements."""
    with next(get_session()) as session:
        engine = EngagementEngine(session)
        engagements = engine.list_engagements()

    if not engagements:
        console.print("[yellow]No engagements yet.[/yellow]")
        return

    console.print(_engagement_table(engagements))


@main.command()
@click.argument("engagement_id", type=int)
def export(engagement_id: int) -> None:
    """Export findings to Sigma + Atomic test formats."""
    with next(get_session()) as session:
        engine = EngagementEngine(session)
        engagement = engine.get_engagement(engagement_id)
        if not engagement:
            console.print(f"[red]Engagement {engagement_id} not found[/red]")
            sys.exit(1)

        findings = [
            {"title": f.title, "severity": f.severity, "category": f.category,
             "description": f.description}
            for f in engagement.findings
        ]

        sigma = export_sigma_rules(findings)
        atomic = export_atomic_tests(findings)

        sigma_dir = Path(f"sigma_{engagement_id}")
        sigma_dir.mkdir(exist_ok=True)
        for rule in sigma:
            (sigma_dir / rule["filename"]).write_text(rule["content"], encoding="utf-8")

        atomic_dir = Path(f"atomic_{engagement_id}")
        atomic_dir.mkdir(exist_ok=True)
        for test in atomic:
            (atomic_dir / test["filename"]).write_text(test["content"], encoding="utf-8")

        console.print(f"[green]Exported {len(sigma)} Sigma rules to {sigma_dir}/[/green]")
        console.print(f"[green]Exported {len(atomic)} atomic tests to {atomic_dir}/[/green]")


@main.command()
def serve() -> None:
    """Start the GrooveStrike API server."""
    import uvicorn
    console.print("[green]Starting GrooveStrike API on http://127.0.0.1:8001[/green]")
    uvicorn.run("groovestrike.api:app", host="127.0.0.1", port=8001, reload=False)


if __name__ == "__main__":
    main()

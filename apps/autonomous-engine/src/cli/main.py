"""ReconX CLI — command-line interface for autonomous security operations.

Usage:
  reconx scan --target https://example.com --mode autonomous
  reconx triage --workspace test-ws
  reconx report --finding-id abc123 --format hackerone
  reconx monitor --target https://example.com --interval 3600
  reconx intel --category sqli
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

import httpx

console = Console()

DEFAULT_API = "http://localhost:8004"
VULN_API = "http://localhost:8002"
TRIAGE_API = "http://localhost:8003"


@click.group()
@click.option("--api-url", default=DEFAULT_API, help="Autonomous engine API URL")
@click.pass_context
def cli(ctx, api_url):
    """ReconX — Autonomous AI Security Operations Platform"""
    ctx.ensure_object(dict)
    ctx.obj["api_url"] = api_url


@cli.command()
@click.option("--target", "-t", required=True, multiple=True, help="Target URL(s)")
@click.option("--workspace", "-w", default="default", help="Workspace ID")
@click.option("--mode", "-m", type=click.Choice(["autonomous", "recon", "vuln", "full"]), default="autonomous")
@click.option("--cycles", "-c", default=3, help="Max autonomous cycles")
def scan(target, workspace, mode, cycles):
    """Launch an autonomous security scan."""
    console.print(Panel.fit(
        f"[bold cyan]ReconX Autonomous Scan[/]\n"
        f"Targets: {', '.join(target)}\nMode: {mode}\nCycles: {cycles}",
        border_style="cyan",
    ))

    async def run():
        async with httpx.AsyncClient(timeout=600) as client:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
                task = progress.add_task("Starting autonomous session...", total=None)
                resp = await client.post(f"{DEFAULT_API}/api/v1/agents/session/start", json={
                    "workspace_id": workspace, "targets": list(target),
                    "max_cycles": cycles, "mode": mode,
                })
                if resp.status_code == 200:
                    result = resp.json()
                    progress.update(task, description="Session complete!")
                    console.print(f"\n[green]✓[/] Session ID: {result.get('session_id', 'N/A')}")
                    console.print(f"[green]✓[/] Findings: {result.get('metrics', {}).get('total_findings', 0)}")
                    console.print(f"[green]✓[/] Cycles: {result.get('metrics', {}).get('total_cycles', 0)}")
                else:
                    console.print(f"[red]✗[/] Error: {resp.text}")

    asyncio.run(run())


@cli.command()
@click.option("--workspace", "-w", required=True, help="Workspace ID")
@click.option("--file", "-f", type=click.Path(exists=True), help="Findings JSON file")
def triage(workspace, file):
    """Triage findings through the AI pipeline."""
    findings = []
    if file:
        with open(file) as f:
            findings = json.load(f)

    async def run():
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(f"{TRIAGE_API}/api/v1/triage/batch", json={
                "workspace_id": workspace, "findings": findings,
            })
            if resp.status_code == 200:
                data = resp.json()
                table = Table(title="Triaged Findings")
                table.add_column("Priority", style="bold")
                table.add_column("Severity", style="bold")
                table.add_column("Title")
                table.add_column("CVSS", justify="right")
                table.add_column("CWE")
                for f in data.get("findings", [])[:20]:
                    sev_color = {"critical": "red", "high": "yellow", "medium": "cyan"}.get(f.get("severity", ""), "white")
                    table.add_row(
                        str(f.get("priority_rank", "")),
                        f"[{sev_color}]{f.get('severity', '').upper()}[/]",
                        f.get("title", "")[:60],
                        str(f.get("cvss_score", "")),
                        f.get("cwe_id", ""),
                    )
                console.print(table)
            else:
                console.print(f"[red]Error:[/] {resp.text}")

    asyncio.run(run())


@cli.command()
@click.option("--finding", "-f", type=str, help="Finding JSON or file path")
@click.option("--format", "-fmt", type=click.Choice(["hackerone", "bugcrowd", "intigriti", "cve", "executive", "technical"]),
              default="hackerone")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
def report(finding, format, output):
    """Generate a vulnerability report."""
    finding_data = json.loads(finding) if finding and finding.startswith("{") else {}

    async def run():
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(f"{TRIAGE_API}/api/v1/reports/generate", json={
                "finding": finding_data, "format": format,
            })
            if resp.status_code == 200:
                content = resp.json().get("content", "")
                if output:
                    with open(output, "w") as f:
                        f.write(content)
                    console.print(f"[green]✓[/] Report saved to {output}")
                else:
                    console.print(Panel(content, title=f"Report ({format})", border_style="green"))
            else:
                console.print(f"[red]Error:[/] {resp.text}")

    asyncio.run(run())


@cli.command()
@click.option("--target", "-t", required=True, help="Target URL to monitor")
@click.option("--interval", "-i", default=3600, help="Check interval in seconds")
def monitor(target, interval):
    """Start continuous monitoring of a target."""
    console.print(f"[cyan]Monitoring:[/] {target} every {interval}s")
    console.print("[dim]Press Ctrl+C to stop[/]")

    async def run():
        async with httpx.AsyncClient(timeout=30) as client:
            while True:
                resp = await client.post(f"{DEFAULT_API}/api/v1/monitor/check", json={"urls": [target]})
                if resp.status_code == 200:
                    changes = resp.json().get("changes", [])
                    if changes:
                        console.print(f"[yellow]⚠ {len(changes)} changes detected![/]")
                        for c in changes:
                            console.print(f"  → {c.get('type', '')}: {c.get('url', '')}")
                    else:
                        console.print(f"[green]✓[/] No changes detected")
                await asyncio.sleep(interval)

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        console.print("\n[dim]Monitoring stopped[/]")


@cli.command()
@click.option("--category", "-c", required=True, help="Vulnerability category")
@click.option("--url", "-u", default="", help="Target URL for context")
def intel(category, url):
    """Query exploit intelligence."""
    async def run():
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(f"{TRIAGE_API}/api/v1/intel/exploit-intel", json={
                "category": category, "url": url,
            })
            if resp.status_code == 200:
                data = resp.json()
                console.print(Panel.fit(f"[bold]Exploit Intelligence: {category}[/]", border_style="purple"))
                if data.get("similar_findings"):
                    console.print(f"\n[cyan]Similar findings:[/] {len(data['similar_findings'])}")
                if data.get("effective_payloads"):
                    console.print(f"[cyan]Effective payloads:[/] {len(data['effective_payloads'])}")
                if data.get("ai_recommendation"):
                    console.print(f"\n[green]AI Recommendation:[/]\n{data['ai_recommendation']}")

    asyncio.run(run())


@cli.command()
def status():
    """Check platform service status."""
    services = [
        ("API Gateway", "http://localhost:8000/health"),
        ("Vuln Engine", "http://localhost:8002/health"),
        ("Triage Engine", "http://localhost:8003/health"),
        ("Autonomous Engine", f"{DEFAULT_API}/health"),
    ]

    async def run():
        table = Table(title="ReconX Service Status")
        table.add_column("Service")
        table.add_column("Status")
        table.add_column("URL")

        async with httpx.AsyncClient(timeout=5) as client:
            for name, url in services:
                try:
                    resp = await client.get(url)
                    status = "[green]HEALTHY[/]" if resp.status_code == 200 else f"[yellow]{resp.status_code}[/]"
                except Exception:
                    status = "[red]DOWN[/]"
                table.add_row(name, status, url)

        console.print(table)

    asyncio.run(run())


if __name__ == "__main__":
    cli()

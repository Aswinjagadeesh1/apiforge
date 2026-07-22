"""APIForge command-line interface."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table

from apiforge.auth.jwt_auth import JWTAuthenticator
from apiforge.models import UserSession
from apiforge.parser.postman import PostmanParser
from apiforge.parser.openapi import OpenAPIParser
from apiforge.parser.openapi import OpenAPIParser
from apiforge.reporter.report import Reporter
from apiforge.scanner import Scanner

app = typer.Typer(add_completion=False, help="APIForge — automated OWASP API Top 10 scanner.")
console = Console()

_SEV_COLOR = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "blue",
}


@app.command()
def scan(
    collection: Path = typer.Option(..., "--collection", "-c", help="Postman collection JSON."),
    users: Path = typer.Option(..., "--users", "-u", help="Users config JSON."),
    base_url: str = typer.Option(..., "--base-url", "-b", help="Target API base URL."),
    environment: Optional[Path] = typer.Option(None, "--env", "-e", help="Postman environment JSON."),
    output: Path = typer.Option("apiforge_report.xlsx", "--output", "-o", help="Excel report path."),
    json_output: Optional[Path] = typer.Option(None, "--json", help="Optional JSON report path."),
    word_output: Optional[Path] = typer.Option(None, "--word", help="Optional Word (.docx) report path."),
) -> None:
    """Scan an API described by a Postman collection for OWASP API Top 10 issues."""
    console.print(
        Panel.fit(
            "[bold cyan]APIForge[/bold cyan]  ·  OWASP API Top 10 Scanner\n"
            f"[dim]Target:[/dim] {base_url}",
            border_style="cyan",
        )
    )
    asyncio.run(_run(collection, users, base_url, environment, output, json_output, word_output))


async def _run(
    collection: Path,
    users: Path,
    base_url: str,
    environment: Optional[Path],
    output: Path,
    json_output: Optional[Path],
    word_output: Optional[Path] = None,
) -> None:
    # ---- config ----
    with open(users, encoding="utf-8") as f:
        cfg = json.load(f)

    # ---- parse ----
    base_vars = {
        "url": base_url,
        "base_url": base_url,
        "baseUrl": base_url,
        "URL": base_url,
        "host": base_url,
        "url_mail": "http://localhost:8025",
    }
    import json as _json
    with open(collection, encoding="utf-8") as _f:
        _peek = _json.load(_f)
    if "swagger" in _peek or "openapi" in _peek:
        parser = OpenAPIParser(collection, extra_vars=base_vars)
    else:
        parser = PostmanParser(collection, environment_path=environment, extra_vars=base_vars)
    endpoints = parser.parse()
    console.print(f"[green]✓[/green] Parsed [bold]{len(endpoints)}[/bold] endpoints")

    # ---- authenticate ----
    auth = JWTAuthenticator(
        base_url=base_url,
        login_endpoint=cfg["login_endpoint"],
        token_json_path=cfg.get("token_json_path"),
        login_field=cfg.get("login_field", "email"),
        password_field=cfg.get("password_field", "password"), 
    )
    sessions: dict[str, UserSession] = {}
    try:
        # Build the list of users to log in. Admin is optional (opt-in for
        # role-aware privilege-escalation testing).
        user_labels = ["user_a", "user_b"]
        if "user_admin" in cfg:
            user_labels.append("user_admin")
        for label in user_labels:
            u = cfg[label]
            login_field = cfg.get("login_field", "email")
            sessions[label] = await auth.login(
                label, password=u["password"], **{login_field: u[login_field]}
            )
        # Map the admin config label to the "admin" key the privilege-
        # escalation check looks for.
        if "user_admin" in sessions:
            sessions["admin"] = sessions["user_admin"]
        console.print("[green]✓[/green] Authenticated users")
    except Exception as exc:
        console.print(f"[red]✗ Authentication failed:[/red] {exc}")
        await auth.close()
        raise typer.Exit(code=1)
    finally:
        await auth.close()

    # ---- scan ----
    # Configure dynamic BOLA check from config (config over code).
    from apiforge.checks.bola_dynamic import BolaDynamicCheck
    BolaDynamicCheck.id_fields = cfg.get("bola_id_fields", BolaDynamicCheck.id_fields)
    BolaDynamicCheck.owner_field = cfg.get("bola_owner_field", BolaDynamicCheck.owner_field)

    scanner = Scanner(
        base_url=base_url,
        auth_header=cfg.get("auth_header", "Authorization"),
        auth_scheme=cfg.get("auth_scheme", "Bearer"),
    )
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Scanning…", total=1)

        def on_progress(done: int, total: int) -> None:
            progress.update(task, completed=done, total=max(total, 1))

        result = await scanner.scan(endpoints, sessions, on_progress=on_progress)
    await scanner.close()

    # ---- report to console ----
    _print_findings(result.findings)
    if result.errors:
        console.print(f"[dim]{len(result.errors)} non-fatal errors during scan.[/dim]")

    # ---- write files ----
    reporter = Reporter()
    reporter.to_excel(result.findings, output, target=base_url)
    console.print(f"[green]✓[/green] Excel report → [bold]{output}[/bold]")
    if json_output:
        reporter.to_json(result.findings, json_output)
        console.print(f"[green]✓[/green] JSON report → [bold]{json_output}[/bold]")
    if word_output:
        from apiforge.reporter.report_word import write_word_report
        write_word_report(result.findings, word_output, target=base_url)
        console.print(f"[green]✓[/green] Word report → [bold]{word_output}[/bold]")


def _print_findings(findings: list) -> None:
    if not findings:
        console.print("\n[bold green]No findings.[/bold green] "
                      "(Verify the target is reachable and the checks applied.)")
        return
    table = Table(title=f"\nFindings ({len(findings)})", show_lines=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Check")
    table.add_column("Endpoint")
    for f in sorted(findings, key=lambda x: x.severity.rank):
        style = _SEV_COLOR.get(f.severity.value, "white")
        table.add_row(
            f"[{style}]{f.severity.value}[/{style}]",
            f.title,
            f"{f.method} {f.endpoint}",
        )
    console.print(table)


if __name__ == "__main__":
    app()

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
    blind_ssrf: bool = typer.Option(False, "--blind-ssrf", help="Enable blind SSRF detection via a local out-of-band listener (target must be able to reach this machine: localhost/Docker/lab)."),
) -> None:
    """Scan an API described by a Postman collection for OWASP API Top 10 issues."""
    console.print(
        Panel.fit(
            "[bold cyan]APIForge[/bold cyan]  ·  OWASP API Top 10 Scanner\n"
            f"[dim]Target:[/dim] {base_url}",
            border_style="cyan",
        )
    )
    asyncio.run(_run(collection, users, base_url, environment, output, json_output, word_output, blind_ssrf))


async def _run(
    collection: Path,
    users: Path,
    base_url: str,
    environment: Optional[Path],
    output: Path,
    json_output: Optional[Path],
    word_output: Optional[Path] = None,
    blind_ssrf: bool = False,
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
    # Detect format from the raw text so YAML specs and http(s) URLs don't crash
    # a JSON-only peek. Postman collections are always JSON with an "item" key.
    _collection_str = str(collection)
    if _collection_str.startswith(("http://", "https://")):
        import httpx
        _peek_text = httpx.get(_collection_str, timeout=15.0, verify=False).text
    else:
        with open(collection, encoding="utf-8") as _f:
            _peek_text = _f.read()
    _is_openapi = False
    try:
        import json as _json
        _peek = _json.loads(_peek_text)
        _is_openapi = ("swagger" in _peek or "openapi" in _peek)
    except Exception:
        # Not JSON -> almost certainly a YAML OpenAPI spec (Postman is always JSON)
        _is_openapi = ("swagger:" in _peek_text or "openapi:" in _peek_text)
    if _is_openapi:
        parser = OpenAPIParser(collection, extra_vars=base_vars)
    else:
        parser = PostmanParser(collection, environment_path=environment, extra_vars=base_vars)
    endpoints = parser.parse()
    console.print(f"[green]✓[/green] Parsed [bold]{len(endpoints)}[/bold] endpoints")

    # ---- authenticate ----
    # login_endpoint is only required when at least one user logs in with
    # credentials; pure token mode does not need it.
    auth = JWTAuthenticator(
        base_url=base_url,
        login_endpoint=cfg.get("login_endpoint", ""),
        token_json_path=cfg.get("token_json_path"),
        login_field=cfg.get("login_field", "email"),
        password_field=cfg.get("password_field", "password"),
    )
    sessions: dict[str, UserSession] = {}
    try:
        # Build the list of users. Admin is optional (opt-in for role-aware
        # privilege-escalation testing).
        user_labels = ["user_a", "user_b"]
        if "user_admin" in cfg:
            user_labels.append("user_admin")
        login_field = cfg.get("login_field", "email")
        used_token = False
        for label in user_labels:
            u = cfg.get(label)
            if not u:
                continue
            if u.get("token"):
                # Token mode: use the supplied token directly, skip login.
                sessions[label] = UserSession(
                    label=label,
                    email=str(u.get(login_field, u.get("email", label))),
                    token=str(u["token"]),
                )
                used_token = True
            elif u.get("password") is not None:
                # Credential mode: log in as before.
                if not cfg.get("login_endpoint"):
                    raise RuntimeError(
                        f"'{label}' uses email/password but no 'login_endpoint' "
                        f"is set in the users config. Add login_endpoint, or give "
                        f"'{label}' a 'token' instead."
                    )
                sessions[label] = await auth.login(
                    label, password=u["password"], **{login_field: u[login_field]}
                )
            else:
                raise RuntimeError(
                    f"'{label}' must have either a 'token' or a "
                    f"'{login_field}'+'password' pair."
                )
        # Map the admin config label to the "admin" key the privilege-
        # escalation check looks for.
        if "user_admin" in sessions:
            sessions["admin"] = sessions["user_admin"]
        if used_token:
            console.print(
                "[green]✓[/green] Authenticated users "
                "[dim](token mode — tokens can expire mid-scan; if you see 401s, "
                "refresh them)[/dim]"
            )
        else:
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

        oob = None
        if blind_ssrf:
            from apiforge.executor.oob_listener import OOBListener
            adv = OOBListener.docker_host_gateway() or "127.0.0.1"
            oob = OOBListener(host="0.0.0.0", advertise_host=adv)
            oob.start()
            scanner.executor.oob = oob
            console.print(f"[dim]Blind-SSRF OOB listener on :{oob.port} (advertising {adv})[/dim]")

        result = await scanner.scan(endpoints, sessions, on_progress=on_progress)
        if oob is not None:
            oob.stop()
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
    from apiforge.reporter.report import group_findings
    groups = group_findings(findings)
    table = Table(title=f"\nFindings ({len(groups)})", show_lines=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Check")
    table.add_column("Affected Endpoint(s)")
    for g in groups:
        style = _SEV_COLOR.get(g["severity"].value, "white")
        eps = g["endpoints"]
        ep_disp = eps[0] if len(eps) == 1 else f"{eps[0]}  (+{len(eps) - 1} more)"
        table.add_row(
            f"[{style}]{g['severity'].value}[/{style}]",
            g["title"],
            ep_disp,
        )
    console.print(table)


if __name__ == "__main__":
    app()

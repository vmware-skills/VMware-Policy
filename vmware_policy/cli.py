"""CLI for querying the unified VMware audit log.

Usage::

    vmware-audit log --last 20
    vmware-audit log --skill vmware-nsx --status denied --since 2026-03-28
    vmware-audit export --format json > audit.json
    vmware-audit stats --days 7
"""

from __future__ import annotations

import json
import sys

import typer
from rich.console import Console
from rich.table import Table

from vmware_policy.audit import get_engine

app = typer.Typer(
    name="vmware-audit",
    help="Query the unified VMware audit log (~/.vmware/audit.db).",
    no_args_is_help=True,
)
console = Console()


@app.command()
def log(
    last: int = typer.Option(20, help="Number of recent entries to show"),
    skill: str | None = typer.Option(None, help="Filter by skill name"),
    tool: str | None = typer.Option(None, help="Filter by tool name"),
    status: str | None = typer.Option(None, help="Filter by status (ok/denied/error)"),
    workflow_id: str | None = typer.Option(None, "--workflow-id", help="Filter by workflow ID"),
    since: str | None = typer.Option(None, help="Show entries after date (ISO format)"),
) -> None:
    """Show recent audit log entries."""
    engine = get_engine()
    rows = engine.query(
        skill=skill,
        tool=tool,
        status=status,
        workflow_id=workflow_id,
        since=since,
        limit=last,
    )

    if not rows:
        console.print("[dim]No audit records found.[/dim]")
        return

    table = Table(title=f"Audit Log (last {len(rows)} entries)", show_lines=False)
    table.add_column("Time", style="dim", width=20)
    table.add_column("Skill", style="cyan", width=10)
    table.add_column("Tool", style="green", width=24)
    table.add_column("Status", width=10)
    table.add_column("Agent", style="dim", width=8)
    table.add_column("Duration", justify="right", width=8)

    for row in reversed(rows):  # oldest first
        ts = row["ts"][:19].replace("T", " ")
        st = row["status"]
        style = "red" if "denied" in st or "error" in st else ""
        table.add_row(
            ts,
            row["skill"],
            row["tool"],
            f"[{style}]{st}[/{style}]" if style else st,
            row["agent"],
            f"{row['duration_ms']}ms",
        )

    console.print(table)


@app.command()
def export(
    format: str = typer.Option("json", help="Export format: json"),
    skill: str | None = typer.Option(None, help="Filter by skill"),
    since: str | None = typer.Option(None, help="Export entries after date"),
    limit: int = typer.Option(10000, help="Max entries to export"),
) -> None:
    """Export audit log as JSON to stdout."""
    engine = get_engine()
    rows = engine.query(skill=skill, since=since, limit=limit)
    json.dump(rows, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


@app.command()
def stats(
    days: int = typer.Option(7, help="Number of days to analyze"),
) -> None:
    """Show aggregate audit statistics."""
    engine = get_engine()
    data = engine.stats(days=days)

    console.print(f"\n[bold]Audit Statistics (last {days} days)[/bold]\n")
    console.print(f"  Total operations: [bold]{data['total']}[/bold]")

    if data["by_status"]:
        console.print("\n  By status:")
        for st, count in sorted(data["by_status"].items()):
            style = "red" if "denied" in st or "error" in st else "green"
            console.print(f"    [{style}]{st}[/{style}]: {count}")

    if data["by_skill"]:
        console.print("\n  By skill:")
        for sk, count in sorted(data["by_skill"].items(), key=lambda x: -x[1]):
            console.print(f"    [cyan]{sk}[/cyan]: {count}")

    console.print()


@app.command("undo-list")
def undo_list(
    status: str | None = typer.Option(None, help="Filter by status (recorded/applied/expired)"),
    last: int = typer.Option(20, help="Number of recent undo records to show"),
) -> None:
    """List recorded undo tokens (inverse operations for prior writes)."""
    from vmware_policy.undo import get_undo_store

    rows = get_undo_store().list(status=status, limit=last)
    if not rows:
        console.print("[dim]No undo records found.[/dim]")
        return
    table = Table(title=f"Undo Log (last {len(rows)})", show_lines=False)
    table.add_column("Undo ID", style="cyan", width=16)
    table.add_column("Time", style="dim", width=20)
    table.add_column("Original", style="green", width=22)
    table.add_column("Inverse", style="yellow", width=22)
    table.add_column("Status", width=10)
    for row in rows:
        table.add_row(
            row["undo_id"],
            row["ts"][:19].replace("T", " "),
            f"{row['skill']}.{row['tool']}",
            f"{row['undo_skill']}.{row['undo_tool']}",
            row["status"],
        )
    console.print(table)


@app.command("undo-show")
def undo_show(undo_id: str) -> None:
    """Show the exact inverse operation recorded for an undo token.

    Prints the inverse tool + params an operator (or vmware-pilot) can replay to
    roll the change back. This command does NOT execute anything.
    """
    from vmware_policy.undo import get_undo_store

    rec = get_undo_store().get(undo_id)
    if not rec:
        console.print(f"[red]No undo record with id '{undo_id}'.[/red]")
        raise typer.Exit(1)
    console.print(f"\n[bold]Undo {undo_id}[/bold] (status: {rec['status']})")
    console.print(f"  Original : [green]{rec['skill']}.{rec['tool']}[/green]")
    console.print(f"  Inverse  : [yellow]{rec['undo_skill']}.{rec['undo_tool']}[/yellow]")
    console.print(f"  Params   : {rec['undo_params']}")
    if rec["note"]:
        console.print(f"  Note     : {rec['note']}")
    console.print(
        "\n[dim]Replay is not automatic — run the inverse via the owning skill "
        "or a vmware-pilot rollback workflow.[/dim]\n"
    )




@app.command()
def policy(
    operation: str = typer.Option(
        "", "--operation", "-o", help="Tool name to explain, e.g. vm_delete."
    ),
    env: str = typer.Option("", "--env", "-e", help="Target environment, e.g. production."),
    risk: str = typer.Option("medium", "--risk", "-r", help="Risk level the tool declares."),
) -> None:
    """Show which policy rules are in force, and what they do to an operation.

    The failure this exists to prevent: rules that look configured but never
    load. Run it with no arguments to see where your rules came from, or with
    --operation to see the approval tier a specific call would get.
    """
    from vmware_policy.policy import DEFAULT_RULES_PATH, get_policy_engine

    engine = get_policy_engine()
    source = engine.active_rules_source()

    explain = {
        "user": f"your rules file ({engine._path})",
        "packaged-default": f"the shipped baseline ({DEFAULT_RULES_PATH}) — you have no {engine._path}",
        "user-invalid": f"NOTHING — {engine._path} exists but failed to parse, so no rules are enforced",
        "none": "NOTHING — no rules could be loaded",
    }
    colour = {"user": "green", "packaged-default": "cyan", "user-invalid": "red", "none": "red"}

    console.print(f"[bold]Rules in force:[/bold] [{colour[source]}]{explain[source]}[/]")

    tiers = engine._rules.get("risk_tiers") or []
    deny = engine._rules.get("deny") or []
    window = engine._rules.get("maintenance_window")
    console.print(
        f"  {len(tiers)} approval tier rule(s), {len(deny)} deny rule(s), "
        f"maintenance window: {'set' if window else 'none'}"
    )

    # Branch on the same three-valued parse the engine uses. A truthiness test
    # here reported ENFORCED for the string 'false' — which the engine reads as
    # off — so this command contradicted itself on screen, in the one release
    # that tells operators to go and set this key.
    if "require_declared_environment" in engine._rules:
        from vmware_policy.policy import _parse_requirement

        requirement = _parse_requirement(engine._rules.get("require_declared_environment"))
        if requirement == "warn":
            console.print(
                "  [yellow]Declared-environment requirement: WARN ONLY[/] — writes "
                "against a target with no 'environment:' still run, but a future "
                "release will refuse them. Declare them now and that upgrade is a "
                "no-op."
            )
        elif requirement == "enforce":
            console.print(
                "  [bold]Declared-environment requirement: ENFORCED[/] — writes "
                "against a target with no 'environment:' are refused."
            )
        else:
            console.print(
                "  Declared-environment requirement: [dim]OFF[/] — the key is set "
                "but disabled, so undeclared targets are not gated. Set it to "
                "'warn' or true to turn it on."
            )

    if source == "user-invalid":
        console.print(
            "\n[red]Every operation is currently unrestricted.[/] "
            "Fix the YAML syntax, then re-run this command."
        )
        raise typer.Exit(code=1)

    if not operation:
        console.print("\nPass --operation to see what happens to a specific call.")
        return

    allowed = engine.check_allowed(operation, env=env, risk_level=risk)
    decision = engine.required_approval_tier(operation, env=env, risk_level=risk)

    console.print(f"\n[bold]{operation}[/bold] (env={env or 'unset'}, risk={risk})")
    if not allowed.allowed:
        console.print(f"  [red]DENIED[/] by rule '{allowed.rule}': {allowed.reason}")
        return

    console.print(f"  allowed, approval tier [bold]{decision.tier}[/] (rule: {decision.rule})")
    if decision.requires_approver:
        console.print(
            "  [yellow]Requires a named approver[/] — set VMWARE_AUDIT_APPROVED_BY "
            "(and VMWARE_AUDIT_RATIONALE) or the call is denied."
        )
    if decision.reason:
        console.print(f"  {decision.reason.strip()}")


if __name__ == "__main__":
    app()

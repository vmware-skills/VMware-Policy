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
from rich.markup import escape
from rich.table import Table

from vmware_policy import cli_local
from vmware_policy.audit import get_engine
from vmware_policy.renames import old_names_any_skill, other_names


def _harden_console_encoding() -> None:
    """Never let one unrepresentable glyph kill a command.

    On a console whose encoding cannot carry the characters we print -- cp936 on
    the Chinese Windows boxes this family is tested on, or any ASCII locale --
    ``print`` raises ``UnicodeEncodeError`` and the whole command dies with a
    traceback. ``--help`` died that way in four repos. A mangled dash is a
    cosmetic loss; a dead ``--help`` is an outage, so the error handler is
    relaxed rather than the vocabulary narrowed.

    Best effort: ``reconfigure`` is absent when stdout has been replaced by a
    plain object (pytest capture, some MCP hosts), and losing the hardening
    there is not worth an exception at import.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass


_harden_console_encoding()

app = typer.Typer(
    name="vmware-audit",
    help="Query the unified VMware audit log (~/.vmware/audit.db).",
    no_args_is_help=True,
)
console = Console()


@app.command()
@cli_local("reads the local audit database")
def log(
    last: int = typer.Option(20, help="Number of recent entries to show"),
    skill: str | None = typer.Option(None, help="Filter by skill name"),
    tool: str | None = typer.Option(None, help="Filter by tool name"),
    status: str | None = typer.Option(
        None, help="Filter by status (ok/dry_run/denied/rejected/error/interrupted)"
    ),
    workflow_id: str | None = typer.Option(None, "--workflow-id", help="Filter by workflow ID"),
    since: str | None = typer.Option(None, help="Show entries after date (ISO format)"),
    surface: str | None = typer.Option(
        None, help="Filter by entry point (mcp-stdio/mcp-https/mcp-http-loopback/cli/daemon)"
    ),
    correlation_id: str | None = typer.Option(
        None,
        "--correlation-id",
        help="Filter by the calling platform's trace id (traceparent / X-Request-ID)",
    ),
) -> None:
    """Show recent audit log entries."""
    engine = get_engine()
    rows = engine.query(
        skill=skill,
        tool=tool,
        surface=surface,
        status=status,
        workflow_id=workflow_id,
        since=since,
        limit=last,
        correlation_id=correlation_id,
    )

    if not rows:
        console.print("[dim]No audit records found.[/dim]")
        return

    table = Table(title=f"Audit Log (last {len(rows)} entries)", show_lines=False, pad_edge=False)
    # Fixed widths for the short columns; Tool is the one that gives way on a
    # narrow terminal (HLD §16 D-14 added "Via" to what was an 80-column table).
    table.add_column("Time (UTC)", style="dim", width=14, no_wrap=True)
    table.add_column("Skill", style="cyan", width=8, no_wrap=True, overflow="ellipsis")
    table.add_column("Tool", style="green", ratio=1, overflow="fold")
    table.add_column("Status", width=11, no_wrap=True)
    table.add_column("Via", style="dim", width=6, no_wrap=True, overflow="ellipsis")
    table.add_column("Agent", style="dim", width=6, no_wrap=True, overflow="ellipsis")
    table.add_column("Took", justify="right", width=6, no_wrap=True, overflow="ellipsis")

    for row in reversed(rows):  # oldest first
        ts = row["ts"][5:19].replace("T", " ")  # MM-DD HH:MM:SS
        st = row["status"]
        if "denied" in st or "error" in st:
            style = "red"
        elif st.startswith("interrupted"):
            style = "yellow"
        else:
            style = "dim" if st.startswith("dry_run") else ""
        table.add_row(
            ts,
            row["skill"],
            row["tool"],
            f"[{style}]{st}[/{style}]" if style else st,
            (row.get("surface") or "-").removeprefix("mcp-"),
            row["agent"],
            f"{row['duration_ms']}ms",
        )

    console.print(table)


@app.command()
@cli_local("exports rows from the local audit database")
def export(
    format: str = typer.Option("json", help="Export format: json"),
    skill: str | None = typer.Option(None, help="Filter by skill"),
    since: str | None = typer.Option(None, help="Export entries after date"),
    limit: int = typer.Option(10000, help="Max entries to export"),
    correlation_id: str | None = typer.Option(
        None,
        "--correlation-id",
        help="Only entries with this caller trace id (traceparent / X-Request-ID)",
    ),
) -> None:
    """Export audit log as JSON to stdout."""
    engine = get_engine()
    rows = engine.query(skill=skill, since=since, limit=limit, correlation_id=correlation_id)
    json.dump(rows, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


@app.command()
@cli_local("summarises the local audit database")
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
            if "denied" in st or "error" in st:
                style = "red"
            elif st.startswith("interrupted"):
                # As in `log`: a cancelled call may still be running remotely,
                # so it is neither a success nor a plain failure.
                style = "yellow"
            else:
                style = "green"
            console.print(f"    [{style}]{st}[/{style}]: {count}")

    if data["by_skill"]:
        console.print("\n  By skill:")
        for sk, count in sorted(data["by_skill"].items(), key=lambda x: -x[1]):
            console.print(f"    [cyan]{sk}[/cyan]: {count}")

    console.print()


@app.command("undo-list")
@cli_local("lists undo tokens in the local store")
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
@cli_local("shows one undo token from the local store")
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
@cli_local("prints the local policy rules")
def policy(
    operation: str = typer.Option(
        "", "--operation", "-o", help="Tool name to explain, e.g. vm_delete."
    ),
    env: str = typer.Option("", "--env", "-e", help="Target environment, e.g. production."),
    risk: str = typer.Option("medium", "--risk", "-r", help="Risk level the tool declares."),
    skill: str = typer.Option(
        "", "--skill", "-s",
        help="Skill the tool belongs to (aiops, monitor, …): old 2.0-renamed names count for it.",
    ),
) -> None:
    """Show which policy rules are in force, and what they do to an operation.

    The failure this exists to prevent: rules that look configured but never
    load. Run it with no arguments to see where your rules came from, or with
    --operation to see whether a specific call is allowed.
    """
    from vmware_policy.policy import DEFAULT_RULES_PATH, get_policy_engine

    engine = get_policy_engine()
    source = engine.active_rules_source()

    explain = {
        "user": f"your rules file ({engine._path})",
        "packaged-default": f"the shipped baseline ({DEFAULT_RULES_PATH}) — you have no {engine._path}",
        "user-unreadable": f"NOTHING — {engine._path} exists but would not load",
        "baseline-unreadable": f"NOTHING — the shipped baseline ({DEFAULT_RULES_PATH}) would not load",
    }
    colour = {"user": "green", "packaged-default": "cyan"}

    # Unknown sources read as broken, not as fine. `.get` with a red default is
    # the fail-closed direction for the report too: a state this command has not
    # been taught about must not be printed in green.
    console.print(
        f"[bold]Rules in force:[/bold] "
        f"[{colour.get(source, 'red')}]{explain.get(source, f'UNKNOWN state {source!r}')}[/]"
    )

    deny = engine._rules.get("deny") or []
    window = engine._rules.get("maintenance_window")
    console.print(
        f"  {len(deny)} deny rule(s), maintenance window: {'set' if window else 'none'}"
    )

    if engine._load_error is not None:
        console.print(
            f"\n[red]Every operation is currently DENIED.[/] {engine._load_error}"
        )
        raise typer.Exit(code=1)

    widened = engine.rename_widenings()
    if widened:
        console.print(
            f"\n[yellow]{len(widened)} match(es) widened by the 2.0 tool renames[/] — these "
            "rules now also deny tools they did not match before (old name in brackets):"
        )
        for w in widened[:20]:
            console.print(
                f"  rule {escape(w['rule'])!r} ({escape(w['pattern'])}): "
                f"vmware-{w['skill'].replace('_', '-')} {w['tool']} {escape('[' + w['old'] + ']')}"
            )
        if len(widened) > 20:
            console.print(f"  … and {len(widened) - 20} more")

    if not operation:
        console.print("\nPass --operation to see what happens to a specific call.")
        return

    # Same matching as guard(): a pre-2.0 name in a rule still applies (HLD §16
    # D-15). Without --skill, every skill's old names for this tool count.
    aliases = other_names(skill, operation) if skill else old_names_any_skill(operation)
    allowed = engine.check_allowed(operation, env=env, risk_level=risk, aliases=aliases)

    console.print(f"\n[bold]{operation}[/bold] (env={env or 'unset'}, risk={risk})")
    if not allowed.allowed:
        console.print(f"  [red]DENIED[/] by rule '{allowed.rule}': {allowed.reason}")
        return

    console.print(f"  [green]allowed[/] (rule: {allowed.rule})")

token_app = typer.Typer(
    help="Bearer tokens for MCP servers on --transport https/http (one per caller).",
    no_args_is_help=True,
)
app.add_typer(token_app, name="token")


def _token_path(opt: str | None):
    from pathlib import Path

    from vmware_policy.tokens import token_file

    return Path(opt).expanduser() if opt else token_file()


def _audit_privilege(tool: str, params: dict, status: str = "ok", error: str = "") -> None:
    """Privilege changes are audit rows too (HLD §18 D-25), surface ``cli``."""
    from vmware_policy.guard import audit_call

    audit_call(
        "policy", tool, params=params, status=status,
        result={"error": error} if error else {"ok": True}, surface="cli",
    )


def _known_role(role: str) -> None:
    """A token may only get a role that exists: built in, or defined in roles.yaml."""
    from vmware_policy.roles import BUILTIN, RoleFile

    if role in BUILTIN:
        return
    found, why = RoleFile().get(role)
    if found is None:
        typer.echo(f"Error: {why}. Built-in roles: {', '.join(BUILTIN)}.", err=True)
        raise typer.Exit(2)


@token_app.command("create")
@cli_local("writes a token hash to the local token file")
def token_create(
    name: str,
    role: str = typer.Option(
        None,
        "--role",
        help="reader, admin or a role in roles.yaml (HLD §18). Required once roles are enabled.",
    ),
    token_file_opt: str = typer.Option(None, "--token-file", help="Default $OPS_HOME/mcp-tokens."),
) -> None:
    """Create a token NAME; the secret is printed once and never stored."""
    from vmware_policy.tokens import TokenError, create_token, v2_file

    path = _token_path(token_file_opt)
    if role is not None:
        _known_role(role)
    try:
        secret = create_token(name, path, role=role)
    except TokenError as exc:
        _audit_privilege("token_create", {"name": name, "role": role}, "error", str(exc))
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc
    _audit_privilege("token_create", {"name": name, "role": role or "admin (no roles)"})
    typer.echo(secret)
    where = v2_file(path) if role is not None else path
    role_note = f" with role '{role}'" if role is not None else ""
    typer.echo(
        f"Token '{name}'{role_note} created in {where}. Copy it now: it is not stored "
        "and cannot be "
        f"shown again. Clients send it as 'Authorization: Bearer <token>'; audit rows record "
        f"'token:{name}'.",
        err=True,
    )


@token_app.command("list")
@cli_local("reads token names from the local token file")
def token_list(
    long: bool = typer.Option(
        False, "--long", "-l", help="Also show each token's role, file and state."
    ),
    token_file_opt: str = typer.Option(None, "--token-file", help="Default $OPS_HOME/mcp-tokens."),
) -> None:
    """List token names (secrets are not stored); --long adds role and file."""
    from vmware_policy.tokens import TokenError, list_token_info

    try:
        infos = list_token_info(_token_path(token_file_opt))
    except TokenError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc
    for t in infos:
        if not long:
            typer.echo(t.name)
            continue
        state = "" if t.usable else "  REFUSED"
        note = f"  ({t.note})" if t.note else ""
        typer.echo(f"{t.name}\t{t.role}\t{t.file}{state}{note}")
    if not infos:
        typer.echo("No tokens. Create one with 'vmware-audit token create NAME'.", err=True)


@token_app.command("revoke")
@cli_local("removes a token hash from the local token file")
def token_revoke(
    name: str,
    token_file_opt: str = typer.Option(None, "--token-file", help="Default $OPS_HOME/mcp-tokens."),
) -> None:
    """Revoke token NAME; running servers refuse it from their next request."""
    from vmware_policy.tokens import TokenError, revoke_token

    try:
        revoke_token(name, _token_path(token_file_opt))
    except TokenError as exc:
        _audit_privilege("token_revoke", {"name": name}, "error", str(exc))
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc
    _audit_privilege("token_revoke", {"name": name})
    typer.echo(f"Token '{name}' revoked.", err=True)


@token_app.command("set-role")
@cli_local("changes a token's role in the local token file")
def token_set_role(
    name: str,
    role: str,
    token_file_opt: str = typer.Option(None, "--token-file", help="Default $OPS_HOME/mcp-tokens."),
) -> None:
    """Give role token NAME the role ROLE; applies from its next request."""
    from vmware_policy.tokens import TokenError, set_role

    _known_role(role)
    try:
        old = set_role(name, role, _token_path(token_file_opt))
    except TokenError as exc:
        _audit_privilege("token_set_role", {"name": name, "role": role}, "error", str(exc))
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc
    _audit_privilege("token_set_role", {"name": name, "old_role": old, "role": role})
    typer.echo(f"Token '{name}': role {old} -> {role}.", err=True)


roles_app = typer.Typer(
    help="Roles for network callers (HLD §18): which tools and targets each token may use.",
    no_args_is_help=True,
)
app.add_typer(roles_app, name="roles")


@roles_app.command("enable")
@cli_local("moves legacy tokens into the role-token file")
def roles_enable(
    assign: list[str] = typer.Option(
        [], "--assign", help="NAME=ROLE for a legacy token (repeatable). Others become admin."
    ),
    token_file_opt: str = typer.Option(None, "--token-file", help="Default $OPS_HOME/mcp-tokens."),
) -> None:
    """Turn roles on: every legacy token moves to the role file (admin unless --assign).

    Older vmware-policy servers on this host then refuse every request, because the
    legacy file is left with no tokens — upgrade them or run them with new tokens.
    """
    from vmware_policy.tokens import TokenError, enable_roles, v2_file

    pairs: dict[str, str] = {}
    for item in assign:
        name, sep, role = item.partition("=")
        if not sep or not name or not role:
            typer.echo(f"Error: --assign takes NAME=ROLE, got {item!r}.", err=True)
            raise typer.Exit(2)
        _known_role(role)
        pairs[name] = role
    path = _token_path(token_file_opt)
    try:
        moved = enable_roles(path, pairs)
    except TokenError as exc:
        _audit_privilege("roles_enable", {"assign": pairs}, "error", str(exc))
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc
    _audit_privilege("roles_enable", {"moved": moved})
    for name, role in sorted(moved.items()):
        typer.echo(f"{name}\t{role}")
    typer.echo(
        f"Roles enabled: {len(moved)} token(s) moved to {v2_file(path)}. Servers running an older "
        "vmware-policy on this host now refuse every request until they are upgraded.",
        err=True,
    )


@roles_app.command("list")
@cli_local("reads roles.yaml")
def roles_list() -> None:
    """Defined roles, plus any that cannot be used and why."""
    from vmware_policy.roles import BUILTIN, RoleFile

    store = RoleFile()
    for name in BUILTIN:
        typer.echo(f"{name}\tbuilt in")
    for name in store.names():
        typer.echo(f"{name}\t{store.path}")
    for name, why in sorted(store.problems().items()):
        typer.echo(f"{name}\tUNUSABLE: {why}")


@roles_app.command("check")
@cli_local("reads roles.yaml and the token files")
def roles_check(
    token_file_opt: str = typer.Option(None, "--token-file", help="Default $OPS_HOME/mcp-tokens."),
) -> None:
    """Exit 1 when a role is unusable or a token is refused; prints why."""
    from vmware_policy.roles import RoleFile
    from vmware_policy.tokens import TokenError, list_token_info

    bad = 0
    store = RoleFile()
    for name, why in sorted(store.problems().items()):
        typer.echo(f"role {name}: {why}")
        bad += 1
    try:
        infos = list_token_info(_token_path(token_file_opt))
    except TokenError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc
    for t in infos:
        if not t.usable:
            typer.echo(f"token {t.name}: refused ({t.note or 'duplicate name'})")
            bad += 1
            continue
        role, why = store.get(t.role)
        if role is None:
            typer.echo(f"token {t.name}: role {t.role!r} unusable: {why}")
            bad += 1
    if bad:
        raise typer.Exit(1)
    typer.echo("All roles and tokens are usable.", err=True)


if __name__ == "__main__":
    app()


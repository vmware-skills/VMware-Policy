"""Start a skill's MCP server on stdio (default) or an authenticated network transport.

HLD §16.

``https``: TLS with the operator's certificate, any bind address, Host/Origin
limited to ``--public-name``. ``http``: loopback only, for a TLS-terminating
reverse proxy that passes ``Authorization`` through. Both require at least one
bearer token (``vmware-audit token create NAME``) before anything binds — there
is no unauthenticated listener (I-11).

Every caller of an endpoint acts with that server's account; tokens identify
callers for the audit log, they authorize nothing at the platform (D-12). One
endpoint is one trust group.
"""

from __future__ import annotations

import ipaddress
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vmware_policy.surface import set_process_surface
from vmware_policy.tokens import FileTokenVerifier, TokenError, TokenStore, token_file

TRANSPORTS = ("stdio", "https", "http")
_LOOPBACK = ("127.0.0.1", "::1", "localhost")
_SURFACE = {"stdio": "mcp-stdio", "https": "mcp-https", "http": "mcp-http-loopback"}


class ServeError(ValueError):
    """The server must not start; the message says what to change."""


@dataclass(frozen=True)
class ServeOptions:
    skill: str
    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8443
    certfile: Path | None = None
    keyfile: Path | None = None
    public_names: tuple[str, ...] = ()
    token_path: Path | None = None
    idle_timeout: float = 1800.0
    pooled: bool = False


_HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")


def _is_host_name(name: str) -> bool:
    """A DNS name or an IP literal (no scheme, port, zone id or spaces)."""
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return bool(_HOST.match(name)) and ".." not in name
    return "%" not in name


def _allowed(
    names: tuple[str, ...], port: int, schemes: tuple[str, ...]
) -> tuple[list[str], list[str]]:
    hosts: list[str] = []
    origins: list[str] = []
    for name in names:
        shown = f"[{name}]" if ":" in name else name
        hosts += [shown, f"{shown}:{port}"]
        for scheme in schemes:
            origins += [f"{scheme}://{shown}", f"{scheme}://{shown}:{port}"]
    return hosts, origins


def _check(opts: ServeOptions) -> TokenStore | None:
    if opts.transport not in TRANSPORTS:
        raise ServeError(
            f"Unknown transport {opts.transport!r}. Use one of: {', '.join(TRANSPORTS)}."
        )
    if opts.transport == "stdio":
        return None
    if not 0 < opts.port < 65536:
        raise ServeError(f"--port must be 1-65535 (got {opts.port}).")
    store = TokenStore(opts.token_path or token_file())
    try:
        count = store.count()
    except TokenError as exc:
        raise ServeError(str(exc)) from exc
    if count == 0:
        raise ServeError(
            f"No access tokens in {store.path}, so every request would be refused. Create one per "
            "caller first: 'vmware-audit token create NAME' (the token is shown once)."
        )
    if opts.transport == "http" and opts.host not in _LOOPBACK:
        raise ServeError(
            "--transport http binds loopback only (127.0.0.1, ::1, localhost), "
            f"not {opts.host!r}: it is for a TLS-terminating reverse proxy on this "
            "machine. Use --transport https to listen on the network."
        )
    if opts.transport == "https":
        for flag, path in (("--cert", opts.certfile), ("--key", opts.keyfile)):
            if path is None or not Path(path).is_file():
                raise ServeError(
                    f"--transport https needs {flag} pointing at a PEM file (got {path!s}). "
                    "Use the certificate your clients trust for the names given with "
                    "--public-name."
                )
        bad = [n for n in opts.public_names if not _is_host_name(n)]
        if bad:
            raise ServeError(
                f"--public-name takes host names or IP addresses only, without scheme, port or "
                f"spaces (got {', '.join(repr(b) for b in bad)}); the port comes from --port."
            )
        if not opts.public_names:
            raise ServeError(
                "--transport https needs --public-name with each host name clients use to reach "
                "this server (repeat it or comma-separate). Requests for any other Host or Origin "
                "are refused, which is the DNS-rebinding protection."
            )
    return store


def configure(server: Any, opts: ServeOptions) -> str:
    """Validate ``opts`` and prepare ``server`` for its transport. Returns the audit surface.

    Raises ServeError before anything binds. stdio leaves the server untouched.
    """
    store = _check(opts)
    surface = _SURFACE[opts.transport]
    if store is None:
        set_process_surface(surface)
        return surface

    from mcp.server.auth.settings import AuthSettings
    from mcp.server.transport_security import TransportSecuritySettings

    # The SDK takes its verifier only in the constructor, so it is set on a
    # private attribute below. Refuse rather than fail open if that attribute is
    # gone (a newer SDK), or if the HTTP app was already built without it.
    if not hasattr(server, "_token_verifier"):
        raise ServeError(
            "This MCP SDK version has no '_token_verifier' attribute, so authentication cannot "
            "be attached; refusing to serve without it. Install mcp>=1.28,<2.0."
        )
    if getattr(server, "_session_manager", None) is not None:
        raise ServeError(
            "The server's HTTP app was built before configure(); it would serve without "
            "authentication. Call vmware_policy.serve.run_server (or configure) first."
        )

    from vmware_policy.callgate import offload_sync_tools

    names = opts.public_names or ("127.0.0.1", "localhost", "::1")
    schemes = ("https",) if opts.transport == "https" else ("http", "https")
    hosts, origins = _allowed(names, opts.port, schemes)
    first = f"[{names[0]}]" if ":" in names[0] else names[0]

    settings = server.settings
    settings.host = opts.host
    settings.port = opts.port
    settings.auth = AuthSettings(issuer_url=f"https://{first}", resource_server_url=None)
    settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True, allowed_hosts=hosts, allowed_origins=origins
    )
    # The SDK takes the verifier only in its constructor; our servers are built
    # at import time, so it is set here, before streamable_http_app() reads it.
    server._token_verifier = FileTokenVerifier(store)
    offload_sync_tools(server, pooled=opts.pooled)
    set_process_surface(surface)
    return surface


def assert_auth_enforced(app: Any, path: str, opts: ServeOptions) -> None:
    """Before binding: an unauthenticated POST/GET/DELETE to the MCP path must get 401.

    Checks the behaviour, not the wiring, so an SDK change that leaves the route
    unwrapped stops the server instead of exposing it.
    """
    import anyio
    import httpx

    name = opts.public_names[0] if opts.public_names else "127.0.0.1"
    host = f"[{name}]:{opts.port}" if ":" in name else f"{name}:{opts.port}"
    headers = {"Host": host, "Accept": "application/json, text/event-stream"}

    async def probe() -> list[tuple[str, str]]:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url=f"http://{host}") as client:
            got = []
            for method in ("POST", "GET", "DELETE"):
                body = {} if method == "POST" else None
                try:
                    resp = await client.request(method, path, headers=headers, json=body)
                    got.append((method, str(resp.status_code)))
                except Exception as exc:  # reached the app unauthenticated
                    got.append((method, type(exc).__name__))
            return got

    statuses = anyio.run(probe)
    wrong = [f"{m} {code}" for m, code in statuses if code != "401"]
    if wrong:
        raise ServeError(
            f"Self-check failed: unauthenticated requests to {path} were not refused "
            f"({', '.join(wrong)}). Refusing to serve; this SDK version may attach "
            "authentication differently. Install mcp>=1.28,<2.0 and report the version."
        )


def run(server: Any, opts: ServeOptions) -> None:
    """Configure and serve. Blocks until the server stops."""
    surface = configure(server, opts)
    if surface == "mcp-stdio":
        server.run()  # FastMCP's default transport is stdio
        return

    import uvicorn

    app = server.streamable_http_app()
    server.session_manager.session_idle_timeout = opts.idle_timeout
    assert_auth_enforced(app, server.settings.streamable_http_path, opts)
    scheme = "https" if opts.transport == "https" else "http"
    names = ", ".join(opts.public_names) or opts.host
    print(
        f"vmware-{opts.skill.replace('_', '-')} MCP server: {scheme}://{opts.host}:{opts.port}"
        f"{server.settings.streamable_http_path} (names: {names}). Every caller needs a bearer "
        "token and acts with this server's account.",
        file=sys.stderr,
    )
    config: dict[str, Any] = {"host": opts.host, "port": opts.port, "log_level": "warning"}
    if opts.transport == "https":
        config.update(ssl_certfile=str(opts.certfile), ssl_keyfile=str(opts.keyfile))
    uvicorn.run(app, **config)


def run_server(
    server: Any,
    *,
    skill: str,
    expose: str | None = None,
    allow_write: str | None = None,
    transport: str | None = None,
    host: str | None = None,
    port: int | None = None,
    cert: str | None = None,
    key: str | None = None,
    public_name: str | None = None,
    token_file: str | None = None,
    pooled: bool = False,
) -> None:
    """What every skill's ``main()`` calls: apply exposure, check the transport, serve.

    Arguments are the ``<cli> mcp`` flags (None when not given). A setting that
    cannot be honoured stops the process with exit code 2 and the reason on
    stderr, before anything binds. ``pooled`` is the skill's declaration that
    its connections come from ``vmware_policy.pool.SessionPool`` (D-13(2)), so
    calls on one target may run side by side.
    """
    from vmware_policy.exposure import apply_or_exit

    apply_or_exit(server, skill=skill, expose=expose, allow_write=allow_write)
    names = tuple(n.strip() for n in (public_name or "").split(",") if n.strip())
    opts = ServeOptions(
        skill=skill,
        transport=transport or "stdio",
        host=host or "127.0.0.1",
        port=port if port is not None else 8443,
        certfile=Path(cert).expanduser() if cert else None,
        keyfile=Path(key).expanduser() if key else None,
        public_names=names,
        token_path=Path(token_file).expanduser() if token_file else None,
        pooled=pooled,
    )
    try:
        run(server, opts)
    except ServeError as exc:
        print(f"vmware-{skill.replace('_', '-')} MCP server not started: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

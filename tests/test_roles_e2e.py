"""HLD §18 I-17 (Policy part): roles enforced over the authenticated HTTP transport."""

from __future__ import annotations

import os

import pytest

pytest.importorskip("mcp")

from mcp.server.fastmcp import FastMCP  # noqa: E402

from tests.test_serve import _call, _run_app, _session, _sse_json, ops_home  # noqa: E402,F401
from vmware_policy import roles, serve, tokens  # noqa: E402
from vmware_policy.decorators import vmware_tool  # noqa: E402

MOD = "vmware_storage.mcp_server.server"

ROLES = """\
roles:
  ops:
    skills:
      storage:
        tools: read
        allow_write: [set_thing]
        allow_escape: []
        targets: ["vc-prod-*"]
    approve: none
"""


def _tool(fn):
    fn.__module__ = MOD  # the skill is inferred from the module: "storage"
    return vmware_tool(fn)


def _server() -> FastMCP:
    mcp = FastMCP("vmware-storage")

    def get_thing(target: str = "") -> dict:
        """[READ] one target."""
        return {"target": target}

    def set_thing(target: str = "") -> dict:
        """[WRITE] change one target."""
        return {"changed": target}

    def wipe_thing(target: str = "") -> dict:
        """[WRITE] another write."""
        return {"wiped": target}

    def fetch_file(local_path: str = "") -> dict:
        """[READ] escapes: touches a host file."""
        return {"ok": True}

    def get_everything() -> dict:
        """[READ] reads every target."""
        return {"all": True}

    mcp.tool(annotations={"readOnlyHint": True})(_tool(get_thing))
    mcp.tool(annotations={"readOnlyHint": False})(_tool(set_thing))
    mcp.tool(annotations={"readOnlyHint": False})(_tool(wipe_thing))
    mcp.tool(annotations={"readOnlyHint": True})(_tool(fetch_file))
    mcp.tool(annotations={"readOnlyHint": True})(_tool(get_everything))
    return mcp


@pytest.fixture
def enabled(ops_home):  # noqa: F811
    roles._reset_for_tests()
    roles.declare_role_metadata(
        "storage",
        escapes={"fetch_file"},
        target_scope={
            "get_thing": "one",
            "set_thing": "one",
            "wipe_thing": "one",
            "fetch_file": "none",
        },
        resolver=lambda t: t or "vc-prod-1",
    )
    path = ops_home / "roles.yaml"
    path.write_text(ROLES, encoding="utf-8")
    os.chmod(path, 0o600)
    secrets = {
        "reader": tokens.create_token("r1", role="reader"),
        "ops": tokens.create_token("o1", role="ops"),
        "admin": tokens.create_token("a1", role="admin"),
    }
    yield secrets
    roles._reset_for_tests()


def _configured():
    server = _server()
    serve._record_registry(server, "storage")
    serve.configure(server, serve.ServeOptions(skill="storage", transport="http"))
    return server


def _list_and_calls(secret, calls):
    async def go(c):
        _, _, headers = await _session(c, secret)
        r = await c.post(
            "/mcp", json={"jsonrpc": "2.0", "id": 9, "method": "tools/list"}, headers=headers
        )
        names = sorted(t["name"] for t in _sse_json(r.text)["result"]["tools"])
        results = []
        for i, (name, args) in enumerate(calls):
            _, body = await _call(c, headers, name, args, rid=10 + i)
            results.append(body["result"])
        return names, results

    return _run_app(_configured(), go)


def _refused(result) -> bool:
    return bool(result.get("isError"))


def _rows(ops_home):  # noqa: F811
    from vmware_policy.audit import AuditEngine

    return AuditEngine(db_path=ops_home / "audit.db").query(limit=50)


@pytest.mark.unit
def test_reader_sees_and_calls_only_read_tools_without_escapes(enabled, ops_home):  # noqa: F811
    names, results = _list_and_calls(
        enabled["reader"],
        [("get_thing", {"target": "vc-lab"}), ("set_thing", {}), ("fetch_file", {})],
    )
    assert names == ["get_everything", "get_thing"]
    assert not _refused(results[0])
    assert _refused(results[1]) and _refused(results[2])
    denied = [r for r in _rows(ops_home) if r["status"] == "denied"]
    assert {r["tool"] for r in denied} == {"set_thing", "fetch_file"}
    assert all(r["role"] == "reader" and r["user"] == "token:r1" for r in denied)


@pytest.mark.unit
def test_custom_role_allow_write_and_targets(enabled, ops_home):  # noqa: F811
    names, results = _list_and_calls(
        enabled["ops"],
        [
            ("set_thing", {"target": "vc-prod-2"}),
            ("set_thing", {"target": "vc-lab"}),
            ("wipe_thing", {"target": "vc-prod-2"}),
            ("get_everything", {}),
            ("get_thing", {}),  # default target resolves to vc-prod-1
        ],
    )
    assert names == ["get_everything", "get_thing", "set_thing"]
    ok, lab, wipe, everything, default = results
    assert not _refused(ok) and not _refused(default)
    assert _refused(lab) and "outside this role" in lab["content"][0]["text"]
    assert _refused(wipe) and _refused(everything)
    rows = {(r["tool"], r["status"]) for r in _rows(ops_home) if r["role"] == "ops"}
    assert ("set_thing", "ok") in rows and ("set_thing", "denied") in rows


@pytest.mark.unit
def test_admin_sees_and_calls_everything(enabled):
    names, results = _list_and_calls(enabled["admin"], [("wipe_thing", {}), ("fetch_file", {})])
    assert names == ["fetch_file", "get_everything", "get_thing", "set_thing", "wipe_thing"]
    assert not any(_refused(r) for r in results)


@pytest.mark.unit
def test_a_role_change_applies_on_the_next_call_without_reconnect(enabled):
    async def go(c):
        _, _, headers = await _session(c, enabled["reader"])
        _, first = await _call(c, headers, "set_thing", {}, rid=3)
        tokens.set_role("r1", "admin")
        _, second = await _call(c, headers, "set_thing", {}, rid=4)
        return first["result"], second["result"]

    first, second = _run_app(_configured(), go)
    assert _refused(first) and not _refused(second)


@pytest.mark.unit
def test_unknown_role_and_broken_file_refuse_custom_roles_only(enabled, ops_home):  # noqa: F811
    (ops_home / "roles.yaml").write_text("roles: [", encoding="utf-8")
    _, results = _list_and_calls(enabled["ops"], [("get_thing", {})])
    assert _refused(results[0])
    _, results = _list_and_calls(enabled["reader"], [("get_thing", {})])
    assert not _refused(results[0])


@pytest.mark.unit
def test_undeclared_skill_admits_admin_only(enabled):
    roles._reset_for_tests()  # metadata gone: an older skill under this Policy
    _, results = _list_and_calls(enabled["reader"], [("get_thing", {})])
    assert _refused(results[0]) and "role metadata" in results[0]["content"][0]["text"]
    _, results = _list_and_calls(enabled["admin"], [("get_thing", {})])
    assert not _refused(results[0])


@pytest.mark.unit
def test_before_opt_in_nothing_changes(ops_home):  # noqa: F811
    roles._reset_for_tests()  # no metadata at all, legacy token only
    secret = tokens.create_token("legacy")
    names, results = _list_and_calls(secret, [("wipe_thing", {})])
    assert "wipe_thing" in names and not _refused(results[0])


@pytest.mark.unit
def test_no_caller_in_a_network_process_is_refused(enabled):
    """A thread a tool starts has no caller; it must not run as an operator (review H3)."""
    import threading

    server = _configured()
    assert server  # configure() set the network surface
    got = {}

    def run():
        from vmware_policy.policy import PolicyDenied

        fn = _tool(lambda: None)
        fn.__name__ = "get_thing"
        try:
            vmware_tool(fn)()
        except PolicyDenied as exc:
            got["rule"] = exc.result.rule

    t = threading.Thread(target=run)
    t.start()
    t.join()
    assert got.get("rule") == "role:no-caller"


@pytest.mark.unit
def test_a_role_naming_a_tool_this_server_lacks_is_refused(enabled, ops_home):  # noqa: F811
    """Closed set (D-20): a typo in allow_write must not silently grant nothing — refuse."""
    text = ROLES.replace("allow_write: [set_thing]", "allow_write: [set_thing, no_such_tool]")
    (ops_home / "roles.yaml").write_text(text, encoding="utf-8")
    _, results = _list_and_calls(enabled["ops"], [("get_thing", {})])
    assert _refused(results[0]) and "no_such_tool" in results[0]["content"][0]["text"]
    denied = [r for r in _rows(ops_home) if r["status"] == "denied"]
    assert denied and '"role:invalid"' in denied[-1]["result"]


@pytest.mark.unit
def test_a_pre_2_0_name_in_allow_write_is_not_unknown(enabled, ops_home):  # noqa: F811
    roles.register_registry("storage", {"rescan_storage": False, "get_thing": True})
    text = ROLES.replace("allow_write: [set_thing]", "allow_write: [storage_rescan]")
    (ops_home / "roles.yaml").write_text(text, encoding="utf-8")
    from vmware_policy.roles import RoleFile, _unknown_names

    role, _ = RoleFile(ops_home / "roles.yaml").get("ops")
    assert _unknown_names(role, "storage") == []

"""Tools may not read or write this server's own control files (HLD §18 step 0).

Over a network transport a caller names paths on the server host
(``download_vm_guest_file(local_path=…, overwrite=True)``, an OVA to read, a
kubeconfig to write). Without a check, any token holder could overwrite
``$OPS_HOME/mcp-tokens`` or ``rules.yaml``, read a skill's ``.env``, or upload
the TLS private key into a VM. ``check_host_path`` refuses any path that
resolves (symlinks included) into a protected location: ``$OPS_HOME``, every
``~/.vmware-*`` skill directory, the directory of any ``VMWARE_*_CONFIG`` file,
and the files a running server registered (token file, TLS cert and key).
"""

from __future__ import annotations

import os

import pytest

from vmware_policy import hostpaths
from vmware_policy.hostpaths import HostPathRefusedError, check_host_path


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".vmware").mkdir(parents=True)
    (home / ".vmware-aiops").mkdir()
    (home / "work").mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("OPS_HOME", str(home / ".vmware"))
    for k in [k for k in os.environ if k.startswith("VMWARE_") and k.endswith("_CONFIG")]:
        monkeypatch.delenv(k)
    hostpaths.reset_registered()
    yield home
    hostpaths.reset_registered()


@pytest.mark.unit
@pytest.mark.parametrize(
    "rel",
    [
        ".vmware/mcp-tokens",
        ".vmware/rules.yaml",
        ".vmware/audit.db",
        ".vmware",
        ".vmware/new/file.txt",
        ".vmware-aiops/.env",
        ".vmware-aiops/config.yaml",
    ],
)
def test_control_files_are_refused(home, rel):
    with pytest.raises(HostPathRefusedError, match="outside"):
        check_host_path(str(home / rel))


@pytest.mark.unit
def test_tilde_and_dotdot_are_resolved(home):
    with pytest.raises(HostPathRefusedError):
        check_host_path("~/.vmware/mcp-tokens")
    with pytest.raises(HostPathRefusedError):
        check_host_path(str(home / "work" / ".." / ".vmware" / "rules.yaml"))


@pytest.mark.unit
def test_a_symlink_into_a_protected_dir_is_refused(home):
    link = home / "work" / "innocent"
    link.symlink_to(home / ".vmware")
    with pytest.raises(HostPathRefusedError):
        check_host_path(str(link / "mcp-tokens"))
    file_link = home / "work" / "tokens.txt"
    file_link.symlink_to(home / ".vmware" / "mcp-tokens")
    with pytest.raises(HostPathRefusedError):
        check_host_path(str(file_link))


@pytest.mark.unit
def test_ordinary_paths_pass(home):
    for p in (home / "work" / "vm.ova", home / "work" / "new" / "out.yaml", "/tmp/x.iso"):
        assert check_host_path(str(p)) is None
    # a sibling whose name only starts like a protected dir is not inside it
    assert check_host_path(str(home / ".vmware2" / "x")) is None


@pytest.mark.unit
def test_a_config_override_directory_is_protected(home, tmp_path, monkeypatch):
    cfg = tmp_path / "etc" / "monitor"
    cfg.mkdir(parents=True)
    monkeypatch.setenv("VMWARE_MONITOR_CONFIG", str(cfg / "config.yaml"))
    with pytest.raises(HostPathRefusedError):
        check_host_path(str(cfg / ".env"))


@pytest.mark.unit
def test_registered_server_files_are_protected(home, tmp_path):
    key = tmp_path / "pki" / "server-key.pem"
    key.parent.mkdir()
    key.write_text("k", encoding="utf-8")
    hostpaths.register_protected(key)
    with pytest.raises(HostPathRefusedError):
        check_host_path(str(key))
    assert check_host_path(str(tmp_path / "pki" / "other.pem")) is None


@pytest.mark.unit
def test_the_message_teaches_and_ends_with_the_path(home):
    with pytest.raises(HostPathRefusedError) as exc:
        check_host_path(str(home / ".vmware" / "rules.yaml"))
    msg = str(exc.value)
    assert "configuration, tokens and audit log" in msg
    assert msg.rstrip().endswith("rules.yaml")


@pytest.mark.unit
def test_empty_or_non_string_is_not_a_path(home):
    assert check_host_path("") is None
    assert check_host_path(None) is None  # type: ignore[arg-type]


@pytest.mark.unit
def test_vmware_tool_refuses_a_host_path_param_before_the_body_runs(home):
    import vmware_policy.audit as audit_mod
    from vmware_policy.decorators import vmware_tool

    audit_mod._engine = None
    ran = []

    @vmware_tool
    def download_vm_guest_file(vm_name: str, local_path: str, overwrite: bool = False) -> dict:
        ran.append(local_path)
        return {"ok": True}

    with pytest.raises(HostPathRefusedError):
        download_vm_guest_file(
            "vm1", local_path=str(home / ".vmware" / "mcp-tokens"), overwrite=True
        )
    assert ran == []
    row = audit_mod.AuditEngine().query(limit=1)[0]
    assert row["tool"] == "download_vm_guest_file" and row["status"] == "error"
    assert download_vm_guest_file("vm1", local_path=str(home / "work" / "f.txt")) == {"ok": True}
    audit_mod._engine = None


@pytest.mark.unit
def test_vmware_tool_ignores_paths_that_are_not_host_paths(home):
    from vmware_policy.decorators import vmware_tool

    @vmware_tool
    def browse_datastore(path: str) -> dict:  # a datastore path, not the host's
        return {"path": path}

    assert browse_datastore(path=str(home / ".vmware")) == {"path": str(home / ".vmware")}


@pytest.mark.unit
def test_serving_https_protects_the_token_file_and_tls_files(home, tmp_path):
    pytest.importorskip("mcp")
    from mcp.server.fastmcp import FastMCP

    from vmware_policy import serve, tokens

    pki = tmp_path / "pki"
    pki.mkdir()
    cert, key = pki / "server.pem", pki / "server-key.pem"
    cert.write_text("c", encoding="utf-8")
    key.write_text("k", encoding="utf-8")
    token_file = tmp_path / "elsewhere" / "tokens"
    tokens.create_token("alice", token_file)
    opts = serve.ServeOptions(
        skill="storage",
        transport="https",
        host="0.0.0.0",
        certfile=cert,
        keyfile=key,
        public_names=("mcp.example.com",),
        token_path=token_file,
    )
    serve.configure(FastMCP("t"), opts)
    for p in (cert, key, token_file):
        with pytest.raises(HostPathRefusedError):
            check_host_path(str(p))
    assert check_host_path(str(pki / "unrelated.txt")) is None


@pytest.mark.unit
def test_a_path_object_is_checked_too(home):
    from pathlib import Path

    with pytest.raises(HostPathRefusedError):
        check_host_path(Path(home / ".vmware" / "mcp-tokens"))
    assert check_host_path(Path(home / "work" / "x")) is None


# ── review 2026-10-16: case, /dev/fd, network allow-list ─────────────────────


@pytest.mark.unit
@pytest.mark.parametrize("rel", [".VMWARE/MCP-TOKENS", ".Vmware/rules.yaml", ".VMWARE-AIOPS/.env"])
def test_letter_case_does_not_bypass_the_check(home, rel):
    (home / ".vmware" / "mcp-tokens").write_text("x", encoding="utf-8")
    with pytest.raises(HostPathRefusedError):
        check_host_path(str(home / rel))


@pytest.mark.unit
@pytest.mark.parametrize("p", ["/dev/fd/3", "/dev/stdin", "/proc/self/fd/3", "/proc/1/environ"])
def test_device_and_proc_paths_are_refused(home, p):
    with pytest.raises(HostPathRefusedError):
        check_host_path(p)


@pytest.fixture
def network_caller(monkeypatch):
    import vmware_policy.caller as caller_mod

    monkeypatch.setattr(caller_mod, "current_caller", lambda: "token:alice")
    monkeypatch.delenv("VMWARE_MCP_FILE_ROOT", raising=False)


@pytest.mark.unit
def test_over_the_network_host_files_are_off_by_default(home, network_caller):
    with pytest.raises(HostPathRefusedError, match="VMWARE_MCP_FILE_ROOT"):
        check_host_path(str(home / "work" / "vm.ova"))
    with pytest.raises(HostPathRefusedError):
        check_host_path(str(home / ".ssh" / "authorized_keys"))


@pytest.mark.unit
def test_over_the_network_only_the_file_root_is_allowed(home, network_caller, monkeypatch):
    root = home / "work" / "mcp-files"
    root.mkdir()
    monkeypatch.setenv("VMWARE_MCP_FILE_ROOT", str(root))
    assert check_host_path(str(root / "vm.ova")) is None
    assert check_host_path(str(root / "sub" / "out.yaml")) is None
    for bad in (home / "work" / "vm.ova", home / ".ssh" / "authorized_keys", root / ".." / "x"):
        with pytest.raises(HostPathRefusedError, match="VMWARE_MCP_FILE_ROOT"):
            check_host_path(str(bad))
    # a symlink inside the root that leads out is followed, then refused
    (root / "out").symlink_to(home / ".ssh", target_is_directory=False)
    with pytest.raises(HostPathRefusedError):
        check_host_path(str(root / "out" / "authorized_keys"))


@pytest.mark.unit
def test_a_file_root_inside_a_protected_dir_still_refuses_control_files(
    home, network_caller, monkeypatch
):
    monkeypatch.setenv("VMWARE_MCP_FILE_ROOT", str(home / ".vmware"))
    with pytest.raises(HostPathRefusedError):
        check_host_path(str(home / ".vmware" / "mcp-tokens"))


@pytest.mark.unit
def test_stdio_and_cli_keep_the_deny_list_only(home, monkeypatch):
    monkeypatch.delenv("VMWARE_MCP_FILE_ROOT", raising=False)
    assert check_host_path(str(home / "work" / "vm.ova")) is None


@pytest.mark.unit
def test_case_is_ignored_even_before_the_protected_dir_exists(tmp_path, monkeypatch):
    # OPS_HOME not created yet: only the name comparison can protect it, and a
    # write to ~/.VMWARE/rules.yaml would create the directory and its rules.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("OPS_HOME", str(tmp_path / ".vmware"))
    hostpaths.reset_registered()
    with pytest.raises(HostPathRefusedError):
        check_host_path(str(tmp_path / ".VMWARE" / "rules.yaml"))

"""Tool exposure (HLD §17 D-16): which tools a server offers, chosen at startup.

Storage#18 removed our write tools by editing the SDK's private registry, which
breaks on the next SDK major. Exposure gives that a public, closed-set form:
``expose="read"`` keeps only tools annotated ``readOnlyHint: true``;
``allow_write`` keeps chosen write tools on top. It shrinks what a client is
offered; it does not authorize anything (RBAC does).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from types import SimpleNamespace

import pytest

from vmware_policy import exposure


@dataclass
class FakeServer:
    """The two public FastMCP methods exposure uses: list_tools and remove_tool."""

    tools: dict[str, object] = field(default_factory=dict)

    async def list_tools(self):
        return [SimpleNamespace(name=n, annotations=a) for n, a in self.tools.items()]

    def remove_tool(self, name: str) -> None:
        del self.tools[name]


def _ann(read_only):
    return None if read_only is None else SimpleNamespace(readOnlyHint=read_only)


def _server() -> FakeServer:
    return FakeServer(
        {
            "list_all_datastores": _ann(True),
            "get_fc_adapters": _ann(True),
            "enable_iscsi": _ann(False),
            "rescan_storage": _ann(False),
            "no_annotation_tool": _ann(None),
            "read_hint_is_none": SimpleNamespace(readOnlyHint=None),
        }
    )


@pytest.mark.unit
def test_all_is_the_default_and_changes_nothing():
    server = _server()
    result = exposure.restrict_tools(server, skill="storage")

    assert result.expose == "all"
    assert result.removed == ()
    assert len(server.tools) == 6


@pytest.mark.unit
def test_read_keeps_only_tools_annotated_read_only_true():
    server = _server()
    result = exposure.restrict_tools(server, skill="storage", expose="read")

    assert set(server.tools) == {"list_all_datastores", "get_fc_adapters"}
    assert set(result.removed) == {
        "enable_iscsi",
        "rescan_storage",
        "no_annotation_tool",
        "read_hint_is_none",
    }


@pytest.mark.unit
def test_allow_write_keeps_chosen_write_tools_on_top_of_read():
    server = _server()
    result = exposure.restrict_tools(
        server, skill="storage", expose="read", allow_write=["rescan_storage"]
    )

    assert set(server.tools) == {"list_all_datastores", "get_fc_adapters", "rescan_storage"}
    assert result.kept_write == ("rescan_storage",)


@pytest.mark.unit
def test_an_unknown_allow_write_name_refuses_before_removing_anything():
    server = _server()
    with pytest.raises(exposure.ExposureError) as excinfo:
        exposure.restrict_tools(
            server, skill="storage", expose="read", allow_write=["rescan_storge"]
        )

    message = str(excinfo.value)
    assert "rescan_storge" in message and "rescan_storage" in message
    assert len(server.tools) == 6


@pytest.mark.unit
def test_allow_write_naming_a_read_tool_is_refused_as_a_mistake():
    server = _server()
    with pytest.raises(exposure.ExposureError, match="read tool"):
        exposure.restrict_tools(
            server, skill="storage", expose="read", allow_write=["get_fc_adapters"]
        )


@pytest.mark.unit
def test_allow_write_without_read_is_refused():
    server = _server()
    with pytest.raises(exposure.ExposureError, match="expose"):
        exposure.restrict_tools(
            server, skill="storage", expose="all", allow_write=["rescan_storage"]
        )


@pytest.mark.unit
@pytest.mark.parametrize("bad", ["readonly", "READ ", "none", ""])
def test_an_unknown_expose_value_is_refused(bad):
    with pytest.raises(exposure.ExposureError, match="all, read"):
        exposure.restrict_tools(_server(), skill="storage", expose=bad)


@pytest.mark.unit
def test_a_pre_2_0_write_name_is_accepted_through_the_rename_map():
    # vmware-aria renamed nothing that writes, so use AIops: vm_power_on -> power_on_vm.
    server = FakeServer(
        {"list_vms": _ann(True), "power_on_vm": _ann(False), "delete_vm": _ann(False)}
    )
    result = exposure.restrict_tools(
        server, skill="aiops", expose="read", allow_write=["vm_power_on"]
    )

    assert set(server.tools) == {"list_vms", "power_on_vm"}
    assert result.kept_write == ("power_on_vm",)


@pytest.mark.unit
def test_settings_come_from_flags_then_env_then_default(monkeypatch):
    monkeypatch.setenv("VMWARE_NSX_SECURITY_MCP_EXPOSE", "read")
    monkeypatch.setenv("VMWARE_NSX_SECURITY_MCP_ALLOW_WRITE", " a , b ,")

    assert exposure.settings("nsx_security") == ("read", ("a", "b"))
    assert exposure.settings("nsx_security", expose="all", allow_write="") == ("all", ())
    monkeypatch.delenv("VMWARE_NSX_SECURITY_MCP_EXPOSE")
    monkeypatch.delenv("VMWARE_NSX_SECURITY_MCP_ALLOW_WRITE")
    assert exposure.settings("nsx_security") == ("all", ())


@pytest.mark.unit
def test_inside_a_running_loop_the_async_form_is_required():
    async def call_sync():
        exposure.restrict_tools(_server(), skill="storage", expose="read")

    with pytest.raises(exposure.ExposureError, match="arestrict_tools"):
        asyncio.run(call_sync())

    server = _server()
    asyncio.run(exposure.arestrict_tools(server, skill="storage", expose="read"))
    assert set(server.tools) == {"list_all_datastores", "get_fc_adapters"}


@pytest.mark.unit
def test_the_startup_line_names_the_exposure_and_kept_write_tools():
    server = _server()
    result = exposure.restrict_tools(
        server, skill="storage", expose="read", allow_write=["rescan_storage"]
    )

    line = result.describe()
    assert "read" in line and "rescan_storage" in line
    assert "not authorization" in line


@pytest.mark.unit
def test_apply_or_exit_stops_the_server_on_a_bad_setting(capsys):
    server = _server()
    with pytest.raises(SystemExit) as excinfo:
        exposure.apply_or_exit(server, skill="storage", expose="read", allow_write="nope")

    assert excinfo.value.code == 2
    assert "not started" in capsys.readouterr().err
    assert len(server.tools) == 6


@pytest.mark.unit
def test_apply_or_exit_reads_the_environment_and_reports(monkeypatch, capsys):
    monkeypatch.setenv("VMWARE_STORAGE_MCP_EXPOSE", "read")
    server = _server()
    exposure.apply_or_exit(server, skill="storage")

    assert set(server.tools) == {"list_all_datastores", "get_fc_adapters"}
    assert "read tools only" in capsys.readouterr().err


@pytest.mark.unit
def test_apply_or_exit_is_silent_when_everything_is_exposed(capsys):
    exposure.apply_or_exit(_server(), skill="storage")
    assert capsys.readouterr().err == ""


@pytest.mark.unit
def test_the_default_never_touches_the_server():
    """A server object with no tool API at all still starts with the default."""
    result = exposure.apply_or_exit(object(), skill="storage")
    assert result.expose == "all"


@pytest.mark.unit
def test_the_default_works_inside_a_running_loop():
    async def call():
        return exposure.restrict_tools(object(), skill="storage")

    assert asyncio.run(call()).expose == "all"


@pytest.mark.unit
def test_any_flag_means_the_environment_is_ignored_for_both_fields(monkeypatch):
    """`--expose read` with a leftover ALLOW_WRITE in the environment must not offer it."""
    monkeypatch.setenv("VMWARE_AIOPS_MCP_ALLOW_WRITE", "delete_vm")
    monkeypatch.setenv("VMWARE_AIOPS_MCP_EXPOSE", "all")

    assert exposure.settings("aiops", expose="read") == ("read", ())
    assert exposure.settings("aiops", allow_write="power_on_vm") == ("all", ("power_on_vm",))


@pytest.mark.unit
def test_an_empty_environment_value_counts_as_unset(monkeypatch):
    monkeypatch.setenv("VMWARE_STORAGE_MCP_EXPOSE", "")
    monkeypatch.setenv("VMWARE_STORAGE_MCP_ALLOW_WRITE", "")

    assert exposure.settings("storage") == ("all", ())


@pytest.mark.unit
@pytest.mark.parametrize("flag", ["", "  ", ","])
def test_an_empty_flag_counts_as_not_given(monkeypatch, flag):
    """A templated `--allow-write ${WRITES}` with WRITES empty must not drop env EXPOSE=read."""
    monkeypatch.setenv("VMWARE_STORAGE_MCP_EXPOSE", "read")

    assert exposure.settings("storage", allow_write=flag) == ("read", ())
    if not flag.strip():
        assert exposure.settings("storage", expose=flag) == ("read", ())


@pytest.mark.unit
def test_a_non_blank_bad_expose_flag_is_refused_not_ignored(monkeypatch):
    monkeypatch.setenv("VMWARE_STORAGE_MCP_EXPOSE", "read")
    with pytest.raises(SystemExit):
        exposure.apply_or_exit(_server(), skill="storage", expose=",")


@pytest.mark.unit
def test_refusing_allow_write_without_read_names_the_flag_when_a_flag_was_given(capsys):
    with pytest.raises(SystemExit):
        exposure.apply_or_exit(_server(), skill="storage", allow_write="enable_iscsi")
    assert "--expose read" in capsys.readouterr().err

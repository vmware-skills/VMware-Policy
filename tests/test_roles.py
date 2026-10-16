"""HLD §18: role definitions, skill metadata and the per-call decision."""

from __future__ import annotations

import os

import pytest

from vmware_policy import roles
from vmware_policy.roles import ADMIN, READER, RoleError, RoleFile, decide, parse_roles, visible

GOOD = """\
roles:
  storage-operator:
    skills:
      storage:
        tools: read
        allow_write: [rescan_storage]
        allow_escape: []
        targets: ["vc-prod-*"]
      vmware-monitor: { tools: read, allow_write: [], allow_escape: [], targets: "*" }
    approve: none
  planner:
    skills:
      aiops:
        tools: read
        allow_write: [apply_vm_plan, power_off_vm]
        allow_escape: []
        targets: "*"
    approve: others
"""


@pytest.fixture(autouse=True)
def _metadata():
    roles._reset_for_tests()
    roles.declare_role_metadata(
        "storage",
        target_scope={"list_all_datastores": "one", "rescan_storage": "one", "get_cache": "none"},
        resolver=lambda t: t or "vc-prod-1",
    )
    roles.register_registry(
        "storage",
        {
            "list_all_datastores": True,
            "rescan_storage": False,
            "enable_iscsi": False,
            "get_cache": True,
            "get_everything": True,
        },
    )
    roles.declare_role_metadata(
        "aiops",
        escapes={"run_vm_guest_command", "download_vm_guest_file"},
        reaches={"apply_vm_plan": {"power_off_vm", "delete_vm", "run_vm_guest_command"}},
        target_scope={"apply_vm_plan": "one", "power_off_vm": "one", "list_vms": "one"},
        resolver=lambda t: t or "vc-a",
    )
    roles.register_registry(
        "aiops",
        {
            "apply_vm_plan": False,
            "power_off_vm": False,
            "delete_vm": False,
            "run_vm_guest_command": False,
            "download_vm_guest_file": False,
            "list_vms": True,
        },
    )
    roles.register_registry("monitor", {"list_vms": True})  # registry, but never declared
    yield
    roles._reset_for_tests()


def _role(name: str) -> roles.Role:
    parsed, problems = parse_roles(GOOD)
    assert not problems
    return parsed[name]


# ── parsing ─────────────────────────────────────────────────────────────


def test_good_file_parses_and_skill_keys_are_canonical():
    role = _role("storage-operator")
    assert set(role.skills) == {"storage", "monitor"}
    assert role.skills["storage"].targets == ("vc-prod-*",)
    assert role.skills["monitor"].targets is None


@pytest.mark.parametrize(
    "drop",
    ["targets", "allow_write", "allow_escape", "tools"],
)
def test_a_missing_key_refuses_the_role_never_widens_it(drop):
    """A file truncated mid-edit loses a line; that must not read as "all" (review H5)."""
    text = GOOD.replace(f"        {drop}:", "        x_removed:", 1)
    parsed, problems = parse_roles(text)
    assert "storage-operator" not in parsed
    assert "storage-operator" in problems
    assert "planner" in parsed  # the other role still works


def test_reserved_and_bad_names_are_refused():
    grant = "{tools: '*', allow_write: [], allow_escape: [], targets: '*'}"
    text = f"roles:\n  admin: {{skills: {{storage: {grant}}}, approve: any}}\n"
    parsed, problems = parse_roles(text)
    assert not parsed and "built in" in problems["admin"]
    parsed, problems = parse_roles(text.replace("admin:", "'a:b':"))
    assert not parsed and "role name" in problems["a:b"]


@pytest.mark.parametrize("text", ["", "roles: []", "other: {}", "roles: {}\nextra: 1", ":::"])
def test_an_unusable_file_raises(text):
    with pytest.raises(RoleError):
        parse_roles(text)


def test_empty_targets_and_bad_modes_are_refused():
    bad = GOOD.replace('targets: ["vc-prod-*"]', "targets: []")
    assert "storage-operator" in parse_roles(bad)[1]
    bad = GOOD.replace("approve: none", "approve: maybe")
    assert "storage-operator" in parse_roles(bad)[1]
    bad = GOOD.replace(
        "tools: read\n        allow_write: [rescan", "tools: all\n        allow_write: [rescan"
    )
    assert "storage-operator" in parse_roles(bad)[1]


# ── the role file on disk ─────────────────────────────────────────────


def _write(path, text, mode=0o600):
    path.write_text(text, encoding="utf-8")
    os.chmod(path, mode)


def test_role_file_reloads_on_change(tmp_path):
    path = tmp_path / "roles.yaml"
    _write(path, GOOD)
    store = RoleFile(path)
    assert store.get("planner")[0] is not None
    _write(path, GOOD.replace("planner:", "planner2:"))
    assert store.get("planner")[0] is None
    assert store.get("planner2")[0] is not None


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits")
def test_a_group_readable_role_file_refuses_custom_roles_only(tmp_path):
    path = tmp_path / "roles.yaml"
    _write(path, GOOD, 0o640)
    store = RoleFile(path)
    role, why = store.get("planner")
    assert role is None and "Permissions too open" in why
    assert store.get("reader")[0] is READER and store.get("admin")[0] is ADMIN


def test_a_broken_file_refuses_custom_roles_and_keeps_builtins(tmp_path):
    path = tmp_path / "roles.yaml"
    _write(path, "roles: [")
    store = RoleFile(path)
    assert store.get("planner")[0] is None
    assert store.get("reader")[0] is READER
    assert "*" in store.problems()


def test_missing_file_names_the_file(tmp_path):
    role, why = RoleFile(tmp_path / "roles.yaml").get("planner")
    assert role is None and "does not exist" in why


# ── decisions ──────────────────────────────────────────────────────────


def test_admin_may_do_anything_even_without_metadata():
    assert decide(ADMIN, "monitor", "list_vms", {}).allowed
    assert decide(ADMIN, "aiops", "delete_vm", {}).allowed


def test_undeclared_skill_refuses_reader_and_custom_roles():
    """A new Policy with an old skill must not fail open (review R2-Hb)."""
    d = decide(READER, "monitor", "list_vms", {})
    assert not d.allowed and d.rule == "role:no-metadata"
    assert not visible(READER, "monitor", "list_vms")


def test_reader_reads_but_never_writes_or_escapes():
    assert decide(READER, "storage", "list_all_datastores", {"target": "anything"}).allowed
    assert not decide(READER, "storage", "rescan_storage", {}).allowed
    escape = decide(READER, "aiops", "download_vm_guest_file", {})
    assert not escape.allowed and "more than read" in escape.reason


def test_unknown_tool_counts_as_write():
    assert not decide(READER, "storage", "not_in_registry", {}).allowed


def test_custom_role_tools_and_allow_write():
    role = _role("storage-operator")
    assert decide(role, "storage", "rescan_storage", {"target": "vc-prod-2"}).allowed
    d = decide(role, "storage", "enable_iscsi", {"target": "vc-prod-2"})
    assert not d.allowed and d.rule == "role:storage-operator" and "allow_write" in d.reason


def test_skill_not_in_role_is_refused():
    d = decide(_role("storage-operator"), "aiops", "list_vms", {})
    assert not d.allowed and "does not include skill" in d.reason


def test_target_scope_one_uses_the_resolved_name():
    role = _role("storage-operator")
    assert decide(
        role, "storage", "list_all_datastores", {"target": None}
    ).allowed  # default vc-prod-1
    d = decide(role, "storage", "list_all_datastores", {"target": "vc-lab"})
    assert not d.allowed and "outside this role" in d.reason


def test_untagged_tool_counts_as_all_targets_and_is_refused_under_a_scoped_role():
    d = decide(_role("storage-operator"), "storage", "get_everything", {})
    assert not d.allowed and "reads every target" in d.reason


def test_scope_none_ignores_targets():
    assert decide(_role("storage-operator"), "storage", "get_cache", {}).allowed


def test_resolver_failure_is_a_refusal():
    roles.declare_role_metadata(
        "storage",
        target_scope={"list_all_datastores": "one"},
        resolver=lambda t: (_ for _ in ()).throw(KeyError(t)),
    )
    d = decide(_role("storage-operator"), "storage", "list_all_datastores", {"target": "x"})
    assert not d.allowed and "cannot be resolved" in d.reason


def test_composite_needs_every_tool_it_can_reach():
    """A plan that can delete is refused unless the role may delete (review B1)."""
    d = decide(_role("planner"), "aiops", "apply_vm_plan", {})
    assert not d.allowed and "can run" in d.reason
    assert ("delete_vm" in d.reason) or ("run_vm_guest_command" in d.reason)


def test_composite_allowed_when_role_lists_everything_it_reaches():
    text = GOOD.replace(
        "allow_write: [apply_vm_plan, power_off_vm]\n        allow_escape: []",
        "allow_write: [apply_vm_plan, power_off_vm, delete_vm]\n"
        "        allow_escape: [run_vm_guest_command]",
    )
    role = parse_roles(text)[0]["planner"]
    assert decide(role, "aiops", "apply_vm_plan", {}).allowed


def test_pre_2_0_names_in_a_role_match_the_new_tool():
    text = GOOD.replace("allow_write: [rescan_storage]", "allow_write: [storage_rescan]")
    role = parse_roles(text)[0]["storage-operator"]
    assert decide(role, "storage", "rescan_storage", {"target": "vc-prod-1"}).allowed


def test_visible_matches_decide_for_tools():
    role = _role("storage-operator")
    assert visible(role, "storage", "rescan_storage")
    assert not visible(role, "storage", "enable_iscsi")
    assert visible(ADMIN, "storage", "enable_iscsi")

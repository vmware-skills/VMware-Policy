"""Access self-diagnosis for vSphere skills (HLD §17 D-17).

The account's privileges are asked of vCenter for the current session at the
root folder. "Not granted at the root" is never reported as "no access" (it may
be granted on specific objects), and a failed lookup is "undetermined" with a
reason — never read as granted.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vmware_policy.access import vsphere_access_info

REQ = {
    "list_vms": ["System.View"],
    "power_on_vm": ["VirtualMachine.Interact.PowerOn"],
    "get_local_thing": [],
}


class FakeAM:
    def __init__(self, granted: set[str], fail: Exception | None = None, perms=None, roles=None):
        self.granted = granted
        self.fail = fail
        self.asked: list = []
        self._perms = perms or []
        self.roleList = roles or []

    def HasPrivilegeOnEntities(self, entity, sessionId, privId):  # noqa: N802,N803
        self.asked.append((entity, sessionId, list(privId)))
        if self.fail:
            raise self.fail
        return [
            SimpleNamespace(
                entity=entity[0],
                privAvailability=[
                    SimpleNamespace(privId=p, isGranted=p in self.granted) for p in privId
                ],
            )
        ]

    def RetrieveAllPermissions(self):  # noqa: N802
        return self._perms


def fake_si(am: FakeAM, user: str = "VSPHERE.LOCAL\\svc-mcp", session=True):
    current = SimpleNamespace(userName=user, key="sess-1") if session else None
    return SimpleNamespace(
        content=SimpleNamespace(
            sessionManager=SimpleNamespace(currentSession=current),
            authorizationManager=am,
            rootFolder="root-folder",
        )
    )


@pytest.mark.unit
def test_a_tool_whose_privileges_are_granted_at_the_root():
    am = FakeAM({"VirtualMachine.Interact.PowerOn"})
    out = vsphere_access_info(fake_si(am), target="vc1", requirements=REQ, tool="power_on_vm")
    assert out["account"] == "VSPHERE.LOCAL\\svc-mcp"
    assert out["tool"]["verdict"] == "granted_at_root"
    assert out["tool"]["requires"] == ["VirtualMachine.Interact.PowerOn"]
    assert am.asked[0][0] == ["root-folder"] and am.asked[0][1] == "sess-1"


@pytest.mark.unit
def test_not_granted_at_the_root_is_not_reported_as_no_access():
    am = FakeAM(set())
    out = vsphere_access_info(fake_si(am), target="vc1", requirements=REQ, tool="power_on_vm")
    assert out["tool"]["verdict"] == "not_granted_at_root"
    assert out["tool"]["missing_at_root"] == ["VirtualMachine.Interact.PowerOn"]
    assert "specific" in out["tool"]["meaning"]


@pytest.mark.unit
def test_a_failed_lookup_is_undetermined_with_the_reason_class():
    am = FakeAM(set(), fail=RuntimeError("secret host detail"))
    out = vsphere_access_info(fake_si(am), target="vc1", requirements=REQ, tool="power_on_vm")
    assert out["tool"]["verdict"] == "undetermined"
    assert "RuntimeError" in out["tool"]["reason"]
    assert "secret host detail" not in str(out)


@pytest.mark.unit
def test_no_session_means_undetermined_not_granted():
    am = FakeAM({"System.View"})
    out = vsphere_access_info(
        fake_si(am, session=False), target="vc1", requirements=REQ, tool="list_vms"
    )
    assert out["account"] is None
    assert out["tool"]["verdict"] == "undetermined"
    assert not am.asked


@pytest.mark.unit
def test_a_tool_needing_no_platform_privilege_says_so():
    am = FakeAM(set())
    out = vsphere_access_info(fake_si(am), target="vc1", requirements=REQ, tool="get_local_thing")
    assert out["tool"]["verdict"] == "no_platform_privilege_needed"


@pytest.mark.unit
def test_an_unknown_tool_is_refused_with_close_names():
    with pytest.raises(ValueError, match="power_on_vm"):
        vsphere_access_info(fake_si(FakeAM(set())), target="vc1", requirements=REQ, tool="power_on")


@pytest.mark.unit
def test_without_a_tool_every_tool_is_summarized():
    am = FakeAM({"System.View"})
    out = vsphere_access_info(fake_si(am), target="vc1", requirements=REQ)
    assert out["tools_granted_at_root"] == ["list_vms"]
    assert out["tools_no_privilege_needed"] == ["get_local_thing"]
    assert out["tools_not_granted_at_root"] == ["power_on_vm"]
    assert out["tools_undetermined"] == []
    assert out["privileges"] == {
        "System.View": "granted_at_root",
        "VirtualMachine.Interact.PowerOn": "not_granted_at_root",
    }


@pytest.mark.unit
def test_a_privilege_missing_from_the_answer_is_undetermined():
    class Partial(FakeAM):
        def HasPrivilegeOnEntities(self, entity, sessionId, privId):  # noqa: N802,N803
            return [SimpleNamespace(entity=entity[0], privAvailability=[])]

    out = vsphere_access_info(
        fake_si(Partial(set())), target="vc1", requirements=REQ, tool="list_vms"
    )
    assert out["tool"]["verdict"] == "undetermined"


@pytest.mark.unit
def test_permissions_held_directly_by_the_account_are_listed_by_role_name():
    perms = [
        SimpleNamespace(
            principal="VSPHERE.LOCAL\\svc-mcp",
            roleId=-2,
            entity=SimpleNamespace(name="Datacenters"),
            propagate=True,
        ),
        SimpleNamespace(
            principal="VSPHERE.LOCAL\\other",
            roleId=-1,
            entity=SimpleNamespace(name="Datacenters"),
            propagate=True,
        ),
    ]
    roles = [SimpleNamespace(roleId=-2, name="ReadOnly"), SimpleNamespace(roleId=-1, name="Admin")]
    am = FakeAM({"System.View"}, perms=perms, roles=roles)
    out = vsphere_access_info(fake_si(am), target="vc1", requirements=REQ, tool="list_vms")
    assert out["direct_permissions"] == [
        {"role": "ReadOnly", "on": "Datacenters", "propagate": True}
    ]
    assert "group" in out["direct_permissions_note"]


@pytest.mark.unit
def test_permissions_that_cannot_be_read_are_reported_as_unread():
    class NoPerms(FakeAM):
        def RetrieveAllPermissions(self):  # noqa: N802
            raise PermissionError("no")

    out = vsphere_access_info(fake_si(NoPerms({"System.View"})), target="vc1", requirements=REQ)
    assert out["direct_permissions"] is None
    assert "PermissionError" in out["direct_permissions_note"]


@pytest.mark.unit
def test_a_summary_with_undetermined_tools_does_not_say_granted():
    am = FakeAM(set(), fail=RuntimeError("x"))
    out = vsphere_access_info(fake_si(am), target="vc1", requirements=REQ)
    assert out["tools_undetermined"] == ["list_vms", "power_on_vm"]
    assert out["tools_granted_at_root"] == []
    assert "unknown" in out["meaning"]


@pytest.mark.unit
def test_an_unreadable_permission_object_does_not_leak_or_fail():
    class Hidden:
        _moId = "vm-42"  # noqa: N815 (pyVmomi's attribute name)

        @property
        def name(self):
            raise PermissionError("NoPermission on vm-42 at vc01.corp.example")

    perms = [
        SimpleNamespace(
            principal="VSPHERE.LOCAL\\svc-mcp", roleId=-5, entity=Hidden(), propagate=False
        )
    ]
    am = FakeAM({"System.View"}, perms=perms, roles=[SimpleNamespace(roleId=-5, name="NoAccess")])
    out = vsphere_access_info(fake_si(am), target="vc1", requirements=REQ, tool="list_vms")
    assert out["direct_permissions"] == [{"role": "NoAccess", "on": "vm-42", "propagate": False}]
    assert "corp.example" not in str(out)


@pytest.mark.unit
def test_a_summary_of_local_only_tools_does_not_claim_a_grant():
    out = vsphere_access_info(
        fake_si(FakeAM(set())), target="vc1", requirements={"get_local_thing": []}
    )
    assert out["tools_no_privilege_needed"] == ["get_local_thing"]
    assert "root folder" not in out["meaning"]


@pytest.mark.unit
def test_a_tool_decided_outside_vsphere_is_undetermined_not_granted():
    req = {**REQ, "create_tkc": None}
    out = vsphere_access_info(
        fake_si(FakeAM({"System.View"})), target="vc1", requirements=req, tool="create_tkc"
    )
    assert out["tool"]["verdict"] == "undetermined"
    assert "namespace role" in out["tool"]["reason"]
    summary = vsphere_access_info(fake_si(FakeAM({"System.View"})), target="vc1", requirements=req)
    assert "create_tkc" in summary["tools_undetermined"]


@pytest.mark.unit
def test_one_privilege_the_host_does_not_define_leaves_the_others_answered():
    class Picky(FakeAM):
        def HasPrivilegeOnEntities(self, entity, sessionId, privId):  # noqa: N802,N803
            if "Namespaces.Manage" in privId:
                raise ValueError("InvalidArgument privId")
            return super().HasPrivilegeOnEntities(entity, sessionId, privId)

    req = {**REQ, "create_namespace": ["Namespaces.Manage"]}
    out = vsphere_access_info(fake_si(Picky({"System.View"})), target="esx1", requirements=req)
    assert out["privileges"]["System.View"] == "granted_at_root"
    assert out["privileges"]["Namespaces.Manage"] == "undetermined"
    assert out["tools_undetermined"] == ["create_namespace"]
    assert "Namespaces.Manage" in out["reason"]


@pytest.mark.unit
def test_unknown_tool_message_needs_no_connection():
    from vmware_policy.access import unknown_tool_message

    assert unknown_tool_message(None, REQ) is None
    assert unknown_tool_message("list_vms", REQ) is None
    msg = unknown_tool_message("power_on", REQ)
    assert "power_on_vm" in msg and "doctor" not in msg


@pytest.mark.unit
def test_platform_text_is_sanitized():
    evil = "VSPHERE.LOCAL\\svc\x1b[2J\x07" + "A" * 900
    perms = [
        SimpleNamespace(
            principal=evil,
            roleId=-2,
            entity=SimpleNamespace(name="dc\x00" + "B" * 900),
            propagate=True,
        )
    ]
    roles = [SimpleNamespace(roleId=-2, name="Role\x1b" + "C" * 900)]
    am = FakeAM({"System.View"}, perms=perms, roles=roles)
    out = vsphere_access_info(
        fake_si(am, user=evil), target="vc1", requirements=REQ, tool="list_vms"
    )
    text = str(out)
    assert "\x1b" not in text and "\x00" not in text and "\x07" not in text
    assert len(out["account"]) <= 300
    perm = out["direct_permissions"][0]
    assert len(perm["on"]) <= 300 and len(perm["role"]) <= 300


@pytest.mark.unit
def test_a_dead_link_does_not_cost_one_timeout_per_privilege():
    am = FakeAM(set(), fail=ConnectionError("down"))
    req = {f"tool{i}": [f"Priv.P{i}"] for i in range(40)}
    out = vsphere_access_info(fake_si(am), target="vc1", requirements=req)
    assert len(am.asked) <= 4  # the batch + at most 3 single asks
    assert len(out["tools_undetermined"]) == 40


@pytest.mark.unit
def test_granted_meaning_does_not_claim_every_object():
    from vmware_policy.access import _MEANING, GRANTED

    assert "every object" not in _MEANING[GRANTED]


@pytest.mark.unit
def test_ids_the_host_lacks_do_not_hide_the_ones_it_answers():
    known = {"System.Read", "System.View"}

    class Esx(FakeAM):
        def HasPrivilegeOnEntities(self, entity, sessionId, privId):  # noqa: N802,N803
            if any(p not in known for p in privId):
                self.asked.append((entity, sessionId, list(privId)))
                raise ValueError("InvalidArgument")
            return super().HasPrivilegeOnEntities(entity, sessionId, privId)

    req = {
        "a": ["Alarm.Acknowledge"],
        "b": ["Alarm.SetStatus"],
        "c": ["Certificate.Manage"],
        "read": ["System.Read", "System.View"],
    }
    out = vsphere_access_info(fake_si(Esx(known)), target="esx1", requirements=req)
    assert out["privileges"]["System.Read"] == "granted_at_root"
    assert "read" in out["tools_granted_at_root"]
    assert sorted(out["tools_undetermined"]) == ["a", "b", "c"]


class _RefusedError(Exception):
    """Stands in for vim.fault.NotAuthenticated / NoPermission."""


class _Entity:
    """Stands in for vim.ManagedEntity."""


def _si_with_view(session: bool, view_error: Exception | None):
    si = fake_si(FakeAM(set()), session=session)
    calls = []

    class View:
        def Destroy(self):  # noqa: N802
            calls.append("destroy")

    def create(container, types, recursive):
        calls.append(("create", container, tuple(types), recursive))
        if view_error:
            raise view_error
        return View()

    si.content.viewManager = SimpleNamespace(CreateContainerView=create)
    return si, calls


@pytest.mark.unit
def test_a_role_less_login_needs_both_signals():
    from vmware_policy.access import login_has_no_session

    kw = {"entity_type": _Entity, "refused": (_RefusedError,)}
    # no session AND inventory refused -> role-less
    si, calls = _si_with_view(session=False, view_error=_RefusedError())
    assert login_has_no_session(si, **kw) is True
    # no session but inventory readable (a scoped or namespace-only account) -> not refused
    si, calls = _si_with_view(session=False, view_error=None)
    assert login_has_no_session(si, **kw) is False
    assert calls[-1] == "destroy"  # the probe view is cleaned up
    # a session -> never probed
    si, calls = _si_with_view(session=True, view_error=_RefusedError())
    assert login_has_no_session(si, **kw) is False and calls == []
    # any other error from the probe is unknown, and unknown is not a verdict
    si, _ = _si_with_view(session=False, view_error=RuntimeError("socket"))
    assert login_has_no_session(si, **kw) is False


@pytest.mark.unit
def test_a_role_less_login_is_not_concluded_without_pyvmomi():
    from vmware_policy.access import login_has_no_session

    si, calls = _si_with_view(session=False, view_error=_RefusedError())
    try:
        import pyVmomi  # noqa: F401
    except ImportError:
        assert login_has_no_session(si) is False and calls == []


@pytest.mark.unit
def test_an_unreadable_session_property_is_not_a_verdict():
    from vmware_policy.access import login_has_no_session, no_role_message

    class Broken:
        @property
        def content(self):
            raise RuntimeError("cannot tell")

    assert login_has_no_session(Broken(), entity_type=_Entity, refused=(_RefusedError,)) is False
    msg = no_role_message("vc1", "vmware-monitor")
    assert "vc1" in msg and "role" in msg and "vmware-monitor doctor" in msg
    assert "password" in msg  # says changing it will not help


@pytest.mark.unit
def test_the_role_message_fits_the_skills_error_cap():
    from vmware_policy.access import no_role_message

    msg = no_role_message("vcenter-prod-01", "vmware-nsx-security")
    assert len(msg) <= 300 and msg.endswith("A new password will not help.")

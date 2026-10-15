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
    assert out["tools_granted_at_root"] == ["get_local_thing", "list_vms"]
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

"""The 2.0 tool renames, applied where policy reads names written before them (HLD §16 D-15).

Servers expose only the new names. Two places still see old ones: deny rules an
operator wrote in ``rules.yaml``, and ``vmware-audit`` filters over history.
Both go through here. The map is keyed by skill because two old names were
reused: ``scan_datastore_images`` (aiops renamed it, storage did not) and
``list_vm_snapshots`` (vks renamed it; it became aiops/monitor's new name).
"""

from __future__ import annotations

import json
from functools import cache
from importlib import resources


@cache
def table() -> dict[str, dict[str, str]]:
    """``{"vmware-<skill>": {old: new}}``, exactly as reviewed in design/tool-rename-2.0.json."""
    text = resources.files("vmware_policy").joinpath("data/tool_renames_2_0.json").read_text(
        encoding="utf-8"
    )
    return json.loads(text)


def _server(skill: str) -> str:
    """``"nsx_security"`` (the policy skill key) -> ``"vmware-nsx-security"``."""
    return "vmware-" + skill.replace("_", "-")


@cache
def old_names(skill: str, tool: str) -> tuple[str, ...]:
    """The pre-2.0 name(s) of ``tool`` in ``skill``; empty when it was not renamed."""
    pairs = table().get(_server(skill), {})
    return tuple(sorted(old for old, new in pairs.items() if new == tool))


@cache
def all_names_for(tool: str) -> tuple[str, ...]:
    """``tool`` plus every name it was renamed from or to, in any skill (audit filters)."""
    names = {tool}
    for pairs in table().values():
        for old, new in pairs.items():
            if tool in (old, new):
                names.update((old, new))
    return tuple(sorted(names))

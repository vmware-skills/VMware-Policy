"""Limits use backend-read sizing, in both directions, and fail closed."""

import os
import pytest
import yaml
from vmware_policy.policy import PolicyEngine


def engine(tmp_path, limits):
    rules = tmp_path / "rules.yaml"
    rules.write_text(yaml.safe_dump({"change_limits": limits}), encoding="utf-8")
    return PolicyEngine(rules)


@pytest.mark.parametrize(
    "before,after,threshold,allowed",
    [
        (4, 5, 25, True),
        (4, 3, 25, True),
        (4, 6, 25, False),
        (4, 2, 25, False),
        (4, 4, 0, True),
        (4, 5, 0, False),
    ],
)
def test_percentage_boundary(tmp_path, before, after, threshold, allowed):
    e = engine(tmp_path, {"max_cpu_change_pct": threshold})
    result = e.check_vm_reconfiguration(
        before={"cpu": before}, after={"cpu": after}, change_version="v1"
    )
    assert result.allowed is allowed
    assert result.rule == "change_limits"


@pytest.mark.parametrize(
    "limits",
    [
        {"max_cpu_change_pct": -1},
        {"max_cpu_change_pct": True},
        {"max_cpu_change_pct": "20"},
        {"max_cpu_change_pct": float("nan")},
        {"max_cpu_change_pct": float("inf")},
        {"max_cpu_change_pct": 10**400},
        {"unknown_limit": 1},
        [20],
    ],
)
def test_malformed_limits_cannot_allow_resize(tmp_path, limits):
    e = engine(tmp_path, limits)
    assert not e.check_vm_reconfiguration(
        before={"cpu": 4}, after={"cpu": 4}, change_version="v1"
    ).allowed


@pytest.mark.parametrize(
    "before,after,version",
    [
        ({}, {"cpu": 4}, "v1"),
        ({"cpu": 0}, {"cpu": 4}, "v1"),
        ({"cpu": True}, {"cpu": 4}, "v1"),
        ({"cpu": 4}, {"cpu": 0}, "v1"),
        ({"cpu": 4}, {"cpu": 4}, None),
        ({"cpu": 4}, {"cpu": 4}, ""),
    ],
)
def test_missing_configuration_is_not_permission(tmp_path, before, after, version):
    e = engine(tmp_path, {"max_cpu_change_pct": 20})
    assert not e.check_vm_reconfiguration(
        before=before, after=after, change_version=version
    ).allowed


def test_memory_limit_does_not_become_cpu_limit(tmp_path):
    e = engine(tmp_path, {"max_memory_change_pct": 50})
    assert e.check_vm_reconfiguration(
        before={"memory_mb": 4096}, after={"memory_mb": 6144}, change_version="v1"
    ).allowed
    assert not e.check_vm_reconfiguration(
        before={"memory_mb": 4096}, after={"memory_mb": 8192}, change_version="v1"
    ).allowed
    assert e.check_vm_reconfiguration(before={}, after={"cpu": 8}, change_version=None).allowed


def test_no_limits_preserves_legacy_behavior(tmp_path):
    assert (
        engine(tmp_path, {})
        .check_vm_reconfiguration(before={}, after={"cpu": 8}, change_version=None)
        .allowed
    )


def test_limits_hot_reload(tmp_path):
    e = engine(tmp_path, {"max_cpu_change_pct": 50})
    args = dict(before={"cpu": 4}, after={"cpu": 5}, change_version="v1")
    assert e.check_vm_reconfiguration(**args).allowed
    path = tmp_path / "rules.yaml"
    before = path.stat().st_mtime
    path.write_text("change_limits:\n  max_cpu_change_pct: 20\n", encoding="utf-8")
    os.utime(path, (before + 2, before + 2))
    assert not e.check_vm_reconfiguration(**args).allowed

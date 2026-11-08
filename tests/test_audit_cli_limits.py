"""Nonpositive CLI bounds must not reach SQLite as empty/unlimited reads."""

from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from vmware_policy import cli, undo


@pytest.mark.parametrize(
    "command,option", [("log", "--last"), ("export", "--limit"), ("undo-list", "--last")]
)
@pytest.mark.parametrize("value", ["0", "-1"])
def test_invalid_bound_is_rejected_before_store_access(monkeypatch, command, option, value):
    calls = []
    monkeypatch.setattr(cli, "get_engine", lambda: calls.append("audit"))
    monkeypatch.setattr(undo, "get_undo_store", lambda: calls.append("undo"))
    result = CliRunner().invoke(cli.app, [command, option, value])
    assert result.exit_code == 2
    assert calls == []
    assert "1" in result.output and "Traceback" not in result.output


@pytest.mark.parametrize(
    "command,option", [("log", "--last"), ("export", "--limit"), ("undo-list", "--last")]
)
def test_positive_bound_reaches_the_store_unchanged(monkeypatch, command, option):
    bounds = []

    def read(**kwargs):
        bounds.append(kwargs["limit"])
        return []

    monkeypatch.setattr(cli, "get_engine", lambda: SimpleNamespace(query=read))
    monkeypatch.setattr(undo, "get_undo_store", lambda: SimpleNamespace(list=read))
    result = CliRunner().invoke(cli.app, [command, option, "1"])
    assert result.exit_code == 0 and bounds == [1]

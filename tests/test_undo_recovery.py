"""Transient undo-store failures must recover without hiding unavailable data."""

import sqlite3

import pytest
from typer.testing import CliRunner

import vmware_policy.undo as undo_mod
from vmware_policy.cli import app
from vmware_policy.undo import UndoStore


def _record(store):
    return store.record(
        skill="aiops",
        tool="power_off_vm",
        undo_descriptor={"tool": "power_on_vm", "params": {"password": "do-not-print"}},
    )


def test_initial_failure_recovers_after_directory_is_fixed(tmp_path, capsys):
    blocker = tmp_path / "ops"
    blocker.write_text("not a directory", encoding="utf-8")
    store = UndoStore(blocker / "undo.db")
    assert _record(store) is None
    assert "undo record lost" in capsys.readouterr().err
    blocker.unlink()
    blocker.mkdir()
    uid = _record(store)
    assert uid and store.get(uid)["undo_tool"] == "power_on_vm"


def test_deleted_database_recovers_on_next_record(tmp_path):
    db = tmp_path / "undo.db"
    store = UndoStore(db)
    assert _record(store)
    for suffix in ("", "-wal", "-shm"):
        db.with_name(db.name + suffix).unlink(missing_ok=True)
    assert _record(store) is None
    uid = _record(store)
    assert uid and store.get(uid)


@pytest.mark.parametrize("operation", ["get", "list", "mark"])
def test_unavailable_store_is_not_reported_as_empty(tmp_path, operation):
    blocker = tmp_path / "ops"
    blocker.write_text("not a directory", encoding="utf-8")
    store = UndoStore(blocker / "undo.db")
    with pytest.raises(RuntimeError, match="Undo store unavailable"):
        getattr(store, operation)(*{"get": ["x"], "list": [], "mark": ["x", "applied"]}[operation])


def test_record_failure_never_exposes_descriptor_or_exception(tmp_path, monkeypatch, capsys):
    store = UndoStore(tmp_path / "undo.db")

    def fail():
        raise sqlite3.OperationalError("password=do-not-print")

    monkeypatch.setattr(store, "_connect", fail)
    assert _record(store) is None
    err = capsys.readouterr().err
    assert "undo record lost" in err
    assert "do-not-print" not in err and "Traceback" not in err


@pytest.mark.parametrize("args", [["undo-list"], ["undo-show", "x"]])
def test_cli_reports_unavailable_store_without_traceback(tmp_path, monkeypatch, args):
    blocker = tmp_path / "ops"
    blocker.write_text("not a directory", encoding="utf-8")
    monkeypatch.setattr(undo_mod, "_store", UndoStore(blocker / "undo.db"))
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 1
    assert "Undo store unavailable" in result.output
    assert "No undo record" not in result.output
    assert "Traceback" not in result.output

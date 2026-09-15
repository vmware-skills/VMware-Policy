"""A lost audit row is never silent.

HLD §8.1 says audit failure "degrades to a stderr warning and never blocks the
operation (availability, not silent loss)". A family survey on 2026-09-15 found the
second half untrue:

* When the database could not be initialised (unwritable directory, a file where
  the directory should be), ``AuditEngine`` set ``_ok = False`` once and every later
  ``log()`` returned without a word — one logging warning at start-up, then nothing
  for the life of the process. The condition was never retried, so fixing the
  directory did not help until restart.
* When a single insert failed (read-only file, a lock held past the busy
  timeout) the only trace was a ``logging`` warning, which an MCP host or a CLI
  with no logging configured does not show, and nothing counted it.

These tests pin the replacement: every lost row writes one line to stderr naming
what was lost and why, the engine retries initialisation on the next call, and
the process keeps a count of lost rows.
"""

from __future__ import annotations

import os
import sqlite3
import stat

import pytest

from vmware_policy.audit import AuditEngine


def _row_count(db) -> int:
    with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as con:
        return con.execute("SELECT count(*) FROM audit_log").fetchone()[0]


def test_every_row_lost_to_an_uninitialisable_db_is_reported_on_stderr(tmp_path, capsys):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("a file where the audit directory should be", encoding="utf-8")
    engine = AuditEngine(blocker / "audit.db")
    capsys.readouterr()  # start-up output is not what is under test

    engine.log(skill="aria", tool="list_alerts", status="ok")
    engine.log(skill="aria", tool="get_alert", status="error")

    err = capsys.readouterr().err
    lost = [line for line in err.splitlines() if "audit row lost" in line]
    assert len(lost) == 2, f"expected one stderr line per lost row, got: {err!r}"
    assert "aria" in lost[0] and "list_alerts" in lost[0] and "ok" in lost[0]
    assert "get_alert" in lost[1] and "error" in lost[1]
    assert engine.lost_rows == 2


def test_initialisation_is_retried_so_a_fixed_directory_starts_recording(tmp_path, capsys):
    blocker = tmp_path / "later-a-dir"
    blocker.write_text("temporarily a file", encoding="utf-8")
    engine = AuditEngine(blocker / "audit.db")

    engine.log(skill="aria", tool="list_alerts", status="ok")  # lost
    blocker.unlink()
    blocker.mkdir()
    engine.log(skill="aria", tool="get_alert", status="ok")  # must land

    db = blocker / "audit.db"
    assert db.exists(), "the engine never retried initialisation"
    assert _row_count(db) == 1
    assert engine.lost_rows == 1


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")
def test_a_failed_insert_is_reported_on_stderr_and_counted(tmp_path, capsys):
    db = tmp_path / "audit.db"
    engine = AuditEngine(db)
    engine.log(skill="monitor", tool="get_events", status="ok")
    assert _row_count(db) == 1
    capsys.readouterr()

    db.chmod(stat.S_IRUSR)
    try:
        engine.log(skill="monitor", tool="vm_info", status="ok")
    finally:
        db.chmod(stat.S_IRUSR | stat.S_IWUSR)

    err = capsys.readouterr().err
    assert any("audit row lost" in line and "vm_info" in line for line in err.splitlines()), err
    assert engine.lost_rows == 1
    assert _row_count(db) == 1


def test_a_healthy_engine_reports_nothing(tmp_path, capsys):
    engine = AuditEngine(tmp_path / "audit.db")
    capsys.readouterr()

    engine.log(skill="debug", tool="case_open", status="ok")

    assert "audit row lost" not in capsys.readouterr().err
    assert engine.lost_rows == 0

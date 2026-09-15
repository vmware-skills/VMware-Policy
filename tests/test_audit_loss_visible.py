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


# ── Review follow-ups, 2026-09-15 (D4) ──────────────────────────────────────


def _delete_db(db) -> None:
    for suffix in ("", "-wal", "-shm"):
        db.with_name(db.name + suffix).unlink(missing_ok=True)


def test_a_db_deleted_after_start_heals_on_the_next_write(tmp_path, capsys):
    """``_ok`` stayed True after a successful start, so every later write failed
    with ``no such table`` for the life of the process."""
    db = tmp_path / "audit.db"
    engine = AuditEngine(db)
    engine.log(skill="aria", tool="list_alerts", status="ok")
    _delete_db(db)
    capsys.readouterr()

    engine.log(skill="aria", tool="get_alert", status="ok")  # lost, and said so
    assert engine.lost_rows == 1
    assert "audit row lost" in capsys.readouterr().err

    engine.log(skill="aria", tool="list_resources", status="ok")  # must land
    assert engine.lost_rows == 1, "the engine never re-initialised the deleted database"
    assert _row_count(db) == 1


def test_a_directory_deleted_after_start_heals_on_the_next_write(tmp_path, capsys):
    import shutil

    db = tmp_path / "ops" / "audit.db"
    engine = AuditEngine(db)
    engine.log(skill="nsx", tool="list_segments", status="ok")
    shutil.rmtree(db.parent)

    engine.log(skill="nsx", tool="get_segment", status="ok")  # lost
    engine.log(skill="nsx", tool="list_gateways", status="ok")  # must land

    assert engine.lost_rows == 1
    assert _row_count(db) == 1


def test_lost_rows_is_incremented_under_a_lock(tmp_path):
    """Several threads of one MCP server can lose rows at once; the count is shared."""
    held_during_increment: list[bool] = []

    class _SpyLock:
        held = False

        def __enter__(self):
            _SpyLock.held = True
            return self

        def __exit__(self, *exc):
            _SpyLock.held = False
            return False

    class _Spy(AuditEngine):
        @property
        def lost_rows(self):
            return self.__dict__.get("_lost", 0)

        @lost_rows.setter
        def lost_rows(self, value):
            if self.__dict__.get("_spying"):
                held_during_increment.append(_SpyLock.held)
            self.__dict__["_lost"] = value

    blocker = tmp_path / "file"
    blocker.write_text("not a directory", encoding="utf-8")
    engine = _Spy(blocker / "audit.db")
    engine._lost_lock = _SpyLock()
    engine.__dict__["_spying"] = True

    engine.log(skill="s", tool="t")
    engine.log(skill="s", tool="u")

    assert held_during_increment == [True, True]
    assert engine.lost_rows == 2


def test_the_loss_reason_is_scrubbed_of_credentials(tmp_path, capsys, monkeypatch):
    engine = AuditEngine(tmp_path / "audit.db")
    capsys.readouterr()

    def _fail():
        raise sqlite3.OperationalError(
            "unable to open https://admin:S3cr3tPW@vc01/db password=Hunter2Secret!"
        )

    monkeypatch.setattr(engine, "_connect", _fail)
    engine.log(skill="aiops", tool="vm_info", status="ok")

    err = capsys.readouterr().err
    assert "audit row lost" in err
    assert "S3cr3tPW" not in err and "Hunter2Secret!" not in err, err


def test_a_lost_row_prints_one_line_not_a_traceback(tmp_path, capsys, caplog, monkeypatch):
    import logging

    engine = AuditEngine(tmp_path / "audit.db")
    capsys.readouterr()

    def _fail():
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(engine, "_connect", _fail)
    with caplog.at_level(logging.DEBUG, logger="vmware-policy.audit"):
        engine.log(skill="aiops", tool="vm_info", status="ok")

    loud = [r for r in caplog.records if r.levelno >= logging.WARNING and r.exc_info]
    assert not loud, f"a traceback was logged at {loud[0].levelname} for one lost row"
    err_lines = [line for line in capsys.readouterr().err.splitlines() if line.strip()]
    assert len(err_lines) == 1 and "audit row lost" in err_lines[0], err_lines

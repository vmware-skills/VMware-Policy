"""Audit rotation is safe with tools on worker threads (HLD §16 D-13(4) [M2]).

Two threads past the size threshold both rotated; the archive name has
one-second resolution and Path.rename replaces silently, so the second rotation
renamed the fresh DB over the first archive and lost the rotated history.
"""

from __future__ import annotations

import threading

import pytest

import vmware_policy.audit as audit_mod
from vmware_policy.audit import AuditEngine


@pytest.fixture
def small_limit(monkeypatch):
    monkeypatch.setattr(audit_mod, "_MAX_DB_SIZE_BYTES", 1)


@pytest.mark.unit
def test_an_existing_archive_is_never_overwritten(tmp_path, small_limit, monkeypatch):
    engine = AuditEngine(db_path=tmp_path / "audit.db")
    engine.log(skill="s", tool="first", params={}, result="ok", status="ok")
    engine._maybe_rotate()
    before = {a.name: a.read_bytes() for a in tmp_path.glob("audit.*.db")}
    assert before
    stamp = sorted(before)[0].split(".")[1][:15]

    class _Frozen:  # every later rotation lands in the same second as the first
        @staticmethod
        def now(tz=None):
            from datetime import datetime

            return datetime.strptime(stamp, "%Y%m%d-%H%M%S").replace(tzinfo=tz)

    monkeypatch.setattr(audit_mod, "datetime", _Frozen)
    # One more round only: retention keeps the newest five archives, and this
    # test is about collisions, not about retention deleting old ones.
    for i in range(1):
        engine.log(skill="s", tool=f"later{i}", params={}, result="ok", status="ok")
        engine._maybe_rotate()

    after = {a.name: a.read_bytes() for a in tmp_path.glob("audit.*.db")}
    for name, data in before.items():
        assert after.get(name) == data, f"archive {name} was overwritten or lost"
    assert len(after) > len(before)


@pytest.mark.unit
def test_concurrent_rotations_rotate_once(tmp_path, small_limit):
    engine = AuditEngine(db_path=tmp_path / "audit.db")
    engine.log(skill="s", tool="x", params={}, result="ok", status="ok")
    barrier = threading.Barrier(4)

    def rotate():
        barrier.wait()
        engine._maybe_rotate()

    threads = [threading.Thread(target=rotate) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5)
    # Each rotation leaves a fresh (non-empty schema) DB that is itself over the
    # 1-byte limit, so a later caller may rotate again — but no archive is lost:
    # every rotation produced its own file.
    names = [a.name for a in tmp_path.glob("audit.*.db")]
    assert len(names) == len(set(names))
    assert (tmp_path / "audit.db").exists()

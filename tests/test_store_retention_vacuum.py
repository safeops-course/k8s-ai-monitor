"""Tests for DB_RETENTION_DAYS and VACUUM/compaction wiring."""
import sqlite3
import time

import pytest

from src import config
from src.engine.store.sqlite import SqliteStore


@pytest.fixture
def store(tmp_path):
    db_path = str(tmp_path / "test.db")
    s = SqliteStore(db_path=db_path)
    yield s


def _make_incident(store, state_key, *, status="resolved", updated_at=None):
    """Create an incident directly in the DB for retention tests."""
    conn = store._get_conn()
    now = updated_at or time.time()
    conn.execute(
        "INSERT INTO incidents (state_key, fingerprint, issue_type, severity, "
        "first_seen_at, last_seen_at, active_since, status, created_at, updated_at) "
        "VALUES (?, ?, 'oom', 'warning', ?, ?, ?, ?, ?, ?)",
        (state_key, f"fp-{state_key}", now, now, now, status, now, now),
    )
    conn.commit()
    return conn.execute(
        "SELECT id FROM incidents WHERE state_key = ?", (state_key,),
    ).fetchone()["id"]


def test_cleanup_uses_db_retention_days_by_default(store, monkeypatch):
    """cleanup() with no arg should read DB_RETENTION_DAYS from config."""
    monkeypatch.setattr(config, "DB_RETENTION_DAYS", 30)

    # Two resolved incidents: one 40 days old, one 10 days old.
    now = time.time()
    old_ts = now - 40 * 86400
    recent_ts = now - 10 * 86400
    _make_incident(store, "old-one", status="resolved", updated_at=old_ts)
    _make_incident(store, "recent-one", status="resolved", updated_at=recent_ts)

    store.cleanup()

    remaining = store._get_conn().execute(
        "SELECT state_key FROM incidents ORDER BY state_key",
    ).fetchall()
    keys = [r["state_key"] for r in remaining]
    assert "old-one" not in keys
    assert "recent-one" in keys


def test_cleanup_max_age_hours_explicit_override(store):
    """When max_age_hours is passed explicitly it still wins over config."""
    now = time.time()
    _make_incident(store, "old", status="resolved", updated_at=now - 10 * 86400)
    _make_incident(store, "recent", status="resolved", updated_at=now - 1 * 86400)

    store.cleanup(max_age_hours=24 * 7)  # 7 days — "old" at 10d should go

    keys = [r["state_key"] for r in store._get_conn().execute(
        "SELECT state_key FROM incidents").fetchall()]
    assert "old" not in keys
    assert "recent" in keys


def test_post_cleanup_compact_smoke(store):
    """_post_cleanup_compact must run without raising on a healthy DB."""
    _make_incident(store, "a", status="resolved",
                    updated_at=time.time() - 100 * 86400)
    store._post_cleanup_compact()


def test_cleanup_triggers_wal_truncate(store, tmp_path):
    """End-to-end: after cleanup() the WAL sidecar file stays small.

    Without wal_checkpoint(TRUNCATE) a long-running process can grow a
    multi-hundred-MB WAL. Seeding ~1000 incidents then running cleanup
    should leave a compact WAL (< 1MB is plenty of headroom; the file is
    truncated to its frame-header on a successful truncate).
    """
    import os
    db_path = store._db_path
    wal_path = db_path + "-wal"

    # Seed enough writes that the WAL would otherwise be non-trivial.
    conn = store._get_conn()
    for i in range(500):
        ts = time.time() - 100 * 86400  # all old, get deleted
        conn.execute(
            "INSERT INTO incidents (state_key, fingerprint, issue_type, "
            "severity, first_seen_at, last_seen_at, active_since, status, "
            "created_at, updated_at) VALUES "
            "(?, ?, 'oom', 'warning', ?, ?, ?, 'resolved', ?, ?)",
            (f"k{i}", f"fp{i}", ts, ts, ts, ts, ts),
        )
    conn.commit()

    store.cleanup()

    # WAL should exist (journal_mode=WAL) but be small after truncate.
    assert os.path.exists(wal_path)
    assert os.path.getsize(wal_path) < 1_000_000


def test_full_vacuum_runs(store):
    """full_vacuum just delegates to VACUUM; must not raise on a healthy DB."""
    # Seed a bit of data so VACUUM has something to compact.
    _make_incident(store, "x", status="resolved",
                    updated_at=time.time() - 100 * 86400)
    store.cleanup()  # delete → leaves free pages
    store.full_vacuum()  # should complete without raising


def test_auto_vacuum_pragma_set_on_new_db(tmp_path):
    """Fresh DBs should come up in auto_vacuum=INCREMENTAL (mode 2)."""
    db_path = str(tmp_path / "fresh.db")
    SqliteStore(db_path=db_path)

    # Re-open directly with sqlite3 to avoid SqliteStore's thread-local caching.
    with sqlite3.connect(db_path) as conn:
        mode = conn.execute("PRAGMA auto_vacuum").fetchone()[0]
    # 0=NONE, 1=FULL, 2=INCREMENTAL
    assert mode == 2

"""The periodic stale reaper must NAME what it closed, so the fleet board
can be told.

Regression: SqliteStore.cleanup() closed >7d active incidents with a bulk
UPDATE that returned nothing. The monitor considered them resolved while the
central ClickHouse board kept showing them 'active' forever — 11 such fossils
accumulated across the three GKE clusters, and every one of them had
resolved_by = '' locally, which is the fingerprint of that path.
"""
import time

import pytest

from src.engine.store.sqlite import SqliteStore


@pytest.fixture
def store(tmp_path):
    return SqliteStore(db_path=str(tmp_path / "test.db"))


def _active(store, state_key, *, last_seen_at):
    conn = store._get_conn()
    now = time.time()
    conn.execute(
        "INSERT INTO incidents (state_key, fingerprint, issue_type, severity, "
        "first_seen_at, last_seen_at, active_since, status, created_at, updated_at) "
        "VALUES (?, ?, 'mount', 'critical', ?, ?, ?, 'active', ?, ?)",
        (state_key, f"fp-{state_key}", last_seen_at, last_seen_at,
         last_seen_at, now, now),
    )
    conn.commit()


def test_reaper_returns_what_it_closed(store):
    now = time.time()
    _active(store, "Pod:platform/app-postgres-1:mount",
            last_seen_at=now - 10 * 86400)
    _active(store, "Pod:production/fresh:mount", last_seen_at=now - 3600)

    reaped = store.cleanup()

    assert [i.state_key for i in reaped] == [
        "Pod:platform/app-postgres-1:mount"
    ], "only the >7d incident may be reaped, and it must be returned"
    assert reaped[0].severity == "critical"
    assert reaped[0].occurrence_count is not None


def test_reaper_stamps_resolved_by(store):
    """An unattributed resolve is indistinguishable from a legacy row."""
    _active(store, "Pod:production/stale:mount",
            last_seen_at=time.time() - 8 * 86400)

    reaped = store.cleanup()

    assert len(reaped) == 1
    row = store._get_conn().execute(
        "SELECT status, resolved_by FROM incidents WHERE state_key = ?",
        ("Pod:production/stale:mount",),
    ).fetchone()
    assert row["status"] == "resolved"
    assert row["resolved_by"] == "reaper"


def test_reaper_returns_empty_when_nothing_is_stale(store):
    """No incidents closed means no central push — not an empty-batch push."""
    _active(store, "Pod:production/fresh:mount", last_seen_at=time.time() - 60)
    assert store.cleanup() == []

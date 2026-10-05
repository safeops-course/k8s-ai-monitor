"""Tests for the store-aware /healthz liveness handler.

/healthz used to return 200 "ok" unconditionally, so a pod whose SQLite
store had wedged (e.g. "unable to open database file" on a stale RWO
volume handle — the papa incident where the pod sat Running but dead for
72h) still looked healthy and was never restarted. The handler now pings
the store and returns 503 when it is uninitialized or unreachable, so a
liveness probe can self-heal the pod.
"""
import asyncio

import pytest

from src.engine.store.sqlite import SqliteStore
from src.handlers import startup


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _reset_store():
    original = startup._store
    yield
    startup._store = original


def test_healthz_503_when_store_uninitialized(monkeypatch):
    """A None store (init never completed) reports unhealthy."""
    monkeypatch.setattr(startup, "_store", None)
    resp = _run(startup._handle_healthz(None))
    assert resp.status == 503
    assert "uninitialized" in resp.text


def test_healthz_ok_when_store_healthy(monkeypatch, tmp_path):
    """A live store passes the ping and returns 200."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    monkeypatch.setattr(startup, "_store", store)
    resp = _run(startup._handle_healthz(None))
    assert resp.status == 200
    assert resp.text == "ok"


def test_healthz_503_when_ping_fails(monkeypatch):
    """A store whose ping raises (disk full / read-only remount) is 503."""
    class _BrokenStore:
        def ping(self):
            raise OSError("disk I/O error")

    monkeypatch.setattr(startup, "_store", _BrokenStore())
    resp = _run(startup._handle_healthz(None))
    assert resp.status == 503
    assert "unhealthy" in resp.text

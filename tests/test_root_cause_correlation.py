"""Tests for Sprint 8 root-cause correlation (not suppression).

Dependent alerts STILL fire — we want the cascade visible because it
exposes services that aren't resilient to dep outages. What we add is
a correlation hint pointing at the active root cause.
"""
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src import config
from src.engine import enrichment, pipeline
from src.engine.store.sqlite import SqliteStore


# ── Store methods ────────────────────────────────────────────────────────

@pytest.fixture
def store(tmp_path):
    return SqliteStore(db_path=str(tmp_path / "test.db"))


def test_record_and_get_active_root_cause(store):
    store.record_root_cause(
        namespace="production",
        root_fingerprint="fp-pg-oom",
        root_state_key="Pod:production/postgres-0:oom",
        root_incident_id=42,
        ttl_seconds=600,
    )
    root = store.get_active_root_cause("production")
    assert root is not None
    assert root["root_state_key"] == "Pod:production/postgres-0:oom"
    assert root["root_incident_id"] == 42


def test_get_active_root_cause_ignores_expired(store):
    store.record_root_cause(
        namespace="production", root_fingerprint="fp",
        root_state_key="k", root_incident_id=1, ttl_seconds=600,
    )
    store._get_conn().execute(
        "UPDATE active_root_causes SET expires_at = ? WHERE namespace = ?",
        (time.time() - 1, "production"),
    )
    store._get_conn().commit()
    assert store.get_active_root_cause("production") is None


def test_record_root_cause_upsert_refreshes_full_payload(store):
    """Re-recording the same fingerprint should refresh started_at AND
    state_key/incident_id — otherwise the correlation hint shows stale
    'fired Xm ago' and stale state_key for a newer occurrence."""
    store.record_root_cause(
        namespace="production",
        root_fingerprint="fp",
        root_state_key="old-key",
        root_incident_id=1,
        ttl_seconds=600,
    )
    first = store.get_active_root_cause("production")
    assert first is not None
    first_started = first["started_at"]

    # Force at least 1ms gap so started_at comparison is meaningful.
    time.sleep(0.01)

    store.record_root_cause(
        namespace="production",
        root_fingerprint="fp",  # same key → upsert branch
        root_state_key="new-key",
        root_incident_id=2,
        ttl_seconds=600,
    )
    second = store.get_active_root_cause("production")
    assert second is not None
    assert second["root_state_key"] == "new-key"
    assert second["root_incident_id"] == 2
    assert second["started_at"] > first_started


def test_clear_root_cause_is_idempotent(store):
    store.clear_root_cause("production", "fp-nope")
    store.record_root_cause(
        namespace="production", root_fingerprint="fp",
        root_state_key="k", root_incident_id=1, ttl_seconds=600,
    )
    store.clear_root_cause("production", "fp")
    assert store.get_active_root_cause("production") is None


def test_cleanup_expired_root_causes(store):
    now = time.time()
    conn = store._get_conn()
    conn.execute(
        "INSERT INTO active_root_causes ("
        "namespace, root_fingerprint, root_state_key, root_incident_id,"
        "started_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("production", "fp-fresh", "k1", 1, now, now + 1000),
    )
    conn.execute(
        "INSERT INTO active_root_causes ("
        "namespace, root_fingerprint, root_state_key, root_incident_id,"
        "started_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("production", "fp-stale", "k2", 2, now - 2000, now - 100),
    )
    conn.commit()
    store.cleanup_expired_root_causes()
    keys = [r["root_fingerprint"] for r in conn.execute(
        "SELECT root_fingerprint FROM active_root_causes").fetchall()]
    assert "fp-fresh" in keys
    assert "fp-stale" not in keys


# ── Pipeline: _maybe_record_root_cause ───────────────────────────────────

def _scan_result(**overrides):
    base = {
        "state_key": "Pod:production/my-worker:crash",
        "title": "my-worker crash",
        "severity": "warning",
        "resource": "Pod/my-worker",
        "namespace": "production",
        "issue_type": "crash",
        "pod_name": "my-worker-abc",
        "node_name": "",
        "auto_resolve": False,
        "skip_llm": True,
        "metadata": {},
        "context_override": "",
        "event_reason": "",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_maybe_record_root_cause_records_for_critical_service(monkeypatch):
    monkeypatch.setattr(config, "ROOT_CAUSE_CORRELATION_ENABLED", True)
    monkeypatch.setattr(config, "ROOT_CAUSE_CORRELATION_SECONDS", 300)
    store = MagicMock()
    incident = SimpleNamespace(id=7, fingerprint="fp-redis")
    r = _scan_result(
        state_key="Pod:production/redis-master-0:oom",
        resource="Pod/redis-master-0",
        pod_name="redis-master-0",
    )
    with patch("src.engine.pipeline.config.is_nonprod_namespace", return_value=False):
        pipeline._maybe_record_root_cause(store, r, incident)
    store.record_root_cause.assert_called_once()
    kwargs = store.record_root_cause.call_args.kwargs
    assert kwargs["namespace"] == "production"
    assert kwargs["root_fingerprint"] == "fp-redis"
    assert kwargs["ttl_seconds"] == 300


def test_maybe_record_root_cause_skipped_for_nonprod(monkeypatch):
    monkeypatch.setattr(config, "ROOT_CAUSE_CORRELATION_ENABLED", True)
    monkeypatch.setattr(config, "ROOT_CAUSE_CORRELATION_SECONDS", 300)
    store = MagicMock()
    r = _scan_result(
        namespace="develop",
        resource="Pod/redis-master-0", pod_name="redis-master-0",
    )
    with patch("src.engine.pipeline.config.is_nonprod_namespace", return_value=True):
        pipeline._maybe_record_root_cause(
            store, r, SimpleNamespace(id=1, fingerprint="fp"),
        )
    store.record_root_cause.assert_not_called()


def test_maybe_record_root_cause_skipped_for_non_critical(monkeypatch):
    monkeypatch.setattr(config, "ROOT_CAUSE_CORRELATION_ENABLED", True)
    monkeypatch.setattr(config, "ROOT_CAUSE_CORRELATION_SECONDS", 300)
    store = MagicMock()
    pipeline._maybe_record_root_cause(
        store, _scan_result(),
        SimpleNamespace(id=1, fingerprint="fp"),
    )
    store.record_root_cause.assert_not_called()


def test_maybe_record_root_cause_disabled(monkeypatch):
    monkeypatch.setattr(config, "ROOT_CAUSE_CORRELATION_ENABLED", False)
    store = MagicMock()
    r = _scan_result(
        resource="Pod/redis-master-0", pod_name="redis-master-0",
    )
    pipeline._maybe_record_root_cause(
        store, r, SimpleNamespace(id=1, fingerprint="fp"),
    )
    store.record_root_cause.assert_not_called()


# ── Enrichment: _root_cause_correlation ──────────────────────────────────

def test_root_cause_correlation_empty_when_disabled(monkeypatch):
    monkeypatch.setattr(config, "ROOT_CAUSE_CORRELATION_ENABLED", False)
    store = MagicMock()
    out = enrichment._root_cause_correlation(store, _scan_result(), {})
    assert out == ""
    store.get_active_root_cause.assert_not_called()


def test_root_cause_correlation_empty_when_no_root(monkeypatch):
    monkeypatch.setattr(config, "ROOT_CAUSE_CORRELATION_ENABLED", True)
    store = MagicMock()
    store.get_active_root_cause.return_value = None
    assert enrichment._root_cause_correlation(store, _scan_result(), {}) == ""


def test_root_cause_correlation_empty_for_critical_service_alert(monkeypatch):
    """A critical-service alert IS a root cause — don't point it at
    another root."""
    monkeypatch.setattr(config, "ROOT_CAUSE_CORRELATION_ENABLED", True)
    store = MagicMock()
    store.get_active_root_cause.return_value = {
        "root_state_key": "Pod:production/redis-broker-0:oom",
        "started_at": time.time() - 120,
    }
    r = _scan_result(
        resource="Pod/redis-master-0", pod_name="redis-master-0",
    )
    assert enrichment._root_cause_correlation(store, r, {}) == ""


def test_root_cause_correlation_empty_for_the_root_itself(monkeypatch):
    monkeypatch.setattr(config, "ROOT_CAUSE_CORRELATION_ENABLED", True)
    store = MagicMock()
    same_state_key = "Pod:production/postgres-0:oom"
    store.get_active_root_cause.return_value = {
        "root_state_key": same_state_key,
        "started_at": time.time() - 30,
    }
    r = _scan_result(state_key=same_state_key)
    assert enrichment._root_cause_correlation(store, r, {}) == ""


def test_root_cause_correlation_emits_hint_for_dependent_alert(monkeypatch):
    monkeypatch.setattr(config, "ROOT_CAUSE_CORRELATION_ENABLED", True)
    store = MagicMock()
    store.get_active_root_cause.return_value = {
        "root_state_key": "Pod:production/postgres-0:oom",
        "started_at": time.time() - 180,
    }
    out = enrichment._root_cause_correlation(store, _scan_result(), {})
    assert "Correlates with active root" in out
    assert "postgres-0" in out
    assert "fired" in out
    # Alert is NOT suppressed — this is just a hint, ensure the message
    # explicitly encourages resilience audit.
    assert "still worth" in out or "downstream symptom" in out

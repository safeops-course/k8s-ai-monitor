"""A suppressed incident must keep telling the central store it is still alive.

While an incident sits inside its cooldown the pipeline records the occurrence
in SQLite and stays silent everywhere else — including towards ClickHouse. The
central row therefore froze at whatever was last pushed.

Measured on example 2026-09-17, one incident the scanner was still detecting on
every single cycle:

    local   occurrence_count 7452, last_seen_at 2026-09-17 12:23
    central occurrence_count 5191, last_seen_at 2026-09-15 07:56

Two days and 2261 occurrences apart. The consequence is worse than a stale
number: on the dashboard a live outage looked exactly like a fossil — an
incident whose condition is long gone but which nothing ever closed. Both show
an old timestamp, and only one of them needs someone to wake up.
"""
import time
from unittest.mock import MagicMock, patch

import pytest

from src import config
from src.engine import pipeline

_INTERVAL = 900


@pytest.fixture(autouse=True)
def _pin_interval():
    """Pin the throttle window so these tests do not depend on the ambient env.

    CENTRAL_HEARTBEAT_INTERVAL_SECONDS is operator-tunable and 0 disables
    heartbeats entirely — a deployment that sets it would turn every
    positive-path assertion here into a failure for a reason that has nothing
    to do with the code under test. test_zero_interval_disables_heartbeats
    patches over this with its own explicit 0.
    """
    with patch.object(config, "CENTRAL_HEARTBEAT_INTERVAL_SECONDS", _INTERVAL):
        yield


def _result(state_key="CriticalEndpoint:production/frontend-delta:prod.example.com"):
    r = MagicMock()
    r.state_key = state_key
    r.issue_type = "critical_endpoint"
    r.namespace = "production"
    r.resource = "Frontend/example"
    r.title = "Frontend down"
    return r


def _fresh(status="active", occurrence_count=7452, last_seen_at=1.0,
           active_since=555.0, first_seen_at=111.0):
    inc = MagicMock()
    inc.status = status
    inc.fingerprint = "fp"
    inc.severity = "critical"
    inc.owner_ref = "owner"
    inc.occurrence_count = occurrence_count
    inc.first_seen_at = first_seen_at
    inc.active_since = active_since
    inc.last_seen_at = last_seen_at
    return inc


def _store(incident):
    store = MagicMock()
    store.get_incident.return_value = incident
    return store


def setup_function():
    pipeline._last_heartbeat_push.clear()


def test_suppressed_incident_pushes_a_heartbeat():
    """The example case: still firing, so the central clock must move."""
    store = _store(_fresh(occurrence_count=7452, last_seen_at=999.0))
    with patch.object(pipeline.central_push, "push_incident") as push:
        pipeline._push_central_heartbeat(store, _result())
    push.assert_called_once()
    sent = push.call_args[0][0]
    assert sent["occurrence_count"] == 7452
    assert sent["last_seen_at"] == 999.0
    assert sent["status"] == "active"
    assert sent["event_type"] == "heartbeat"
    assert sent["auto_resolved"] is False
    # Omitting this is not neutral — the column DEFAULTs to first_seen_at, so a
    # heartbeat row would replace a good one and reset the active cycle start.
    assert sent["active_since"] == 555.0


def test_heartbeat_is_throttled_per_incident():
    """A chronic incident must not write a central row every scan cycle."""
    store = _store(_fresh())
    with patch.object(pipeline.central_push, "push_incident") as push:
        pipeline._push_central_heartbeat(store, _result())
        pipeline._push_central_heartbeat(store, _result())
        pipeline._push_central_heartbeat(store, _result())
    assert push.call_count == 1


def test_heartbeat_resumes_after_the_interval():
    store = _store(_fresh())
    r = _result()
    with patch.object(pipeline.central_push, "push_incident") as push:
        pipeline._push_central_heartbeat(store, r)
        pipeline._last_heartbeat_push[r.state_key] = time.time() - _INTERVAL - 1
        pipeline._push_central_heartbeat(store, r)
    assert push.call_count == 2


def test_resolved_incident_is_not_heartbeated():
    """A heartbeat says "still happening". A resolved row must not claim that."""
    store = _store(_fresh(status="resolved"))
    with patch.object(pipeline.central_push, "push_incident") as push:
        pipeline._push_central_heartbeat(store, _result())
    push.assert_not_called()


def test_vanished_incident_is_not_heartbeated():
    store = _store(None)
    with patch.object(pipeline.central_push, "push_incident") as push:
        pipeline._push_central_heartbeat(store, _result())
    push.assert_not_called()


def test_zero_interval_disables_heartbeats():
    store = _store(_fresh())
    with patch.object(config, "CENTRAL_HEARTBEAT_INTERVAL_SECONDS", 0):
        with patch.object(pipeline.central_push, "push_incident") as push:
            pipeline._push_central_heartbeat(store, _result())
    push.assert_not_called()
    store.get_incident.assert_not_called()


def test_push_failure_does_not_raise_and_does_not_mark_as_sent():
    """Best-effort: a failed heartbeat must not break the scan cycle, and must
    not pretend it succeeded — the next tick should try again."""
    store = _store(_fresh())
    r = _result()
    with patch.object(pipeline.central_push, "push_incident", side_effect=RuntimeError("boom")):
        pipeline._push_central_heartbeat(store, r)  # must not raise
    assert r.state_key not in pipeline._last_heartbeat_push


def test_silent_occurrence_triggers_a_heartbeat():
    """The wiring itself: the suppressed path is the only caller."""
    store = _store(_fresh())
    incident = MagicMock()
    incident.id = 7
    with patch.object(pipeline, "_record_occurrence"), \
         patch.object(pipeline, "_collect_context", return_value={}), \
         patch.object(pipeline, "_push_central_heartbeat") as hb:
        pipeline._record_silent_occurrence(store, incident, _result(), lambda *a, **k: {})
    hb.assert_called_once()


def test_active_since_falls_back_to_first_seen_at():
    """A never-reopened incident has no separate active cycle start."""
    store = _store(_fresh(active_since=None, first_seen_at=111.0))
    with patch.object(pipeline.central_push, "push_incident") as push:
        pipeline._push_central_heartbeat(store, _result())
    assert push.call_args[0][0]["active_since"] == 111.0


def test_throttle_map_does_not_grow_without_bound():
    """`Pod:{ns}/{name}` keys carry a pod name, and pod names churn forever."""
    store = _store(_fresh())
    with patch.object(pipeline.central_push, "push_incident"):
        for i in range(50):
            pipeline._push_central_heartbeat(store, _result(f"Pod:production/api-{i}:unhealthy"))
        assert len(pipeline._last_heartbeat_push) == 50

        # Age every entry past the window, then push once more.
        for key in pipeline._last_heartbeat_push:
            pipeline._last_heartbeat_push[key] = time.time() - _INTERVAL - 1
        pipeline._push_central_heartbeat(store, _result("Pod:production/api-fresh:unhealthy"))

    assert list(pipeline._last_heartbeat_push) == ["Pod:production/api-fresh:unhealthy"]


def test_eviction_does_not_break_throttling_for_a_live_entry():
    """Only entries that already fail the throttle check may be dropped."""
    store = _store(_fresh())
    r = _result()
    with patch.object(pipeline.central_push, "push_incident") as push:
        pipeline._push_central_heartbeat(store, r)
        pipeline._push_central_heartbeat(store, _result("Pod:production/other:unhealthy"))
        pipeline._push_central_heartbeat(store, r)  # still inside the window
    assert push.call_count == 2
    assert r.state_key in pipeline._last_heartbeat_push


def test_store_read_failure_does_not_raise_and_does_not_mark_as_sent():
    """SQLite raises on lock contention. A heartbeat is the last thing the
    suppressed path does, so an escaping error would abort the scan cycle
    part-way through incidents that still need handling."""
    import sqlite3
    store = MagicMock()
    store.get_incident.side_effect = sqlite3.OperationalError("database is locked")
    r = _result()
    with patch.object(pipeline.central_push, "push_incident") as push:
        pipeline._push_central_heartbeat(store, r)  # must not raise
    push.assert_not_called()
    assert r.state_key not in pipeline._last_heartbeat_push

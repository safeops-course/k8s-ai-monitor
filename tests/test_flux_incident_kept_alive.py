"""A Flux incident nobody will mention again must not decay into "resolved".

`Flux:HelmRelease:*` incidents are raised only by kopf events on the Flux
resource. Once Flux exhausts its retries it stops writing to the object, the
events stop, and the incident goes silent — while the problem remains exactly
as broken. The stale reaper in the store then closes any active incident whose
last_seen_at is over seven days old, reasoning that "a scanner would have
re-detected them". Nothing re-detects this one.

Measured on foxtrot, four minutes apart:

    occurrences=11  last_seen 81884s ago
    occurrences=11  last_seen 82125s ago

Frozen count, climbing age, on `frontend-7f09f73c` — a HelmRelease 290 hours
out of date, rolled back four times, that Flux had permanently given up on. At
seven days it would have been reported as recovered.

This is the inverse of every other fix in this area: those stop incidents being
closed too eagerly, this stops one being closed for lack of anyone talking
about it.
"""
from unittest.mock import MagicMock, patch

import pytest
from kubernetes import client as k8s

from src.scanners.reconcile import ReconcileScanner, _flux_resource_state


def _incident(state_key="Flux:HelmRelease:production/frontend-7f09f73c:stalled"):
    inc = MagicMock()
    inc.id = 42
    inc.state_key = state_key
    inc.issue_type = "stalled"
    inc.namespace = "production"
    return inc


def _store(incidents):
    store = MagicMock()
    # Only the first prefix query returns rows; the event-handler query is empty.
    store.get_active_incidents_by_prefix.side_effect = [incidents, []]
    return store


def _api(ready=None, status=None):
    api = MagicMock()
    if status is not None:
        api.get_namespaced_custom_object.side_effect = k8s.ApiException(status=status)
    else:
        conds = [] if ready is None else [{"type": "Ready", "status": ready}]
        api.get_namespaced_custom_object.return_value = {"status": {"conditions": conds}}
    return api


def _run(store, api):
    with patch("src.scanners.reconcile.k8s.CustomObjectsApi", return_value=api):
        return ReconcileScanner()._reconcile_flux(store)


# --- the tri-state read ------------------------------------------------------

@pytest.mark.parametrize("ready,status,expected", [
    ("True", None, "ready"),
    ("False", None, "failing"),
    (None, None, "unknown"),      # no Ready condition yet — mid-first-reconcile
    (None, 404, "gone"),
    (None, 500, "unknown"),
])
def test_resource_state(ready, status, expected):
    with patch("src.scanners.reconcile.k8s.CustomObjectsApi",
               return_value=_api(ready=ready, status=status)):
        assert _flux_resource_state("HelmRelease", "production", "x") == expected


def test_unknown_kind_makes_no_api_call():
    api = _api(ready="True")
    with patch("src.scanners.reconcile.k8s.CustomObjectsApi", return_value=api):
        assert _flux_resource_state("Nonsense", "production", "x") == "unknown"
    api.get_namespaced_custom_object.assert_not_called()


# --- keeping a failing incident alive ---------------------------------------

def test_failing_resource_is_kept_alive_and_not_resolved():
    """The foxtrot case: Flux gave up, events stopped, the chart is still wrong."""
    store = _store([_incident()])
    assert _run(store, _api(ready="False")) == []
    store.touch_incident.assert_called_once_with(42)


def test_ready_resource_resolves_and_is_not_touched():
    store = _store([_incident()])
    results = _run(store, _api(ready="True"))
    assert len(results) == 1 and results[0].auto_resolve is True
    store.touch_incident.assert_not_called()


def test_deleted_resource_resolves_and_is_not_touched():
    store = _store([_incident()])
    results = _run(store, _api(status=404))
    assert len(results) == 1 and results[0].auto_resolve is True
    store.touch_incident.assert_not_called()


def test_unreadable_resource_neither_resolves_nor_lies_about_being_seen():
    """An API error says nothing about the resource. Closing it would be a
    false resolve; touching it would be a false observation. Do neither and
    let the next pass decide."""
    store = _store([_incident()])
    assert _run(store, _api(status=500)) == []
    store.touch_incident.assert_not_called()


def test_keep_alive_failure_does_not_break_the_scan():
    """touch_incident is best-effort — the reconcile pass must survive it."""
    store = _store([_incident()])
    store.touch_incident.side_effect = RuntimeError("database is locked")
    assert _run(store, _api(ready="False")) == []


def test_keeping_alive_is_silent():
    """No ScanResult means no occurrence, no Slack, no escalation — the only
    thing that changes is last_seen_at. A chronic failure must not become a
    recurring alert just because we started watching it properly."""
    store = _store([_incident()])
    results = _run(store, _api(ready="False"))
    assert results == []
    store.record_occurrence.assert_not_called()
    store.bump_incident.assert_not_called()


def test_touch_incident_moves_last_seen_without_counting_an_occurrence(tmp_path):
    """The store-level guarantee the reaper depends on."""
    import time

    from src.engine.store.sqlite import SqliteStore

    store = SqliteStore(str(tmp_path / "t.db"))
    inc = store.create_incident(state_key="Flux:HelmRelease:production/x:stalled",
                                fingerprint="f", issue_type="stalled",
                                severity="critical", owner_ref="", namespace="production")
    conn = store._get_conn()
    conn.execute("UPDATE incidents SET last_seen_at = ? WHERE id = ?",
                 (time.time() - 8 * 86400, inc.id))
    conn.commit()

    before = store.get_incident("Flux:HelmRelease:production/x:stalled")
    assert time.time() - before.last_seen_at > 7 * 86400, "starts older than the reaper window"

    store.touch_incident(inc.id)

    after = store.get_incident("Flux:HelmRelease:production/x:stalled")
    assert time.time() - after.last_seen_at < 5
    assert after.occurrence_count == before.occurrence_count, "must not count as a sighting"
    assert after.status == "active"


# --- the keep-alive must win against the reaper ------------------------------
#
# touch_incident runs from the reconcile scanner; the stale reaper runs from the
# store-cleanup loop, on another thread with its own connection. The reaper used
# to SELECT stale ids and then UPDATE each one, so a touch landing between the
# two would be overwritten — closing an incident we had just confirmed is still
# failing, and which nothing will raise again. It is now one conditional UPDATE,
# so the predicate is evaluated at write time.

def _stale_incident(tmp_path, age_days=8):
    import time

    from src.engine.store.sqlite import SqliteStore

    store = SqliteStore(str(tmp_path / "t.db"))
    inc = store.create_incident(state_key="Flux:HelmRelease:production/x:stalled",
                                fingerprint="f", issue_type="stalled",
                                severity="critical", owner_ref="", namespace="production")
    conn = store._get_conn()
    conn.execute("UPDATE incidents SET last_seen_at = ? WHERE id = ?",
                 (time.time() - age_days * 86400, inc.id))
    conn.commit()
    return store, inc


def test_untouched_stale_incident_is_still_reaped(tmp_path):
    """The control. Without this the next test could pass on a broken reaper."""
    store, _ = _stale_incident(tmp_path)
    store.cleanup()
    assert store.get_incident("Flux:HelmRelease:production/x:stalled").status == "resolved"


def test_touch_before_the_reaper_saves_the_incident(tmp_path):
    store, inc = _stale_incident(tmp_path)
    store.touch_incident(inc.id)
    store.cleanup()
    assert store.get_incident("Flux:HelmRelease:production/x:stalled").status == "active"


# No interleaving test here, deliberately. An attempt using a sqlite3 progress
# handler to force a touch inside the reaper's window passed against the OLD
# SELECT-then-UPDATE implementation too — the handler fires on the first
# statement of cleanup(), long before the reaper, so the touch landed ahead of
# the SELECT rather than between it and the UPDATE. A test that cannot fail
# against the bug it describes is worse than no test, so it was removed rather
# than kept as decoration.
#
# The window is closed structurally instead: the reaper is now a single
# conditional UPDATE, so the predicate is evaluated at write time and there is
# no read-then-write gap for a concurrent touch to fall into.

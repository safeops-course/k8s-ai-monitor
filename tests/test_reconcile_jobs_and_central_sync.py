"""Incidents that stayed "active" although their cause was gone.

Jobs: a FailedMount event on a CronJob run raises `Job:ns/name:mount`. `mount`
is an event-only alias the pod scanner does not sweep, and the reconcile
scanner only looked at Deployment/StatefulSet/DaemonSet/Pod — so scheduled
job runs and a database init Job sat active for days after the Job finished
and was deleted.

Central board: every resolve is pushed once, without waiting or retrying.
An OOM incident was resolved locally, but the
board only ever got the earlier `escalation` row and showed it open three days
later. The CLI resolve path never pushed at all.
"""
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from kubernetes import client as k8s

from src import config
from src.engine import central_push
from src.scanners.reconcile import ReconcileScanner


def _incident(state_key, issue_type="mount"):
    inc = MagicMock()
    inc.state_key = state_key
    inc.issue_type = issue_type
    inc.namespace = ""
    inc.last_seen_at = time.time() - config.EVENT_ONLY_RESOLVE_GRACE_SECONDS - 60
    return inc


def _store(incidents):
    store = MagicMock()
    store.get_active_incidents_by_prefix.return_value = incidents
    return store


def _run(store, *, job=None, status=None):
    api = MagicMock()
    if status is not None:
        api.read_namespaced_job.side_effect = k8s.ApiException(status=status)
    else:
        api.read_namespaced_job.return_value = job
    with patch("src.scanners.reconcile.k8s.BatchV1Api", return_value=api):
        return ReconcileScanner()._reconcile_event_only_workloads(store)


def _job(succeeded=0, failed=0, active=0, conditions=()):
    conds = [SimpleNamespace(type=t, status=st) for t, st in conditions]
    return SimpleNamespace(status=SimpleNamespace(
        succeeded=succeeded, failed=failed, active=active, conditions=conds))


def test_job_prefix_is_queried():
    store = _store([])
    _run(store, status=404)
    prefixes = store.get_active_incidents_by_prefix.call_args[0][0]
    assert "Job:" in prefixes


def test_deleted_job_resolves():
    store = _store([_incident("Job:production/minute-changed-29842900:mount")])
    results = _run(store, status=404)
    assert [r.state_key for r in results] == ["Job:production/minute-changed-29842900:mount"]
    assert results[0].auto_resolve is True


def test_succeeded_job_resolves():
    store = _store([_incident("Job:platform/storage-usage-checker-29842365:mount")])
    assert len(_run(store, job=_job(succeeded=1, conditions=[("Complete", "True")]))) == 1


def test_partially_succeeded_job_is_kept_open():
    """completions: 3 with one pod done is not a finished Job."""
    store = _store([_incident("Job:production/x:mount")])
    assert _run(store, job=_job(succeeded=1, active=1)) == []


def test_failed_job_is_kept_open():
    store = _store([_incident("Job:production/postgresql-1-initdb:mount")])
    assert _run(store, job=_job(failed=1, conditions=[("Failed", "True")])) == []
    store.touch_incident.assert_called()


def test_running_job_is_kept_open():
    store = _store([_incident("Job:production/x:mount")])
    assert _run(store, job=_job(active=1)) == []


def test_unreadable_job_changes_nothing():
    store = _store([_incident("Job:production/x:mount")])
    assert _run(store, status=403) == []


# --------------------------------------------------------------------------
# central sync
# --------------------------------------------------------------------------

def _local(state_key, status):
    return SimpleNamespace(
        state_key=state_key, status=status, fingerprint="fp", issue_type="oom",
        severity="critical", owner_ref="", namespace="production", occurrence_count=1,
        first_seen_at=1.0, active_since=1.0, last_seen_at=2.0,
    )


def test_sync_repushes_only_locally_resolved_keys(monkeypatch):
    monkeypatch.setattr(config, "CENTRAL_AGGREGATE", True)
    local = {
        "Deployment:production/ai-service:oom": _local("Deployment:production/ai-service:oom", "resolved"),
        "Deployment:production/still-bad:oom": _local("Deployment:production/still-bad:oom", "active"),
    }
    store = MagicMock()
    store.get_incident.side_effect = local.get
    with patch.object(central_push, "_central_open_keys",
                      return_value=list(local) + ["Pod:production/gone-locally:mount"]), \
         patch.object(central_push, "_push") as push:
        n = central_push.sync_resolved_to_central(store)
    assert n == 1
    rows = push.call_args[0][1]
    assert [r["state_key"] for r in rows] == ["Deployment:production/ai-service:oom"]
    assert rows[0]["status"] == "resolved"


def test_sync_does_nothing_when_board_unreadable(monkeypatch):
    monkeypatch.setattr(config, "CENTRAL_AGGREGATE", True)
    store = MagicMock()
    with patch.object(central_push, "_central_open_keys", return_value=None), \
         patch.object(central_push, "_push") as push:
        assert central_push.sync_resolved_to_central(store) == 0
    push.assert_not_called()


def test_sync_is_off_without_central_aggregate(monkeypatch):
    monkeypatch.setattr(config, "CENTRAL_AGGREGATE", False)
    with patch.object(central_push, "_central_open_keys") as read:
        assert central_push.sync_resolved_to_central(MagicMock()) == 0
    read.assert_not_called()

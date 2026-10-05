"""A healthy pod must be able to clear its OOM incident.

uptrace-0 on devops accumulated 16 restarts over months. It was 1/1 Ready and
serving, yet `restart_count <= 1` made it permanently ineligible for recovery,
so its key stayed in `problem_keys` and the sweep at the end of PodScanner.scan
could never close the incident. The board showed a CRITICAL for a pod with
nothing wrong with it.

restart_count is cumulative over the container's lifetime — it says nothing
about now, and it never falls. uptime_s does: it is measured from the CURRENT
container's start, so it is exactly "time since the last restart", and
Kubernetes caps CrashLoopBackOff at 5 minutes, so past that cap the container
is provably not in a restart-backoff loop.
"""
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from src import config
from src.scanners.pod import PodScanner


def _oom_pod(*, restart_count, uptime_s, ready=True, phase="Running",
             name="uptrace-0", namespace="uptrace"):
    now = datetime.now(timezone.utc)
    pod = MagicMock()
    pod.metadata.name = name
    pod.metadata.namespace = namespace
    pod.metadata.owner_references = []
    pod.spec.node_name = "node-1"
    pod.status.phase = phase
    pod.status.reason = None
    cond = MagicMock()
    cond.type = "Ready"
    cond.status = "True" if ready else "False"
    pod.status.conditions = [cond]

    cs = MagicMock()
    cs.ready = ready
    cs.restart_count = restart_count
    cs.state.waiting = None
    cs.state.terminated = None
    cs.state.running.started_at = now - timedelta(seconds=uptime_s)
    cs.last_state.terminated.reason = "OOMKilled"
    cs.last_state.terminated.finished_at = now - timedelta(seconds=uptime_s + 1)
    pod.status.container_statuses = [cs]
    return pod


def _scan(pod):
    """Run PodScanner over one pod; return its ScanResults."""
    core = MagicMock()
    core.list_namespaced_pod.return_value = MagicMock(items=[pod])
    store = MagicMock()
    store.get_active_incidents_by_prefix.return_value = []
    with patch("src.scanners.pod.k8s.CoreV1Api", return_value=core), \
         patch("src.scanners.pod.config.get_namespaces", return_value=["uptrace"]), \
         patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.scanners.pod.resolve_owner_key",
               return_value="StatefulSet:uptrace/uptrace"):
        return PodScanner().scan()


def _oom_results(results):
    return [r for r in results if r.state_key.endswith(":oom")]


def test_many_restarts_do_not_block_recovery():
    """The uptrace-0 case: 16 restarts, Ready, long uptime -> recovered."""
    results = _oom_results(_scan(_oom_pod(restart_count=16, uptime_s=3600)))
    assert results, "the scanner produced no oom ScanResult at all"
    assert results[0].auto_resolve is True
    assert "recovered" in results[0].title


def test_recent_restart_is_not_recovery():
    """Inside the stability window the pod may still be looping."""
    results = _oom_results(_scan(_oom_pod(restart_count=1, uptime_s=30)))
    assert results
    assert results[0].auto_resolve is False


def test_not_ready_is_not_recovery():
    """Uptime alone is not enough — the pod has to actually be serving."""
    results = _oom_results(
        _scan(_oom_pod(restart_count=0, uptime_s=3600, ready=False)))
    assert results
    assert results[0].auto_resolve is False


def test_window_is_configurable(monkeypatch):
    """A workload that OOMs on a slow cycle needs a longer window."""
    pod = _oom_pod(restart_count=3, uptime_s=700)
    monkeypatch.setattr(config, "POD_OOM_RECOVERY_STABLE_SECONDS", 600)
    assert _oom_results(_scan(pod))[0].auto_resolve is True
    monkeypatch.setattr(config, "POD_OOM_RECOVERY_STABLE_SECONDS", 1800)
    assert _oom_results(_scan(pod))[0].auto_resolve is False


@pytest.mark.parametrize("seconds", [599, 601])
def test_window_boundary(seconds):
    """The default is 2x Kubernetes' 5-minute CrashLoopBackOff cap."""
    assert config.POD_OOM_RECOVERY_STABLE_SECONDS == 600
    recovered = _oom_results(
        _scan(_oom_pod(restart_count=9, uptime_s=seconds)))[0].auto_resolve
    assert recovered is (seconds > 600)

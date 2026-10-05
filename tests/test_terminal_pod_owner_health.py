"""A terminal pod whose owner is healthy is a corpse, not an incident.

Kubernetes keeps Evicted/Failed pods in the API until the terminated-pod GC
threshold is reached (12500 by default), so on a cluster that evicts rarely they
never leave. Every scan rediscovers them and re-raises the same incident.

An Evicted pod (`worker-history-86dfb94449-84cl4`) alerted 1495 times over the next 11 days while its Deployment sat at 1/1
Available. The eviction cause — a missing memory request — was fixed the day
after. The pod kept repeating the original kubelet message, `request is 0`,
long after it had stopped being true.
"""
from unittest.mock import MagicMock, patch

from src.scanners.pod import PodScanner, _owner_is_healthy


def _pod(phase="Failed", owner_kind="ReplicaSet", owner_name="rs-1"):
    p = MagicMock()
    p.status.phase = phase
    p.metadata.namespace = "platform"
    p.metadata.name = "worker-history-86dfb94449-84cl4"
    ref = MagicMock()
    ref.kind = owner_kind
    ref.name = owner_name
    p.metadata.owner_references = [ref] if owner_kind else []
    return p


def _apps(ready, want, kind="Deployment"):
    """AppsV1Api stub: ReplicaSet -> Deployment/StatefulSet with given replicas."""
    api = MagicMock()
    rs = MagicMock()
    rs_owner = MagicMock()
    rs_owner.kind = kind
    rs_owner.name = "worker-history"
    rs.metadata.owner_references = [rs_owner]
    api.read_namespaced_replica_set.return_value = rs
    workload = MagicMock()
    workload.spec.replicas = want
    workload.status.ready_replicas = ready
    api.read_namespaced_deployment.return_value = workload
    api.read_namespaced_stateful_set.return_value = workload
    return api


def test_failed_pod_with_healthy_deployment_is_a_corpse():
    """The real case: Evicted pod, Deployment 1/1 Available."""
    with patch("src.scanners.pod.k8s.AppsV1Api", return_value=_apps(ready=1, want=1)):
        assert _owner_is_healthy(_pod(), "platform") is True


def test_failed_pod_with_degraded_deployment_still_alerts():
    """0 of 1 ready — the eviction is current, not history."""
    with patch("src.scanners.pod.k8s.AppsV1Api", return_value=_apps(ready=0, want=1)):
        assert _owner_is_healthy(_pod(), "platform") is False


def test_partially_available_deployment_still_alerts():
    """2 of 3 ready is degraded, even though something is serving."""
    with patch("src.scanners.pod.k8s.AppsV1Api", return_value=_apps(ready=2, want=3)):
        assert _owner_is_healthy(_pod(), "platform") is False


def test_running_pod_is_never_suppressed():
    """A Running pod's own state is the signal — the owner is irrelevant.

    Without this guard a healthy Deployment would mask a pod that is genuinely
    failing right now.
    """
    with patch("src.scanners.pod.k8s.AppsV1Api", return_value=_apps(ready=1, want=1)):
        assert _owner_is_healthy(_pod(phase="Running"), "platform") is False


def test_statefulset_owner_is_handled():
    """StatefulSet pods name the StatefulSet directly — there is no ReplicaSet
    in between, unlike Deployments."""
    with patch("src.scanners.pod.k8s.AppsV1Api", return_value=_apps(ready=3, want=3)):
        assert _owner_is_healthy(
            _pod(owner_kind="StatefulSet", owner_name="redis"), "platform") is True


def test_statefulset_owner_degraded_still_alerts():
    with patch("src.scanners.pod.k8s.AppsV1Api", return_value=_apps(ready=1, want=3)):
        assert _owner_is_healthy(
            _pod(owner_kind="StatefulSet", owner_name="redis"), "platform") is False


def test_scaled_to_zero_is_not_healthy():
    """0 desired replicas must not read as 'fully available' and swallow the pod."""
    with patch("src.scanners.pod.k8s.AppsV1Api", return_value=_apps(ready=0, want=0)):
        assert _owner_is_healthy(_pod(), "platform") is False


def test_bare_pod_with_no_owner_still_alerts():
    """No owner to vouch for it — report rather than swallow."""
    with patch("src.scanners.pod.k8s.AppsV1Api", return_value=_apps(ready=1, want=1)):
        assert _owner_is_healthy(_pod(owner_kind=None), "platform") is False


def test_api_failure_still_alerts():
    """Unknown owner state must not silence a terminal pod."""
    api = MagicMock()
    api.read_namespaced_replica_set.side_effect = RuntimeError("apiserver down")
    with patch("src.scanners.pod.k8s.AppsV1Api", return_value=api):
        assert _owner_is_healthy(_pod(), "platform") is False


def _terminated_container(reason="OOMKilled"):
    cs = MagicMock()
    cs.state.waiting = None
    cs.state.running = None
    cs.state.terminated.reason = reason
    cs.last_state.terminated = None
    cs.restart_count = 0
    return cs


def _scan(pod, apps):
    core = MagicMock()
    core.list_namespaced_pod.return_value = MagicMock(items=[pod])
    store = MagicMock()
    store.get_active_incidents_by_prefix.return_value = []
    with patch("src.scanners.pod.k8s.CoreV1Api", return_value=core), \
         patch("src.scanners.pod.k8s.AppsV1Api", return_value=apps), \
         patch("src.scanners.pod.config.get_namespaces", return_value=["platform"]), \
         patch("src.scanners.pod.resolve_owner_key",
               return_value="Deployment:platform/worker-history"), \
         patch("src.handlers.startup.get_store", return_value=store):
        return PodScanner().scan()


def _corpse(pod_reason=""):
    """A terminal pod carrying an OOMKilled terminated container."""
    p = _pod()
    p.status.reason = pod_reason
    p.status.conditions = []
    p.status.container_statuses = [_terminated_container()]
    p.spec.node_name = "node-1"
    return p


def test_scan_emits_nothing_for_a_corpse_with_an_oomkilled_container():
    """The gate has to cover the whole pod, not just the pod-reason branch.

    A terminal pod also carries terminated container states, and those are read
    further down the loop. `OOMKilled` is deliberately NOT in POD_PROBLEM_REASONS
    — it is matched on the container — so a Failed pod whose status.reason falls
    outside that set would previously reach the container checks and raise a
    critical OOM alert even though its Deployment was fully available.
    """
    results = _scan(_corpse(), _apps(ready=1, want=1))
    assert [r for r in results if not r.auto_resolve] == []


def test_scan_still_reports_the_same_corpse_when_the_owner_is_degraded():
    """Same pod, same container state — the only difference is 0/1 ready. This
    is what proves the test above measures owner health and not a mock that
    silently produces nothing."""
    results = _scan(_corpse(), _apps(ready=0, want=1))
    assert [r.issue_type for r in results if not r.auto_resolve] == ["oom"]


def test_scan_still_reports_an_evicted_pod_when_the_owner_is_degraded():
    results = _scan(_corpse(pod_reason="Evicted"), _apps(ready=0, want=1))
    active = [r for r in results if not r.auto_resolve]
    assert len(active) == 1
    assert active[0].title == "Pod Issue: Evicted"

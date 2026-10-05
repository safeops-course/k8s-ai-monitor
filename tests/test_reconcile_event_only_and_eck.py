"""Incidents that nothing was closing: ECK CRs and event-only workload aliases.

Two separate holes, both found by auditing active incidents: most had a
condition that was verifiably gone.

ECK: every sweeper keys off a state_key prefix, and no prefix matched
`Elasticsearch:` / `Kibana:` / `ApmServer:`. Not one incident on those kinds
had ever been auto-resolved - a Kibana incident could stay active for months
while `kubectl get kibana` read green throughout.

Event-only workload aliases: `events.py` raises these (a probe failure lands as
`unhealthy`) and schedules an in-memory deferred check to close them. The pod
scanner then refuses to sweep them by design — it cannot confirm a probe-level
condition from pod state, so closing them blindly would resolve live problems.
That leaves the deferred task as the only closer, and it is neither durable nor
repeated: india's monitor restarted at 07:32 and three incidents raised at
07:26-07:27 by the previous pod stayed active for hours, and a fourth was
checked once while its owner was still restarting and never revisited.
"""
import time
from unittest.mock import MagicMock, patch

from kubernetes import client as k8s

from src import config
from src.scanners.reconcile import ReconcileScanner


def _incident(state_key, issue_type="unhealthy", last_seen_at=None, namespace=""):
    inc = MagicMock()
    inc.state_key = state_key
    inc.issue_type = issue_type
    inc.namespace = namespace
    # Default well past the grace window so tests opt IN to freshness.
    inc.last_seen_at = (
        last_seen_at
        if last_seen_at is not None
        else time.time() - config.EVENT_ONLY_RESOLVE_GRACE_SECONDS - 60
    )
    return inc


def _store(incidents):
    store = MagicMock()
    store.get_active_incidents_by_prefix.return_value = incidents
    return store


# --------------------------------------------------------------------------
# ECK
# --------------------------------------------------------------------------

def _eck_api(obj=None, status=None):
    api = MagicMock()
    if status is not None:
        api.get_namespaced_custom_object.side_effect = k8s.ApiException(status=status)
    else:
        api.get_namespaced_custom_object.return_value = obj
    return api


def _run_eck(store, api):
    with patch("src.scanners.reconcile.k8s.CustomObjectsApi", return_value=api):
        return ReconcileScanner()._reconcile_eck(store)


def test_green_elasticsearch_resolves():
    """The devops case, inverted: green means the incident is over."""
    store = _store([_incident("Elasticsearch:elastic-system/devops:unhealthy")])
    results = _run_eck(store, _eck_api(obj={"status": {"health": "green"}}))
    assert len(results) == 1
    assert results[0].auto_resolve is True
    assert results[0].state_key == "Elasticsearch:elastic-system/devops:unhealthy"


def test_green_kibana_resolves():
    """Kibana publishes the same status.health, and was the six-month fossil."""
    store = _store([_incident("Kibana:elastic-system/devops:unhealthy")])
    results = _run_eck(store, _eck_api(obj={"status": {"health": "green"}}))
    assert len(results) == 1
    assert results[0].auto_resolve is True


def test_deleted_eck_resource_resolves():
    """A CR that is gone cannot still be unhealthy."""
    store = _store([_incident("ApmServer:elastic-system/devops:unhealthy")])
    results = _run_eck(store, _eck_api(status=404))
    assert len(results) == 1
    assert results[0].auto_resolve is True


def test_red_elasticsearch_is_kept_alive_not_resolved():
    """Still broken: hold it open AND refresh last_seen so the reaper waits."""
    inc = _incident("Elasticsearch:elastic-system/devops:unhealthy")
    inc.id = 42
    store = _store([inc])
    results = _run_eck(store, _eck_api(obj={"status": {"health": "red"}}))
    assert results == []
    store.touch_incident.assert_called_once_with(42)


def test_yellow_elasticsearch_is_not_resolved():
    store = _store([_incident("Elasticsearch:elastic-system/devops:unhealthy")])
    assert _run_eck(store, _eck_api(obj={"status": {"health": "yellow"}})) == []


def test_unreadable_eck_resource_changes_nothing():
    """A failed read is not recovery — leave the incident exactly as found.

    Deliberately NOT kept alive, unlike a red CR or an unrecovered workload.
    "Cannot read" is not "still broken", and `_reconcile_flux` has always made
    the same call for the identical case. Touching last_seen_at here would make
    an incident immortal to the stale reaper for as long as the API keeps
    failing — trading a fossil we can close for one we never can.
    """
    inc = _incident("Elasticsearch:elastic-system/devops:unhealthy")
    store = _store([inc])
    results = _run_eck(store, _eck_api(status=500))
    assert results == []
    store.touch_incident.assert_not_called()


# --------------------------------------------------------------------------
# Event-only workload aliases
# --------------------------------------------------------------------------

def _run_workloads(store, healthy=True):
    with patch("src.scanners.reconcile.owner_fully_available", return_value=healthy):
        return ReconcileScanner()._reconcile_event_only_workloads(store)


def test_recovered_deployment_with_unhealthy_alias_resolves():
    """india's admin-web: owner healthy, incident orphaned by a restart."""
    store = _store([_incident("Deployment:platform/admin-web:unhealthy")])
    results = _run_workloads(store, healthy=True)
    assert len(results) == 1
    assert results[0].auto_resolve is True
    assert results[0].state_key == "Deployment:platform/admin-web:unhealthy"


def test_statefulset_with_unhealthy_alias_resolves():
    store = _store([_incident(
        "StatefulSet:platform/alertmanager-prometheus-kube-prometheus-alertmanager:unhealthy"
    )])
    assert len(_run_workloads(store, healthy=True)) == 1


def test_owner_still_unhealthy_is_left_open_and_kept_alive():
    """owner_fully_available fails closed; so must we — and the incident must
    also survive the 7-day reaper, since an owner that is quietly down emits no
    fresh events to refresh last_seen_at on its own."""
    inc = _incident("Deployment:production/asset-service:unhealthy")
    inc.id = 7
    store = _store([inc])
    assert _run_workloads(store, healthy=False) == []
    store.touch_incident.assert_called_once_with(7)


def test_alias_the_pod_scanner_sweeps_is_left_alone():
    """`crash` is pod.py's job. Two closers for one incident is a bug, not a fix."""
    store = _store([_incident("Deployment:production/asset-service:crash")])
    assert _run_workloads(store, healthy=True) == []


def test_fresh_incident_is_left_to_the_deferred_check():
    """Inside the grace window the in-memory fast path still owns it."""
    store = _store([_incident(
        "Deployment:platform/admin-web:unhealthy",
        last_seen_at=time.time(),
    )])
    assert _run_workloads(store, healthy=True) == []


def test_deleted_pod_resolves():
    """india's app-postgres-1: owner_fully_available says False for a
    bare Pod key, so the pod is read directly and a 404 means recovered."""
    store = _store([_incident("Pod:platform/app-postgres-1:unhealthy")])
    api = MagicMock()
    api.read_namespaced_pod.side_effect = k8s.ApiException(status=404)
    with patch("src.scanners.reconcile.k8s.CoreV1Api", return_value=api):
        results = ReconcileScanner()._reconcile_event_only_workloads(store)
    assert len(results) == 1
    assert results[0].auto_resolve is True


def test_running_ready_pod_resolves():
    store = _store([_incident("Pod:platform/app-postgres-1:unhealthy")])
    pod = MagicMock()
    pod.status.phase = "Running"
    cond = MagicMock()
    cond.type, cond.status = "Ready", "True"
    pod.status.conditions = [cond]
    api = MagicMock()
    api.read_namespaced_pod.return_value = pod
    with patch("src.scanners.reconcile.k8s.CoreV1Api", return_value=api):
        results = ReconcileScanner()._reconcile_event_only_workloads(store)
    assert len(results) == 1


def test_running_but_not_ready_pod_is_left_open():
    store = _store([_incident("Pod:platform/app-postgres-1:unhealthy")])
    pod = MagicMock()
    pod.status.phase = "Running"
    cond = MagicMock()
    cond.type, cond.status = "Ready", "False"
    pod.status.conditions = [cond]
    api = MagicMock()
    api.read_namespaced_pod.return_value = pod
    with patch("src.scanners.reconcile.k8s.CoreV1Api", return_value=api):
        assert ReconcileScanner()._reconcile_event_only_workloads(store) == []
    store.touch_incident.assert_called_once()


def test_unreadable_pod_is_left_open():
    """A 500 is not a 404. Cannot tell must never close an incident."""
    inc = _incident("Pod:platform/app-postgres-1:unhealthy")
    inc.id = 9
    store = _store([inc])
    api = MagicMock()
    api.read_namespaced_pod.side_effect = k8s.ApiException(status=500)
    with patch("src.scanners.reconcile.k8s.CoreV1Api", return_value=api):
        assert ReconcileScanner()._reconcile_event_only_workloads(store) == []
    store.touch_incident.assert_called_once_with(9)


# --------------------------------------------------------------------------
# The grace window vs the deferred delay — an invariant, not a suggestion
# --------------------------------------------------------------------------

def _reloaded_config(**env):
    """Values config computes under these env vars, with the module restored.

    Returns a snapshot, not the module: importlib.reload mutates in place and
    returns the same object, so handing back the module would hand back one the
    restoring reload had already reset.
    """
    import importlib
    import os
    import src.config
    old = {k: os.environ.get(k) for k in env}
    os.environ.update({k: str(v) for k, v in env.items()})
    try:
        reloaded = importlib.reload(src.config)
        return {
            "grace": reloaded.EVENT_ONLY_RESOLVE_GRACE_SECONDS,
            "delay": reloaded.EVENT_AUTO_RESOLVE_DELAY_SECONDS,
        }
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        importlib.reload(src.config)


def test_grace_window_sits_above_the_deferred_delay():
    """The durable path must never race the fast one."""
    assert (
        config.EVENT_ONLY_RESOLVE_GRACE_SECONDS
        > config.EVENT_AUTO_RESOLVE_DELAY_SECONDS
    )


def test_a_too_low_grace_override_is_raised_not_honoured():
    """min_value alone cannot catch this: 60 is a legal non-negative int."""
    cfg = _reloaded_config(EVENT_ONLY_RESOLVE_GRACE_SECONDS=60)
    assert cfg["grace"] > cfg["delay"]


def test_a_raised_deferred_delay_also_lifts_the_grace_window():
    """The other side of the invariant, and the one min_value cannot see at all
    — parse_env_int never range-checks a default."""
    cfg = _reloaded_config(EVENT_AUTO_RESOLVE_DELAY_SECONDS=3600)
    assert cfg["delay"] == 3600
    assert cfg["grace"] > 3600


# --------------------------------------------------------------------------
# cert-manager (event-born Certificate / Challenge / Order / CertificateRequest)
# --------------------------------------------------------------------------
#
# Found in practice: the same three warnings stayed open for 4-5
# days — `Certificate:platform/project-tls:error` plus two
# `Challenge:…:error` — while `kubectl get certificate project-tls` read READY
# and the Challenges no longer existed. The certificate scanner closes under
# `Certificate:ns/name` (no alias), so it never matched the event-born key,
# and nothing at all keyed off `Challenge:`.

def _run_cert_manager(store, api):
    with patch("src.scanners.reconcile.k8s.CustomObjectsApi", return_value=api):
        return ReconcileScanner()._reconcile_cert_manager(store)


def test_ready_certificate_resolves_event_born_incident():
    store = _store([_incident("Certificate:platform/project-tls:error", issue_type="error")])
    api = _eck_api(obj={"status": {"conditions": [{"type": "Ready", "status": "True"}]}})
    results = _run_cert_manager(store, api)
    assert len(results) == 1
    assert results[0].auto_resolve is True
    assert results[0].state_key == "Certificate:platform/project-tls:error"
    assert results[0].issue_type == "error"
    api.get_namespaced_custom_object.assert_called_once_with(
        "cert-manager.io", "v1", "platform", "certificates", "project-tls",
    )


def test_deleted_challenge_resolves():
    """cert-manager garbage-collects Challenges once the Order completes."""
    store = _store([_incident("Challenge:platform/project-tls-5-1430682407-3632305355:error")])
    api = _eck_api(status=404)
    results = _run_cert_manager(store, api)
    assert len(results) == 1
    assert results[0].auto_resolve is True
    api.get_namespaced_custom_object.assert_called_once_with(
        "acme.cert-manager.io", "v1", "platform", "challenges",
        "project-tls-5-1430682407-3632305355",
    )


def test_valid_order_resolves():
    store = _store([_incident("Order:platform/project-tls-5-1430682407:error")])
    results = _run_cert_manager(store, _eck_api(obj={"status": {"state": "valid"}}))
    assert len(results) == 1
    assert results[0].auto_resolve is True


def test_errored_challenge_is_kept_alive_not_resolved():
    inc = _incident("Challenge:platform/project-tls-5-1-2:error")
    inc.id = 7
    store = _store([inc])
    results = _run_cert_manager(store, _eck_api(obj={"status": {"state": "errored"}}))
    assert results == []
    store.touch_incident.assert_called_once_with(7)


def test_not_ready_certificate_is_kept_alive_not_resolved():
    inc = _incident("Certificate:platform/project-tls:error")
    inc.id = 8
    store = _store([inc])
    api = _eck_api(obj={"status": {"conditions": [{"type": "Ready", "status": "False"}]}})
    assert _run_cert_manager(store, api) == []
    store.touch_incident.assert_called_once_with(8)


def test_pending_challenge_changes_nothing():
    """In-flight is neither recovered nor failed — wait for cert-manager."""
    store = _store([_incident("Challenge:platform/project-tls-5-1-2:error")])
    assert _run_cert_manager(store, _eck_api(obj={"status": {"state": "pending"}})) == []
    store.touch_incident.assert_not_called()


def test_forbidden_read_changes_nothing():
    """The RBAC gap: a Forbidden read must never be mistaken for recovery."""
    store = _store([_incident("Challenge:platform/project-tls-5-1-2:error")])
    assert _run_cert_manager(store, _eck_api(status=403)) == []
    store.touch_incident.assert_not_called()


def test_scanner_owned_certificate_key_is_left_alone():
    """`Certificate:ns/name` without an alias belongs to the certificate scanner."""
    store = _store([_incident("Certificate:platform/project-tls", issue_type="certificate")])
    api = _eck_api(obj={"status": {"conditions": [{"type": "Ready", "status": "True"}]}})
    assert _run_cert_manager(store, api) == []
    api.get_namespaced_custom_object.assert_not_called()


def test_scan_wires_in_cert_manager():
    store = _store([])
    with patch("src.handlers.startup.get_store", return_value=store), \
         patch.object(ReconcileScanner, "_reconcile_cert_manager", return_value=[]) as m:
        ReconcileScanner().scan()
    m.assert_called_once_with(store)


def _cond(type_, status, reason=None):
    c = {"type": type_, "status": status}
    if reason:
        c["reason"] = reason
    return c


def test_pending_certificaterequest_changes_nothing():
    """Ready=False/Pending is cert-manager still waiting on the issuer."""
    store = _store([_incident("CertificateRequest:platform/project-tls-abc:error")])
    api = _eck_api(obj={"status": {"conditions": [_cond("Ready", "False", "Pending")]}})
    assert _run_cert_manager(store, api) == []
    store.touch_incident.assert_not_called()


def test_certificate_awaiting_first_issuance_changes_nothing():
    """Ready=False/DoesNotExist: the Secret is not written yet, not a failure."""
    store = _store([_incident("Certificate:platform/project-tls:error")])
    api = _eck_api(obj={"status": {"conditions": [_cond("Ready", "False", "DoesNotExist")]}})
    assert _run_cert_manager(store, api) == []
    store.touch_incident.assert_not_called()


def test_denied_certificaterequest_is_kept_alive_even_if_ready_is_pending():
    inc = _incident("CertificateRequest:platform/project-tls-abc:error")
    inc.id = 9
    store = _store([inc])
    api = _eck_api(obj={"status": {"conditions": [
        _cond("Ready", "False", "Pending"), _cond("Denied", "True", "policy.cert-manager.io"),
    ]}})
    assert _run_cert_manager(store, api) == []
    store.touch_incident.assert_called_once_with(9)


def test_invalid_certificaterequest_is_kept_alive_without_ready_condition():
    inc = _incident("CertificateRequest:platform/project-tls-abc:error")
    inc.id = 10
    store = _store([inc])
    api = _eck_api(obj={"status": {"conditions": [_cond("InvalidRequest", "True", "RequestParsingError")]}})
    assert _run_cert_manager(store, api) == []
    store.touch_incident.assert_called_once_with(10)


def test_failed_certificaterequest_is_kept_alive():
    inc = _incident("CertificateRequest:platform/project-tls-abc:error")
    inc.id = 11
    store = _store([inc])
    api = _eck_api(obj={"status": {"conditions": [_cond("Ready", "False", "Failed")]}})
    assert _run_cert_manager(store, api) == []
    store.touch_incident.assert_called_once_with(11)


def test_certificate_ready_unknown_status_changes_nothing():
    store = _store([_incident("Certificate:platform/project-tls:error")])
    api = _eck_api(obj={"status": {"conditions": [_cond("Ready", "Unknown")]}})
    assert _run_cert_manager(store, api) == []
    store.touch_incident.assert_not_called()


def test_denied_condition_false_does_not_count_as_terminal():
    """Denied=False is the approver saying nothing; Ready=True still closes."""
    store = _store([_incident("CertificateRequest:platform/project-tls-abc:error")])
    api = _eck_api(obj={"status": {"conditions": [
        _cond("Denied", "False"), _cond("Ready", "True", "Issued"),
    ]}})
    results = _run_cert_manager(store, api)
    assert len(results) == 1 and results[0].auto_resolve is True

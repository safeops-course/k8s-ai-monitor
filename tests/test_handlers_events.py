"""Tests for Sprint 9 events.py pipeline unification (PRs #51 + #52).

The pod-event batch flush, non-pod event fallback and NodeNotReady path
previously called `notifier.post_alert` directly. Post-Sprint-9 they all
emit `ScanResult`s and invoke `process_scan_results`. These tests cover
the emission contract (individual mode, collective batch mode, non-pod
fallback, NodeNotReady path), the deferred auto-resolve path — which now
emits `auto_resolve=True` ScanResults through the pipeline instead of
posting `post_resolved` directly — and regression guards against the
re-introduction of the deleted `_analyze_and_alert` / `is_seen` /
`mark_seen` helpers.
"""
import asyncio
import logging
from unittest.mock import patch

import pytest

from src import config
from src.engine.store.sqlite import SqliteStore
from src.handlers import events as events_handler


@pytest.fixture(autouse=True)
def _clear_in_flight():
    events_handler._in_flight.clear()
    events_handler._pod_event_batch.clear()
    yield
    events_handler._in_flight.clear()
    events_handler._pod_event_batch.clear()


@pytest.fixture(autouse=True)
def _watch_everything(monkeypatch):
    monkeypatch.setattr(config, "WATCH_ALL_NAMESPACES", True)
    monkeypatch.setattr(config, "EXCLUDE_NAMESPACES", set())
    monkeypatch.setattr(config, "NON_PROD_NAMESPACES", set())
    monkeypatch.setattr(config, "ALERT_EXCLUDE_WORKLOADS", ())


def _run(coro):
    return asyncio.run(coro)


# ── _flush_pod_event_batch — individual mode ──────────────────────────

def test_individual_mode_emits_scanresult_per_event(tmp_path):
    """Below the batch threshold, each surviving event becomes its own
    ScanResult and they all go through one process_scan_results call."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    events_handler._pod_event_batch["prod"] = [
        ("api-1", "Deployment:prod/api", "Deployment:prod/api:oom", "node-a", "OOMKilled"),
        ("web-1", "Deployment:prod/web", "Deployment:prod/web:crash", "node-b", "CrashLoopBackOff"),
    ]

    with patch("src.handlers.events.process_scan_results") as psr, \
         patch("src.handlers.events._get_collector") as col, \
         patch("src.handlers.events._is_pod_ready_now", return_value=False), \
         patch("src.handlers.events._pod_exists", return_value=True), \
         patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.handlers.events._BATCH_WINDOW_SECONDS", 0):
        col.return_value.collect_pod_context_with_diagnostics.return_value = {"pod": {}}
        _run(events_handler._flush_pod_event_batch("prod"))

    psr.assert_called_once()
    results = psr.call_args.args[0]
    assert len(results) == 2
    oom, crash = results
    assert oom.state_key == "Deployment:prod/api:oom"
    assert oom.severity == "critical"         # OOMKilled → critical
    assert oom.issue_type == "oom"
    assert oom.skip_llm is True
    assert oom.pod_name == "api-1"
    assert oom.node_name == "node-a"
    assert crash.state_key == "Deployment:prod/web:crash"
    assert crash.severity == "warning"        # CrashLoop → warning
    assert crash.issue_type == "crash"


def test_individual_mode_skips_recovered_pods(tmp_path):
    """Pod reported ready before the flush fires — no ScanResult."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    events_handler._pod_event_batch["prod"] = [
        ("api-1", "Deployment:prod/api", "Deployment:prod/api:crash", "", "CrashLoopBackOff"),
    ]

    with patch("src.handlers.events.process_scan_results") as psr, \
         patch("src.handlers.events._get_collector") as col, \
         patch("src.handlers.events._is_pod_ready_now", return_value=True), \
         patch("src.handlers.events._pod_exists", return_value=True), \
         patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.handlers.events._BATCH_WINDOW_SECONDS", 0):
        col.return_value.collect_pod_context_with_diagnostics.return_value = {"pod": {}}
        _run(events_handler._flush_pod_event_batch("prod"))

    psr.assert_not_called()


def test_individual_mode_skips_deleted_pods(tmp_path):
    """Pod was deleted between event firing and flush — no ScanResult."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    events_handler._pod_event_batch["prod"] = [
        ("api-1", "Deployment:prod/api", "Deployment:prod/api:crash", "", "CrashLoopBackOff"),
    ]

    with patch("src.handlers.events.process_scan_results") as psr, \
         patch("src.handlers.events._get_collector") as col, \
         patch("src.handlers.events._is_pod_ready_now", return_value=False), \
         patch("src.handlers.events._pod_exists", return_value=False), \
         patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.handlers.events._BATCH_WINDOW_SECONDS", 0):
        col.return_value.collect_pod_context_with_diagnostics.return_value = {"pod": {}}
        _run(events_handler._flush_pod_event_batch("prod"))

    psr.assert_not_called()


def test_individual_mode_survives_context_collection_failure(tmp_path):
    """Collector raises? Emission still happens with a minimal fallback
    context — we must not lose the alert just because the pod vanished
    mid-flight or the API 429'd."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    events_handler._pod_event_batch["prod"] = [
        ("api-1", "Deployment:prod/api", "Deployment:prod/api:oom", "n1", "OOMKilled"),
    ]

    with patch("src.handlers.events.process_scan_results") as psr, \
         patch("src.handlers.events._get_collector") as col, \
         patch("src.handlers.events._is_pod_ready_now", return_value=False), \
         patch("src.handlers.events._pod_exists", return_value=True), \
         patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.handlers.events._BATCH_WINDOW_SECONDS", 0):
        col.return_value.collect_pod_context_with_diagnostics.side_effect = RuntimeError("API 429")
        _run(events_handler._flush_pod_event_batch("prod"))

    psr.assert_called_once()
    result = psr.call_args.args[0][0]
    assert result.context_override == {"event": {"pod": "api-1", "reason": "OOMKilled"}}


# ── _flush_pod_event_batch — collective mode ──────────────────────────

def test_batch_mode_emits_single_collective_scanresult(tmp_path):
    """≥ _BATCH_THRESHOLD (3) events → one aggregated ScanResult with
    `issue_type='collective_incident'`, not N individual ScanResults."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    events_handler._pod_event_batch["prod"] = [
        ("api-1", "Deployment:prod/api", "Deployment:prod/api:oom", "n1", "OOMKilled"),
        ("web-1", "Deployment:prod/web", "Deployment:prod/web:crash", "n2", "CrashLoopBackOff"),
        ("wrk-1", "Deployment:prod/wrk", "Deployment:prod/wrk:unhealthy", "n3", "Unhealthy"),
    ]

    with patch("src.handlers.events.process_scan_results") as psr, \
         patch("src.handlers.events._get_collector") as col, \
         patch("src.handlers.events._is_pod_ready_now", return_value=False), \
         patch("src.handlers.events._pod_exists", return_value=True), \
         patch("src.handlers.events.get_node_metrics_summary", return_value=""), \
         patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.handlers.events._BATCH_WINDOW_SECONDS", 0):
        col.return_value.collect_pod_context_with_diagnostics.return_value = {"pod": {}}
        _run(events_handler._flush_pod_event_batch("prod"))

    psr.assert_called_once()
    results = psr.call_args.args[0]
    assert len(results) == 1
    collective = results[0]
    assert collective.state_key == "Collective:prod"
    assert collective.issue_type == "collective_incident"
    assert collective.severity == "critical"  # OOMKilled in the mix
    assert collective.metadata["event_count"] == 3
    assert collective.metadata["services_total"] == 3
    assert "api" in collective.metadata["services_sample"]


def test_batch_mode_downgrades_to_warning_without_oom(tmp_path):
    """No OOMKilled in the batch + no critical service match → warning,
    not critical. Pipeline routes warning collective-incident to Slack
    via the is_collective branch (always posts), not via severity."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    events_handler._pod_event_batch["prod"] = [
        ("p1", "Deployment:prod/random", "Deployment:prod/random:unhealthy", "", "Unhealthy"),
        ("p2", "Deployment:prod/other", "Deployment:prod/other:crash", "", "CrashLoopBackOff"),
        ("p3", "Deployment:prod/third", "Deployment:prod/third:error", "", "Error"),
    ]

    with patch("src.handlers.events.process_scan_results") as psr, \
         patch("src.handlers.events._get_collector") as col, \
         patch("src.handlers.events._is_pod_ready_now", return_value=False), \
         patch("src.handlers.events._pod_exists", return_value=True), \
         patch("src.handlers.events.get_node_metrics_summary", return_value=""), \
         patch("src.handlers.events.matches_critical_service", return_value=False), \
         patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.handlers.events._BATCH_WINDOW_SECONDS", 0):
        col.return_value.collect_pod_context_with_diagnostics.return_value = {"pod": {}}
        _run(events_handler._flush_pod_event_batch("prod"))

    collective = psr.call_args.args[0][0]
    assert collective.severity == "warning"


# ── Maintenance / non-prod title prefixing ─────────────────────────────

def test_individual_mode_prefixes_maintenance_title(tmp_path):
    """When maintenance is active the title must carry the [Maintenance]
    prefix BEFORE entering the pipeline — the pipeline's own
    maintenance logic skips the prefix once skip_llm is True."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    store.activate_auto_maintenance(reason="rollout", duration_hours=1)
    events_handler._pod_event_batch["prod"] = [
        ("api-1", "Deployment:prod/api", "Deployment:prod/api:oom", "", "OOMKilled"),
    ]

    with patch("src.handlers.events.process_scan_results") as psr, \
         patch("src.handlers.events._get_collector") as col, \
         patch("src.handlers.events._is_pod_ready_now", return_value=False), \
         patch("src.handlers.events._pod_exists", return_value=True), \
         patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.handlers.events._BATCH_WINDOW_SECONDS", 0):
        col.return_value.collect_pod_context_with_diagnostics.return_value = {"pod": {}}
        _run(events_handler._flush_pod_event_batch("prod"))

    result = psr.call_args.args[0][0]
    assert result.title.startswith("[Maintenance]")


def test_individual_mode_prefixes_nonprod_title(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "NON_PROD_NAMESPACES", {"staging"})
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    events_handler._pod_event_batch["staging"] = [
        ("api-1", "Deployment:staging/api", "Deployment:staging/api:oom", "", "OOMKilled"),
    ]

    with patch("src.handlers.events.process_scan_results") as psr, \
         patch("src.handlers.events._get_collector") as col, \
         patch("src.handlers.events._is_pod_ready_now", return_value=False), \
         patch("src.handlers.events._pod_exists", return_value=True), \
         patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.handlers.events._BATCH_WINDOW_SECONDS", 0):
        col.return_value.collect_pod_context_with_diagnostics.return_value = {"pod": {}}
        _run(events_handler._flush_pod_event_batch("staging"))

    result = psr.call_args.args[0][0]
    # Non-prod prefix is e.g. "[STG]" or "[DEV]" — exact prefix depends on
    # config.nonprod_title_prefix; just assert *some* bracket prefix is
    # prepended before the severity word.
    assert result.title.startswith("[") and "Warning:" in result.title


# ── Non-pod fallback path ──────────────────────────────────────────────

def test_non_pod_event_emits_scanresult(tmp_path):
    """Non-pod events (e.g. PVC FailedAttachVolume, Node KubeletReady)
    must also flow through the pipeline."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    evt = {
        "type": "MODIFIED",
        "object": {
            "type": "Warning",
            "reason": "FailedAttachVolume",
            "metadata": {"namespace": "production"},
            "involvedObject": {"kind": "Pod", "name": "ignored-here"},
            "message": "Unable to attach or mount volumes: timed out",
        },
    }
    # Hack: set kind to something non-Pod so the non-pod fallback runs
    evt["object"]["involvedObject"]["kind"] = "PersistentVolumeClaim"
    evt["object"]["involvedObject"]["name"] = "data-pvc"

    import logging
    with patch("src.handlers.events.process_scan_results") as psr, \
         patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.handlers.events._startup_time", 0.0):
        _run(events_handler.on_warning_event(evt, logging.getLogger("t")))

    psr.assert_called_once()
    result = psr.call_args.args[0][0]
    # FailedAttachVolume maps to "mount" alias via PROBLEM_ALIASES
    assert result.state_key == "PersistentVolumeClaim:production/data-pvc:mount"
    assert result.issue_type == "mount"
    assert result.resource == "PersistentVolumeClaim/data-pvc"
    assert result.skip_llm is True
    assert result.context_override["event"]["message"].startswith("Unable to attach")


def test_non_pod_event_in_flight_prevents_duplicate(tmp_path):
    """A second handler invocation with the same state_key returns
    early if the first is still processing."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    state_key = "PersistentVolumeClaim:production/data-pvc:mount"
    events_handler._in_flight.add(state_key)
    evt = {
        "type": "MODIFIED",
        "object": {
            "type": "Warning",
            "reason": "FailedAttachVolume",
            "metadata": {"namespace": "production"},
            "involvedObject": {"kind": "PersistentVolumeClaim", "name": "data-pvc"},
            "message": "timeout",
        },
    }

    import logging
    with patch("src.handlers.events.process_scan_results") as psr, \
         patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.handlers.events._startup_time", 0.0):
        _run(events_handler.on_warning_event(evt, logging.getLogger("t")))

    psr.assert_not_called()


# ── Deferred auto-resolve now flows through the pipeline ──────────────

def test_deferred_auto_resolve_emits_auto_resolve_scanresult(tmp_path):
    """After the grace delay, the recovered owner must emit an
    auto_resolve=True ScanResult through the pipeline — the pipeline
    then flips incident.status to resolved and posts `post_resolved`
    for critical severity. This replaces the old direct set_status +
    post_resolved call path."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    # Seed an active incident so the auto-resolve path finds it.
    store.create_incident(
        state_key="Deployment:prod/api:oom", fingerprint="fp", issue_type="oom",
        severity="critical", namespace="prod", owner_ref="Deployment:prod/api",
    )

    with patch("src.handlers.events._AUTO_RESOLVE_DELAY", 0), \
         patch("src.handlers.events._is_owner_healthy", return_value=True), \
         patch("src.handlers.events.process_scan_results") as psr, \
         patch("src.handlers.startup.get_store", return_value=store):
        _run(events_handler._deferred_auto_resolve(
            [("Deployment:prod/api:oom", "prod", "Deployment:prod/api")],
        ))

    psr.assert_called_once()
    results = psr.call_args.args[0]
    assert len(results) == 1
    assert results[0].auto_resolve is True
    assert results[0].state_key == "Deployment:prod/api:oom"


def test_deferred_auto_resolve_skips_unhealthy_owners(tmp_path):
    """If the owner hasn't actually recovered after the grace, no
    auto_resolve is emitted — the incident stays active for the next
    scanner tick / re-fire cycle."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    store.create_incident(
        state_key="Deployment:prod/api:oom", fingerprint="fp", issue_type="oom",
        severity="critical", namespace="prod", owner_ref="Deployment:prod/api",
    )

    with patch("src.handlers.events._AUTO_RESOLVE_DELAY", 0), \
         patch("src.handlers.events._is_owner_healthy", return_value=False), \
         patch("src.handlers.events.process_scan_results") as psr, \
         patch("src.handlers.startup.get_store", return_value=store):
        _run(events_handler._deferred_auto_resolve(
            [("Deployment:prod/api:oom", "prod", "Deployment:prod/api")],
        ))

    psr.assert_not_called()


# ── Pipeline integration: incident row + fingerprint ──────────────────

def test_pipeline_creates_incident_with_fingerprint_for_pod_event(tmp_path):
    """End-to-end: individual-mode flush creates an `incidents` row
    with fingerprint populated — the previous direct post_alert path
    never created this row, bypassing net-new fingerprint promotion
    and root-cause correlation."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    events_handler._pod_event_batch["prod"] = [
        ("api-1", "Deployment:prod/api", "Deployment:prod/api:oom", "n1", "OOMKilled"),
    ]

    with patch("src.handlers.events._get_collector") as col, \
         patch("src.handlers.events._is_pod_ready_now", return_value=False), \
         patch("src.handlers.events._pod_exists", return_value=True), \
         patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.handlers.events._BATCH_WINDOW_SECONDS", 0), \
         patch("src.engine.pipeline.post_alert", return_value=""), \
         patch("src.engine.central_push.push_incident"):
        col.return_value.collect_pod_context_with_diagnostics.return_value = {"pod": {"phase": "Running"}}
        _run(events_handler._flush_pod_event_batch("prod"))

    inc = store.get_incident("Deployment:prod/api:oom")
    assert inc is not None
    assert inc.fingerprint != ""
    assert inc.issue_type == "oom"
    assert inc.severity == "critical"
    assert inc.namespace == "prod"
    assert inc.status == "active"


# ── NodeNotReady path (PR3 migration) ──────────────────────────────────

def _node_not_ready_event(pod_name: str = "pod-a", namespace: str = "production") -> dict:
    """Build the kopf event shape that triggers the NodeNotReady path."""
    return {
        "type": "MODIFIED",
        "object": {
            "type": "Warning",
            "reason": "NodeNotReady",
            "metadata": {"namespace": namespace},
            "involvedObject": {"kind": "Pod", "name": pod_name},
            "message": "Node is not ready",
        },
    }


def _fake_pod(node_name: str = "node-a"):
    pod = type("Pod", (), {})()
    pod.spec = type("Spec", (), {"node_name": node_name})()
    return pod


def _fake_node(age_seconds: int = 3600):
    """Node old enough to skip the new-node grace bonus."""
    from datetime import datetime, timedelta, timezone
    node = type("Node", (), {})()
    node.metadata = type("Meta", (), {
        "creation_timestamp": datetime.now(timezone.utc) - timedelta(seconds=age_seconds),
    })()
    return node


def test_node_not_ready_emits_scanresult_after_grace(tmp_path, monkeypatch):
    """NodeNotReady path now emits a ScanResult through the pipeline
    instead of calling _analyze_and_alert. The node still-NotReady
    post-grace check must short-circuit fire; a healthy node skips."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    monkeypatch.setattr(config, "NODE_NOT_READY_GRACE_SECONDS", 0)
    monkeypatch.setattr(config, "NODE_READY_GRACE_SECONDS", 0)

    core_mock = type("Core", (), {})()
    core_mock.read_namespaced_pod = lambda name, ns: _fake_pod("node-a")
    core_mock.read_node = lambda node_name: _fake_node()

    import logging
    with patch("src.handlers.events.process_scan_results") as psr, \
         patch("src.handlers.events._get_collector") as col, \
         patch("src.handlers.events._is_node_being_deleted", return_value=(True, False, False)), \
         patch("src.handlers.events.k8s.CoreV1Api", return_value=core_mock), \
         patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.handlers.events._startup_time", 0.0):
        col.return_value.collect_pod_context_with_diagnostics.return_value = {"pod": {}}
        _run(events_handler.on_warning_event(_node_not_ready_event(), logging.getLogger("t")))

    psr.assert_called_once()
    result = psr.call_args.args[0][0]
    assert result.state_key == "Node:node-a:notready"
    assert result.issue_type == "notready"
    assert result.severity == "warning"
    assert result.resource == "Node/node-a"
    assert result.node_name == "node-a"
    assert result.pod_name == "pod-a"
    assert result.skip_llm is True


def test_node_not_ready_skips_when_node_recovers(tmp_path, monkeypatch):
    """Post-grace check: if node is Ready again, no emission."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    monkeypatch.setattr(config, "NODE_NOT_READY_GRACE_SECONDS", 0)
    monkeypatch.setattr(config, "NODE_READY_GRACE_SECONDS", 0)

    core_mock = type("Core", (), {})()
    core_mock.read_namespaced_pod = lambda name, ns: _fake_pod("node-a")
    core_mock.read_node = lambda node_name: _fake_node()

    import logging
    with patch("src.handlers.events.process_scan_results") as psr, \
         patch("src.handlers.events._get_collector") as col, \
         patch("src.handlers.events._is_node_being_deleted", return_value=(True, True, False)), \
         patch("src.handlers.events.k8s.CoreV1Api", return_value=core_mock), \
         patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.handlers.events._startup_time", 0.0):
        col.return_value.collect_pod_context_with_diagnostics.return_value = {"pod": {}}
        _run(events_handler.on_warning_event(_node_not_ready_event(), logging.getLogger("t")))

    psr.assert_not_called()


def test_node_not_ready_skips_when_node_is_being_drained(tmp_path, monkeypatch):
    """Autoscaler scale-down / drain — no emission."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    monkeypatch.setattr(config, "NODE_NOT_READY_GRACE_SECONDS", 0)
    monkeypatch.setattr(config, "NODE_READY_GRACE_SECONDS", 0)

    core_mock = type("Core", (), {})()
    core_mock.read_namespaced_pod = lambda name, ns: _fake_pod("node-a")
    core_mock.read_node = lambda node_name: _fake_node()

    import logging
    with patch("src.handlers.events.process_scan_results") as psr, \
         patch("src.handlers.events._get_collector") as col, \
         patch("src.handlers.events._is_node_being_deleted", return_value=(True, False, True)), \
         patch("src.handlers.events.k8s.CoreV1Api", return_value=core_mock), \
         patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.handlers.events._startup_time", 0.0):
        col.return_value.collect_pod_context_with_diagnostics.return_value = {"pod": {}}
        _run(events_handler.on_warning_event(_node_not_ready_event(), logging.getLogger("t")))

    psr.assert_not_called()


def test_node_not_ready_in_flight_prevents_duplicate(tmp_path, monkeypatch):
    """If another handler is already processing this node's NotReady
    (in the grace sleep), a second pod's NotReady event returns early
    without doing any work."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    events_handler._in_flight.add("Node:node-a:notready")
    monkeypatch.setattr(config, "NODE_NOT_READY_GRACE_SECONDS", 0)
    monkeypatch.setattr(config, "NODE_READY_GRACE_SECONDS", 0)

    core_mock = type("Core", (), {})()
    core_mock.read_namespaced_pod = lambda name, ns: _fake_pod("node-a")

    import logging
    with patch("src.handlers.events.process_scan_results") as psr, \
         patch("src.handlers.events._get_collector") as col, \
         patch("src.handlers.events.k8s.CoreV1Api", return_value=core_mock), \
         patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.handlers.events._startup_time", 0.0):
        _run(events_handler.on_warning_event(_node_not_ready_event(), logging.getLogger("t")))

    psr.assert_not_called()
    col.return_value.collect_pod_context_with_diagnostics.assert_not_called()


def test_node_not_ready_creates_incident_with_fingerprint(tmp_path, monkeypatch):
    """End-to-end: NodeNotReady event lands a fingerprinted incident
    row via the pipeline — previously this path bypassed fingerprinting
    via direct post_alert."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    monkeypatch.setattr(config, "NODE_NOT_READY_GRACE_SECONDS", 0)
    monkeypatch.setattr(config, "NODE_READY_GRACE_SECONDS", 0)

    core_mock = type("Core", (), {})()
    core_mock.read_namespaced_pod = lambda name, ns: _fake_pod("node-a")
    core_mock.read_node = lambda node_name: _fake_node()

    import logging
    with patch("src.handlers.events._get_collector") as col, \
         patch("src.handlers.events._is_node_being_deleted", return_value=(True, False, False)), \
         patch("src.handlers.events.k8s.CoreV1Api", return_value=core_mock), \
         patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.handlers.events._startup_time", 0.0), \
         patch("src.engine.pipeline.post_alert", return_value=""), \
         patch("src.engine.central_push.push_incident"):
        col.return_value.collect_pod_context_with_diagnostics.return_value = {"pod": {}}
        _run(events_handler.on_warning_event(_node_not_ready_event(), logging.getLogger("t")))

    inc = store.get_incident("Node:node-a:notready")
    assert inc is not None
    assert inc.fingerprint != ""
    assert inc.issue_type == "notready"
    assert inc.namespace == "production"
    assert inc.status == "active"


# ── Regression: dead code removed ──────────────────────────────────────

def test_analyze_and_alert_function_removed():
    """`_analyze_and_alert` had zero callers after PR3. Its removal is
    part of the unification goal — guarding against re-introduction."""
    assert not hasattr(events_handler, "_analyze_and_alert")


def test_store_is_seen_and_mark_seen_removed():
    """`is_seen` / `mark_seen` helpers were the last bypass surface;
    removed after PR3. `is_owner_in_cooldown` stays (used by pipeline)."""
    from src.engine.store.sqlite import SqliteStore as _Store
    assert not hasattr(_Store, "is_seen")
    assert not hasattr(_Store, "mark_seen")
    assert hasattr(_Store, "is_owner_in_cooldown")


# ── Elasticsearch Unhealthy grace (transient cluster-health-degraded) ──

def _es_event(message="Elasticsearch cluster health degraded"):
    return {
        "type": "MODIFIED",
        "object": {
            "type": "Warning",
            "reason": "Unhealthy",
            "message": message,
            "involvedObject": {"kind": "Elasticsearch", "name": "devops"},
            "metadata": {"namespace": "elastic-system"},
        },
    }


def _es_patches(store, monkeypatch, health):
    monkeypatch.setattr(config, "ELASTICSEARCH_HEALTH_GRACE_SECONDS", 0)
    monkeypatch.setattr(config, "WATCH_ALL_NAMESPACES", True)
    monkeypatch.setattr(config, "EXCLUDE_NAMESPACES", set())
    monkeypatch.setattr(events_handler, "_startup_time", 0.0)
    return (
        patch("src.handlers.events.process_scan_results"),
        patch("src.handlers.events._get_elasticsearch_health", return_value=health),
        patch("src.handlers.startup.get_store", return_value=store),
    )


def test_elasticsearch_unhealthy_skips_when_recovered_green(tmp_path, monkeypatch):
    """Transient ECK "cluster health degraded" that recovers to green → no alert."""
    import logging
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    psr_p, health_p, store_p = _es_patches(store, monkeypatch, "green")
    with psr_p as psr, health_p, store_p:
        _run(events_handler.on_warning_event(_es_event(), logging.getLogger("t")))
    psr.assert_not_called()


def test_elasticsearch_unhealthy_alerts_when_still_red(tmp_path, monkeypatch):
    """Persistent red after grace → an actionable alert tagged with the colour."""
    import logging
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    psr_p, health_p, store_p = _es_patches(store, monkeypatch, "red")
    with psr_p as psr, health_p, store_p:
        _run(events_handler.on_warning_event(_es_event(), logging.getLogger("t")))
    psr.assert_called_once()
    result = psr.call_args.args[0][0]
    assert result.issue_type == "unhealthy"
    assert result.severity == "critical"          # red → critical
    assert result.resource == "Elasticsearch/devops"
    assert result.metadata["health"] == "red"


def test_elasticsearch_unhealthy_yellow_is_warning(tmp_path, monkeypatch):
    """Persistent yellow → warning (not critical)."""
    import logging
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    psr_p, health_p, store_p = _es_patches(store, monkeypatch, "yellow")
    with psr_p as psr, health_p, store_p:
        _run(events_handler.on_warning_event(_es_event(), logging.getLogger("t")))
    psr.assert_called_once()
    assert psr.call_args.args[0][0].severity == "warning"


def test_get_elasticsearch_health_reads_status():
    """Helper returns the CR status.health, 'unknown' on 404/missing/green."""
    with patch("src.handlers.events.k8s.CustomObjectsApi") as api:
        api.return_value.get_namespaced_custom_object.return_value = {"status": {"health": "yellow"}}
        assert events_handler._get_elasticsearch_health("elastic-system", "devops") == "yellow"
        api.return_value.get_namespaced_custom_object.return_value = {"status": {}}
        assert events_handler._get_elasticsearch_health("elastic-system", "devops") == "unknown"
        # green (and any non-yellow/red) normalizes to "unknown" (benign, skip).
        api.return_value.get_namespaced_custom_object.return_value = {"status": {"health": "green"}}
        assert events_handler._get_elasticsearch_health("elastic-system", "devops") == "unknown"


def test_get_elasticsearch_health_read_errors():
    """404 → 'unknown' (CR gone); any other read failure → 'error' (not recovered)."""
    with patch("src.handlers.events.k8s.CustomObjectsApi") as api:
        gnc = api.return_value.get_namespaced_custom_object
        gnc.side_effect = events_handler.k8s.ApiException(status=404, reason="NotFound")
        assert events_handler._get_elasticsearch_health("elastic-system", "devops") == "unknown"
        gnc.side_effect = events_handler.k8s.ApiException(status=503, reason="ServiceUnavailable")
        assert events_handler._get_elasticsearch_health("elastic-system", "devops") == "error"
        gnc.side_effect = RuntimeError("boom")
        assert events_handler._get_elasticsearch_health("elastic-system", "devops") == "error"


def test_elasticsearch_unhealthy_alerts_on_read_error(tmp_path, monkeypatch):
    """Health re-read fails ('error') → fail loud: forward as a warning, don't skip.

    Also asserts the emitted event message is sanitized (no secret leak) and
    capped at 1KB, matching the general Warning-event path.
    """
    import logging
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    # Secret near the start (survives the 1024-char cap), then padded past 1KB.
    secret_msg = "cluster degraded password=SUPERSECRET123 " + ("x" * 2000)
    psr_p, health_p, store_p = _es_patches(store, monkeypatch, "error")
    with psr_p as psr, health_p, store_p:
        _run(events_handler.on_warning_event(_es_event(secret_msg), logging.getLogger("t")))
    psr.assert_called_once()
    result = psr.call_args.args[0][0]
    assert result.severity == "warning"           # can't confirm colour → warning
    assert result.metadata["health"] == "error"
    assert "fail-loud" in result.event_reason
    emitted = result.context_override["event"]["message"]
    assert len(emitted) <= 1024                    # capped
    assert "SUPERSECRET123" not in emitted         # sanitized
    assert "[REDACTED]" in emitted


def test_elasticsearch_unhealthy_disabled_flag_forwards_normally(tmp_path, monkeypatch):
    """ELASTICSEARCH_HEALTH_CHECK_ENABLED=False → no re-read, but the event still
    gets forwarded once through the normal warning path."""
    import logging
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    monkeypatch.setattr(config, "ELASTICSEARCH_HEALTH_CHECK_ENABLED", False)
    psr_p, health_p, store_p = _es_patches(store, monkeypatch, "red")
    with psr_p as psr, health_p as health_mock, store_p:
        _run(events_handler.on_warning_event(_es_event(), logging.getLogger("t")))
    health_mock.assert_not_called()               # feature disabled → no re-read
    psr.assert_called_once()                       # falls through to normal warning flow


def test_elasticsearch_unhealthy_clears_in_flight_on_exception(tmp_path, monkeypatch):
    """If process_scan_results raises, the state_key must not leak in _in_flight."""
    import logging
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    psr_p, health_p, store_p = _es_patches(store, monkeypatch, "red")
    state_key = "Elasticsearch:elastic-system/devops:unhealthy"
    with psr_p as psr, health_p, store_p:
        psr.side_effect = RuntimeError("boom")
        with pytest.raises(RuntimeError):
            _run(events_handler.on_warning_event(_es_event(), logging.getLogger("t")))
    assert state_key not in events_handler._in_flight


# --- startup settle window (Unhealthy probe events on young pods) ---

def _unhealthy_pod_event(ns="prod", pod="prometheus-0"):
    return {
        "type": "ADDED",
        "object": {
            "type": "Warning",
            "reason": "Unhealthy",
            "message": "Readiness probe failed",
            "metadata": {"namespace": ns, "name": "evt-1"},
            "involvedObject": {"kind": "Pod", "name": pod, "namespace": ns},
        },
    }


def _run_settle_case(tmp_path, *, pod_age, ready_after_wait, sleeps):
    """Drive on_warning_event through the settle branch; returns (batched, sleeps)."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))

    async def fake_sleep(sec):
        sleeps.append(sec)

    async def fake_flush(ns, maintenance=False):
        return None

    events_handler._pod_event_batch.clear()
    events_handler._pod_event_batch_task.clear()
    with (
        patch("src.handlers.events._get_probe_grace_seconds",
              return_value=(40, pod_age)),
        patch("src.handlers.events._is_pod_ready_now",
              return_value=ready_after_wait),
        patch("src.handlers.events.resolve_owner_key_by_name",
              return_value="StatefulSet:prod/prometheus"),
        patch("src.handlers.events._get_pod_status_reason",
              return_value=("", "node-a")),
        patch("src.handlers.events._in_watched_namespace", return_value=True),
        patch("src.handlers.events._startup_time", 0),
        patch.object(config, "UNHEALTHY_STARTUP_SETTLE_SECONDS", 300),
        patch("src.handlers.events.asyncio.sleep", fake_sleep),
        patch("src.handlers.events._flush_pod_event_batch", fake_flush),
        patch("src.handlers.startup.get_store", return_value=store),
    ):
        _run(events_handler.on_warning_event(
            _unhealthy_pod_event(), logger=logging.getLogger("t")))
    batched = list(events_handler._pod_event_batch.get("prod", []))
    events_handler._pod_event_batch.clear()
    for t in events_handler._pod_event_batch_task.values():
        t.cancel()
    events_handler._pod_event_batch_task.clear()
    return batched


def test_unhealthy_young_pod_recovered_within_settle_is_silent(tmp_path):
    """Pod 50s old (past the 40s probe budget) recovers during the settle
    window — no batch entry, no alert. The 2026-09-01 WAL-replay case."""
    sleeps = []
    batched = _run_settle_case(tmp_path, pod_age=50, ready_after_wait=True, sleeps=sleeps)
    assert batched == []
    assert sleeps and sleeps[0] == 250  # изчаква остатъка до settle (300-50)


def test_unhealthy_young_pod_still_sick_after_settle_alerts(tmp_path):
    sleeps = []
    batched = _run_settle_case(tmp_path, pod_age=50, ready_after_wait=False, sleeps=sleeps)
    assert len(batched) == 1
    assert batched[0][2] == "StatefulSet:prod/prometheus:unhealthy"


def test_unhealthy_old_pod_alerts_without_settle_wait(tmp_path):
    """Pod far older than the settle window — immediate batch, no sleep."""
    sleeps = []
    batched = _run_settle_case(tmp_path, pod_age=4000, ready_after_wait=False, sleeps=sleeps)
    assert len(batched) == 1
    assert sleeps == []


def test_unhealthy_unknown_age_alerts_immediately(tmp_path):
    """Pod unreadable (age None) — fail loud, no settle wait."""
    sleeps = []
    batched = _run_settle_case(tmp_path, pod_age=None, ready_after_wait=False, sleeps=sleeps)
    assert len(batched) == 1
    assert sleeps == []

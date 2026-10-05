"""Tests for Sprint 9 PR1 — flux.py pipeline unification.

The handler previously called `notifier.post_alert` directly. Post-Sprint-9
it emits a `ScanResult` and invokes `process_scan_results`. These tests
verify the emission contract and the integration with the pipeline's
fingerprinting / escalation path.
"""
import asyncio
import logging
import time
from unittest.mock import MagicMock, patch

import pytest

from src import config
from src.engine.store.sqlite import SqliteStore
from src.handlers import flux as flux_handler


@pytest.fixture(autouse=True)
def _clear_in_flight():
    """Every test starts with an empty `_in_flight` set."""
    flux_handler._in_flight.clear()
    yield
    flux_handler._in_flight.clear()


@pytest.fixture(autouse=True)
def _skip_startup_grace(monkeypatch):
    """Move the startup marker far into the past so every test bypasses
    the 30s grace window without sleeping."""
    monkeypatch.setattr(flux_handler, "_startup_time", 0.0)


@pytest.fixture(autouse=True)
def _namespace_allowed(monkeypatch):
    """Watch every namespace by default; individual tests override when
    they need to exercise the namespace filter."""
    monkeypatch.setattr(config, "WATCH_ALL_NAMESPACES", True)
    monkeypatch.setattr(config, "EXCLUDE_NAMESPACES", set())
    monkeypatch.setattr(config, "NON_PROD_NAMESPACES", set())


def _stalled_event(kind: str = "HelmRelease", name: str = "demo",
                   namespace: str = "production",
                   stalled_status: str = "True",
                   event_type: str = "MODIFIED") -> dict:
    """Build a minimal kopf-shaped event payload for a Flux CR."""
    return {
        "type": event_type,
        "object": {
            "metadata": {"name": name, "namespace": namespace},
            "status": {
                "conditions": [
                    {"type": "Stalled", "status": stalled_status,
                     "message": "install retries exhausted"},
                    {"type": "Ready", "status": "False", "message": ""},
                ],
            },
        },
    }


def _run(coro):
    """Drive an async coroutine to completion in a test."""
    return asyncio.run(coro)


def _flux_context(name: str, namespace: str, kind: str) -> dict:
    return {
        "flux_resource": {"kind": kind, "name": name, "namespace": namespace},
        "conditions": [
            {"type": "Stalled", "status": "True", "message": "install retries exhausted"},
        ],
    }


# ── Basic emission contract ─────────────────────────────────────────────

def test_stalled_helmrelease_emits_scanresult(tmp_path):
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    event = _stalled_event(kind="HelmRelease", name="my-app", namespace="production")

    with patch("src.handlers.flux.process_scan_results") as psr, \
         patch("src.handlers.flux._get_collector") as col, \
         patch("src.handlers.startup.get_store", return_value=store):
        col.return_value.collect_flux_context.return_value = _flux_context(
            "my-app", "production", "HelmRelease",
        )
        _run(flux_handler._handle_flux_event(event, "HelmRelease", logging.getLogger("t")))

    psr.assert_called_once()
    results, passed_store, ctx_fn, *_ = psr.call_args.args
    assert passed_store is store   # pipeline must receive the real store, not a copy
    assert len(results) == 1
    r = results[0]
    assert r.state_key == "Flux:HelmRelease:production/my-app:stalled"
    assert r.severity == "critical"
    assert r.issue_type == "stalled"
    assert r.resource == "HelmRelease/my-app"
    assert r.namespace == "production"
    assert r.skip_llm is True
    assert r.metadata == {"kind": "HelmRelease", "name": "my-app"}
    assert ctx_fn is None  # context_override is set — no collector needed


def test_stalled_kustomization_uses_kind_in_state_key(tmp_path):
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    event = _stalled_event(kind="Kustomization", name="infra", namespace="flux-managed")

    with patch("src.handlers.flux.process_scan_results") as psr, \
         patch("src.handlers.flux._get_collector") as col, \
         patch("src.handlers.startup.get_store", return_value=store):
        col.return_value.collect_flux_context.return_value = _flux_context(
            "infra", "flux-managed", "Kustomization",
        )
        _run(flux_handler._handle_flux_event(event, "Kustomization", logging.getLogger("t")))

    psr.assert_called_once()
    r = psr.call_args.args[0][0]
    assert r.state_key == "Flux:Kustomization:flux-managed/infra:stalled"
    assert r.resource == "Kustomization/infra"


# ── Gating: maintenance, non-stalled, filters ──────────────────────────

def test_maintenance_mode_skips_emission(tmp_path):
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    store.activate_auto_maintenance(reason="test", duration_hours=1)
    event = _stalled_event()

    with patch("src.handlers.flux.process_scan_results") as psr, \
         patch("src.handlers.flux._get_collector") as col, \
         patch("src.handlers.startup.get_store", return_value=store):
        col.return_value.collect_flux_context.return_value = {}
        _run(flux_handler._handle_flux_event(event, "HelmRelease", logging.getLogger("t")))

    psr.assert_not_called()
    col.return_value.collect_flux_context.assert_not_called()


def test_non_stalled_condition_skips_emission(tmp_path):
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    event = _stalled_event(stalled_status="False")

    with patch("src.handlers.flux.process_scan_results") as psr, \
         patch("src.handlers.flux._get_collector") as col, \
         patch("src.handlers.startup.get_store", return_value=store):
        _run(flux_handler._handle_flux_event(event, "HelmRelease", logging.getLogger("t")))

    psr.assert_not_called()
    col.return_value.collect_flux_context.assert_not_called()


def test_excluded_namespace_skips_emission(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "EXCLUDE_NAMESPACES", {"production"})
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    event = _stalled_event()

    with patch("src.handlers.flux.process_scan_results") as psr, \
         patch("src.handlers.flux._get_collector") as col, \
         patch("src.handlers.startup.get_store", return_value=store):
        _run(flux_handler._handle_flux_event(event, "HelmRelease", logging.getLogger("t")))

    psr.assert_not_called()
    col.return_value.collect_flux_context.assert_not_called()


# ── Startup grace gate ─────────────────────────────────────────────────

def test_startup_grace_blocks_emission(tmp_path, monkeypatch):
    """Events that fire within the first 30s of the process lifetime
    must not emit ScanResults. The autouse `_skip_startup_grace` fixture
    rewinds `_startup_time` so every other test can run, which would
    otherwise hide regressions in this gate — explicitly restore it
    here to exercise the real code path."""
    monkeypatch.setattr(flux_handler, "_startup_time", time.time())
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    event = _stalled_event(kind="HelmRelease", name="early", namespace="production")

    with patch("src.handlers.flux.process_scan_results") as psr, \
         patch("src.handlers.flux._get_collector") as col, \
         patch("src.handlers.startup.get_store", return_value=store):
        _run(flux_handler._handle_flux_event(event, "HelmRelease", logging.getLogger("t")))

    psr.assert_not_called()
    col.return_value.collect_flux_context.assert_not_called()


# ── _in_flight concurrent dedup ────────────────────────────────────────

def test_in_flight_prevents_duplicate_processing(tmp_path):
    """A second kopf invocation for the same state_key returns early
    while the first is still inside the try block. We simulate that by
    pre-seeding the _in_flight set before calling the handler."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    event = _stalled_event(kind="HelmRelease", name="busy", namespace="production")
    flux_handler._in_flight.add("Flux:HelmRelease:production/busy:stalled")

    with patch("src.handlers.flux.process_scan_results") as psr, \
         patch("src.handlers.flux._get_collector") as col, \
         patch("src.handlers.startup.get_store", return_value=store):
        _run(flux_handler._handle_flux_event(event, "HelmRelease", logging.getLogger("t")))

    psr.assert_not_called()
    col.return_value.collect_flux_context.assert_not_called()


# ── Pipeline integration: incident row + fingerprint ───────────────────

def test_pipeline_creates_incident_with_fingerprint(tmp_path):
    """End-to-end: stalled event hits the real pipeline and lands a row
    in `incidents` with fingerprint populated — the previous direct
    post_alert path never created this row, bypassing net-new
    fingerprint promotion and root-cause correlation."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    event = _stalled_event(kind="HelmRelease", name="api", namespace="production")

    # central_push.push_incident is a no-op when CENTRAL_AGGREGATE is
    # off (the default), but mocking it makes the test hermetic even
    # if the runner's env happens to enable the central aggregator.
    with patch("src.handlers.flux._get_collector") as col, \
         patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.engine.pipeline.post_alert", return_value="") as post, \
         patch("src.engine.central_push.push_incident"):
        col.return_value.collect_flux_context.return_value = _flux_context(
            "api", "production", "HelmRelease",
        )
        _run(flux_handler._handle_flux_event(event, "HelmRelease", logging.getLogger("t")))

    # Slack post did happen — pipeline routed it through.
    assert post.called
    # Incident row exists with fingerprint populated.
    inc = store.get_incident("Flux:HelmRelease:production/api:stalled")
    assert inc is not None
    assert inc.fingerprint != ""
    assert inc.issue_type == "stalled"
    assert inc.severity == "critical"
    assert inc.namespace == "production"
    assert inc.status == "active"


def test_second_occurrence_escalates_to_recurring(tmp_path):
    """Pipeline's escalation kicks in on the 2nd occurrence within the
    recurring window. Previous direct path had no such escalation."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    event = _stalled_event(kind="HelmRelease", name="flappy", namespace="production")

    # First occurrence — top-level alert. central_push mocked for
    # hermeticity (same reasoning as test_pipeline_creates_incident_*).
    with patch("src.handlers.flux._get_collector") as col, \
         patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.engine.pipeline.post_alert", return_value=""), \
         patch("src.engine.central_push.push_incident"):
        col.return_value.collect_flux_context.return_value = _flux_context(
            "flappy", "production", "HelmRelease",
        )
        _run(flux_handler._handle_flux_event(event, "HelmRelease", logging.getLogger("t")))

    # Clear the per-CR cooldown so the 2nd occurrence is not suppressed
    # by the exponential backoff (exists by design for scanners but we
    # want to validate escalation semantics here, not cooldown).
    inc = store.get_incident("Flux:HelmRelease:production/flappy:stalled")
    assert inc is not None
    store.bump_incident(inc.id, cooldown_until=0)

    # Second occurrence — expect RECURRING prefix in the Slack title.
    with patch("src.handlers.flux._get_collector") as col, \
         patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.engine.pipeline.post_alert", return_value="") as post, \
         patch("src.engine.central_push.push_incident"):
        col.return_value.collect_flux_context.return_value = _flux_context(
            "flappy", "production", "HelmRelease",
        )
        _run(flux_handler._handle_flux_event(event, "HelmRelease", logging.getLogger("t")))

    assert post.called
    title_arg = post.call_args.kwargs.get("title") or post.call_args.args[0]
    assert "RECURRING" in title_arg


# ── context_override round-trip ────────────────────────────────────────

def test_flux_context_reaches_pipeline_as_context_override(tmp_path):
    """The flux context dict must be passed verbatim as context_override
    so the pipeline doesn't attempt (and fail) to collect pod context
    for a non-pod resource."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    ctx = {
        "flux_resource": {"kind": "HelmRelease", "name": "svc", "namespace": "production"},
        "conditions": [
            {"type": "Stalled", "status": "True", "message": "chart not found"},
        ],
        "failure_counts": {"total": 5, "upgrade": 3, "install": 2},
    }
    event = _stalled_event(kind="HelmRelease", name="svc", namespace="production")

    captured: dict = {}
    real_psr = MagicMock(side_effect=lambda results, *a, **kw: captured.update(
        {"results": list(results)}))

    with patch("src.handlers.flux.process_scan_results", real_psr), \
         patch("src.handlers.flux._get_collector") as col, \
         patch("src.handlers.startup.get_store", return_value=store):
        col.return_value.collect_flux_context.return_value = ctx
        _run(flux_handler._handle_flux_event(event, "HelmRelease", logging.getLogger("t")))

    r = captured["results"][0]
    assert r.context_override == ctx

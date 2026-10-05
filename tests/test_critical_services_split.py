"""Tests for the CRITICAL_SERVICES -> INFRA/IMPORTANT split, with the default tiers."""
from src import config
from src.engine import critical


# ── Tier membership ─────────────────────────────────────────────────────

def test_infra_services_are_infra_only():
    """postgres/redis match infra, NOT important."""
    for infra in ("postgresql", "postgres", "redis"):
        assert critical.matches_infra_critical(f"Pod/{infra}-0", f"{infra}-0"), \
            f"{infra} should match infra"
        # Same input should NOT match the important-only filter.
        assert not critical.matches_important(f"Pod/{infra}-0", f"{infra}-0"), \
            f"{infra} should NOT match important (it's infra)"


def test_important_services_are_important_only():
    """backend/frontend match important, NOT infra."""
    cases = [
        ("Deployment/backend", "backend-abc"),
        ("Deployment/frontend", "frontend-xyz"),
    ]
    for resource, pod in cases:
        assert critical.matches_important(resource, pod), \
            f"{pod} should match important"
        assert not critical.matches_infra_critical(resource, pod), \
            f"{pod} should NOT match infra (it's important)"


def test_union_matches_both_tiers():
    """Back-compat matches_critical_service returns True for both tiers."""
    assert critical.matches_critical_service("Pod/postgres-0", "postgres-0")
    assert critical.matches_critical_service("Pod/backend-abc", "backend-abc")


def test_unrelated_services_match_nothing():
    assert not critical.matches_infra_critical("Pod/my-worker-0", "my-worker-0")
    assert not critical.matches_important("Pod/my-worker-0", "my-worker-0")
    assert not critical.matches_critical_service("Pod/my-worker-0", "my-worker-0")


# ── Substring protection (preserved from the pre-split implementation) ──

def test_no_substring_false_match_on_infra():
    """predis-worker must NOT match redis."""
    assert not critical.matches_infra_critical("Pod/predis-worker", "predis-worker")


def test_no_substring_false_match_on_important():
    """api-server must NOT match api-gateway (gateway token missing)."""
    assert not critical.matches_important("Pod/api-server", "api-server-1")


# ── Custom config via monkeypatch ────────────────────────────────────────

def test_custom_infra_list_via_config(monkeypatch):
    monkeypatch.setattr(config, "INFRA_CRITICAL_SERVICES", {"customsql"})
    assert critical.matches_infra_critical("Pod/customsql-0", "customsql-0")
    # Default infra services don't match when list is overridden.
    assert not critical.matches_infra_critical("Pod/postgres-0", "postgres-0")


def test_custom_important_list_via_config(monkeypatch):
    monkeypatch.setattr(config, "IMPORTANT_SERVICES", {"my-app"})
    assert critical.matches_important("Deployment/my-app", "my-app-1")
    assert not critical.matches_important("Deployment/frontend", "frontend")


# ── Empty input ──────────────────────────────────────────────────────────

def test_empty_input_matches_nothing():
    assert not critical.matches_infra_critical("")
    assert not critical.matches_important("")
    assert not critical.matches_critical_service("")


# ── Pipeline integration: the split wiring ──────────────────────────────

def test_pipeline_forces_critical_only_on_infra():
    """_should_post_slack promotes infra to critical but respects scanner
    severity for important services."""
    from src.engine.pipeline import _should_post_slack
    from src.scanners._base import ScanResult

    # Infra (postgres) with scanner severity=warning → forced to critical
    infra_r = ScanResult(
        state_key="Pod:prod/postgres-0:crash", title="x",
        severity="warning", resource="Pod/postgres-0",
        namespace="prod", issue_type="crash", pod_name="postgres-0",
    )
    should, _, sev = _should_post_slack(None, infra_r, is_collective=False)
    assert sev == "critical"
    assert should is True

    # Important (frontend) with scanner severity=warning → stays warning
    # → routed to daily report (not Slack) via A-fix.
    important_r = ScanResult(
        state_key="Pod:prod/frontend-abc:crash", title="x",
        severity="warning", resource="Pod/frontend-abc",
        namespace="prod", issue_type="crash", pod_name="frontend-abc",
    )
    should, _, sev = _should_post_slack(None, important_r, is_collective=False)
    assert sev == "warning"
    assert should is False  # warning without LLM verdict → no Slack

    # Important (frontend) with scanner severity=critical → stays critical
    important_critical = ScanResult(
        state_key="Pod:prod/frontend-abc:oom", title="x",
        severity="critical", resource="Pod/frontend-abc",
        namespace="prod", issue_type="oom", pod_name="frontend-abc",
    )
    should, _, sev = _should_post_slack(None, important_critical, is_collective=False)
    assert sev == "critical"
    assert should is True


# ── Back-compat: legacy CRITICAL_SERVICES env var ───────────────────────

def test_legacy_critical_services_env_seeds_infra(monkeypatch):
    """Verify the legacy CRITICAL_SERVICES env seeds INFRA_CRITICAL_SERVICES
    when the new var is unset.

    Config is normally evaluated at import time, so we use importlib.reload
    to exercise the env-resolution logic without leaking state: this test
    first loads with the legacy var set, asserts it wins, then reloads
    with a clean env so the rest of the test suite sees defaults again.
    """
    import importlib

    from src import config

    monkeypatch.delenv("INFRA_CRITICAL_SERVICES", raising=False)
    monkeypatch.setenv("CRITICAL_SERVICES", "legacy-svc-one,legacy-svc-two")
    try:
        importlib.reload(config)
        assert "legacy-svc-one" in config.INFRA_CRITICAL_SERVICES
        assert "legacy-svc-two" in config.INFRA_CRITICAL_SERVICES
        # Default infra entries are replaced by the legacy var, not merged.
        assert "postgres" not in config.INFRA_CRITICAL_SERVICES
    finally:
        # Restore module state for other tests — monkeypatch removes the
        # env var automatically on teardown, then we reload once more so
        # config.INFRA_CRITICAL_SERVICES rebuilds from defaults.
        monkeypatch.delenv("CRITICAL_SERVICES", raising=False)
        importlib.reload(config)


def test_new_infra_env_wins_over_legacy(monkeypatch):
    """INFRA_CRITICAL_SERVICES takes precedence when both are set."""
    import importlib

    from src import config

    monkeypatch.setenv("CRITICAL_SERVICES", "legacy-one")
    monkeypatch.setenv("INFRA_CRITICAL_SERVICES", "new-one")
    try:
        importlib.reload(config)
        assert "new-one" in config.INFRA_CRITICAL_SERVICES
        assert "legacy-one" not in config.INFRA_CRITICAL_SERVICES
    finally:
        monkeypatch.delenv("CRITICAL_SERVICES", raising=False)
        monkeypatch.delenv("INFRA_CRITICAL_SERVICES", raising=False)
        importlib.reload(config)


def test_legacy_critical_services_emits_deprecation_warning(monkeypatch, caplog):
    """When only legacy CRITICAL_SERVICES is set, a one-shot deprecation
    warning must be emitted at import time so operators see it and
    migrate to INFRA_CRITICAL_SERVICES."""
    import importlib
    import logging

    from src import config

    monkeypatch.delenv("INFRA_CRITICAL_SERVICES", raising=False)
    monkeypatch.setenv("CRITICAL_SERVICES", "legacy-one")
    try:
        with caplog.at_level(logging.WARNING, logger="src.config"):
            importlib.reload(config)
        messages = " ".join(record.message for record in caplog.records)
        assert "CRITICAL_SERVICES" in messages
        assert "deprecated" in messages
        assert "INFRA_CRITICAL_SERVICES" in messages
    finally:
        monkeypatch.delenv("CRITICAL_SERVICES", raising=False)
        importlib.reload(config)


def test_no_warning_when_new_env_var_is_set(monkeypatch, caplog):
    """If INFRA_CRITICAL_SERVICES is set, no deprecation warning fires —
    even if the legacy var is also set (the new one wins silently)."""
    import importlib
    import logging

    from src import config

    monkeypatch.setenv("INFRA_CRITICAL_SERVICES", "only-new")
    monkeypatch.setenv("CRITICAL_SERVICES", "legacy-too")
    try:
        with caplog.at_level(logging.WARNING, logger="src.config"):
            importlib.reload(config)
        messages = " ".join(record.message for record in caplog.records)
        assert "deprecated" not in messages.lower()
    finally:
        monkeypatch.delenv("INFRA_CRITICAL_SERVICES", raising=False)
        monkeypatch.delenv("CRITICAL_SERVICES", raising=False)
        importlib.reload(config)


def test_no_warning_when_neither_env_var_is_set(monkeypatch, caplog):
    """Clean default state (neither var set) must not log a warning."""
    import importlib
    import logging

    from src import config

    monkeypatch.delenv("INFRA_CRITICAL_SERVICES", raising=False)
    monkeypatch.delenv("CRITICAL_SERVICES", raising=False)
    with caplog.at_level(logging.WARNING, logger="src.config"):
        importlib.reload(config)
    messages = " ".join(record.message for record in caplog.records)
    assert "deprecated" not in messages.lower()

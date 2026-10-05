"""Tests for the @ai mention cooldown (AI_MENTION_REMINDER_HOURS).

Rationale: chronic critical incidents re-fire every cooldown cycle
(~30m). Pre-change, each re-fire tagged @ai — the bot burned context
re-analysing the same known issue. This gate suppresses the @ai tag on
re-fires within a configurable window while keeping the Slack alert
itself critical/visible.
"""
import time
from dataclasses import replace
from unittest.mock import patch

import pytest

from src import config
from src.engine import pipeline
from src.engine.store.sqlite import SqliteStore
from src.scanners._base import ScanResult


@pytest.fixture(autouse=True)
def _watch_everything(monkeypatch):
    monkeypatch.setattr(config, "WATCH_ALL_NAMESPACES", True)
    monkeypatch.setattr(config, "EXCLUDE_NAMESPACES", set())
    monkeypatch.setattr(config, "ALERT_EXCLUDE_WORKLOADS", ())
    # Default — tests that care override.
    monkeypatch.setattr(config, "AI_MENTION_REMINDER_HOURS", 6)
    monkeypatch.setattr(config, "SLACK_CRITICAL_MENTION", "<@U0AI>")


def _crit_result(state_key="Deployment:prod/svc:crash") -> ScanResult:
    return ScanResult(
        state_key=state_key,
        title="Pod Issue: CrashLoopBackOff",
        severity="critical",
        resource="Pod/svc-abc",
        namespace="prod",
        issue_type="crash",
        pod_name="svc-abc",
        context_override={"event": {"pod": "svc-abc"}},
        skip_llm=True,
    )


def _run_pipeline(results, store, post_return="1700000000.1"):
    with patch("src.engine.pipeline.post_alert", return_value=post_return) as post, \
         patch("src.engine.central_push.push_incident"), \
         patch("src.collectors.uptrace._resolve_token", return_value=""):
        pipeline.process_scan_results(results, store)
    return post


def test_first_critical_fire_includes_ai_mention(tmp_path):
    """First alert on a fresh incident — @ai mention included
    (`skip_ai_mention=False`), and `last_ai_mention_at` gets bumped so
    future re-fires can gate on it."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    post = _run_pipeline([_crit_result()], store)

    assert post.called
    kwargs = post.call_args.kwargs
    assert kwargs["skip_ai_mention"] is False
    inc = store.get_incident("Deployment:prod/svc:crash")
    assert inc is not None
    assert inc.last_ai_mention_at > 0


def test_recurring_fire_within_cooldown_skips_ai_mention(tmp_path):
    """Incident just re-fired within AI_MENTION_REMINDER_HOURS window —
    alert still goes critical, but @ai mention is suppressed so the bot
    isn't re-tagged for the same chronic issue."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))

    # First fire — @ai tagged, timestamp bumped.
    _run_pipeline([_crit_result()], store)
    inc_first = store.get_incident("Deployment:prod/svc:crash")
    assert inc_first.last_ai_mention_at > 0

    # Simulate cooldown expiry (so the SECOND alert isn't suppressed by
    # the pipeline's own cooldown check — we're testing the @ai gate,
    # not incident cooldown).
    store.bump_incident(inc_first.id, cooldown_until=0)

    # Second fire — within AI_MENTION_REMINDER_HOURS (default 6h).
    post = _run_pipeline([_crit_result()], store)
    assert post.called
    kwargs = post.call_args.kwargs
    assert kwargs["skip_ai_mention"] is True

    # Timestamp must NOT be re-bumped when the mention is skipped —
    # otherwise the cooldown would perpetually reset and never re-fire.
    inc_second = store.get_incident("Deployment:prod/svc:crash")
    assert inc_second.last_ai_mention_at == inc_first.last_ai_mention_at


def test_recurring_fire_after_cooldown_window_includes_ai_mention(tmp_path, monkeypatch):
    """Once AI_MENTION_REMINDER_HOURS has elapsed since the last
    @ai mention, the next re-fire includes it again (chronic issue
    gets a fresh bot analysis after the window)."""
    monkeypatch.setattr(config, "AI_MENTION_REMINDER_HOURS", 6)
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    _run_pipeline([_crit_result()], store)
    inc = store.get_incident("Deployment:prod/svc:crash")

    # Manually backdate last_ai_mention_at beyond the 6h window.
    conn = store._get_conn()
    conn.execute(
        "UPDATE incidents SET last_ai_mention_at = ? WHERE id = ?",
        (time.time() - (6.5 * 3600), inc.id),
    )
    conn.commit()
    store.bump_incident(inc.id, cooldown_until=0)

    post = _run_pipeline([_crit_result()], store)
    kwargs = post.call_args.kwargs
    assert kwargs["skip_ai_mention"] is False
    # And the timestamp got bumped to now for the next window.
    inc_after = store.get_incident("Deployment:prod/svc:crash")
    assert inc_after.last_ai_mention_at > (time.time() - 5)


def test_reopened_incident_always_includes_ai_mention(tmp_path):
    """Resolved → active transition is treated as a fresh incident:
    even if we tagged @ai within the window for the previous active
    cycle, the new cycle's root cause may differ and deserves a fresh
    bot analysis."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    # First active cycle — @ai tagged.
    _run_pipeline([_crit_result()], store)
    inc = store.get_incident("Deployment:prod/svc:crash")

    # Resolve it.
    store.set_status(inc.id, "resolved")

    # Re-occurrence reopens. Pipeline sets reopened=True.
    post = _run_pipeline([_crit_result()], store)
    kwargs = post.call_args.kwargs
    # Reopened path bypasses the cooldown — fresh bot analysis.
    assert kwargs["skip_ai_mention"] is False


def test_cooldown_disabled_always_mentions(tmp_path, monkeypatch):
    """`AI_MENTION_REMINDER_HOURS=0` disables cooldown — every critical
    re-fire re-tags @ai (pre-change behaviour, available via env flip)."""
    monkeypatch.setattr(config, "AI_MENTION_REMINDER_HOURS", 0)
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    _run_pipeline([_crit_result()], store)
    inc = store.get_incident("Deployment:prod/svc:crash")
    store.bump_incident(inc.id, cooldown_until=0)

    post = _run_pipeline([_crit_result()], store)
    kwargs = post.call_args.kwargs
    assert kwargs["skip_ai_mention"] is False


def test_warning_severity_never_bumps_timestamp(tmp_path, monkeypatch):
    """Only critical alerts carry the @ai mention today, so warnings
    that stay warnings (no net-new / persistent promotion to critical)
    must never bump `last_ai_mention_at`. Non-prod namespaces skip
    net-new promotion per the existing design — using staging here
    isolates the warning-stays-warning path."""
    monkeypatch.setattr(config, "NON_PROD_NAMESPACES", {"staging"})
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    warn = replace(
        _crit_result(state_key="Deployment:staging/svc:crash"),
        severity="warning", namespace="staging",
    )

    with patch("src.engine.pipeline.post_alert", return_value=""), \
         patch("src.engine.central_push.push_incident"), \
         patch("src.collectors.uptrace._resolve_token", return_value=""):
        pipeline.process_scan_results([warn], store)

    inc = store.get_incident("Deployment:staging/svc:crash")
    assert inc is not None
    # No mention bump — warning in non-prod routes via non-prod webhook
    # but doesn't get promoted to critical and isn't @ai-mentioned.
    assert inc.last_ai_mention_at == 0


def test_delivery_failure_does_not_bump_ai_mention_timestamp(tmp_path):
    """If Slack delivery fails entirely (post_alert returns None —
    no transport OR both bot+webhook failed → console only), we must
    NOT bump `last_ai_mention_at`. Otherwise a cluster with broken
    Slack transport would silently lock in the cooldown and future
    re-fires would skip the @ai mention even though no human ever
    saw the original alert."""
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    # post_alert returns None → delivery failed (console-only fallback).
    post = _run_pipeline([_crit_result()], store, post_return=None)

    assert post.called
    inc = store.get_incident("Deployment:prod/svc:crash")
    assert inc is not None
    # Incident row was still created (new-incident branch ran), but
    # the @ai cooldown timestamp was NOT bumped — so the very next
    # re-fire will still carry the @ai mention (no spurious cooldown
    # lock-in during a Slack outage).
    assert inc.last_ai_mention_at == 0


def test_post_alert_honors_skip_ai_mention_flag():
    """Unit: notifier.post_alert must omit the @ai mention when
    `skip_ai_mention=True`, keep it when False (with severity=critical
    + SLACK_CRITICAL_MENTION set)."""
    from src.engine import notifier

    # skip=False → mention IS in payload's top-level text
    captured: dict = {}

    def capture_send(payload: dict, webhook_url=None) -> bool:
        captured["payload"] = payload
        return True

    with patch.object(notifier, "_send", side_effect=capture_send), \
         patch.object(notifier, "_resolve_bot_token", return_value=""), \
         patch.object(notifier.config, "SLACK_WEBHOOK_URL", "https://hook.test"), \
         patch.object(notifier.config, "SLACK_CRITICAL_MENTION", "<@U0AI>"):
        notifier.post_alert(
            title="t", analysis="a", severity="critical",
            resource="Pod/svc", namespace="prod",
            skip_ai_mention=False,
        )
        top_text = captured["payload"].get("text", "")
        assert "<@U0AI>" in top_text

    # skip=True → mention is NOT in top-level text (alert stays critical)
    captured.clear()
    with patch.object(notifier, "_send", side_effect=capture_send), \
         patch.object(notifier, "_resolve_bot_token", return_value=""), \
         patch.object(notifier.config, "SLACK_WEBHOOK_URL", "https://hook.test"), \
         patch.object(notifier.config, "SLACK_CRITICAL_MENTION", "<@U0AI>"):
        notifier.post_alert(
            title="t", analysis="a", severity="critical",
            resource="Pod/svc", namespace="prod",
            skip_ai_mention=True,
        )
        top_text = captured["payload"].get("text", "")
        assert "<@U0AI>" not in top_text

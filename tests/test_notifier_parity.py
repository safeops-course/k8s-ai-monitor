"""Tests for notifier bot/webhook parity on non-alert notices + permanent
bot-error logging.

Pre-fix, `post_daily_report`, `post_weekly_report`, `_post_daily_report_str`
and `post_maintenance_notice` only used the webhook path — a cluster that
retired `SLACK_WEBHOOK_URL` in favour of bot-only transport lost visibility
of daily/weekly summaries and maintenance notices (they fell through to
console print). Post-fix all four go through the `_post_notice` helper
that mirrors `post_alert`'s bot-first + webhook-fallback dual-path.

Also validates that permanent Slack Bot API errors (invalid_auth,
channel_not_found, not_in_channel, token_revoked…) log at ERROR level
so they surface in log dashboards, vs WARNING for transient failures.
"""
import json
import logging
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

from src import config
from src.engine import notifier


@dataclass
class _FakeAR:
    parsed: dict | None
    raw_text: str = ""
    model: str = ""
    parse_error: bool = False


@pytest.fixture(autouse=True)
def _reset_bot_cache():
    notifier._bot_token_cache = None
    yield
    notifier._bot_token_cache = None


def _ok_response(ts: str = "1713555000.123"):
    resp = MagicMock()
    resp.content = b'{"ok":true,"ts":"' + ts.encode() + b'"}'
    resp.json.return_value = {"ok": True, "ts": ts}
    return resp


def _bad_response(error: str):
    resp = MagicMock()
    resp.content = b'{"ok":false,"error":"' + error.encode() + b'"}'
    resp.json.return_value = {"ok": False, "error": error}
    return resp


# ── _post_notice dual-path ────────────────────────────────────────────

def test_post_notice_uses_bot_api_when_configured(monkeypatch):
    """Bot token + channel present → chat.postMessage wins, webhook
    never touched."""
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-t")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "C0123")
    monkeypatch.setattr(config, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/hook")

    with patch("src.engine.notifier.requests.post", return_value=_ok_response()) as post_mock:
        ok = notifier._post_notice("Daily Report", {"attachments": [{"color": "good", "blocks": []}]})

    assert ok is True
    # One call to chat.postMessage, NOT to the webhook URL
    assert post_mock.call_count == 1
    call_url = post_mock.call_args.args[0]
    assert "chat.postMessage" in call_url


def test_post_notice_falls_back_to_webhook_on_bot_failure(monkeypatch):
    """Bot API returns ok=false (transient or permanent) → webhook
    fallback delivers the notice."""
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-t")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "C0123")
    monkeypatch.setattr(config, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/hook")

    bot_fail = _bad_response("rate_limited")
    webhook_ok = MagicMock(status_code=200, text="ok")

    def fake_post(url, *a, **kw):
        return bot_fail if "chat.postMessage" in url else webhook_ok

    with patch("src.engine.notifier.requests.post", side_effect=fake_post) as post_mock:
        ok = notifier._post_notice("Daily Report", {"attachments": [{"color": "good", "blocks": []}]})

    assert ok is True
    # Two calls total: bot API attempt + webhook fallback
    assert post_mock.call_count == 2


def test_post_notice_bot_only_cluster_delivers_without_webhook(monkeypatch):
    """Bot token + channel set, SLACK_WEBHOOK_URL EMPTY (bot-only
    retirement scenario) → chat.postMessage delivers, no console
    fallback needed."""
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-t")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "C0123")
    monkeypatch.setattr(config, "SLACK_WEBHOOK_URL", "")

    with patch("src.engine.notifier.requests.post", return_value=_ok_response()):
        ok = notifier._post_notice("Daily Report", {"attachments": [{"color": "good", "blocks": []}]})

    assert ok is True  # Delivered via bot API — previously this would have printed to console


def test_post_notice_returns_false_when_no_transport(monkeypatch):
    """Neither bot configured nor webhook set → returns False so the
    caller can render to console as last-resort."""
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "")
    monkeypatch.setattr(config, "SLACK_WEBHOOK_URL", "")

    ok = notifier._post_notice("Daily Report", {"attachments": [{"color": "good", "blocks": []}]})

    assert ok is False


def test_post_notice_returns_false_when_both_paths_fail(monkeypatch):
    """Bot API fails AND webhook _send returns False → caller renders
    to console."""
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-t")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "C0123")
    monkeypatch.setattr(config, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/hook")

    def fake_post(url, *a, **kw):
        return _bad_response("rate_limited") if "chat.postMessage" in url else MagicMock(status_code=500, text="err")

    with patch("src.engine.notifier.requests.post", side_effect=fake_post):
        ok = notifier._post_notice("Daily Report", {"attachments": [{"color": "good", "blocks": []}]})

    assert ok is False


# ── Permanent vs transient bot errors ──────────────────────────────────

def test_permanent_bot_error_logs_at_error_level(monkeypatch, caplog):
    """invalid_auth, channel_not_found, etc. → ERROR level + actionable
    message so operators see it in log dashboards."""
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-t")
    with patch("src.engine.notifier.requests.post", return_value=_bad_response("channel_not_found")), \
         caplog.at_level(logging.ERROR, logger="src.engine.notifier"):
        ts = notifier._post_via_bot_api(channel="C0BAD", text="t")
    assert ts is None
    messages = " ".join(r.message for r in caplog.records)
    assert "PERMANENT" in messages
    assert "channel_not_found" in messages


def test_transient_bot_error_logs_at_warning_level(monkeypatch, caplog):
    """rate_limited, service_unavailable → WARNING (worth noting but
    not urgent — it self-recovers)."""
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-t")
    with patch("src.engine.notifier.requests.post", return_value=_bad_response("rate_limited")), \
         caplog.at_level(logging.DEBUG, logger="src.engine.notifier"):
        ts = notifier._post_via_bot_api(channel="C0123", text="t")
    assert ts is None
    # No ERROR-level record for a transient failure
    error_records = [r for r in caplog.records if r.levelname == "ERROR"]
    assert error_records == []
    warn_records = [r for r in caplog.records if r.levelname == "WARNING"]
    assert any("rate_limited" in r.message for r in warn_records)


def test_all_known_permanent_errors_are_flagged(monkeypatch, caplog):
    """Sanity: every error code in _PERMANENT_BOT_ERRORS routes to
    ERROR level. Guards against future code additions silently falling
    back to WARNING."""
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-t")
    for err in sorted(notifier._PERMANENT_BOT_ERRORS):
        caplog.clear()
        with patch("src.engine.notifier.requests.post", return_value=_bad_response(err)), \
             caplog.at_level(logging.ERROR, logger="src.engine.notifier"):
            notifier._post_via_bot_api(channel="Cx", text="t")
        error_records = [r for r in caplog.records if r.levelname == "ERROR"]
        assert error_records, f"{err!r} should log at ERROR level"
        assert any(err in r.message for r in error_records)


# ── Caller integration: daily / weekly / maintenance ──────────────────

def _daily_result():
    return _FakeAR(parsed={
        "overall_status": "healthy",
        "summary": "all good",
        "issues": [],
        "trends": [],
        "recommendations": [],
    })


def _weekly_result():
    return _FakeAR(parsed={
        "overall_trend": "stable",
        "summary": "steady",
        "recurring_issues": [],
        "trends": [],
        "recommendations": [],
    })


def test_post_daily_report_uses_bot_api_when_configured(monkeypatch):
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-t")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "C0123")
    monkeypatch.setattr(config, "SLACK_WEBHOOK_URL", "")

    with patch("src.engine.notifier.requests.post", return_value=_ok_response()) as post_mock:
        notifier.post_daily_report(_daily_result())

    # Called exactly once; target is chat.postMessage
    assert post_mock.call_count == 1
    assert "chat.postMessage" in post_mock.call_args.args[0]


def test_post_daily_report_parse_error_posts_clean_notice_not_raw(monkeypatch):
    """On parse_error the raw (truncated) JSON must NOT reach Slack — a clean
    failure notice is posted instead. parse_daily_report returns a truthy dict
    on failure, so this must branch on parse_error, not `if result.parsed`."""
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-t")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "C0123")
    monkeypatch.setattr(config, "SLACK_WEBHOOK_URL", "")

    # Mimic parse_daily_report's failure return: truthy dict, raw text as summary.
    bad = _FakeAR(
        parsed={"_parse_error": True, "summary": "RAW_TRUNCATED_JSON_GARBAGE"},
        raw_text="RAW_TRUNCATED_JSON_GARBAGE",
        parse_error=True,
    )
    with patch("src.engine.notifier.requests.post", return_value=_ok_response()) as post_mock:
        notifier.post_daily_report(bad)

    # Inspect EVERY request the poster made (bot API sends json=, webhook data=),
    # not just the last — the raw garbage must appear in none of them.
    assert post_mock.call_args_list, "expected at least one Slack request"
    for call in post_mock.call_args_list:
        payload = json.dumps(
            {"json": call.kwargs.get("json"), "data": call.kwargs.get("data"), "args": call.args},
            default=str,
        )
        assert "Report generation failed" in payload
        assert "RAW_TRUNCATED_JSON_GARBAGE" not in payload


def test_post_weekly_report_uses_bot_api_when_configured(monkeypatch):
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-t")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "C0123")
    monkeypatch.setattr(config, "SLACK_WEBHOOK_URL", "")

    with patch("src.engine.notifier.requests.post", return_value=_ok_response()) as post_mock:
        notifier.post_weekly_report(_weekly_result())

    assert post_mock.call_count == 1
    assert "chat.postMessage" in post_mock.call_args.args[0]


def test_post_maintenance_notice_uses_bot_api_when_configured(monkeypatch):
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-t")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "C0123")
    monkeypatch.setattr(config, "SLACK_WEBHOOK_URL", "")

    with patch("src.engine.notifier.requests.post", return_value=_ok_response()) as post_mock:
        notifier.post_maintenance_notice(activated=True, reason="rollout", duration_hours=2)

    assert post_mock.call_count == 1
    assert "chat.postMessage" in post_mock.call_args.args[0]


def test_post_daily_report_str_uses_bot_api_when_configured(monkeypatch):
    """Plain-string daily report path also respects the bot API."""
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-t")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "C0123")
    monkeypatch.setattr(config, "SLACK_WEBHOOK_URL", "")

    with patch("src.engine.notifier.requests.post", return_value=_ok_response()) as post_mock:
        notifier._post_daily_report_str("plain text report body")

    assert post_mock.call_count == 1
    assert "chat.postMessage" in post_mock.call_args.args[0]


def test_post_daily_report_falls_back_to_console_when_no_transport(monkeypatch, capsys):
    """Neither bot token nor webhook set → console render (last-resort
    visibility for local dev / broken clusters)."""
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "")
    monkeypatch.setattr(config, "SLACK_WEBHOOK_URL", "")

    notifier.post_daily_report(_daily_result())

    captured = capsys.readouterr()
    assert "Daily Report" in captured.out
    assert "all good" in captured.out

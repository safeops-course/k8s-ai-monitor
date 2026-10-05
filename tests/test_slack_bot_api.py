"""Slack Bot API (chat.postMessage) with threading, and the webhook fallback."""
from unittest.mock import MagicMock, patch


from src import config
from src.engine import notifier
from src.engine.store.sqlite import SqliteStore


def _ok_response(ts: str = "1713555000.123"):
    resp = MagicMock()
    resp.content = b'{"ok":true,"ts":"' + ts.encode() + b'"}'
    resp.json.return_value = {"ok": True, "ts": ts}
    return resp


def _bad_response(error: str = "channel_not_found"):
    resp = MagicMock()
    resp.content = b'{"ok":false,"error":"' + error.encode() + b'"}'
    resp.json.return_value = {"ok": False, "error": error}
    return resp


# ── _resolve_bot_token ───────────────────────────────────────────────────

def test_bot_token_comes_from_the_env_var_only(monkeypatch):
    """The monitor reads no Kubernetes Secrets: no env var, no bot token."""
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-env")
    assert notifier._resolve_bot_token() == "xoxb-env"
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "")
    assert notifier._resolve_bot_token() == ""


# ── post_alert bot-primary + webhook fallback ───────────────────────────

def test_post_alert_uses_bot_api_when_token_and_channel_set(monkeypatch):
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-t")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "C0123")
    monkeypatch.setattr(config, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/webhook")

    with patch("src.engine.notifier.requests.post") as post_mock:
        post_mock.return_value = _ok_response(ts="1713555000.999")
        returned_ts = notifier.post_alert(
            title="t", analysis="a", severity="warning",
            resource="r", namespace="production",
        )
    assert returned_ts == "1713555000.999"
    url = post_mock.call_args.args[0]
    assert "chat.postMessage" in url
    # Did NOT call webhook — bot API succeeded
    all_urls = [c.args[0] for c in post_mock.call_args_list]
    assert not any("hooks.slack" in u for u in all_urls)


def test_post_alert_includes_thread_ts_when_provided(monkeypatch):
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-t")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "C0123")

    with patch("src.engine.notifier.requests.post") as post_mock:
        post_mock.return_value = _ok_response()
        notifier.post_alert(
            title="t", analysis="a", severity="warning",
            resource="r", namespace="production",
            thread_ts="1713500000.000",
        )
    body = post_mock.call_args.kwargs["json"]
    assert body["thread_ts"] == "1713500000.000"


def test_post_alert_falls_back_to_webhook_on_bot_failure(monkeypatch):
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-t")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "C0123")
    monkeypatch.setattr(config, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/webhook")

    def fake_post(url, *args, **kwargs):
        if "chat.postMessage" in url:
            return _bad_response("channel_not_found")
        # Webhook call — 200 OK
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        return resp

    with patch("src.engine.notifier.requests.post", side_effect=fake_post) as post_mock:
        returned_ts = notifier.post_alert(
            title="t", analysis="a", severity="warning",
            resource="r", namespace="production",
        )
    assert returned_ts == ""  # webhook path — no ts returned
    urls = [c.args[0] for c in post_mock.call_args_list]
    assert any("chat.postMessage" in u for u in urls)
    assert any("hooks.slack" in u for u in urls)


def test_post_alert_uses_webhook_when_no_bot_token(monkeypatch):
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "")
    monkeypatch.setattr(config, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/webhook")

    def fake_get_namespaces():
        return []

    with patch("src.engine.notifier.requests.post") as post_mock, \
         patch("src.config.get_namespaces", side_effect=fake_get_namespaces):
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        post_mock.return_value = resp
        returned_ts = notifier.post_alert(
            title="t", analysis="a", severity="warning",
            resource="r", namespace="production",
        )
    assert returned_ts == ""
    url = post_mock.call_args.args[0]
    assert "hooks.slack" in url
    assert "chat.postMessage" not in url


def test_post_alert_nonprod_uses_nonprod_channel(monkeypatch):
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-t")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "C_PROD")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID_NONPROD", "C_NONPROD")
    monkeypatch.setattr(config, "NON_PROD_NAMESPACES", {"develop", "staging"})

    with patch("src.engine.notifier.requests.post") as post_mock:
        post_mock.return_value = _ok_response()
        notifier.post_alert(
            title="t", analysis="a", severity="warning",
            resource="r", namespace="develop",
        )
    body = post_mock.call_args.kwargs["json"]
    assert body["channel"] == "C_NONPROD"


# ── Store set/clear_last_slack_ts ───────────────────────────────────────

def test_set_last_slack_ts_persists_value(tmp_path):
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    inc = store.create_incident(
        state_key="k", fingerprint="fp", issue_type="crash",
        severity="warning", namespace="prod", owner_ref="",
    )
    store.set_last_slack_ts(inc.id, "1713555000.000")
    fresh = store.get_incident("k")
    assert fresh is not None
    assert fresh.last_slack_ts == "1713555000.000"


def test_set_last_slack_ts_empty_string_noop(tmp_path):
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    inc = store.create_incident(
        state_key="k", fingerprint="fp", issue_type="crash",
        severity="warning", namespace="prod", owner_ref="",
    )
    store.set_last_slack_ts(inc.id, "abc")
    store.set_last_slack_ts(inc.id, "")  # empty — don't overwrite
    fresh = store.get_incident("k")
    assert fresh is not None
    assert fresh.last_slack_ts == "abc"


def test_clear_last_slack_ts(tmp_path):
    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    inc = store.create_incident(
        state_key="k", fingerprint="fp", issue_type="crash",
        severity="warning", namespace="prod", owner_ref="",
    )
    store.set_last_slack_ts(inc.id, "xyz")
    store.clear_last_slack_ts(inc.id)
    fresh = store.get_incident("k")
    assert fresh is not None
    assert fresh.last_slack_ts == ""


# ── End-to-end: pipeline capture + thread ─────────────────────────────

def test_post_alert_no_silent_drop_when_bot_fails_and_no_webhook(monkeypatch, caplog):
    """When bot API fails AND no webhook is configured, the alert must
    not silently disappear — an ERROR must be logged and console
    fallback must fire.
    """
    import logging
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-t")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "C0123")
    monkeypatch.setattr(config, "SLACK_WEBHOOK_URL", "")

    with patch("src.engine.notifier.requests.post", return_value=_bad_response("channel_not_found")), \
         patch("src.engine.notifier._console_alert") as console_mock, \
         caplog.at_level(logging.ERROR, logger="src.engine.notifier"):
        returned_ts = notifier.post_alert(
            title="t", analysis="a", severity="critical",
            resource="r", namespace="production",
        )
    # Total delivery failure (console-only) → None, so callers gating on
    # `posted_ts is not None` can skip side-effects like @ai cooldown bumping.
    assert returned_ts is None
    console_mock.assert_called_once()
    messages = " ".join(r.message for r in caplog.records)
    assert "DROPPED" in messages
    assert "no webhook" in messages


def test_post_alert_logs_error_when_send_returns_false(monkeypatch, caplog):
    """If the webhook call itself fails (non-2xx / network error),
    _send returns False and we must log ERROR + console fallback
    instead of returning silently.
    """
    import logging
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "")
    monkeypatch.setattr(config, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/webhook")

    with patch("src.engine.notifier._send", return_value=False), \
         patch("src.engine.notifier._console_alert") as console_mock, \
         patch("src.config.get_namespaces", return_value=[]), \
         caplog.at_level(logging.ERROR, logger="src.engine.notifier"):
        returned = notifier.post_alert(
            title="t", analysis="a", severity="critical",
            resource="r", namespace="production",
        )
    # Webhook _send returned False — no Slack delivery happened; return
    # None so callers can skip delivery-dependent side effects.
    assert returned is None
    console_mock.assert_called_once()
    messages = " ".join(r.message for r in caplog.records)
    assert "FAILED" in messages


def test_pipeline_persists_ts_for_preexisting_incident_without_last_ts(tmp_path, monkeypatch):
    """A pre-existing active incident with empty last_slack_ts (e.g.
    created before bot API rollout) must capture the FIRST successful
    bot-API ts so subsequent recurrences thread under it. Previously
    only the `reopened` path persisted — pre-existing incidents stayed
    un-threaded forever.
    """
    from src.engine import pipeline
    from src.scanners._base import ScanResult

    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-t")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "C0123")

    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    # Create an incident the "old way" — existing active with no ts stored.
    inc = store.create_incident(
        state_key="Pod:prod/svc:crash", fingerprint="fp", issue_type="crash",
        severity="critical", namespace="prod", owner_ref="",
    )
    assert inc.last_slack_ts == ""
    # Simulate that the first fire already happened under the webhook
    # era (no ts returned back then) — bumping occurrence_count so the
    # next scan tick is the 2nd occurrence → recurring → should_alert.
    ctx_hash = store.store_context("{}")
    store.record_occurrence(inc.id, context_hash=ctx_hash,
                            batch_status="immediate")

    # Simulate a recurring scan: same state_key re-fires. Pipeline sees
    # the pre-existing incident and calls post_alert → bot returns ts.
    result = ScanResult(
        state_key="Pod:prod/svc:crash", title="svc crash",
        severity="critical", resource="Pod/svc", namespace="prod",
        issue_type="crash", pod_name="svc-abc",
        skip_llm=True,  # this test is about the Slack ts, not the analysis
    )

    def fake_post(url, *args, **kwargs):
        if "chat.postMessage" in url:
            return _ok_response(ts="1700000001.000")
        return _ok_response()

    with patch("src.engine.notifier.requests.post", side_effect=fake_post), \
         patch("src.config.get_namespaces", return_value=["prod"]):
        pipeline.process_scan_results([result], store)

    refreshed = store.get_incident("Pod:prod/svc:crash")
    assert refreshed is not None
    # The fresh top-level bot post should have populated last_slack_ts
    # so the NEXT recurrence threads under it.
    assert refreshed.last_slack_ts == "1700000001.000"


def test_pipeline_does_not_overwrite_last_ts_with_thread_reply(tmp_path, monkeypatch):
    """When an incident already has last_slack_ts and recurs, the new
    post is a thread_ts reply. We must NOT overwrite the stored root
    ts with the reply's ts (future recurrences would then thread under
    the reply instead of the root).
    """
    from src.engine import pipeline
    from src.scanners._base import ScanResult

    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-t")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "C0123")

    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    inc = store.create_incident(
        state_key="Pod:prod/svc:crash", fingerprint="fp", issue_type="crash",
        severity="critical", namespace="prod", owner_ref="",
    )
    # Pre-populate a root ts (simulates earlier successful bot post).
    root_ts = "1700000000.ROOT"
    store.set_last_slack_ts(inc.id, root_ts)

    result = ScanResult(
        state_key="Pod:prod/svc:crash", title="svc crash",
        severity="critical", resource="Pod/svc", namespace="prod",
        issue_type="crash", pod_name="svc-abc",
        skip_llm=True,  # this test is about the Slack ts, not the analysis
    )

    # Bot returns a DIFFERENT ts (the thread reply's ts) on the recurring post.
    def fake_post(url, *args, **kwargs):
        if "chat.postMessage" in url:
            return _ok_response(ts="1700000002.REPLY")
        return _ok_response()

    with patch("src.engine.notifier.requests.post", side_effect=fake_post), \
         patch("src.config.get_namespaces", return_value=["prod"]):
        pipeline.process_scan_results([result], store)

    refreshed = store.get_incident("Pod:prod/svc:crash")
    assert refreshed is not None
    # Root ts MUST be preserved — the reply ts is not a new root.
    assert refreshed.last_slack_ts == root_ts


def test_pipeline_captures_ts_on_new_incident(tmp_path, monkeypatch):
    """A new-incident Slack post should stash its ts via set_last_slack_ts."""
    from src.engine import pipeline
    from src.scanners._base import ScanResult

    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-t")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "C0123")

    store = SqliteStore(db_path=str(tmp_path / "t.db"))
    result = ScanResult(
        state_key="Pod:prod/svc:crash", title="svc crash",
        severity="critical", resource="Pod/svc", namespace="prod",
        issue_type="crash", pod_name="svc-abc",
        skip_llm=True,  # this test is about the Slack ts, not the analysis
    )

    def fake_post(url, *args, **kwargs):
        if "chat.postMessage" in url:
            return _ok_response(ts="1700000000.111")
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        return resp

    with patch("src.engine.notifier.requests.post", side_effect=fake_post), \
         patch("src.config.get_namespaces", return_value=["prod"]):
        pipeline.process_scan_results([result], store)

    inc = store.get_incident("Pod:prod/svc:crash")
    assert inc is not None
    assert inc.last_slack_ts == "1700000000.111"

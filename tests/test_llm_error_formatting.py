"""Tests for the LLM error-formatting helper (`_format_llm_error`).

Before this helper, every LLM failure rendered as a generic Slack line:
    "⚠️ AI daily report unavailable — LLM API error."
Operators had to grep pod logs to see exception type or cause. Now the
fallback message includes exception class, a short sanitized message
snippet, an HTTP-status hint when the error string carries one, and a
pointer to where full detail lives.
"""
from src.engine.llm import _format_llm_error


def test_includes_exception_class_name():
    exc = TimeoutError("request took 65s")
    out = _format_llm_error(exc, "daily report")
    assert "TimeoutError" in out
    assert "daily report" in out
    assert "request took 65s" in out


def test_429_hint_surfaced():
    exc = Exception("Error code: 429 - {'message': 'rate limit exceeded'}")
    out = _format_llm_error(exc, "analysis")
    assert "429" in out
    assert "rate-limited" in out.lower() or "quota" in out.lower()


def test_401_hint_surfaced():
    exc = Exception("Error code: 401 - invalid API key")
    out = _format_llm_error(exc, "analysis")
    assert "credentials" in out.lower()


def test_413_hint_surfaced():
    exc = Exception("HTTP 413 context_length_exceeded")
    out = _format_llm_error(exc, "analysis")
    assert "context too large" in out.lower() or "MAX_CONTEXT" in out


def test_status_hint_ignores_embedded_digits():
    """Regression: `"retry after 4136 seconds"` must NOT match the 413
    hint just because "413" is a substring. Nor "latency:5000ms"
    the 500 hint. The classifier uses word-boundary matching to
    isolate exact 3-digit status codes."""
    exc = Exception("retry after 4136 seconds (latency:5000ms, attempt 1/3)")
    out = _format_llm_error(exc, "analysis")
    assert "context too large" not in out.lower()
    assert "provider internal error" not in out.lower()
    # Still surfaces class + snippet, just no misleading hint.
    assert "Exception" in out


def test_status_hint_matches_bare_token():
    """`"503"` alone (no prefix, no trailing digits) must still match."""
    exc = Exception("503")
    out = _format_llm_error(exc, "analysis")
    assert "retryable" in out.lower() or "unavailable" in out.lower()


def test_unknown_exception_still_actionable():
    """Even a random exception class should produce a usable message —
    not just "LLM API error"."""
    class WeirdError(Exception):
        pass
    exc = WeirdError("something unexpected happened in middleware")
    out = _format_llm_error(exc, "investigation")
    assert "WeirdError" in out
    assert "something unexpected" in out
    # Pointer to logs always present — operator always knows where to dig.
    assert "logs" in out.lower()


def test_message_snippet_is_size_bounded():
    """A 5KB error string must not end up in Slack verbatim — capped
    at ~240 chars so the Slack block doesn't bloat."""
    exc = Exception("x" * 5000)
    out = _format_llm_error(exc, "analysis")
    # Total output should be well under 1KB even with the long message.
    assert len(out) < 1000


def test_message_first_line_only():
    """Multi-line error messages are collapsed to first line so
    stacktraces buried in the exception message don't render into
    the Slack body."""
    exc = Exception("timed out after 30s\n\nTraceback:\n  File \"...\"")
    out = _format_llm_error(exc, "analysis")
    assert "timed out after 30s" in out
    assert "Traceback" not in out


def test_credentials_stripped_from_snippet():
    """If the exception message leaks an API key pattern, the sanitized
    snippet must redact it — we must not post secrets to Slack.
    Uses a realistically-long OpenAI-style key (real keys are 48+ chars)."""
    # built from parts so that secret scanners do not flag the test itself
    leaked_key = "sk-" + "proj-" + "abcdef0123456789ABCDEF0123456789abcdefGHIJKL"
    exc = Exception(f"auth failed with key {leaked_key} please rotate")
    out = _format_llm_error(exc, "analysis")
    assert leaked_key not in out
    assert "[REDACTED_LLM_KEY]" in out


def test_empty_exception_message_handled():
    """Some exceptions carry no message; formatter must still produce
    output (not raise, not emit blank)."""
    out = _format_llm_error(Exception(), "analysis")
    assert "Exception" in out
    assert "unavailable" in out


# ── Retry classifier + wrapper (observed prod issue: lima 503 no-retry)─

def test_classifier_503_is_retryable():
    from src.engine.llm import _is_retryable_llm_error
    exc = Exception("HTTP/1.1 503 Service Unavailable")
    assert _is_retryable_llm_error(exc) is True


def test_classifier_429_is_retryable():
    from src.engine.llm import _is_retryable_llm_error
    exc = Exception("Error code: 429 - rate limit exceeded")
    assert _is_retryable_llm_error(exc) is True


def test_classifier_timeout_is_retryable():
    from src.engine.llm import _is_retryable_llm_error
    assert _is_retryable_llm_error(TimeoutError("timed out")) is True


def test_classifier_connection_error_retryable():
    from src.engine.llm import _is_retryable_llm_error
    assert _is_retryable_llm_error(ConnectionError("refused")) is True


def test_classifier_google_service_unavailable_retryable():
    from src.engine.llm import _is_retryable_llm_error
    exc = Exception("SERVICE_UNAVAILABLE: The service is temporarily down")
    assert _is_retryable_llm_error(exc) is True


def test_classifier_401_not_retryable():
    """Auth failure won't succeed on retry — must propagate immediately."""
    from src.engine.llm import _is_retryable_llm_error
    exc = Exception("Error code: 401 - invalid API key")
    assert _is_retryable_llm_error(exc) is False


def test_classifier_413_not_retryable():
    """Context-too-large won't fix itself — fail fast."""
    from src.engine.llm import _is_retryable_llm_error
    exc = Exception("HTTP 413 context_length_exceeded")
    assert _is_retryable_llm_error(exc) is False


def test_retry_wrapper_retries_on_transient(monkeypatch):
    """Two 503s then success — wrapper must retry + succeed. Exp-backoff
    is mocked to zero so the test doesn't actually sleep."""
    from src.engine import llm
    from src import config
    monkeypatch.setattr(config, "LLM_RETRY_COUNT", 3)
    monkeypatch.setattr(config, "LLM_RETRY_BACKOFF_SECONDS", 0.0)

    calls: list[int] = []

    def flaky(*a, **kw):
        calls.append(1)
        if len(calls) < 3:
            raise Exception("HTTP/1.1 503 Service Unavailable")
        return ("ok", 10, 5, 100.0, 0)

    monkeypatch.setattr(llm, "_call_llm", flaky)
    out = llm._call_llm_with_retry("gemini", None, "m", "sys", "user", 1024)
    assert out[:5] == ("ok", 10, 5, 100.0, 0)
    assert out[5] is False  # effective flex (none requested)
    assert len(calls) == 3  # retried twice, succeeded on third


def test_retry_wrapper_gives_up_after_max_attempts(monkeypatch):
    """Persistent transient error must not infinite-loop — wrapper
    raises after max_retries."""
    import pytest
    from src.engine import llm
    from src import config
    monkeypatch.setattr(config, "LLM_RETRY_COUNT", 2)
    monkeypatch.setattr(config, "LLM_RETRY_BACKOFF_SECONDS", 0.0)

    calls: list[int] = []

    def always_503(*a, **kw):
        calls.append(1)
        raise Exception("HTTP/1.1 503 Service Unavailable")

    monkeypatch.setattr(llm, "_call_llm", always_503)
    with pytest.raises(Exception, match="503"):
        llm._call_llm_with_retry("gemini", None, "m", "sys", "user", 1024)
    assert len(calls) == 3  # 1 initial + 2 retries


def test_retry_wrapper_does_not_retry_on_auth_error(monkeypatch):
    """Non-retryable error (401) propagates on first attempt — no
    retry loop."""
    import pytest
    from src.engine import llm
    from src import config
    monkeypatch.setattr(config, "LLM_RETRY_COUNT", 5)  # large, to prove we don't loop
    monkeypatch.setattr(config, "LLM_RETRY_BACKOFF_SECONDS", 0.0)

    calls: list[int] = []

    def auth_fail(*a, **kw):
        calls.append(1)
        raise Exception("Error code: 401 - invalid API key")

    monkeypatch.setattr(llm, "_call_llm", auth_fail)
    with pytest.raises(Exception, match="401"):
        llm._call_llm_with_retry("gemini", None, "m", "sys", "user", 1024)
    assert len(calls) == 1  # no retries attempted


def test_retry_log_message_sanitizes_provider_keys(monkeypatch, caplog):
    """Regression: on transient failure, the retry logger.warning must
    NOT echo provider API keys from the SDK's exception message. SDK
    errors like `"Incorrect API key provided: sk-..."` would otherwise
    leak the key into monitor logs + central log aggregation."""
    import logging
    from src.engine import llm
    from src import config
    monkeypatch.setattr(config, "LLM_RETRY_COUNT", 1)
    monkeypatch.setattr(config, "LLM_RETRY_BACKOFF_SECONDS", 0.0)

    leaked_key = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"

    calls: list[int] = []

    def fail_with_key(*a, **kw):
        calls.append(1)
        if len(calls) == 1:
            # Transient 503 carrying the leaked key in its message.
            raise Exception(
                f"HTTP/1.1 503 Service Unavailable — last auth used {leaked_key}"
            )
        return ("ok", 10, 5, 100.0, 0)

    monkeypatch.setattr(llm, "_call_llm", fail_with_key)
    with caplog.at_level(logging.WARNING, logger="src.engine.llm"):
        llm._call_llm_with_retry("gemini", None, "m", "sys", "user", 1024)

    warn_msgs = " ".join(r.message for r in caplog.records)
    assert leaked_key not in warn_msgs
    assert "[REDACTED_LLM_KEY]" in warn_msgs


def test_retry_wrapper_disabled_when_count_zero(monkeypatch):
    """`LLM_RETRY_COUNT=0` reverts to single-attempt behaviour for
    operators who want to turn retry off."""
    import pytest
    from src.engine import llm
    from src import config
    monkeypatch.setattr(config, "LLM_RETRY_COUNT", 0)
    monkeypatch.setattr(config, "LLM_RETRY_BACKOFF_SECONDS", 0.0)

    calls: list[int] = []

    def fail_503(*a, **kw):
        calls.append(1)
        raise Exception("503 Service Unavailable")

    monkeypatch.setattr(llm, "_call_llm", fail_503)
    with pytest.raises(Exception, match="503"):
        llm._call_llm_with_retry("gemini", None, "m", "sys", "user", 1024)
    assert len(calls) == 1  # single attempt, no retry


def test_retry_wrapper_drops_flex_after_transient_failure(monkeypatch):
    """Regression (example daily report, 2026-06-03): the flex/batch tier is
    deprioritised under load and yields 503/504 during demand spikes. After
    the first transient failure the wrapper must fall back to the standard
    tier (flex=False) for the remaining attempts."""
    from src.engine import llm
    from src import config
    monkeypatch.setattr(config, "LLM_RETRY_COUNT", 3)
    monkeypatch.setattr(config, "LLM_RETRY_BACKOFF_SECONDS", 0.0)

    flex_seen: list[bool] = []

    def flaky(provider, client, model, system, user_content, max_tokens, flex=False):
        flex_seen.append(flex)
        if len(flex_seen) < 3:
            raise Exception("503 UNAVAILABLE")
        return ("ok", 10, 5, 100.0, 0)

    monkeypatch.setattr(llm, "_call_llm", flaky)
    out = llm._call_llm_with_retry("gemini", None, "m", "sys", "user", 1024, flex=True)
    assert out[:5] == ("ok", 10, 5, 100.0, 0)
    # The successful attempt ran on the standard tier — the returned flag must
    # say so, so the caller bills at the standard (not discounted flex) rate.
    assert out[5] is False
    # First attempt uses flex; every retry after the first failure uses standard tier.
    assert flex_seen == [True, False, False]


def test_retry_wrapper_keeps_flex_false_when_not_requested(monkeypatch):
    """When flex was never requested, the fallback is a no-op — all attempts
    stay on the standard tier."""
    from src.engine import llm
    from src import config
    monkeypatch.setattr(config, "LLM_RETRY_COUNT", 2)
    monkeypatch.setattr(config, "LLM_RETRY_BACKOFF_SECONDS", 0.0)

    flex_seen: list[bool] = []

    def flaky(provider, client, model, system, user_content, max_tokens, flex=False):
        flex_seen.append(flex)
        if len(flex_seen) < 2:
            raise Exception("503 UNAVAILABLE")
        return ("ok", 1, 1, 1.0, 0)

    monkeypatch.setattr(llm, "_call_llm", flaky)
    llm._call_llm_with_retry("gemini", None, "m", "sys", "user", 1024, flex=False)
    assert flex_seen == [False, False]

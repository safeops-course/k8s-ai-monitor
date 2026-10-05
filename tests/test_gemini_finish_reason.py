"""Tests for `_log_gemini_finish` — the loud failure on a truncated Gemini call.

Background: Gemini charges THINKING tokens against
`max_output_tokens` and spends them before the answer. On a busy cluster the
thinking pass consumed the 4096-token ceiling and left ~150 tokens for the
report, so the JSON stopped mid-`reasoning` string. `resp.text` returns that
partial text with no error, so by the time it reached the parser the failure
was indistinguishable from a model that simply wrote bad JSON — and nothing in
the logs named the real cause. 8% of the reports failed this way over two
weeks before anyone could point at the budget.
"""
import logging

from src.engine.llm import _is_gemini_config_rejection, _log_gemini_finish


class _FakeFinish:
    def __init__(self, name):
        self.name = name


class _FakeCandidate:
    def __init__(self, finish_name):
        self.finish_reason = _FakeFinish(finish_name)


class _FakeResp:
    def __init__(self, finish_name):
        self.candidates = [_FakeCandidate(finish_name)]


class _FakeUsage:
    def __init__(self, thoughts, answer):
        self.thoughts_token_count = thoughts
        self.candidates_token_count = answer


def test_stop_is_silent(caplog):
    """A clean finish must not add log noise — every successful call hits this."""
    with caplog.at_level(logging.DEBUG):
        _log_gemini_finish(_FakeResp("STOP"), _FakeUsage(2164, 603), "gemini-3-flash-preview", 16384, 2486)
    assert caplog.records == []


def test_max_tokens_logs_error_with_token_split(caplog):
    """The production signature: thinking ate the budget, answer got ~150 tokens."""
    with caplog.at_level(logging.ERROR):
        _log_gemini_finish(_FakeResp("MAX_TOKENS"), _FakeUsage(2164, 121), "gemini-3-flash-preview", 2300, 515)
    assert len(caplog.records) == 1
    msg = caplog.records[0].getMessage()
    assert caplog.records[0].levelno == logging.ERROR
    # The token arithmetic must be in the message — that is the whole point.
    assert "2164" in msg and "121" in msg and "2300" in msg
    assert "MAX_TOKENS" in msg
    # And it must name the knobs an operator can actually turn.
    assert "GEMINI_THINKING_LEVEL" in msg or "REPORT_MAX_OUTPUT_TOKENS" in msg


def test_other_non_stop_reasons_logged(caplog):
    """SAFETY / RECITATION / OTHER also yield partial text — never swallow them."""
    with caplog.at_level(logging.ERROR):
        _log_gemini_finish(_FakeResp("SAFETY"), _FakeUsage(10, 5), "gemini-3-flash-preview", 16384, 40)
    assert len(caplog.records) == 1
    assert "SAFETY" in caplog.records[0].getMessage()


def test_missing_usage_fields_do_not_raise(caplog):
    """Diagnostics must never break the call path they are diagnosing."""
    with caplog.at_level(logging.ERROR):
        _log_gemini_finish(_FakeResp("MAX_TOKENS"), None, "gemini-3-flash-preview", 16384, 100)
    assert len(caplog.records) == 1


def test_no_candidates_is_silent(caplog):
    class _Empty:
        candidates = []

    with caplog.at_level(logging.DEBUG):
        _log_gemini_finish(_Empty(), _FakeUsage(1, 1), "gemini-3-flash-preview", 16384, 0)
    assert caplog.records == []


# --- _is_gemini_config_rejection -------------------------------------------
# thinking_level / service_tier are OPTIONAL knobs. An SDK that doesn't know
# them raises TypeError; a backend that won't accept them answers HTTP 400
# INVALID_ARGUMENT. Both must degrade to a retry without the knobs. Anything
# else (auth, quota, oversized context) must propagate — retrying is useless
# and would just hide the real error.

def test_sdk_type_error_is_a_rejection():
    assert _is_gemini_config_rejection(TypeError("unexpected keyword 'thinking_config'"))
    assert _is_gemini_config_rejection(ValueError("unknown field"))


def test_backend_400_naming_the_knob_is_a_rejection():
    assert _is_gemini_config_rejection(
        Exception("400 INVALID_ARGUMENT: thinking_level is not supported for this model"))
    assert _is_gemini_config_rejection(
        Exception("400 INVALID_ARGUMENT: service_tier 'flex' not enabled"))


def test_unrelated_400_is_not_a_rejection():
    """A bad request about something else must not be silently retried."""
    assert not _is_gemini_config_rejection(
        Exception("400 INVALID_ARGUMENT: request payload size exceeds the limit"))


def test_auth_and_quota_errors_propagate():
    assert not _is_gemini_config_rejection(Exception("401 UNAUTHENTICATED: API key invalid"))
    assert not _is_gemini_config_rejection(Exception("429 RESOURCE_EXHAUSTED: quota exceeded"))
    assert not _is_gemini_config_rejection(Exception("503 UNAVAILABLE"))

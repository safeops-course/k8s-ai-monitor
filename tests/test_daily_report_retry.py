"""Tests for daily-report-level retry signalling.

Regression: a multi-minute LLM provider outage
(503 UNAVAILABLE / 504 DEADLINE_EXCEEDED) exhausted the per-call retry
budget, an error placeholder was stored as "the report", and the next
attempt was a full day later. `run_daily_report` now returns whether a
real report was produced so the scheduler can re-attempt within the day,
and can suppress the error placeholder on intermediate attempts.
"""
from src import reporter
from src.engine.llm import AnalysisResult


def _result(*, llm_error: bool, parsed=None):
    return AnalysisResult(
        raw_text="x", parsed=parsed, parse_error=parsed is None,
        model="m", tokens_in=0, tokens_out=0, cost_usd=None, llm_error=llm_error,
    )


class _FakeCollector:
    def collect_daily_data(self):
        return {"nodes": []}


def _patch_common(monkeypatch, result, saved, posted):
    monkeypatch.setattr(reporter, "Collector", _FakeCollector)
    monkeypatch.setattr(reporter, "analyze_daily_report", lambda data: result)
    monkeypatch.setattr(reporter, "_save_report", lambda *a, **k: saved.append(1))
    monkeypatch.setattr(reporter, "post_daily_report", lambda r: posted.append(1))
    monkeypatch.setattr(reporter.central_push, "push_report", lambda payload: None)
    monkeypatch.setattr(reporter, "llm_configured", lambda: True)


def test_no_llm_key_skips_the_report(monkeypatch):
    saved, posted = [], []
    _patch_common(monkeypatch, _result(llm_error=False), saved, posted)
    monkeypatch.setattr(reporter, "llm_configured", lambda: False)
    monkeypatch.setattr(reporter, "analyze_daily_report",
                        lambda data: (_ for _ in ()).throw(AssertionError("LLM called")))
    assert reporter.run_daily_report() is False  # nothing produced
    assert saved == [] and posted == []


def test_run_daily_report_returns_true_on_success(monkeypatch):
    saved, posted = [], []
    _patch_common(monkeypatch, _result(llm_error=False, parsed={"overall_status": "healthy"}),
                  saved, posted)
    assert reporter.run_daily_report() is True
    assert saved and posted  # real report is persisted + posted


def test_run_daily_report_returns_false_on_llm_error(monkeypatch):
    saved, posted = [], []
    _patch_common(monkeypatch, _result(llm_error=True), saved, posted)
    # Default (final attempt): still surfaces the error to operators...
    assert reporter.run_daily_report() is False
    assert saved and posted


def test_run_daily_report_suppresses_error_output_on_retry(monkeypatch):
    saved, posted = [], []
    _patch_common(monkeypatch, _result(llm_error=True), saved, posted)
    # Intermediate attempt: no Slack post / no error report row.
    assert reporter.run_daily_report(suppress_error_output=True) is False
    assert not saved and not posted


def test_run_daily_report_skips_when_already_running(monkeypatch):
    """Concurrency guard: while one run holds the lock (e.g. a timed-out but
    still-running executor thread, or a manual trigger), a second invocation
    must return False without doing any work (no double LLM call / publish)."""
    called = []
    monkeypatch.setattr(reporter, "Collector", _FakeCollector)
    monkeypatch.setattr(reporter, "analyze_daily_report", lambda data: called.append(1))
    monkeypatch.setattr(reporter, "llm_configured", lambda: True)
    reporter._daily_report_lock.acquire()
    try:
        assert reporter.run_daily_report() is False
        assert not called  # body never ran — short-circuited on the lock
    finally:
        reporter._daily_report_lock.release()


def test_run_daily_report_releases_lock_on_success(monkeypatch):
    """The lock must be released after a run so the next scheduled run isn't
    permanently blocked."""
    saved, posted = [], []
    _patch_common(monkeypatch, _result(llm_error=False, parsed={"overall_status": "healthy"}),
                  saved, posted)
    assert reporter.run_daily_report() is True
    assert reporter._daily_report_lock.acquire(blocking=False)  # free again
    reporter._daily_report_lock.release()


def test_run_daily_report_suppress_flag_ignored_on_success(monkeypatch):
    """suppress_error_output only gates the error path — a successful report
    is always persisted/posted even when the flag is set."""
    saved, posted = [], []
    _patch_common(monkeypatch, _result(llm_error=False, parsed={"overall_status": "healthy"}),
                  saved, posted)
    assert reporter.run_daily_report(suppress_error_output=True) is True
    assert saved and posted


def test_scheduler_does_not_run_or_retry_without_a_key(monkeypatch):
    """No key: the retry wrapper returns False at once - no attempt, no checkpoint."""
    import asyncio

    from src.handlers import startup
    monkeypatch.setattr(startup, "llm_configured", lambda: False)
    monkeypatch.setattr(startup, "run_daily_report",
                        lambda **kw: (_ for _ in ()).throw(AssertionError("report ran")))
    assert asyncio.run(startup._run_daily_with_retries()) is False

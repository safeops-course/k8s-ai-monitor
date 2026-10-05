"""Tests for Sprint 11 — ES top error pattern enrichment."""
from unittest.mock import patch

from src.collectors import elasticsearch
from src.engine import enrichment


# ── Normalisation ────────────────────────────────────────────────────────

def test_normalise_strips_timestamp():
    line = "2026-04-17T14:23:59.123Z failed to dial postgres"
    norm = elasticsearch._normalise_error_line(line)
    assert "2026-04-17" not in norm
    assert "<ts>" in norm


def test_normalise_strips_uuid():
    line = "request abc12345-abcd-efab-cdef-123456abcdef failed"
    norm = elasticsearch._normalise_error_line(line)
    assert "<uuid>" in norm
    assert "abc12345" not in norm


def test_normalise_strips_long_hex():
    line = "trace_id=abcdef0123456789abcdef0123456789 exception"
    norm = elasticsearch._normalise_error_line(line)
    assert "<hex>" in norm


def test_normalise_strips_ip_and_duration():
    line = "timeout after 1.234s from 10.0.1.5:5432"
    norm = elasticsearch._normalise_error_line(line)
    assert "<dur>" in norm
    assert "<ip>" in norm


def test_normalise_collapses_variants_into_one_key():
    a = "2026-04-17T10:00:00 connect timeout 1.1s from 10.0.0.1:5432"
    b = "2026-04-17T11:15:42 connect timeout 3.9s from 10.0.0.9:5432"
    assert elasticsearch._normalise_error_line(a) == elasticsearch._normalise_error_line(b)


# ── Aggregation ──────────────────────────────────────────────────────────

def test_aggregate_returns_none_when_es_unconfigured():
    with patch("src.collectors.elasticsearch._is_configured", return_value=False):
        assert elasticsearch.aggregate_error_patterns("production") is None


def test_aggregate_returns_empty_list_when_no_logs():
    with patch("src.collectors.elasticsearch._is_configured", return_value=True), \
         patch("src.collectors.elasticsearch.search_error_logs", return_value=[]):
        assert elasticsearch.aggregate_error_patterns("production") == []


def test_aggregate_returns_none_when_es_fails():
    """search_error_logs returning None (connection error) propagates."""
    with patch("src.collectors.elasticsearch._is_configured", return_value=True), \
         patch("src.collectors.elasticsearch.search_error_logs", return_value=None):
        assert elasticsearch.aggregate_error_patterns("production") is None


def test_aggregate_counts_and_normalises():
    fake_logs = [
        # 3× same pattern with different durations / trace IDs (16+ hex)
        {"message": "2026-04-17T10:00:00 connection timeout after 1.1s trace_id=aaaaaaaaaaaaaaaa", "pod": "p1"},
        {"message": "2026-04-17T10:00:01 connection timeout after 3.5s trace_id=bbbbbbbbbbbbbbbb", "pod": "p1"},
        {"message": "2026-04-17T10:00:02 connection timeout after 5.7s trace_id=cccccccccccccccc", "pod": "p1"},
        # 1× distinct pattern
        {"message": "context deadline exceeded", "pod": "p1"},
    ]
    with patch("src.collectors.elasticsearch._is_configured", return_value=True), \
         patch("src.collectors.elasticsearch.search_error_logs", return_value=fake_logs):
        out = elasticsearch.aggregate_error_patterns("production", top=2)
    assert out is not None
    assert len(out) == 2
    assert out[0]["count"] == 3
    assert out[1]["count"] == 1


def test_aggregate_filters_by_pod_exact_match():
    """Pod filter must be exact — a substring match would let unrelated
    pods that share a prefix leak into the aggregation bucket."""
    fake_logs = [
        {"message": "oom", "pod": "frontend"},         # matches
        {"message": "oom", "pod": "frontend"},         # matches
        {"message": "oom", "pod": "frontend-different"},  # prefix match — must be excluded
        {"message": "oom", "pod": "backend-1"},     # unrelated
    ]
    with patch("src.collectors.elasticsearch._is_configured", return_value=True), \
         patch("src.collectors.elasticsearch.search_error_logs", return_value=fake_logs):
        out = elasticsearch.aggregate_error_patterns(
            "production", pod="frontend", top=5,
        )
    assert out is not None
    assert out[0]["count"] == 2


# ── Enrichment block ─────────────────────────────────────────────────────

def test_es_top_errors_skips_when_es_unconfigured():
    with patch("src.engine.enrichment.elasticsearch._is_configured", return_value=False):
        assert enrichment._es_top_errors({"pod": {"namespace": "production"}}) == ""


def test_es_top_errors_skips_without_namespace():
    with patch("src.engine.enrichment.elasticsearch._is_configured", return_value=True):
        assert enrichment._es_top_errors({}) == ""
        assert enrichment._es_top_errors({"pod": {}}) == ""


def test_es_top_errors_skips_non_prod():
    context = {"pod": {"namespace": "develop", "name": "p"}}
    with patch("src.engine.enrichment.elasticsearch._is_configured", return_value=True), \
         patch("src.config.is_nonprod_namespace", return_value=True), \
         patch("src.engine.enrichment.elasticsearch.aggregate_error_patterns") as agg:
        assert enrichment._es_top_errors(context) == ""
    agg.assert_not_called()


def test_es_top_errors_renders_patterns():
    patterns = [
        {"pattern": "connection refused: postgres:5432", "count": 214},
        {"pattern": "context deadline exceeded", "count": 89},
    ]
    context = {"pod": {"namespace": "production", "name": "frontend-1"}}
    with patch("src.engine.enrichment.elasticsearch._is_configured", return_value=True), \
         patch("src.config.is_nonprod_namespace", return_value=False), \
         patch("src.engine.enrichment.elasticsearch.aggregate_error_patterns",
               return_value=patterns):
        out = enrichment._es_top_errors(context)
    assert "Top error patterns" in out
    assert "last 60m" in out
    assert "connection refused: postgres:5432" in out
    assert "×214" in out
    assert "×89" in out


def test_es_top_errors_sanitizes_secrets_in_patterns():
    """If a normalised pattern still carries a DSN credential (rare but
    possible), the sanitizer should strip it before it reaches Slack."""
    patterns = [{"pattern": "connect postgresql://user:s3cret@db error", "count": 10}]
    context = {"pod": {"namespace": "production", "name": "p"}}
    with patch("src.engine.enrichment.elasticsearch._is_configured", return_value=True), \
         patch("src.config.is_nonprod_namespace", return_value=False), \
         patch("src.engine.enrichment.elasticsearch.aggregate_error_patterns",
               return_value=patterns):
        out = enrichment._es_top_errors(context)
    assert "s3cret" not in out
    assert "postgresql://" in out


def test_es_top_errors_empty_when_no_patterns():
    context = {"pod": {"namespace": "production", "name": "p"}}
    with patch("src.engine.enrichment.elasticsearch._is_configured", return_value=True), \
         patch("src.config.is_nonprod_namespace", return_value=False), \
         patch("src.engine.enrichment.elasticsearch.aggregate_error_patterns",
               return_value=[]):
        assert enrichment._es_top_errors(context) == ""


def test_es_top_errors_empty_when_aggregate_returns_none():
    """ES initially configured but the aggregation call fails mid-way
    (returns None — e.g. ES went down between _is_configured() and the
    actual query). Must not raise; must return '' so the alert still
    posts without the block."""
    context = {"pod": {"namespace": "production", "name": "p"}}
    with patch("src.engine.enrichment.elasticsearch._is_configured", return_value=True), \
         patch("src.config.is_nonprod_namespace", return_value=False), \
         patch("src.engine.enrichment.elasticsearch.aggregate_error_patterns",
               return_value=None):
        assert enrichment._es_top_errors(context) == ""


def test_normalise_collapses_multiline_stack_to_first_line():
    """Multi-line stack traces must share a key determined by their
    top line. Earlier draft split on the two-char string '\\n' instead
    of the newline character and silently kept the entire stack in the
    key, so near-identical stacks never aggregated."""
    a = "connect timeout\\nat line 1\\nat line 2"  # literal backslash-n (old bug surface)
    b = "connect timeout\nat real newline 1\nat real newline 2"
    # After fix, the real-newline string collapses to just "connect timeout".
    assert elasticsearch._normalise_error_line(b) == "connect timeout"
    # The literal "\\n" string has no real newlines, so it stays on one
    # line — expected behaviour, just keeping as baseline for the test.
    assert "\\n" in elasticsearch._normalise_error_line(a)

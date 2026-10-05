"""Tests for get_trace: input validation, pagination, error handling."""
from types import SimpleNamespace
from unittest.mock import patch

from src.collectors import uptrace


def _fake_response(spans: list[dict]):
    resp = SimpleNamespace()
    resp.json = lambda: {"spans": spans}
    resp.raise_for_status = lambda: None
    return resp


def _span(span_id: str, parent: str = "", service: str = "svc",
          name: str = "op", status: str = "unset", message: str = ""):
    return {
        "spanId": span_id,
        "parentSpanId": parent,
        "serviceName": service,
        "name": name,
        "statusCode": status,
        "statusMessage": message,
        "durationMs": 10,
        "attrs": {},
    }


def test_get_trace_rejects_invalid_trace_id():
    with patch("src.collectors.uptrace._is_configured", return_value=True):
        assert uptrace.get_trace("not-hex") is None
        assert uptrace.get_trace("") is None
        assert uptrace.get_trace("; drop table spans") is None


def test_get_trace_paginates_until_short_page():
    """Full trace larger than limit should return all spans across pages."""
    valid_trace_id = "a" * 32
    # 3 pages: 5, 5, 2 spans → loop should stop after the short third page.
    pages = [
        [_span(f"p1-{i}") for i in range(5)],
        [_span(f"p2-{i}") for i in range(5)],
        [_span(f"p3-{i}") for i in range(2)],
    ]
    offsets: list[int] = []

    def fake_get(url, params=None, headers=None, timeout=None):
        offsets.append(params["offset"])
        page_idx = params["offset"] // params["limit"]
        return _fake_response(pages[page_idx])

    with patch("src.collectors.uptrace._is_configured", return_value=True), \
         patch("src.collectors.uptrace.requests.get", side_effect=fake_get):
        result = uptrace.get_trace(valid_trace_id, limit=5)
    assert result is not None
    assert len(result) == 12
    assert offsets == [0, 5, 10]
    # Order preserved — first page's spans come first.
    assert result[0]["span_id"] == "p1-0"
    assert result[-1]["span_id"] == "p3-1"


def test_get_trace_stops_at_first_empty_page():
    """Single-page trace shorter than limit should return on first response."""
    valid_trace_id = "b" * 32

    def fake_get(url, params=None, headers=None, timeout=None):
        if params["offset"] == 0:
            return _fake_response([_span("only")])
        raise AssertionError("should not fetch beyond first short page")

    with patch("src.collectors.uptrace._is_configured", return_value=True), \
         patch("src.collectors.uptrace.requests.get", side_effect=fake_get):
        result = uptrace.get_trace(valid_trace_id, limit=100)
    assert result is not None
    assert len(result) == 1


def test_get_trace_returns_none_when_first_page_fails():
    """A hard error on page 0 means we have nothing useful to render —
    return None so the caller falls back cleanly."""
    valid_trace_id = "e" * 32

    import requests

    def fake_get(url, params=None, headers=None, timeout=None):
        assert params["offset"] == 0
        raise requests.ConnectionError("uptrace down")

    with patch("src.collectors.uptrace._is_configured", return_value=True), \
         patch("src.collectors.uptrace.requests.get", side_effect=fake_get):
        result = uptrace.get_trace(valid_trace_id, limit=10)
    assert result is None


def test_get_trace_returns_partial_when_later_page_fails():
    """Success on page 0, failure on page 1 → return the spans we do
    have rather than discarding good data."""
    valid_trace_id = "f" * 32

    import requests

    def fake_get(url, params=None, headers=None, timeout=None):
        if params["offset"] == 0:
            return _fake_response([_span(f"p0-{i}") for i in range(10)])
        # Later page: hard error
        raise requests.HTTPError("502 bad gateway")

    with patch("src.collectors.uptrace._is_configured", return_value=True), \
         patch("src.collectors.uptrace.requests.get", side_effect=fake_get):
        result = uptrace.get_trace(valid_trace_id, limit=10)
    assert result is not None
    assert len(result) == 10
    assert result[0]["span_id"] == "p0-0"


def test_get_trace_honours_page_ceiling():
    """Pathological trace must not loop forever — cap at _TRACE_MAX_PAGES."""
    valid_trace_id = "c" * 32
    page_hits = {"n": 0}

    def fake_get(url, params=None, headers=None, timeout=None):
        page_hits["n"] += 1
        return _fake_response([_span(f"p-{page_hits['n']}-{i}") for i in range(10)])

    with patch("src.collectors.uptrace._is_configured", return_value=True), \
         patch("src.collectors.uptrace.requests.get", side_effect=fake_get):
        result = uptrace.get_trace(valid_trace_id, limit=10)
    assert result is not None
    assert page_hits["n"] == uptrace._TRACE_MAX_PAGES

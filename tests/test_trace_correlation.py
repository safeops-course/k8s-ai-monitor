"""Tests for Sprint 7 trace-correlation enrichment block."""
from unittest.mock import patch

from src.engine import enrichment


# ── trace_id extraction ──────────────────────────────────────────────────

def test_extract_trace_id_from_key_value_log():
    logs = [
        "2026-04-17T10:00:00 INFO request started",
        "2026-04-17T10:00:01 ERROR trace_id=abcdef0123456789abcdef0123456789 failed to dial",
    ]
    assert enrichment._extract_trace_id(logs) == "abcdef0123456789abcdef0123456789"


def test_extract_trace_id_camelcase():
    logs = ["handler traceId=deadbeefcafebabedeadbeefcafebabe returned 500"]
    assert enrichment._extract_trace_id(logs) == "deadbeefcafebabedeadbeefcafebabe"


def test_extract_trace_id_dashed():
    logs = ['{"trace-id":"0123456789abcdef0123456789abcdef","level":"error"}']
    assert enrichment._extract_trace_id(logs) == "0123456789abcdef0123456789abcdef"


def test_extract_trace_id_traceparent():
    logs = ["traceparent=00-abcdef1234567890abcdef1234567890-fedcba0987654321-01"]
    assert enrichment._extract_trace_id(logs) == "abcdef1234567890abcdef1234567890"


def test_extract_trace_id_prefers_last_match():
    logs = [
        "trace_id=111111111111111111111111111111aa older line",
        "trace_id=222222222222222222222222222222bb newest line",
    ]
    assert enrichment._extract_trace_id(logs) == "222222222222222222222222222222bb"


def test_extract_trace_id_string_input():
    assert enrichment._extract_trace_id(
        "prefix trace_id=aabbccddeeff00112233445566778899 suffix"
    ) == "aabbccddeeff00112233445566778899"


def test_extract_trace_id_empty_returns_none():
    assert enrichment._extract_trace_id(None) is None
    assert enrichment._extract_trace_id([]) is None
    assert enrichment._extract_trace_id("") is None
    assert enrichment._extract_trace_id(["no trace here"]) is None


# ── Tree rendering ───────────────────────────────────────────────────────

def _span(span_id, parent_id, name, service, duration_ms, *,
          status="unset", status_message=""):
    return {
        "trace_id": "abc123",
        "span_id": span_id,
        "parent_span_id": parent_id,
        "name": name,
        "service": service,
        "duration_ms": duration_ms,
        "status_code": status,
        "status_message": status_message,
    }


def test_render_trace_tree_basic():
    spans = [
        _span("root", "", "GET /checkout", "ingress-nginx", 2300),
        _span("gw", "root", "api", "api-gateway", 2100),
        _span("svc", "gw", "order.create", "backend", 2000,
              status="error", status_message="dial tcp postgres:5432: timeout"),
    ]
    out = enrichment._render_trace_tree("abc123abc123abc123abc123abc1", spans)
    assert "Trace" in out
    assert "3 spans" in out
    assert "1 error" in out
    assert "ingress-nginx" in out
    assert "api-gateway" in out
    assert "backend" in out
    assert "dial tcp postgres" in out
    # Error marker emoji
    assert "\u274c" in out


def test_render_trace_tree_truncates_long_trace():
    spans = [_span("s0", "", "root", "svc-0", 100)]
    for i in range(1, 50):
        spans.append(_span(f"s{i}", f"s{i-1}", f"call-{i}", f"svc-{i}", 10))
    out = enrichment._render_trace_tree("deadbeef" * 4, spans)
    lines = out.splitlines()
    # Header + at most 10 span lines + "…" overflow marker
    assert any("more spans" in line for line in lines)


def test_render_trace_tree_empty_returns_empty():
    assert enrichment._render_trace_tree("abc", []) == ""


def test_render_trace_tree_keeps_non_error_ancestors_of_errors():
    """When the tree is large enough to trigger keep_errors_only, a
    non-error parent whose subtree contains an error must still be
    rendered (otherwise the ERROR hop appears detached from its chain).
    """
    spans = [_span("root", "", "root-op", "ingress", 1000)]
    # Deep chain: root → a → b → c (error). With 20 spaghetti spans we
    # cross the _TRACE_MAX_TREE_LINES threshold.
    spans.append(_span("a", "root", "step", "svc-a", 500))
    spans.append(_span("b", "a", "step", "svc-b", 300))
    spans.append(_span("c", "b", "boom", "svc-c", 200,
                       status="error", status_message="bang"))
    for i in range(20):
        spans.append(_span(f"n{i}", "root", "sibling", "svc-n", 50))

    out = enrichment._render_trace_tree("1" * 32, spans)

    # The error hop is there.
    assert "svc-c" in out
    # So are its ancestors, even though they're not errors themselves.
    assert "svc-a" in out
    assert "svc-b" in out
    # Clean siblings that don't host an error are pruned.
    assert "svc-n" not in out


def test_render_trace_tree_sanitizes_status_message():
    """Error status messages may carry DSNs / secrets — sanitize first."""
    spans = [_span("root", "", "boom", "api", 100,
                    status="error",
                    status_message="failed postgresql://user:s3kret@primary/db down")]
    out = enrichment._render_trace_tree("d" * 32, spans)
    # The credential must be stripped by sanitize_value (postgresql DSN).
    assert "s3kret" not in out
    assert "postgresql://" in out  # scheme stays for context


# ── Top-level _trace_correlation behaviour ───────────────────────────────

def test_trace_correlation_skipped_when_uptrace_not_configured():
    with patch("src.engine.enrichment.uptrace._is_configured", return_value=False):
        assert enrichment._trace_correlation({"logs": ["trace_id=abc"]}) == ""


def test_trace_correlation_uses_extracted_trace_id():
    spans = [_span("root", "", "GET /x", "api", 100, status="error",
                   status_message="boom")]
    context = {
        "logs": ["oops trace_id=a1b2c3d4e5f60718a1b2c3d4e5f60718 here"],
    }
    with patch("src.engine.enrichment.uptrace._is_configured", return_value=True), \
         patch("src.engine.enrichment.uptrace.get_trace", return_value=spans) as gt:
        out = enrichment._trace_correlation(context)
    gt.assert_called_once_with("a1b2c3d4e5f60718a1b2c3d4e5f60718")
    assert "api" in out
    assert "boom" in out


def test_trace_correlation_falls_back_when_get_trace_returns_empty():
    """trace_id found in logs but Uptrace returns []: same treatment as
    None — fall through to the service-level error-spans search."""
    err_spans = [
        {"name": "order.create", "service": "backend", "duration_ms": 500,
         "trace_id": "t1" * 16,
         "attrs": {"error.message": "pg timeout"},
         "status_code": "error"},
    ]
    context = {
        "logs": ["request trace_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa done"],
        "owner": {"kind": "Deployment", "name": "backend"},
    }
    with patch("src.engine.enrichment.uptrace._is_configured", return_value=True), \
         patch("src.engine.enrichment.uptrace.get_trace",
               return_value=[]) as gt, \
         patch("src.engine.enrichment.uptrace.search_spans",
               return_value=err_spans) as ss:
        out = enrichment._trace_correlation(context)
    gt.assert_called_once_with("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    ss.assert_called_once()
    assert "Recent error spans" in out
    assert "pg timeout" in out


def test_trace_correlation_falls_back_to_service_error_spans():
    err_spans = [
        {"name": "order.create", "service": "backend", "duration_ms": 500,
         "trace_id": "t1" * 16, "attrs": {"error.message": "pg timeout"},
         "status_code": "error"},
    ]
    context = {
        "logs": ["no trace here"],
        "owner": {"kind": "Deployment", "name": "backend"},
    }
    with patch("src.engine.enrichment.uptrace._is_configured", return_value=True), \
         patch("src.engine.enrichment.uptrace.get_trace", return_value=None), \
         patch("src.engine.enrichment.uptrace.search_spans",
               return_value=err_spans) as ss:
        out = enrichment._trace_correlation(context)
    ss.assert_called_once()
    call_kwargs = ss.call_args.kwargs
    assert call_kwargs["status_code"] == "error"
    assert "Recent error spans" in out
    assert "backend" in out
    assert "pg timeout" in out


def test_trace_correlation_skipped_for_nonprod_namespace():
    """Non-prod namespaces must not trigger Uptrace calls — the project
    token is shared across prod/dev/staging and we only care about
    production traces."""
    context = {
        "pod": {"namespace": "develop", "name": "p"},
        "owner": {"kind": "Deployment", "name": "api-gateway"},
        "logs": ["trace_id=aabbccddeeff00112233445566778899"],
    }
    with patch("src.engine.enrichment.uptrace._is_configured", return_value=True), \
         patch("src.config.is_nonprod_namespace", return_value=True), \
         patch("src.engine.enrichment.uptrace.get_trace") as gt, \
         patch("src.engine.enrichment.uptrace.search_spans") as ss:
        out = enrichment._trace_correlation(context)
    assert out == ""
    gt.assert_not_called()
    ss.assert_not_called()


def test_trace_correlation_returns_empty_when_no_trace_and_no_service():
    context = {"logs": ["no trace"]}
    with patch("src.engine.enrichment.uptrace._is_configured", return_value=True):
        assert enrichment._trace_correlation(context) == ""


def test_trace_correlation_strips_replicaset_suffix_from_pod_name():
    """When only pod.name is available, strip the -<rs>-<pod> suffix so
    the fallback service search actually matches."""
    context = {
        "logs": ["no trace"],
        "pod": {"name": "api-gateway-7c5bc9d4bd-x2kq8"},
    }
    with patch("src.engine.enrichment.uptrace._is_configured", return_value=True), \
         patch("src.engine.enrichment.uptrace.search_spans", return_value=None) as ss:
        enrichment._trace_correlation(context)
    ss.assert_called_once()
    # First positional arg is service_name
    assert ss.call_args.args[0] == "api-gateway"

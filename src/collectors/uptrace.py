"""Uptrace REST API client — span search and service stats.

The token comes from the UPTRACE_API_TOKEN env var only - the monitor reads
no Kubernetes Secrets; the Deployment injects the token from its own Secret.
Without UPTRACE_API_URL and a token, every call returns None (not configured).

Uptrace recognises the project from the token itself, so the
`project_id` segment in the REST URL just needs to be present — it
doesn't have to match a numeric ID. We keep UPTRACE_PROJECT_ID as a
configurable knob in case a specific deployment needs a different path.
"""
import logging
import re

import requests

# Callers are internal, but inputs (trace_id extracted from pod logs,
# service_name from owner references) flow from untrusted surfaces. Uptrace
# uses a query DSL that doesn't support parameter binding, so we sanitise
# at the boundary — reject any value that doesn't match the expected shape
# and return None from the call rather than splicing it into a query.
_TRACE_ID_RE = re.compile(r"^[0-9a-fA-F]{16,32}$")
# RFC-1123-ish service names: lowercase alphanumerics + hyphens + dots
# (OTel service.name sometimes carries a subdomain form like
# "foo-service.production"). Length cap matches K8s label limits.
_SERVICE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{0,62}$")

from src import config

logger = logging.getLogger(__name__)

_TIMEOUT = 10

def _resolve_token() -> str:
    return config.UPTRACE_API_TOKEN


def _is_configured() -> bool:
    return bool(config.UPTRACE_API_URL and _resolve_token())


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {_resolve_token()}",
        "Content-Type": "application/json",
    }


def _base_url() -> str:
    url = config.UPTRACE_API_URL.rstrip("/")
    return f"{url}/api/v1/tracing/{config.UPTRACE_PROJECT_ID}"


def search_spans(
    service_name: str,
    since_minutes: int = 30,
    limit: int = 50,
    status_code: str | None = None,
) -> list[dict] | None:
    """Search spans by service name, optionally filtered by status code.

    Args:
        service_name: OTel service.name to filter by.
        since_minutes: Look back window.
        limit: Max spans to return.
        status_code: If "error", filter for error spans only.

    Returns list of span dicts or None if Uptrace is not configured/unreachable.
    """
    if not _is_configured():
        return None
    if not _SERVICE_NAME_RE.match(service_name or ""):
        logger.debug("Uptrace search_spans: rejecting invalid service_name %r",
                     service_name)
        return None

    parts = [f"where service.name = '{service_name}'"]
    if status_code == "error":
        parts.append("where status_code = 'error'")
    query = " | ".join(parts)

    params: dict[str, str | int] = {
        "query": query,
        "time_gte": f"now-{since_minutes}m",
        "time_lt": "now",
        "limit": limit,
        "order_by": "time desc",
    }

    try:
        resp = requests.get(
            f"{_base_url()}/spans",
            params=params,  # type: ignore[arg-type]
            headers=_headers(),
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        spans = data.get("spans", data.get("data", []))
        results = []
        for span in spans:
            results.append({
                "trace_id": span.get("traceId", span.get("trace_id", "")),
                "span_id": span.get("spanId", span.get("span_id", "")),
                "name": span.get("name", ""),
                "service": span.get("serviceName", span.get("service.name", service_name)),
                "duration_ms": span.get("durationMs", span.get("duration_ms", 0)),
                "status_code": span.get("statusCode", span.get("status_code", "")),
                "time": span.get("time", ""),
                "attrs": span.get("attrs", {}),
            })
        return results
    except requests.ConnectionError as exc:
        logger.warning("Uptrace unreachable: %s", exc)
    except requests.HTTPError as exc:
        logger.warning("Uptrace HTTP error: %s", exc)
    except Exception:
        logger.warning("Uptrace span search failed", exc_info=True)
    return None


def search_slow_spans(
    service_name: str,
    since_minutes: int = 30,
    min_duration_ms: int = 1000,
    limit: int = 50,
) -> list[dict] | None:
    """Search for slow spans (duration >= min_duration_ms)."""
    if not _is_configured():
        return None
    if not _SERVICE_NAME_RE.match(service_name or ""):
        logger.debug("Uptrace search_slow_spans: rejecting invalid service_name %r",
                     service_name)
        return None

    query = (
        f"where service.name = '{service_name}' "
        f"| where duration >= {min_duration_ms}ms"
    )

    params: dict[str, str | int] = {
        "query": query,
        "time_gte": f"now-{since_minutes}m",
        "time_lt": "now",
        "limit": limit,
        "order_by": "duration desc",
    }

    try:
        resp = requests.get(
            f"{_base_url()}/spans",
            params=params,  # type: ignore[arg-type]
            headers=_headers(),
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        spans = data.get("spans", data.get("data", []))
        results = []
        for span in spans:
            results.append({
                "trace_id": span.get("traceId", span.get("trace_id", "")),
                "span_id": span.get("spanId", span.get("span_id", "")),
                "name": span.get("name", ""),
                "service": span.get("serviceName", span.get("service.name", service_name)),
                "duration_ms": span.get("durationMs", span.get("duration_ms", 0)),
                "status_code": span.get("statusCode", span.get("status_code", "")),
                "time": span.get("time", ""),
                "attrs": span.get("attrs", {}),
            })
        return results
    except requests.ConnectionError as exc:
        logger.warning("Uptrace unreachable: %s", exc)
    except requests.HTTPError as exc:
        logger.warning("Uptrace HTTP error: %s", exc)
    except Exception:
        logger.warning("Uptrace slow span search failed", exc_info=True)
    return None


_TRACE_MAX_PAGES = 10  # 10 pages × 100 limit = 1000 spans ceiling


def get_trace(trace_id: str, limit: int = 100) -> list[dict] | None:
    """Fetch all spans for a trace, ordered by start time.

    Returns a list of span dicts with keys: span_id, parent_span_id, name,
    service, duration_ms, status_code, status_message, time, attrs.

    Returns None when Uptrace is unconfigured or the request fails, and
    an empty list when the trace simply has no spans (already purged or
    wrong trace_id). The caller renders a span tree from the flat list.
    """
    if not _is_configured():
        return None
    if not trace_id or not _TRACE_ID_RE.match(trace_id):
        logger.debug("Uptrace get_trace: rejecting invalid trace_id %r", trace_id)
        return None

    results: list[dict] = []
    # Paginate with offset so a long trace (microservices with many hops)
    # doesn't get silently truncated to `limit`. Capped at
    # _TRACE_MAX_PAGES to bound latency and response size on pathological
    # traces (>1000 spans isn't operator-useful in an alert anyway).
    for page in range(_TRACE_MAX_PAGES):
        params: dict[str, str | int] = {
            "query": f"where trace_id = '{trace_id}'",
            "limit": limit,
            "offset": page * limit,
            "order_by": "time asc",
        }
        try:
            resp = requests.get(
                f"{_base_url()}/spans",
                params=params,  # type: ignore[arg-type]
                headers=_headers(),
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
            spans = data.get("spans", data.get("data", []))
        except requests.ConnectionError as exc:
            logger.warning("Uptrace unreachable: %s", exc)
            return None if page == 0 else results
        except requests.HTTPError as exc:
            logger.warning("Uptrace HTTP error: %s", exc)
            return None if page == 0 else results
        except Exception:
            logger.warning("Uptrace get_trace failed", exc_info=True)
            return None if page == 0 else results

        if not spans:
            break

        for span in spans:
            attrs = span.get("attrs", {}) or {}
            # OTel convention for error detail is either the attribute
            # "error.message" or the exception attribute. Uptrace also
            # exposes `status.message` on some versions.
            # OTel / Uptrace expose the status-message field under
            # several keys depending on SDK version and server
            # normalisation. Try them all, highest-precedence first,
            # before giving up with "".
            status_msg = (
                span.get("statusMessage")
                or span.get("status.message")
                or span.get("status_message")
                or attrs.get("status.message")
                or attrs.get("status_message")
                or attrs.get("error.message")
                or attrs.get("exception.message")
                or ""
            )
            results.append({
                "trace_id": span.get("traceId", span.get("trace_id", trace_id)),
                "span_id": span.get("spanId", span.get("span_id", "")),
                "parent_span_id": span.get(
                    "parentSpanId", span.get("parent_span_id", ""),
                ),
                "name": span.get("name", ""),
                "service": span.get(
                    "serviceName", span.get("service.name", ""),
                ),
                "duration_ms": span.get(
                    "durationMs", span.get("duration_ms", 0),
                ),
                "status_code": span.get(
                    "statusCode", span.get("status_code", ""),
                ),
                "status_message": status_msg,
                "time": span.get("time", ""),
                "attrs": attrs,
            })

        if len(spans) < limit:
            break  # final page — no point issuing another request
    else:
        logger.warning(
            "Uptrace get_trace: reached page cap (%d × %d) for trace %s — "
            "tree may be truncated",
            _TRACE_MAX_PAGES, limit, trace_id,
        )
    return results


def get_service_stats(
    service_name: str,
    since_minutes: int = 30,
) -> dict | None:
    """Get aggregated stats for a service: span count, error rate, avg duration.

    Returns dict with keys: span_count, error_count, error_rate, avg_duration_ms,
    p50_duration_ms, p99_duration_ms, or None if unavailable.
    """
    if not _is_configured():
        return None

    query = (
        f"where service.name = '{service_name}' "
        f"| group by service.name "
        f"| count() as span_count "
        f"| countIf(status_code = 'error') as error_count "
        f"| avg(duration) as avg_duration "
        f"| p50(duration) as p50_duration "
        f"| p99(duration) as p99_duration"
    )

    params = {
        "query": query,
        "time_gte": f"now-{since_minutes}m",
        "time_lt": "now",
    }

    try:
        resp = requests.get(
            f"{_base_url()}/groups",
            params=params,
            headers=_headers(),
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        groups = data.get("groups", data.get("data", []))
        if not groups:
            return {
                "span_count": 0, "error_count": 0, "error_rate": 0.0,
                "avg_duration_ms": 0, "p50_duration_ms": 0, "p99_duration_ms": 0,
            }
        g = groups[0]
        span_count = g.get("span_count", g.get("count", 0))
        error_count = g.get("error_count", 0)
        error_rate = (error_count / span_count * 100) if span_count else 0.0
        return {
            "span_count": span_count,
            "error_count": error_count,
            "error_rate": round(error_rate, 2),
            "avg_duration_ms": g.get("avg_duration", g.get("avg_duration_ms", 0)),
            "p50_duration_ms": g.get("p50_duration", g.get("p50_duration_ms", 0)),
            "p99_duration_ms": g.get("p99_duration", g.get("p99_duration_ms", 0)),
        }
    except requests.ConnectionError as exc:
        logger.warning("Uptrace unreachable: %s", exc)
    except requests.HTTPError as exc:
        logger.warning("Uptrace HTTP error: %s", exc)
    except Exception:
        logger.warning("Uptrace service stats failed", exc_info=True)
    return None

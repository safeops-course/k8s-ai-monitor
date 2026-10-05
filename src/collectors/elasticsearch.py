"""Elasticsearch log search — stateless, uses requests."""
import logging
import re
from collections import Counter

import requests

from src import config

logger = logging.getLogger(__name__)

_TIMEOUT = 10

# Patterns that make otherwise-identical error lines look different. Replace
# them with stable placeholders before aggregating so 100 lines like
# "pool timeout after 1.2345s trace_id=abc..." collapse into one bucket.
_NORMALISE_PATTERNS: list[tuple[re.Pattern, str]] = [
    # ISO / RFC3339 timestamps
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<ts>"),
    # UUID v4-ish
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<uuid>"),
    # Long hex (trace_ids, span_ids, hashes) — keep short hex for codes like 0x7f
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<hex>"),
    # IPv4 addresses
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{1,5})?\b"), "<ip>"),
    # Durations (e.g. 1.234s, 456ms, 789µs)
    (re.compile(r"\b\d+(?:\.\d+)?(?:ms|µs|us|ns|s)\b", re.IGNORECASE), "<dur>"),
    # Standalone numbers (request IDs, byte counts, retries) — but keep 3-digit
    # HTTP status codes intact when they appear next to "status" / "code".
    (re.compile(r"\b\d{5,}\b"), "<num>"),
]


def _normalise_error_line(msg: str) -> str:
    """Collapse timestamps, IDs, and random numerics so variants of the
    same error message aggregate into one bucket.
    """
    # First keep only the top line — a multi-line stack trace should
    # group by its top exception line, not by the frames below it.
    # splitlines() handles both \n and \r\n. Do this BEFORE collapsing
    # whitespace, otherwise newlines become spaces and the whole stack
    # merges into one key. Earlier draft split on the literal "\\n"
    # two-char sequence by mistake.
    lines = msg.splitlines()
    first_line = (lines[0] if lines else "").strip()
    for pattern, replacement in _NORMALISE_PATTERNS:
        first_line = pattern.sub(replacement, first_line)
    first_line = re.sub(r"\s+", " ", first_line).strip()
    return first_line[:200]


def aggregate_error_patterns(
    namespace: str,
    pod: str | None = None,
    since_minutes: int = 60,
    top: int = 3,
    sample_size: int = 500,
) -> list[dict] | None:
    """Fetch recent error logs and return the top ``top`` distinct patterns.

    Returns a list of dicts ``[{"pattern": str, "count": int}, ...]`` sorted
    by count desc. Returns None when Elasticsearch isn't configured or
    unreachable, and an empty list when the window has no errors.

    The pattern is a normalised version of the log message: timestamps,
    UUIDs, long hex (trace IDs / hashes), IPs, durations and large
    numerics are replaced with placeholders so logically-identical
    errors aggregate even when their wall-clock variables differ.
    """
    if not _is_configured():
        return None
    logs = search_error_logs(
        namespace=namespace,
        since_minutes=since_minutes,
        limit=min(sample_size, 500),
        max_total=sample_size,
    )
    if logs is None:
        return None
    if not logs:
        return []
    counter: Counter[str] = Counter()
    for entry in logs:
        # Pod filter is client-side and EXACT — callers always pass the
        # full pod name (from context["pod"]["name"]) which matches the
        # full pod name stored in ES. Earlier draft also accepted a
        # substring match, but that allowed unrelated pods sharing a
        # name prefix to leak into the aggregation bucket.
        if pod and entry.get("pod", "") != pod:
            continue
        msg = entry.get("message") or ""
        if not msg:
            continue
        key = _normalise_error_line(msg)
        if key:
            counter[key] += 1
    if not counter:
        return []
    return [{"pattern": p, "count": c} for p, c in counter.most_common(top)]


def _get_index() -> str:
    # Daily indices are named "{cluster}-logs-YYYY-MM-DD"; wildcard covers all recent.
    prefix = config.ELASTICSEARCH_INDEX_PREFIX or config.CLUSTER_NAME
    return f"{prefix}-logs-*"


def _make_auth() -> tuple[str, str] | None:
    if config.ELASTICSEARCH_USER and config.ELASTICSEARCH_PASSWORD:
        return (config.ELASTICSEARCH_USER, config.ELASTICSEARCH_PASSWORD)
    return None


def _is_configured() -> bool:
    return bool(config.ELASTICSEARCH_URL)


def search_logs(
    namespace: str,
    pod_pattern: str = "",
    query_string: str = "",
    since_minutes: int = 30,
    limit: int = 100,
) -> list[dict] | None:
    """Search ES logs by namespace, optional pod pattern, and query string.

    Returns list of hit dicts with timestamp, pod, container, message fields,
    or None if ES is not configured / unreachable.
    """
    if not _is_configured():
        return None

    must: list[dict] = [
        {"range": {"timestamp": {"gte": f"now-{since_minutes}m", "lte": "now"}}},
        {"term": {"namespace": namespace}},
    ]
    if pod_pattern:
        must.append({"wildcard": {"pod": pod_pattern}})
    if query_string:
        must.append({"query_string": {"query": query_string, "default_field": "message",
                                       "analyze_wildcard": True}})

    body = {
        "size": limit,
        "sort": [{"timestamp": "desc"}],
        "query": {"bool": {"must": must}},
        "_source": ["timestamp", "message", "log", "stream",
                     "pod", "container", "namespace",
                     "level", "severity"],
    }

    try:
        resp = requests.post(
            f"{config.ELASTICSEARCH_URL}/{_get_index()}/_search",
            json=body,
            auth=_make_auth(),
            timeout=_TIMEOUT,
            verify=True,
        )
        resp.raise_for_status()
        data = resp.json()
        hits = data.get("hits", {}).get("hits", [])
        results = []
        for hit in hits:
            src = hit.get("_source", {})
            results.append({
                "timestamp": src.get("timestamp", ""),
                "pod": src.get("pod", ""),
                "container": src.get("container", ""),
                "message": src.get("message") or src.get("log", ""),
                "stream": src.get("stream", ""),
                "level": src.get("level") or src.get("severity", ""),
            })
        return results
    except requests.ConnectionError as exc:
        logger.warning("Elasticsearch unreachable: %s", exc)
    except requests.HTTPError as exc:
        logger.warning("Elasticsearch HTTP error: %s", exc)
    except Exception:
        logger.warning("Elasticsearch search failed", exc_info=True)
    return None


def search_error_logs(
    namespace: str,
    since_minutes: int = 60,
    limit: int = 100,
    max_total: int | None = None,
) -> list[dict] | None:
    """Search for error-level logs in a namespace.

    Looks for stderr stream OR error/critical severity levels.

    When `max_total` is set and exceeds `limit`, paginates with `search_after`
    to scan up to `max_total` matching docs in the time window. This avoids
    the bias of the single-page newest-first slice when the goal is to
    aggregate patterns across the full window (e.g. daily report).
    """
    if not _is_configured():
        return None

    must: list[dict] = [
        {"range": {"timestamp": {"gte": f"now-{since_minutes}m", "lte": "now"}}},
        {"term": {"namespace": namespace}},
    ]
    should: list[dict] = [
        {"term": {"stream": "stderr"}},
        {"terms": {"level": ["error", "ERROR", "fatal", "FATAL", "critical", "CRITICAL"]}},
        {"terms": {"severity": ["error", "ERROR", "fatal", "FATAL", "critical", "CRITICAL"]}},
    ]
    query = {"bool": {"must": must, "should": should, "minimum_should_match": 1}}
    source_fields = ["timestamp", "message", "log", "stream",
                     "pod", "container", "namespace",
                     "level", "severity"]
    # search_after needs a tiebreaker (_doc) for stable pagination on equal timestamps.
    sort = [{"timestamp": "desc"}, {"_doc": "desc"}]
    target = max(limit, max_total or 0)
    page_size = min(limit, 1000)  # ES soft cap

    results: list[dict] = []
    search_after: list | None = None
    try:
        while len(results) < target:
            body: dict = {
                "size": min(page_size, target - len(results)),
                "sort": sort,
                "query": query,
                "_source": source_fields,
            }
            if search_after is not None:
                body["search_after"] = search_after
            resp = requests.post(
                f"{config.ELASTICSEARCH_URL}/{_get_index()}/_search",
                json=body,
                auth=_make_auth(),
                timeout=_TIMEOUT,
                verify=True,
            )
            resp.raise_for_status()
            data = resp.json()
            hits = data.get("hits", {}).get("hits", [])
            if not hits:
                break
            for hit in hits:
                src = hit.get("_source", {})
                results.append({
                    "timestamp": src.get("timestamp", ""),
                    "pod": src.get("pod", ""),
                    "container": src.get("container", ""),
                    "message": src.get("message") or src.get("log", ""),
                    "stream": src.get("stream", ""),
                    "level": src.get("level") or src.get("severity", ""),
                })
            search_after = hits[-1].get("sort")
            if search_after is None or max_total is None:
                break  # single-page mode (back-compat) or no cursor returned
        return results
    except requests.ConnectionError as exc:
        logger.warning("Elasticsearch unreachable: %s", exc)
    except requests.HTTPError as exc:
        logger.warning("Elasticsearch HTTP error: %s", exc)
    except Exception:
        logger.warning("Elasticsearch error search failed", exc_info=True)
    return None

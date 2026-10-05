"""Alert enrichment blocks appended after format_context_summary.

Each block answers one of three questions:
1. What broke? (blast radius, deploy info, resource trend, HPA state)
2. Is it new or recurring? (flap history)
3. What do I check next? (per-issue directives)

All blocks render to Slack mrkdwn strings and are concatenated by
build_enrichment_blocks(). Empty blocks are skipped silently.
"""
import logging
import math
import re
import threading
import time

from src.collectors import elasticsearch, uptrace
from src.collectors._formatters import fmt_bytes, parse_memory_mi
from src.collectors.metrics_range import prom_range_query
from src.engine.sanitizer import sanitize_value
from src.engine.store import Incident
from src.engine.store.sqlite import SqliteStore

logger = logging.getLogger(__name__)


# ── Per-issue-type investigation directives ──────────────────────────────
#
# 2-4 concrete, actionable checks per issue_type. These replace the
# generic SLACK_CRITICAL_INVESTIGATION_DIRECTIVES with type-specific
# guidance so the @ai bot (and human operators) know exactly what to
# look at first.

ISSUE_DIRECTIVES: dict[str, list[str]] = {
    "oom": [
        "compare peak RSS in logs vs container.resources.limits.memory",
        "check HPA status: has scale-up been triggered or blocked?",
        "look for 90s pre-crash logs in previous container output",
    ],
    "crash": [
        "compare image hash with last known-good deploy",
        "check exit code (137=OOM/SIGKILL, 139=SIGSEGV, 143=SIGTERM)",
        "is this happening on all pods or just one replica?",
    ],
    "image_pull": [
        "is the registry reachable from the cluster? check netpol",
        "is imagePullSecrets configured on the serviceAccount?",
        "does the image tag exist (not deleted by registry retention)?",
    ],
    "scheduling": [
        "cluster headroom per node — any PodDisruptionBudget blocking?",
        "node taints vs pod tolerations",
        "is cluster autoscaler scaling up? look for TriggeredScaleUp events",
    ],
    "mount": [
        "PVC / PV status and storage class provisioner",
        "is the CSI driver pod running on the target node?",
        "any recent node drains or maintenance?",
    ],
    "unhealthy": [
        "which probe is failing — liveness, readiness, or startup?",
        "probe spec: is timeout/period too tight for cold starts?",
        "recent image or config change (check deploy age below)?",
    ],
    "evicted": [
        "node pressure conditions: MemoryPressure, DiskPressure, PIDPressure",
        "kubelet eviction-threshold config on the affected node",
        "noisy-neighbor pods on the same node (check node metrics)",
    ],
    "pvc": [
        "growth rate — how fast is the volume filling?",
        "retention / rotation policy for logs or backups on this volume",
        "can we expand the PVC (storage class allows volume expansion)?",
    ],
    "sli_breach": [
        "read the chain in the alert bottom-up — the deepest breaching SLI is "
        "the one to fix, the ones above it are symptoms",
        "is the threshold still right? an SLO nobody has revisited drifts out "
        "of date faster than the system does",
        "did the breach start with a deploy? correlate against the release "
        "history before looking for a cause inside the service",
    ],
    "hpa": [
        "which metric is over its target — CPU is load, memory usually is not",
        "a Node.js heap grows into whatever it is given, so a memory target can "
        "pin a replica count that CPU does not justify",
        "would the node even hold another pod? if not, raising maxReplicas just "
        "moves the symptom to FailedScheduling",
    ],
    "certificate": [
        "cert-manager: Certificate CR status + ClusterIssuer health",
        "DNS challenge: is the solver CNAME still in DNS?",
        "Let's Encrypt rate limit (5 certs/domain/week)?",
    ],
    "backup": [
        "last error line from the backup job pod logs",
        "is the storage bucket reachable with current credentials?",
        "retention: are older backups still intact?",
    ],
    "critical_endpoint": [
        "chain probe: ingress → gateway → service → backend",
        "recent Flux apply in this namespace? compare with last known-good",
        "trace_id from logs: pull the span tree from Uptrace",
    ],
    "flux_stalled": [
        "compare git revision in the stalled object vs last applied",
        "dry-run the manifest to surface schema / admission errors",
        "check reconciler logs in flux-system for this Kustomization",
    ],
}


def build_enrichment_blocks(store: SqliteStore, incident: Incident | None,
                            result, context: dict) -> str:
    """Compose enrichment blocks for a Slack alert.

    Returns a Slack mrkdwn string with separator-delimited sections.
    Empty string when no enrichment is available.
    """
    blocks: list[str] = []

    if incident:
        try:
            flap = _flap_history(store, incident)
            if flap:
                blocks.append(flap)
        except Exception:
            logger.error("Flap history enrichment failed (alert still posts)",
                         exc_info=True)

    blast = _blast_radius(context)
    if blast:
        blocks.append(blast)

    try:
        trend = _resource_trend(context)
        if trend:
            blocks.append(trend)
    except Exception:
        logger.error("Resource trend enrichment failed (alert still posts)",
                     exc_info=True)

    try:
        hpa = _hpa_state(context)
        if hpa:
            blocks.append(hpa)
    except Exception:
        logger.error("HPA state enrichment failed (alert still posts)",
                     exc_info=True)

    try:
        root = _root_cause_correlation(store, result, context)
        if root:
            blocks.append(root)
    except Exception:
        logger.error("Root-cause correlation enrichment failed",
                     exc_info=True)

    try:
        trace = _trace_correlation(context)
        if trace:
            blocks.append(trace)
    except Exception:
        logger.error("Trace correlation enrichment failed (alert still posts)",
                     exc_info=True)

    try:
        es_errors = _es_top_errors(context)
        if es_errors:
            blocks.append(es_errors)
    except Exception:
        logger.error("ES top-error enrichment failed (alert still posts)",
                     exc_info=True)

    deploy = _deploy_info(context)
    if deploy:
        blocks.append(deploy)

    directives = _directives(result.issue_type)
    if directives:
        blocks.append(directives)

    return "\n".join(blocks)


# ── Flap history ─────────────────────────────────────────────────────────

def _flap_history(store: SqliteStore, incident: Incident) -> str:
    """Render occurrence counts for 1h / 24h / 7d windows + last resolved."""
    now = time.time()
    conn = store._get_conn()

    counts = {}
    for label, hours in [("1h", 1), ("24h", 24), ("7d", 168)]:
        cutoff = now - hours * 3600
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM incident_occurrences "
            "WHERE incident_id = ? AND seen_at >= ?",
            (incident.id, cutoff),
        ).fetchone()
        counts[label] = row["c"] if row else 0

    # +1 for the current (not-yet-recorded) occurrence
    counts["1h"] += 1
    counts["24h"] += 1
    counts["7d"] += 1

    # Last resolved timestamp for this state_key (if ever resolved before)
    last_resolved_row = conn.execute(
        "SELECT MAX(updated_at) AS resolved_at FROM incidents "
        "WHERE fingerprint = ? AND status = 'resolved'",
        (incident.fingerprint,),
    ).fetchone()
    last_resolved = last_resolved_row["resolved_at"] if last_resolved_row else None

    parts = [f"{counts['1h']} in 1h", f"{counts['24h']} in 24h",
             f"{counts['7d']} in 7d"]

    # "First occurrence" must mean both: no prior-resolved row AND only the
    # current tick counted. A stale resolved row for the same fingerprint
    # would otherwise surface as "First occurrence | last resolved 2h ago",
    # which contradicts itself.
    is_truly_first = (
        last_resolved is None
        and counts["1h"] == 1 and counts["24h"] == 1 and counts["7d"] == 1
    )
    if is_truly_first:
        line = "*History:* First occurrence"
    else:
        line = f"*History:* {' | '.join(parts)}"
    if last_resolved:
        age = _fmt_age(now - last_resolved)
        line += f" | last resolved {age} ago"

    return line


# ── Blast radius ─────────────────────────────────────────────────────────

def _blast_radius(context: dict) -> str:
    """Render owner replica status from the collected context."""
    owner = context.get("owner")
    if not isinstance(owner, dict):
        return ""
    kind = owner.get("kind", "")
    name = owner.get("name", "")
    desired = owner.get("desired", 0)
    ready = owner.get("ready", 0)
    if not kind or not name or not desired:
        return ""

    unhealthy = max(0, desired - ready)
    status = "all healthy" if unhealthy == 0 else f"{unhealthy} unhealthy"
    line = f"*Owner:* {kind}/{name} ({ready}/{desired} ready, {status})"

    warnings = owner.get("warnings")
    if isinstance(warnings, list) and warnings:
        line += f"\n  \u26a0\ufe0f {'; '.join(w for w in warnings[:3])}"
    return line


# ── Deploy info ──────────────────────────────────────────────────────────

def _deploy_info(context: dict) -> str:
    """Render image + pod age from container status."""
    pod = context.get("pod") or {}
    containers = (
        (pod.get("containers") if isinstance(pod, dict) else None)
        or context.get("containers")
        or context.get("container_states")
        or []
    )
    if not containers or not isinstance(containers, list):
        return ""
    c = containers[0]
    if not isinstance(c, dict):
        return ""
    image = c.get("image", "")
    if not image:
        return ""

    # Shorten long registry prefixes for readability.
    # ":" can be a tag separator (repo:tag) or a registry port
    # (registry.example.com:5000/app). Only treat the last ":" as a tag
    # separator when it appears AFTER the last "/" — otherwise the colon
    # belongs to the registry host:port.
    short_image = image
    if "/" in image:
        last_slash = image.rfind("/")
        last_colon = image.rfind(":")
        if last_colon > last_slash:
            repo = image[:last_colon].split("/")[-1]
            tag = image[last_colon + 1:]
        else:
            repo = image.split("/")[-1]
            tag = "latest"
        short_image = f"{repo}:{tag}"

    pod = context.get("pod") or {}
    pod_age = (pod.get("age_seconds") if isinstance(pod, dict) else None)
    if pod_age and isinstance(pod_age, (int, float)) and pod_age > 0:
        age_str = _fmt_age(pod_age)
        return f"*Image:* `{short_image}` — pod age {age_str}"
    return f"*Image:* `{short_image}`"


# ── Resource trend (30m) ─────────────────────────────────────────────────

def _resource_trend(context: dict) -> str:
    """Render 30-min memory + CPU trend from Prometheus range queries.

    Returns empty string when Prometheus is unavailable, the pod name /
    namespace can't be read, or the range query has no data.
    """
    pod = context.get("pod") or {}
    if not isinstance(pod, dict):
        return ""
    pod_name = pod.get("name")
    namespace = pod.get("namespace")
    if not pod_name or not namespace:
        return ""

    lines: list[str] = []

    mem_limit_bytes = _container_mem_limit_bytes(pod)
    mem_query = (
        f'sum(container_memory_working_set_bytes{{'
        f'namespace="{namespace}",pod="{pod_name}",'
        f'container!="",container!="POD"}})'
    )
    mem_trend = _summarize_range(prom_range_query(mem_query, since_minutes=30))
    if mem_trend:
        first, peak, last = mem_trend
        parts = [f"{fmt_bytes(first)} \u2192 {fmt_bytes(last)}",
                 f"peak {fmt_bytes(peak)}"]
        if mem_limit_bytes:
            parts.append(f"limit {fmt_bytes(mem_limit_bytes)}")
            pct = peak / mem_limit_bytes * 100
            # A high-but-flat memory level is a heap-bounded plateau (JVM -Xmx,
            # Go GOMEMLIMIT): RSS sits at a fixed level and never grows into an
            # OOM. Only the \u26a0\ufe0f OOM-risk marker requires an actually-rising trend;
            # tag the plateau explicitly so downstream analysis doesn't mistake a
            # steady 80-90% for imminent OOM.
            rising = last > first * 1.05  # >5% growth across the 30m window
            if pct >= 90 and rising:
                parts.append(f"\u26a0\ufe0f {pct:.0f}% of limit and climbing")
            elif pct >= 70:
                parts.append(f"{pct:.0f}% of limit ({'climbing' if rising else 'flat/plateau'})")
        lines.append(f"  Memory  {parts[0]} ({', '.join(parts[1:])})")

    cpu_query = (
        f'sum(rate(container_cpu_usage_seconds_total{{'
        f'namespace="{namespace}",pod="{pod_name}",'
        f'container!="",container!="POD"}}[5m]))'
    )
    cpu_trend = _summarize_range(prom_range_query(cpu_query, since_minutes=30))
    if cpu_trend:
        first, peak, last = cpu_trend
        lines.append(
            f"  CPU     {_fmt_cpu_cores(first)} \u2192 {_fmt_cpu_cores(last)}"
            f" (peak {_fmt_cpu_cores(peak)})"
        )

    if not lines:
        return ""
    return "*Trend (30m):*\n" + "\n".join(lines)


def _summarize_range(series: list[dict] | None) -> tuple[float, float, float] | None:
    """Return (first, peak, last) from a Prometheus range-query series.

    Returns None when no data is present or every sample is unparseable.
    Picks the first result series (aggregated PromQL returns exactly one).
    """
    if not series:
        return None
    values = series[0].get("values") or []
    numeric: list[float] = []
    for _ts, v in values:
        try:
            parsed = float(v)
        except (TypeError, ValueError):
            continue
        if not math.isfinite(parsed):
            continue
        numeric.append(parsed)
    if not numeric:
        return None
    return numeric[0], max(numeric), numeric[-1]


def _container_mem_limit_bytes(pod: dict) -> float | None:
    """Sum memory limits across all containers in the pod, in bytes.

    Returns None when at least one container has no limit (treating the pod
    as unbounded is more useful than summing partial limits).
    """
    containers = pod.get("containers")
    if not isinstance(containers, list) or not containers:
        return None
    total_mi = 0.0
    for c in containers:
        if not isinstance(c, dict):
            return None
        res = c.get("resources")
        if not isinstance(res, dict):
            return None
        raw = res.get("mem_lim")
        if not raw:
            return None
        mi = parse_memory_mi(str(raw))
        if mi is None:
            return None
        total_mi += mi
    if total_mi <= 0:
        return None
    return total_mi * 1024 * 1024


def _fmt_cpu_cores(value: float) -> str:
    """Format CPU cores as millicores or cores."""
    if value >= 1:
        return f"{value:.2f} cores"
    return f"{value * 1000:.0f}m"


# ── HPA state ────────────────────────────────────────────────────────────

_HPA_CACHE_TTL_SEC = 60
_hpa_cache: dict[str, tuple[float, list]] = {}
_hpa_cache_lock = threading.Lock()


def _get_namespace_hpas(namespace: str) -> list:
    """Return HPAs in ``namespace``, cached for _HPA_CACHE_TTL_SEC.

    Cache shared across alerts in the same scan tick so a burst of OOMs from
    one Deployment doesn't trigger N identical list_hpa calls. Failure to
    list (RBAC, API blip) caches an empty list briefly so we fail fast.
    """
    now = time.time()
    with _hpa_cache_lock:
        entry = _hpa_cache.get(namespace)
        if entry and now - entry[0] < _HPA_CACHE_TTL_SEC:
            return entry[1]

    try:
        from kubernetes import client as k8s
        api = k8s.AutoscalingV2Api()
        hpas = api.list_namespaced_horizontal_pod_autoscaler(namespace).items
    except Exception:
        logger.debug("HPA list failed for ns=%s", namespace, exc_info=True)
        hpas = []

    with _hpa_cache_lock:
        _hpa_cache[namespace] = (now, hpas)
    return hpas


def _hpa_state(context: dict) -> str:
    """Render HPA status for the pod's owner, if one targets it.

    Shows current/desired replicas + ScalingLimited/ScalingActive conditions.
    The ScalingLimited=True case is often the root cause of an OOM that
    looks like a workload issue but is actually "HPA wanted more pods but
    couldn't get them."
    """
    pod = context.get("pod") or {}
    owner = context.get("owner") or {}
    if not isinstance(pod, dict) or not isinstance(owner, dict):
        return ""
    namespace = pod.get("namespace")
    owner_kind = owner.get("kind")
    owner_name = owner.get("name")
    if not namespace or not owner_kind or not owner_name:
        return ""

    hpas = _get_namespace_hpas(namespace)
    match = None
    for hpa in hpas:
        ref = hpa.spec.scale_target_ref if hpa.spec else None
        if ref and ref.kind == owner_kind and ref.name == owner_name:
            match = hpa
            break
    if match is None:
        return ""

    status = match.status
    spec = match.spec
    current = getattr(status, "current_replicas", None) or 0
    desired = getattr(status, "desired_replicas", None) or 0
    min_r = getattr(spec, "min_replicas", None)
    max_r = getattr(spec, "max_replicas", None)

    bounds = []
    if min_r is not None:
        bounds.append(f"min {min_r}")
    if max_r is not None:
        bounds.append(f"max {max_r}")
    bounds_str = f" ({', '.join(bounds)})" if bounds else ""

    line = f"*HPA:* {match.metadata.name} {current}/{desired} replicas{bounds_str}"

    limited = _hpa_condition(status, "ScalingLimited")
    active = _hpa_condition(status, "ScalingActive")
    warnings: list[str] = []
    if limited and limited.status == "True":
        reason = (limited.reason or "").strip() or "limited"
        warnings.append(f"ScalingLimited={reason}")
    if active and active.status != "True":
        reason = (active.reason or "").strip() or "inactive"
        warnings.append(f"ScalingActive=False ({reason})")
    if warnings:
        line += f" \u2014 {'; '.join(warnings)}"
    return line


def _hpa_condition(status, cond_type: str):
    for cond in (getattr(status, "conditions", None) or []):
        if getattr(cond, "type", "") == cond_type:
            return cond
    return None


# ── ES top error patterns ────────────────────────────────────────────────
#
# replace the "last 10 raw log lines" tail with "top 3 error
# patterns over the last hour + their count". Most production
# environments churn the same error thousands of times during an
# outage; seeing "connection refused: postgres:5432 ×214" in the alert
# body beats scrolling through stack traces.

_ES_PATTERN_LOOKBACK_MINUTES = 60
_ES_PATTERN_TOP_N = 3


def _es_top_errors(context: dict) -> str:
    """Render the top N aggregated error messages from Elasticsearch.

    Returns empty string when ES isn't configured, the namespace can't
    be resolved, the alert is for a non-prod namespace, or the lookup
    returns nothing.
    """
    if not elasticsearch._is_configured():
        return ""
    pod = context.get("pod") or {}
    if not isinstance(pod, dict):
        return ""
    namespace = pod.get("namespace")
    if not namespace:
        return ""
    # Non-prod alerts deliberately skip the Uptrace trace block too —
    # same reasoning here: staging noise isn't worth the ES round-trip.
    from src import config as _config
    if _config.is_nonprod_namespace(namespace):
        return ""

    pod_name = pod.get("name") or None
    patterns = elasticsearch.aggregate_error_patterns(
        namespace=namespace,
        pod=pod_name,
        since_minutes=_ES_PATTERN_LOOKBACK_MINUTES,
        top=_ES_PATTERN_TOP_N,
    )
    if not patterns:
        return ""

    lines = [
        f"*Top error patterns (last {_ES_PATTERN_LOOKBACK_MINUTES}m):*"
    ]
    for p in patterns:
        # Patterns are already normalised in the collector — sanitize
        # one more time in case any placeholder still reveals secrets
        # (e.g. Basic auth headers in the original log line that
        # survived normalisation).
        msg = sanitize_value(p.get("pattern", ""))[:200]
        count = p.get("count", 0)
        lines.append(f"  \u2022 \"{msg}\" \u00d7{count}")
    return "\n".join(lines)


# ── Root-cause correlation ───────────────────────────────────────────────

def _root_cause_correlation(store: SqliteStore, result, context: dict) -> str:
    """Render a hint when another incident in this namespace is the
    likely root cause.

    We ONLY hint — the dependent alert still fires — because a cascade
    of symptom alerts is useful signal about which services are not
    resilient to dependency outages. Hiding them turns the monitor into
    a cover for code/architecture problems.

    Returns empty when correlation is disabled, no root is active, the
    current alert IS the root, or the current alert is itself a
    critical-service incident (it's its own root).
    """
    from src import config as _config
    from src.engine.critical import matches_infra_critical

    if not _config.ROOT_CAUSE_CORRELATION_ENABLED:
        return ""
    if not result or not getattr(result, "namespace", ""):
        return ""
    # Infra-critical alerts are themselves potential root causes — no
    # need to point them at another root. Business-tier (IMPORTANT)
    # services CAN correlate to an infra root cause, so we only skip
    # the narrower infra match here.
    if matches_infra_critical(
        getattr(result, "resource", ""),
        getattr(result, "pod_name", ""),
    ):
        return ""

    root = store.get_active_root_cause(result.namespace)
    if not root:
        return ""
    if root["root_state_key"] == getattr(result, "state_key", ""):
        return ""

    age_sec = max(0.0, time.time() - root["started_at"])
    age_str = _fmt_age(age_sec)
    return (
        f"\u26a0\ufe0f *Correlates with active root:* `{root['root_state_key']}`"
        f" (fired {age_str} ago). This alert may be a downstream symptom —"
        f" but it's still worth confirming the service handles the"
        f" dependency outage gracefully."
    )


# ── Trace correlation ────────────────────────────────────────────────────
#
# Extracts an OTel trace_id from pod logs and renders the span tree from
# Uptrace so operators see the exact failure point — which hop, which
# span, and the error message — without opening a second tab.
# Falls back to the top recent error spans for the pod's service when
# no trace_id is visible in logs.

_TRACE_ID_RE = re.compile(
    # `trace_id=abc…`, `traceId=abc…`, `trace-id=abc…`
    r"(?:trace[_-]?id|traceId)[\s\"':=]+([a-f0-9]{16,32})"
    r"|"
    # W3C traceparent: `traceparent=00-<trace_id>-<span_id>-01`
    r"traceparent[\s\"':=]+[0-9a-f]{2}-([a-f0-9]{16,32})",
    re.IGNORECASE,
)
_TRACE_MAX_TREE_LINES = 10
_TRACE_LOOKBACK_MINUTES = 15
_TRACE_FALLBACK_LIMIT = 3


def _extract_trace_id(logs) -> str | None:
    """Return the first trace_id found in the collected logs, or None.

    Accepts a list of log lines or a single string (both shapes come
    through the context collector). Searches newest→oldest when given a
    list so we prefer the trace closest to the incident.
    """
    if not logs:
        return None
    if isinstance(logs, str):
        iterable = logs.splitlines()
    elif isinstance(logs, list):
        iterable = [str(line) for line in logs]
    else:
        return None
    for line in reversed(iterable):
        m = _TRACE_ID_RE.search(line)
        if m:
            # Regex has two capture groups (trace_id style + traceparent);
            # pick whichever matched.
            return (m.group(1) or m.group(2)).lower()
    return None


def _trace_correlation(context: dict) -> str:
    """Render a trace tree or top error spans for the alert's workload.

    Returns empty string when Uptrace isn't configured, when the alert is
    for a non-prod namespace (we only want to burn Uptrace calls on
    incidents that matter — the project token also contains develop and
    staging spans but those alerts get the non-prod treatment anyway),
    when no trace_id is in the logs and the fallback search also returns
    nothing, or when the service name can't be resolved.
    """
    if not uptrace._is_configured():
        return ""

    # Skip for non-prod namespaces. The Uptrace project is shared across
    # prod / develop / staging, so a develop alert that triggered
    # trace correlation would return the full trace for that request —
    # but operators don't want an Uptrace lookup (and the extra latency)
    # on staging noise that already skips LLM and @ai mentions.
    from src import config
    pod = context.get("pod") or {}
    namespace = pod.get("namespace") if isinstance(pod, dict) else ""
    if namespace and config.is_nonprod_namespace(namespace):
        return ""

    logs = context.get("logs")
    trace_id = _extract_trace_id(logs)
    if trace_id:
        spans = uptrace.get_trace(trace_id)
        # `spans is None` (API error / unconfigured) and `spans == []`
        # (trace has been purged, the ID was typo'd, or Uptrace hasn't
        # ingested yet) are intentionally treated the same — fall through
        # to the service-level error-spans search so the alert at least
        # shows *something* useful. No special-case: if we have no tree
        # to render, the fallback path is the right next step.
        if spans:
            return _render_trace_tree(trace_id, spans)

    owner = context.get("owner") or {}
    pod = context.get("pod") or {}
    service_name = ""
    if isinstance(owner, dict):
        service_name = owner.get("name", "")
    if not service_name and isinstance(pod, dict):
        # Strip the replica-set suffix (e.g. `backend-7c5bc9d4bd-x2kq8`
        # → `backend`) so search_spans has a chance of matching the
        # OTel service.name label.
        name = pod.get("name", "")
        service_name = re.sub(r"-[0-9a-f]{8,10}-[a-z0-9]{5}$", "", name)
    if not service_name:
        return ""

    fallback_spans = uptrace.search_spans(
        service_name,
        since_minutes=_TRACE_LOOKBACK_MINUTES,
        limit=_TRACE_FALLBACK_LIMIT,
        status_code="error",
    )
    if not fallback_spans:
        return ""
    return _render_error_spans(service_name, fallback_spans)


def _render_trace_tree(trace_id: str, spans: list[dict]) -> str:
    """Render a compact parent→child tree for a list of spans.

    Limits output to _TRACE_MAX_TREE_LINES so long traces don't flood
    the Slack body; when the tree is longer, keeps the root chain plus
    every ERROR span (which is what the operator cares about anyway).
    """
    if not spans:
        return ""

    by_id: dict[str, dict] = {s["span_id"]: s for s in spans if s.get("span_id")}
    children_of: dict[str, list[dict]] = {}
    for s in spans:
        parent = s.get("parent_span_id") or ""
        children_of.setdefault(parent, []).append(s)

    roots = [s for s in spans
             if not s.get("parent_span_id") or s["parent_span_id"] not in by_id]
    if not roots:
        roots = spans[:1]

    # Header: trace-level stats from the root(s)
    total_ms = max((s.get("duration_ms") or 0) for s in spans)
    error_count = sum(
        1 for s in spans if str(s.get("status_code", "")).lower() == "error"
    )
    status = "ERROR" if error_count else "OK"
    header = (
        f"*Trace:* `{trace_id[:12]}…` \u2014 {len(spans)} spans, "
        f"{total_ms:.0f}ms, {error_count} error(s), {status}"
    )

    # Pre-compute which subtrees contain an error. An intermediate span
    # that isn't an error itself is still worth rendering if a descendant
    # is — otherwise the operator sees an ERROR hop floating at random
    # depth without its visual chain of parents.
    error_cache: dict[str, bool] = {}

    def subtree_has_error(span_id: str) -> bool:
        if span_id in error_cache:
            return error_cache[span_id]
        has = False
        for child in children_of.get(span_id, []):
            if str(child.get("status_code", "")).lower() == "error":
                has = True
                break
            if subtree_has_error(child.get("span_id", "")):
                has = True
                break
        error_cache[span_id] = has
        return has

    lines: list[str] = [header]
    emitted_lines = 0  # total lines (span lines + error-message lines)
    emitted_spans = 0  # span lines only — used for the "(+N more spans)" tail
    keep_errors_only = len(spans) > _TRACE_MAX_TREE_LINES

    def render(span: dict, depth: int) -> None:
        nonlocal emitted_lines, emitted_spans
        if emitted_lines >= _TRACE_MAX_TREE_LINES:
            return
        is_error = str(span.get("status_code", "")).lower() == "error"
        span_id = span.get("span_id", "")
        if (keep_errors_only and depth > 0 and not is_error
                and not subtree_has_error(span_id)):
            # Entire subtree is clean — skip silently.
            return
        indent = "  " * depth
        svc = span.get("service", "?")
        name = span.get("name", "?")
        dur = span.get("duration_ms") or 0
        marker = " \u274c" if is_error else ""
        lines.append(f"{indent}  {svc} \u2192 {name}  ({dur:.0f}ms){marker}")
        emitted_lines += 1
        emitted_spans += 1
        msg = (span.get("status_message") or "").strip()
        if is_error and msg and emitted_lines < _TRACE_MAX_TREE_LINES:
            # This is a status-message line, not a span — only bump
            # emitted_lines, not emitted_spans, so the hidden-span tail
            # stays accurate. Status messages are untrusted content (may
            # contain DSNs, tokens, request bodies) and must pass through
            # the sanitizer before going to Slack.
            safe_msg = sanitize_value(msg)[:160]
            lines.append(f"{indent}    \u2192 {safe_msg}")
            emitted_lines += 1
        for child in children_of.get(span_id, []):
            render(child, depth + 1)

    for root in roots:
        render(root, 0)

    hidden_spans = len(spans) - emitted_spans
    if hidden_spans > 0:
        lines.append(f"  \u2026 (+{hidden_spans} more spans)")
    return "\n".join(lines)


def _render_error_spans(service_name: str, spans: list[dict]) -> str:
    """Fallback rendering when no trace_id was in logs — top error spans."""
    lines = [
        f"*Recent error spans ({service_name}, last {_TRACE_LOOKBACK_MINUTES}m):*"
    ]
    for s in spans[:_TRACE_FALLBACK_LIMIT]:
        name = s.get("name", "?")
        svc = s.get("service", service_name)
        dur = s.get("duration_ms") or 0
        trace = s.get("trace_id") or ""
        attrs = s.get("attrs") or {}
        msg = (
            attrs.get("error.message")
            or attrs.get("exception.message")
            or ""
        )
        line = f"  \u274c {svc} \u2192 {name} ({dur:.0f}ms)"
        if trace:
            line += f"  trace=`{trace[:12]}…`"
        lines.append(line)
        if msg:
            # Uptrace attribute values are untrusted — sanitize before
            # embedding in the Slack alert body.
            safe_msg = sanitize_value(str(msg))[:160]
            lines.append(f"    \u2192 {safe_msg}")
    return "\n".join(lines)


# ── Directives ───────────────────────────────────────────────────────────

def _directives(issue_type: str) -> str:
    """Render per-issue-type investigation hints."""
    checks = ISSUE_DIRECTIVES.get(issue_type)
    if not checks:
        return ""
    lines = ["*Next checks:*"]
    for check in checks:
        lines.append(f"  \u2022 {check}")
    return "\n".join(lines)


# ── Helpers ──────────────────────────────────────────────────────────────

def _fmt_age(seconds: float) -> str:
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h"
    return f"{int(seconds // 86400)}d"

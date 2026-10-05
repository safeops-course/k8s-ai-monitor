"""MCP server exposing k8s-ai-monitor tools for Claude Code.

Run: python3 -m src.mcp_server
Transport: stdio (local usage via .mcp.json)
"""
from __future__ import annotations

import datetime as _dt
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from src import config

logger = logging.getLogger(__name__)

mcp = FastMCP("k8s-monitor")

# ---------------------------------------------------------------------------
# Lazy singletons
# ---------------------------------------------------------------------------
_k8s_ready = False


def _ensure_k8s() -> None:
    global _k8s_ready
    if _k8s_ready:
        return
    from kubernetes import config as k8s_config

    try:
        k8s_config.load_incluster_config()
    except Exception:
        k8s_config.load_kube_config()
    _k8s_ready = True


_store_instance: Any = None


def _store():
    global _store_instance
    if _store_instance is None:
        from src.engine.store.sqlite import SqliteStore

        _store_instance = SqliteStore()
    return _store_instance


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe(fn, *args, **kwargs):
    """Call *fn* and return its result; on error return an error dict."""
    try:
        result = fn(*args, **kwargs)
        if result is None:
            return {"status": "not_configured"}
        return result
    except Exception as exc:
        logger.debug("_safe caught %s: %s", type(exc).__name__, exc)
        return {"error": str(exc)}


def _ts(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    return _dt.datetime.fromtimestamp(epoch, tz=_dt.timezone.utc).isoformat()


def _incident_to_dict(inc) -> dict:
    return {
        "id": inc.id,
        "state_key": inc.state_key,
        "issue_type": inc.issue_type,
        "severity": inc.severity,
        "owner_ref": inc.owner_ref,
        "status": inc.status,
        "occurrence_count": inc.occurrence_count,
        "first_seen": _ts(inc.first_seen_at),
        "last_seen": _ts(inc.last_seen_at),
    }


# ---------------------------------------------------------------------------
# Data-source availability
# ---------------------------------------------------------------------------

def _data_sources() -> dict:
    return {
        "prometheus": bool(config.PROMETHEUS_URL),
        "elasticsearch": bool(config.ELASTICSEARCH_URL),
        "uptrace": bool(config.UPTRACE_API_URL and config.UPTRACE_API_TOKEN),
        "sqlite": True,
    }


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def cluster_health(namespace: str | None = None) -> dict:
    """Get cluster health overview: nodes, pod issues, active incidents,
    warning events, backup status, latest daily report, and available data sources.

    Args:
        namespace: Optional namespace to focus on. If omitted, checks all watched namespaces.
    """
    _ensure_k8s()
    from kubernetes import client as k8s_client

    core = k8s_client.CoreV1Api()
    batch = k8s_client.BatchV1Api()
    store = _store()

    # Nodes
    try:
        nodes_raw = core.list_node().items
        nodes = []
        for n in nodes_raw:
            conditions = {c.type: c.status for c in (n.status.conditions or [])}
            nodes.append({
                "name": n.metadata.name,
                "ready": conditions.get("Ready") == "True",
                "conditions": conditions,
            })
    except Exception as exc:
        nodes = {"error": str(exc)}

    # Pod issues
    namespaces = [namespace] if namespace else config.get_namespaces()
    pod_issues: list[dict] = []
    for ns in namespaces:
        try:
            pods = core.list_namespaced_pod(ns).items
            for p in pods:
                phase = p.status.phase
                if phase in ("Running", "Succeeded"):
                    # Check container statuses for restarts / waiting
                    for cs in (p.status.container_statuses or []):
                        if cs.restart_count and cs.restart_count > 3:
                            pod_issues.append({
                                "namespace": ns,
                                "pod": p.metadata.name,
                                "issue": "high_restarts",
                                "restart_count": cs.restart_count,
                                "phase": phase,
                            })
                        if cs.state and cs.state.waiting and cs.state.waiting.reason:
                            pod_issues.append({
                                "namespace": ns,
                                "pod": p.metadata.name,
                                "issue": cs.state.waiting.reason,
                                "phase": phase,
                            })
                elif phase not in ("Succeeded",):
                    reason = ""
                    if p.status.container_statuses:
                        for cs in p.status.container_statuses:
                            if cs.state and cs.state.waiting:
                                reason = cs.state.waiting.reason or ""
                                break
                    pod_issues.append({
                        "namespace": ns,
                        "pod": p.metadata.name,
                        "issue": reason or phase,
                        "phase": phase,
                    })
        except Exception as exc:
            pod_issues.append({"namespace": ns, "error": str(exc)})

    # Warning events (last 30 min)
    warning_events: list[dict] = []
    try:
        cutoff = _dt.datetime.now(tz=_dt.timezone.utc) - _dt.timedelta(minutes=30)
        for ns in namespaces:
            events = core.list_namespaced_event(ns, field_selector="type=Warning").items
            for ev in events:
                ev_time = ev.last_timestamp or ev.event_time
                if ev_time and ev_time.replace(tzinfo=_dt.timezone.utc) >= cutoff:
                    warning_events.append({
                        "namespace": ns,
                        "object": ev.involved_object.name,
                        "reason": ev.reason,
                        "message": ev.message,
                        "count": ev.count,
                        "time": ev_time.isoformat(),
                    })
    except Exception as exc:
        warning_events = [{"error": str(exc)}]

    # Active incidents from store
    incidents = [_incident_to_dict(i) for i in store.list_incidents(status="active")]

    # Latest daily report
    reports = store.list_daily_reports(limit=1)
    latest_report = reports[0] if reports else None

    # Backup jobs (last CronJob runs)
    backup_jobs: list[dict] = []
    try:
        for ns in namespaces:
            jobs = batch.list_namespaced_job(ns, limit=20).items
            for j in jobs:
                if "backup" in (j.metadata.name or "").lower():
                    backup_jobs.append({
                        "namespace": ns,
                        "name": j.metadata.name,
                        "succeeded": bool(j.status.succeeded),
                        "failed": bool(j.status.failed),
                        "completion_time": j.status.completion_time.isoformat() if j.status.completion_time else None,
                    })
    except Exception:
        pass

    return {
        "cluster": config.CLUSTER_NAME,
        "timestamp": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
        "nodes": nodes,
        "pod_issues": pod_issues,
        "warning_events": warning_events[:30],
        "active_incidents": incidents,
        "backup_jobs": backup_jobs[:10],
        "latest_report": latest_report,
        "data_sources": _data_sources(),
    }


@mcp.tool()
def investigate(
    namespace: str,
    pod: str | None = None,
    since_minutes: int = 30,
) -> dict:
    """Deep investigation of a namespace or specific pod. Gathers pods, events,
    incidents, metrics, error logs, and traces.

    Args:
        namespace: Kubernetes namespace to investigate.
        pod: Optional pod name or pattern (e.g. "backend" or "*backend*").
        since_minutes: Look-back window in minutes (default 30).
    """
    _ensure_k8s()
    from kubernetes import client as k8s_client

    core = k8s_client.CoreV1Api()
    result: dict[str, Any] = {"namespace": namespace, "since_minutes": since_minutes}

    # Pods
    try:
        pods = core.list_namespaced_pod(namespace).items
        if pod:
            pods = [p for p in pods if pod.strip("*") in p.metadata.name]
        pod_data = []
        for p in pods:
            containers = []
            for cs in (p.status.container_statuses or []):
                c: dict[str, Any] = {
                    "name": cs.name,
                    "ready": cs.ready,
                    "restart_count": cs.restart_count,
                }
                if cs.state:
                    if cs.state.waiting:
                        c["state"] = "waiting"
                        c["reason"] = cs.state.waiting.reason
                    elif cs.state.running:
                        c["state"] = "running"
                    elif cs.state.terminated:
                        c["state"] = "terminated"
                        c["reason"] = cs.state.terminated.reason
                        c["exit_code"] = cs.state.terminated.exit_code
                containers.append(c)
            pod_data.append({
                "name": p.metadata.name,
                "phase": p.status.phase,
                "containers": containers,
            })
        result["pods"] = pod_data
    except Exception as exc:
        result["pods"] = {"error": str(exc)}

    # Events
    try:
        events = core.list_namespaced_event(namespace, field_selector="type=Warning").items
        cutoff = _dt.datetime.now(tz=_dt.timezone.utc) - _dt.timedelta(minutes=since_minutes)
        ev_list = []
        for ev in events:
            ev_time = ev.last_timestamp or ev.event_time
            if ev_time and ev_time.replace(tzinfo=_dt.timezone.utc) >= cutoff:
                if pod and pod.strip("*") not in (ev.involved_object.name or ""):
                    continue
                ev_list.append({
                    "object": ev.involved_object.name,
                    "reason": ev.reason,
                    "message": ev.message,
                    "count": ev.count,
                })
        result["events"] = ev_list
    except Exception as exc:
        result["events"] = {"error": str(exc)}

    # Incidents
    store = _store()
    prefix = f"{namespace}/"
    all_incidents = store.list_incidents(status="active")
    result["incidents"] = [
        _incident_to_dict(i) for i in all_incidents
        if prefix in i.state_key
    ]

    # Metrics (Prometheus)
    from src.collectors.prometheus import prom_query

    pod_filter = pod.strip("*") if pod else ".*"
    metrics: dict[str, Any] = {}
    cpu_q = f'sum(rate(container_cpu_usage_seconds_total{{namespace="{namespace}",pod=~".*{pod_filter}.*"}}[5m])) by (pod)'
    metrics["cpu"] = _safe(prom_query, cpu_q)
    mem_q = f'sum(container_memory_working_set_bytes{{namespace="{namespace}",pod=~".*{pod_filter}.*"}}) by (pod)'
    metrics["memory"] = _safe(prom_query, mem_q)
    restart_q = f'sum(kube_pod_container_status_restarts_total{{namespace="{namespace}",pod=~".*{pod_filter}.*"}}) by (pod)'
    metrics["restarts"] = _safe(prom_query, restart_q)
    result["metrics"] = metrics

    # Error logs (Elasticsearch)
    from src.collectors.elasticsearch import search_error_logs, search_logs

    if pod:
        result["error_logs"] = _safe(search_logs, namespace, pod, "", since_minutes, 50)
    else:
        result["error_logs"] = _safe(search_error_logs, namespace, since_minutes, 50)

    # Traces (Uptrace) — use pod name as service hint
    if pod:
        from src.collectors.uptrace import get_service_stats

        svc = pod.strip("*").rstrip("-0123456789")
        result["traces"] = _safe(get_service_stats, svc, since_minutes)

    # HPA
    try:
        autoscaling = k8s_client.AutoscalingV2Api()
        hpas = autoscaling.list_namespaced_horizontal_pod_autoscaler(namespace).items
        result["hpa"] = [
            {
                "name": h.metadata.name,
                "min_replicas": h.spec.min_replicas,
                "max_replicas": h.spec.max_replicas,
                "current_replicas": h.status.current_replicas,
                "desired_replicas": h.status.desired_replicas,
            }
            for h in hpas
        ]
    except Exception:
        result["hpa"] = []

    return result


@mcp.tool()
def audit(namespace: str, pod: str | None = None) -> dict:
    """Observability audit: checks deployments for probes, logging, tracing,
    and metrics coverage.

    Args:
        namespace: Kubernetes namespace to audit.
        pod: Optional pod/deployment name filter.
    """
    _ensure_k8s()
    from kubernetes import client as k8s_client

    apps = k8s_client.AppsV1Api()
    deployments_data: list[dict] = []

    try:
        deps = apps.list_namespaced_deployment(namespace).items
        if pod:
            deps = [d for d in deps if pod.strip("*") in d.metadata.name]

        for dep in deps:
            name = dep.metadata.name
            containers = dep.spec.template.spec.containers or []
            dep_info: dict[str, Any] = {"name": name, "containers": []}

            for c in containers:
                c_info: dict[str, Any] = {
                    "name": c.name,
                    "has_liveness_probe": c.liveness_probe is not None,
                    "has_readiness_probe": c.readiness_probe is not None,
                    "has_startup_probe": c.startup_probe is not None,
                    "has_resource_requests": bool(c.resources and c.resources.requests),
                    "has_resource_limits": bool(c.resources and c.resources.limits),
                }
                dep_info["containers"].append(c_info)

            # Check logging (ES)
            from src.collectors.elasticsearch import search_logs

            logs = _safe(search_logs, namespace, f"*{name}*", "", 5, 1)
            dep_info["logging_available"] = isinstance(logs, list) and len(logs) > 0

            # Check tracing (Uptrace)
            from src.collectors.uptrace import get_service_stats

            stats = _safe(get_service_stats, name, 30)
            dep_info["tracing_available"] = (
                isinstance(stats, dict)
                and stats.get("status") != "not_configured"
                and stats.get("span_count", 0) > 0
            )

            # Check metrics (Prometheus)
            from src.collectors.prometheus import prom_query

            pq = f'count(container_cpu_usage_seconds_total{{namespace="{namespace}",pod=~".*{name}.*"}})'
            m = _safe(prom_query, pq)
            dep_info["metrics_available"] = isinstance(m, list) and len(m) > 0

            deployments_data.append(dep_info)

    except Exception as exc:
        return {"error": str(exc)}

    # Summary
    total = len(deployments_data)
    probes_ok = sum(
        1 for d in deployments_data
        if all(c.get("has_readiness_probe") for c in d["containers"])
    )
    logging_ok = sum(1 for d in deployments_data if d.get("logging_available"))
    tracing_ok = sum(1 for d in deployments_data if d.get("tracing_available"))
    metrics_ok = sum(1 for d in deployments_data if d.get("metrics_available"))

    return {
        "namespace": namespace,
        "deployments": deployments_data,
        "summary": {
            "total_deployments": total,
            "with_probes": probes_ok,
            "with_logging": logging_ok,
            "with_tracing": tracing_ok,
            "with_metrics": metrics_ok,
        },
        "data_sources": _data_sources(),
    }


@mcp.tool()
def search_logs(
    namespace: str,
    pod_pattern: str = "",
    query: str = "",
    errors_only: bool = False,
    since_minutes: int = 30,
    limit: int = 100,
) -> dict:
    """Search Elasticsearch logs for a namespace.

    Args:
        namespace: Kubernetes namespace.
        pod_pattern: Pod name pattern with wildcards (e.g. "*backend*").
        query: Lucene query string to filter log messages.
        errors_only: If true, only return error/fatal logs.
        since_minutes: Look-back window in minutes (default 30).
        limit: Max number of log entries to return (default 100).
    """
    from src.collectors.elasticsearch import (
        search_error_logs,
        search_logs as es_search,
    )

    if errors_only:
        result = _safe(search_error_logs, namespace, since_minutes, limit)
    else:
        result = _safe(es_search, namespace, pod_pattern, query, since_minutes, limit)

    if isinstance(result, dict) and ("status" in result or "error" in result):
        return result
    if isinstance(result, list):
        return {"logs": result, "total": len(result)}
    return {"status": "not_configured"}


@mcp.tool()
def search_traces(
    service: str,
    since_minutes: int = 30,
    errors_only: bool = False,
    slow: bool = False,
    min_duration_ms: int = 1000,
    limit: int = 50,
) -> dict:
    """Search Uptrace spans for a service.

    Args:
        service: Service name (e.g. "backend").
        since_minutes: Look-back window in minutes (default 30).
        errors_only: Only return error spans.
        slow: Only return slow spans (above min_duration_ms).
        min_duration_ms: Threshold for slow spans in milliseconds (default 1000).
        limit: Max number of spans to return (default 50).
    """
    from src.collectors.uptrace import (
        search_slow_spans,
        search_spans,
    )

    if slow:
        result = _safe(search_slow_spans, service, since_minutes, min_duration_ms, limit)
    elif errors_only:
        result = _safe(search_spans, service, since_minutes, limit, "error")
    else:
        result = _safe(search_spans, service, since_minutes, limit)

    if isinstance(result, dict) and ("status" in result or "error" in result):
        return result
    if isinstance(result, list):
        return {"spans": result, "total": len(result)}
    return {"status": "not_configured"}


@mcp.tool()
def get_service_stats(service: str, since_minutes: int = 30) -> dict:
    """Get Uptrace service statistics: span count, error rate, latency percentiles.

    Args:
        service: Service name (e.g. "backend").
        since_minutes: Look-back window in minutes (default 30).
    """
    from src.collectors.uptrace import get_service_stats as _get_stats

    result = _safe(_get_stats, service, since_minutes)
    if isinstance(result, dict):
        return result
    return {"status": "not_configured"}


@mcp.tool()
def query_metrics(
    namespace: str | None = None,
    pod: str | None = None,
    query: str | None = None,
    since_minutes: int = 30,
) -> dict:
    """Query Prometheus metrics. Either provide a custom PromQL query, or
    specify namespace/pod for a preset battery (CPU, memory, restarts, HTTP errors).

    Args:
        namespace: Kubernetes namespace (for preset queries).
        pod: Pod name or pattern (for preset queries).
        query: Custom PromQL query (overrides preset).
        since_minutes: Look-back window for range queries (default 30).
    """
    from src.collectors.metrics_range import prom_range_query
    from src.collectors.prometheus import prom_query

    if query:
        instant = _safe(prom_query, query)
        series = _safe(prom_range_query, query, since_minutes)
        return {"query": query, "instant": instant, "series": series}

    if not namespace:
        return {"error": "Provide either 'query' or 'namespace'"}

    pod_filter = pod.strip("*") if pod else ".*"
    pod_re = f'.*{pod_filter}.*'
    results: dict[str, Any] = {}

    queries = {
        "cpu_usage": f'sum(rate(container_cpu_usage_seconds_total{{namespace="{namespace}",pod=~"{pod_re}"}}[5m])) by (pod)',
        "memory_bytes": f'sum(container_memory_working_set_bytes{{namespace="{namespace}",pod=~"{pod_re}"}}) by (pod)',
        "restarts": f'sum(kube_pod_container_status_restarts_total{{namespace="{namespace}",pod=~"{pod_re}"}}) by (pod)',
        "http_errors_rate": f'sum(rate(http_requests_total{{namespace="{namespace}",pod=~"{pod_re}",code=~"5.."}}[5m])) by (pod)',
    }

    for name, q in queries.items():
        results[name] = _safe(prom_query, q)

    return {"namespace": namespace, "pod_filter": pod_filter, "metrics": results}


@mcp.tool()
def list_incidents(status: str = "active", limit: int = 50) -> dict:
    """List incidents from the incident store.

    Args:
        status: Filter by status: "active", "acknowledged", "resolved", or "all" (default "active").
        limit: Max number of incidents to return (default 50).
    """
    store = _store()
    st = None if status == "all" else status
    incidents = store.list_incidents(status=st)
    return {
        "incidents": [_incident_to_dict(i) for i in incidents[:limit]],
        "total": len(incidents),
    }


@mcp.tool()
def get_incident(incident_id: int) -> dict:
    """Get full incident detail including occurrences and analysis.

    Args:
        incident_id: The incident ID.
    """
    store = _store()
    inc = store.get_incident_by_id(incident_id)
    if not inc:
        return {"error": f"Incident {incident_id} not found"}

    occurrences = store.get_occurrences(incident_id)
    detail = _incident_to_dict(inc)
    detail["occurrences"] = [
        {
            "id": o.get("id"),
            "created_at": o.get("created_at"),
            "analysis": o.get("analysis"),
            "analysis_json": o.get("analysis_json"),
            "llm_model": o.get("llm_model"),
        }
        for o in occurrences
    ]
    return detail


@mcp.tool()
def list_reports(limit: int = 10) -> dict:
    """List daily reports.

    Args:
        limit: Max number of reports to return (default 10).
    """
    store = _store()
    reports = store.list_daily_reports(limit=limit)
    return {"reports": reports, "total": len(reports)}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")

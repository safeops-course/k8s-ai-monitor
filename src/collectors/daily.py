"""Daily data collection — extracted from Collector.collect_daily_data()."""
import logging
from datetime import datetime, timezone

from kubernetes import client as k8s

from src import config
from src.collectors._formatters import parse_cpu, parse_memory_mi, fmt_mem, fmt_bytes
from src.collectors.prometheus import prom_scalar, prom_query

logger = logging.getLogger(__name__)


def _extract_current_snapshot(raw_context: dict, issue_type: str) -> dict | None:
    """Pull the most signal-rich fields out of a stored raw_context dict,
    keyed by incident issue_type.

    Returns a small dict the daily LLM can compare against the initial
    analysis — or None when no useful fields are present. Used by the daily
    report enrichment; the LLM uses it to decide whether an incident is
    stable or evolving.
    """
    if not isinstance(raw_context, dict):
        return None

    # Pod-level incidents (crash, oom, unhealthy, error, mount, image_pull,
    # scheduling, evicted) share the same collector output shape.
    pod_issue_types = {
        "crash", "oom", "unhealthy", "error", "mount", "image_pull", "image-pull",
        "scheduling", "evicted",
    }
    if issue_type in pod_issue_types:
        pod = raw_context.get("pod")
        if not isinstance(pod, dict):
            return None
        containers = pod.get("containers") or []
        first = containers[0] if containers and isinstance(containers[0], dict) else {}
        pod_snap: dict = {
            "phase": pod.get("phase", ""),
            "ready": pod.get("node_ready"),
            "restart_count": first.get("restarts"),
            "last_reason": first.get("reason") or first.get("last_reason") or "",
            "last_exit_code": first.get("exit_code"),
        }
        return {k: v for k, v in pod_snap.items() if v is not None and v != ""} or None

    if issue_type in ("endpoint", "critical_endpoint"):
        ctx = raw_context.get("context") or raw_context.get("raw") or ""
        snap: dict = {}
        if isinstance(ctx, str):
            snap["context"] = ctx[:300]
        for k in ("url", "status_code", "reason", "http_status", "status"):
            if k in raw_context:
                snap[k] = raw_context[k]
        return snap or None

    if issue_type in ("pvc", "pvc_usage"):
        snap = {}
        for k in ("usage_pct", "free_bytes", "namespace", "pvc"):
            if k in raw_context:
                snap[k] = raw_context[k]
        return snap or None

    if issue_type in ("certificate", "cert"):
        snap = {}
        for k in ("days_until_expiry", "error", "status"):
            if k in raw_context:
                snap[k] = raw_context[k]
        return snap or None

    if issue_type.startswith("flux") or "flux_resource" in raw_context:
        snap = {}
        conds = raw_context.get("conditions") or []
        if isinstance(conds, list) and conds:
            c0 = conds[0] if isinstance(conds[0], dict) else {}
            if c0.get("message"):
                snap["condition_message"] = str(c0["message"])[:300]
        fres = raw_context.get("flux_resource")
        if isinstance(fres, dict):
            for k in ("generation", "last_applied_revision"):
                if k in fres:
                    snap[k] = fres[k]
        return snap or None

    return None


def collect_daily_data() -> dict:
    core = k8s.CoreV1Api()
    custom = k8s.CustomObjectsApi()
    result = {
        "pod_restarts": [],
        "warning_events": [],
        "flux_failures": [],
        "node_issues": [],
        "nodes": [],
        "pvc_usage": [],
        "cert_issues": [],
        "resource_pressure": [],
    }

    result["error_log_patterns"] = _collect_error_log_patterns(config.get_prod_namespaces())

    for ns in config.get_prod_namespaces():
        # Pod restarts — only include pods with recent restarts (last 24h)
        try:
            pods = core.list_namespaced_pod(ns)
            now_ts = datetime.now(timezone.utc)
            for pod in pods.items:
                for cs in (pod.status.container_statuses or []):
                    if cs.restart_count <= 0:
                        continue
                    reason = ""
                    recent = False
                    age_h = None
                    if cs.last_state and cs.last_state.terminated:
                        reason = cs.last_state.terminated.reason or ""
                        finished = cs.last_state.terminated.finished_at
                        if finished:
                            age_h = (now_ts - finished).total_seconds() / 3600
                            if age_h <= 24:
                                recent = True
                    # Pod-level status context for LLM triage
                    phase = pod.status.phase or ""
                    ready_cond = next(
                        (c for c in (pod.status.conditions or []) if c.type == "Ready"),
                        None,
                    )
                    ready = ready_cond is not None and ready_cond.status == "True"
                    entry = {
                        "namespace": ns,
                        "pod": pod.metadata.name,
                        "container": cs.name,
                        "restarts": cs.restart_count,
                        "last_reason": reason,
                        "node": pod.spec.node_name or "",
                        "phase": phase,
                        "ready": ready,
                    }
                    if age_h is not None:
                        entry["hours_since_last_restart"] = round(age_h, 1)
                    # Only last-24h restarts belong in the DAILY report. Restarts
                    # older than 24h (or undateable) are the weekly report's job —
                    # the daily report focuses on the past day only.
                    if recent:
                        result["pod_restarts"].append(entry)
        except Exception:
            logger.debug("Failed to list pods in %s", ns)

        # Warning events
        try:
            events = core.list_namespaced_event(ns, field_selector="type=Warning")
            if events.items:
                counts: dict[str, int] = {}
                for e in events.items:
                    key = f"{e.reason}: {e.involved_object.kind}/{e.involved_object.name}"
                    counts[key] = counts.get(key, 0) + (e.count or 1)
                top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:15]
                for key, count in top:
                    result["warning_events"].append({
                        "namespace": ns,
                        "key": key,
                        "count": count,
                    })
        except Exception:
            logger.debug("Failed to list events in %s", ns)

    # Flux status — cluster-wide (Flux is critical infra, failures block deployments)
    for kind, group, version, plural in [
        ("Kustomization", "kustomize.toolkit.fluxcd.io", "v1", "kustomizations"),
        ("HelmRelease", "helm.toolkit.fluxcd.io", "v2", "helmreleases"),
    ]:
        try:
            objs = custom.list_cluster_custom_object(group, version, plural)
            for obj in objs.get("items", []):
                obj_ns = obj["metadata"].get("namespace")
                if not obj_ns or obj_ns in config.EXCLUDE_NAMESPACES:
                    continue
                if obj_ns in config.NON_PROD_NAMESPACES:
                    continue
                conditions = obj.get("status", {}).get("conditions", [])
                for c in conditions:
                    # Only Ready=False is an actual failure. Ready=Unknown means
                    # the object is mid-reconcile (reason Progressing/Reconciling/
                    # DependencyNotReady) — a normal transient state that flips to
                    # True in seconds, so it must not be reported as an issue. A
                    # genuinely stuck reconcile eventually times out to Ready=False.
                    if c["type"] == "Ready" and c["status"] == "False":
                        result["flux_failures"].append({
                            "kind": kind,
                            "namespace": obj["metadata"]["namespace"],
                            "name": obj["metadata"]["name"],
                            "reason": c.get("reason", ""),
                            "message": c.get("message", "Not Ready"),
                        })
        except Exception:
            logger.debug("Failed to list Flux %s", plural)

    # Node status + resource usage
    try:
        nodes = core.list_node()
        for node in nodes.items:
            name = node.metadata.name
            ready = True
            schedulable = not bool(node.spec.unschedulable)

            for cond in (node.status.conditions or []):
                if cond.type == "Ready":
                    ready = cond.status == "True"
                    if cond.status != "True":
                        result["node_issues"].append({
                            "node": name,
                            "issue": "NotReady",
                            "message": cond.message or "",
                        })
                elif cond.type in ("MemoryPressure", "DiskPressure", "PIDPressure") and cond.status == "True":
                    result["node_issues"].append({
                        "node": name,
                        "issue": cond.type,
                        "message": cond.message or "",
                    })

            node_ip = ""
            for addr in (node.status.addresses or []):
                if addr.type == "InternalIP":
                    node_ip = addr.address
                    break

            cpu_pct = None
            mem_pct = None
            mem_detail = None
            disk_pct = None

            if config.PROMETHEUS_URL and node_ip:
                inst = f"{node_ip}:.*"
                cpu_val = prom_scalar(
                    f'100 - (avg(rate(node_cpu_seconds_total{{mode="idle",instance=~"{inst}"}}[5m])) * 100)'
                )
                mem_total = prom_scalar(f'node_memory_MemTotal_bytes{{instance=~"{inst}"}}')
                mem_avail = prom_scalar(f'node_memory_MemAvailable_bytes{{instance=~"{inst}"}}')
                if cpu_val is not None:
                    cpu_pct = round(cpu_val, 1)
                if mem_total and mem_avail is not None:
                    mem_pct = round((mem_total - mem_avail) / mem_total * 100, 1)
                    mem_detail = f"{fmt_bytes(mem_total - mem_avail)}/{fmt_bytes(mem_total)}"
                fs_size = prom_scalar(
                    f'node_filesystem_size_bytes{{instance=~"{inst}",mountpoint="/",fstype!~"tmpfs|overlay"}}'
                )
                fs_avail = prom_scalar(
                    f'node_filesystem_avail_bytes{{instance=~"{inst}",mountpoint="/",fstype!~"tmpfs|overlay"}}'
                )
                if fs_size and fs_avail is not None:
                    disk_pct = round((fs_size - fs_avail) / fs_size * 100, 1)
                else:
                    btrfs_total = prom_scalar(f'node_btrfs_device_size_bytes{{instance=~"{inst}"}}')
                    btrfs_used = prom_scalar(f'sum(node_btrfs_used_bytes{{instance=~"{inst}"}})')
                    if btrfs_total and btrfs_used is not None:
                        disk_pct = round(btrfs_used / btrfs_total * 100, 1)
            else:
                try:
                    alloc = node.status.allocatable or {}
                    alloc_cpu_m = parse_cpu(alloc.get("cpu", ""))
                    alloc_mem_mi = parse_memory_mi(alloc.get("memory", ""))
                    nm = custom.get_cluster_custom_object("metrics.k8s.io", "v1beta1", "nodes", name)
                    usage = nm.get("usage", {})
                    usage_cpu_m = parse_cpu(usage.get("cpu", ""))
                    usage_mem_mi = parse_memory_mi(usage.get("memory", ""))
                    if usage_cpu_m is not None and alloc_cpu_m:
                        cpu_pct = round(usage_cpu_m / alloc_cpu_m * 100, 1)
                    if usage_mem_mi is not None and alloc_mem_mi:
                        mem_pct = round(usage_mem_mi / alloc_mem_mi * 100, 1)
                        mem_detail = f"{fmt_mem(usage_mem_mi)}/{fmt_mem(alloc_mem_mi)}"
                except Exception:
                    logger.debug("Failed to get metrics for node %s", name)

            result["nodes"].append({
                "name": name,
                "ready": ready,
                "schedulable": schedulable,
                "cpu_pct": cpu_pct,
                "mem_pct": mem_pct,
                "mem_detail": mem_detail,
                "disk_pct": disk_pct,
            })
    except Exception:
        logger.debug("Failed to list nodes")

    # PVC usage
    result["pvc_usage"] = _query_pvc_usage()

    # cert-manager status
    result["cert_issues"] = _query_cert_status(custom)

    # Resource pressure
    result["resource_pressure"] = _query_resource_pressure()

    # 24-hour history (incidents, restarts, OOM kills)
    history = _collect_24h_history()
    if history:
        result["last_24h"] = history

    # Scanner daily data (backup status, etc.)
    scanner_sections = _collect_scanner_daily_data()
    if scanner_sections:
        result["scanner_sections"] = scanner_sections

    # Maintenance windows in last 24h
    result["maintenance_events"] = _collect_maintenance_events(24)

    return result


def collect_weekly_data() -> dict:
    """Collect aggregated data for a weekly report.

    Pulls last 7 daily reports from the store and 7 days of incidents,
    then aggregates into a structure suitable for LLM analysis.
    """
    from src.handlers.startup import get_store

    result: dict = {
        "period": "7 days",
        "daily_reports": [],
        "incidents_by_type": {},
        "incidents_by_severity": {},
        "incident_details": [],
        "llm_cost_summary": {},
    }

    store = get_store()

    # a) Last 7 daily reports — extract status/summary/issues/trends
    try:
        reports = store.list_daily_reports(limit=7, report_type="daily")
        for r in reports:
            entry: dict = {
                "date": datetime.fromtimestamp(
                    r["created_at"], tz=timezone.utc
                ).strftime("%Y-%m-%d"),
                "overall_status": r.get("overall_status", "unknown"),
                "summary": r.get("summary", ""),
            }
            result["daily_reports"].append(entry)
    except Exception:
        logger.debug("Failed to collect daily reports for weekly summary", exc_info=True)

    # b) 7 days of incidents — aggregate by type and severity (prod only)
    try:
        raw = store.get_recent_prod_incidents(
            168, exclude_namespaces=config.NON_PROD_NAMESPACES)  # 7 * 24
        for inc in raw:
            itype = inc.get("issue_type", "unknown")
            sev = inc.get("severity", "unknown")
            result["incidents_by_type"][itype] = result["incidents_by_type"].get(itype, 0) + 1
            result["incidents_by_severity"][sev] = result["incidents_by_severity"].get(sev, 0) + 1
            result["incident_details"].append({
                "state_key": inc["state_key"],
                "issue_type": itype,
                "severity": sev,
                "status": inc.get("status", "active"),
                "occurrences": inc.get("occurrence_count", 1),
                # Wall-clock span first_seen→last_seen. For continuously
                # re-detected issues (scheduling, persistent unhealthy) this is
                # far more meaningful than occurrences, which is just the number
                # of scan cycles that re-saw the same problem.
                "duration_hours": round(
                    (inc["last_seen_at"] - inc["first_seen_at"]) / 3600, 1
                ),
                "first_seen": datetime.fromtimestamp(
                    inc["first_seen_at"], tz=timezone.utc
                ).isoformat(),
                "last_seen": datetime.fromtimestamp(
                    inc["last_seen_at"], tz=timezone.utc
                ).isoformat(),
            })
        # Cap detail list
        result["incident_details"] = result["incident_details"][:50]
    except Exception:
        logger.debug("Failed to collect weekly incidents", exc_info=True)

    # c) LLM usage summary for the week
    try:
        result["llm_cost_summary"] = store.get_llm_usage_summary(168)
    except Exception:
        logger.debug("Failed to collect weekly LLM usage", exc_info=True)

    # d) Maintenance events in last 7 days
    result["maintenance_events"] = _collect_maintenance_events(168)

    return result


def _collect_error_log_patterns(namespaces: list[str], since_minutes: int = 1440,
                                  max_per_ns: int = 5000, top_n: int = 10) -> list[dict]:
    """Aggregate top error log patterns per namespace/container from ES.

    Paginates through up to ``max_per_ns`` matching errors per namespace in
    the window so the top-N counts reflect the full window, not just the most
    recent slice.

    Returns list of {namespace, container, pattern, count} sorted by count desc.
    No-op when ES is not configured.
    """
    from src.collectors.elasticsearch import search_error_logs
    from src.engine.sanitizer import redact_logs
    import re

    patterns: list[dict] = []
    for ns in namespaces:
        hits = search_error_logs(
            ns, since_minutes=since_minutes,
            limit=1000, max_total=max_per_ns,
        )
        if hits is None:
            logger.debug("ES error log query failed for %s", ns)
            continue
        if not hits:
            continue
        # Normalize message: strip timestamps, UUIDs, numbers so similar errors cluster
        counts: dict[tuple[str, str], int] = {}
        for h in hits:
            msg = (h.get("message") or "").strip()
            if not msg:
                continue
            # Redact passwords/tokens BEFORE normalization so secrets never
            # reach the LLM context, even if the regex below would otherwise
            # mask them.
            msg = redact_logs(msg)
            norm = re.sub(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', '<uuid>', msg, flags=re.I)
            norm = re.sub(r'\b\d{10,}\b', '<ts>', norm)  # epoch timestamps
            norm = re.sub(r'\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*', '<iso>', norm)
            norm = re.sub(r'\b\d+\b', '<n>', norm)
            norm = norm[:200]
            key = (h.get("container") or "-", norm)
            counts[key] = counts.get(key, 0) + 1
        top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:top_n]
        for (container, pattern), count in top:
            patterns.append({
                "namespace": ns,
                "container": container,
                "pattern": pattern,
                "count": count,
            })
    # Global sort across all namespaces so the most frequent patterns appear
    # first regardless of which namespace produced them — matches the docstring.
    patterns.sort(key=lambda p: p["count"], reverse=True)
    return patterns


def _collect_scanner_daily_data() -> list[str]:
    """Collect daily data sections from enabled scanners."""
    from src.scanners import get_enabled_scanners

    sections = []
    for scanner in get_enabled_scanners():
        try:
            data = scanner.collect_daily_data()
            if data:
                sections.append(data)
        except Exception:
            logger.debug("Failed to collect daily data from scanner %s", scanner.name, exc_info=True)
    return sections


def _collect_24h_history() -> dict:
    """Collect 24-hour history from SQLite incidents and Prometheus metrics."""
    result = {}

    # a) Incidents from SQLite, enriched with latest occurrence context.
    # Non-prod namespaces are filtered out — daily reports are production-only.
    try:
        from src.handlers.startup import get_store
        store = get_store()
        raw = store.get_recent_prod_incidents(
            24, exclude_namespaces=config.NON_PROD_NAMESPACES)
        if raw:
            result["incidents"] = [
                {
                    "state_key": r["state_key"],
                    "issue_type": r["issue_type"],
                    "severity": r["severity"],
                    "status": r["status"],
                    "occurrences": r["occurrence_count"],
                    "first_seen": datetime.fromtimestamp(
                        r["first_seen_at"], tz=timezone.utc
                    ).isoformat(),
                    "last_seen": datetime.fromtimestamp(
                        r["last_seen_at"], tz=timezone.utc
                    ).isoformat(),
                    "_last_seen_ts": r["last_seen_at"],
                }
                for r in raw
            ]

            # Enrich each incident with:
            #   - `initial_analysis`: the first LLM diagnosis of this incident
            #      in the 24h window (reuse root_cause / hypotheses / actions
            #      instead of re-deriving them).
            #   - `repetition`: how many times it fired after that analysis,
            #      and for how long — tells the LLM whether the suggested
            #      actions have obviously not been applied.
            #   - `current_snapshot`: most recent observed state, so the LLM
            #      can detect evolution vs. a static recurrence.
            # Per-incident try/except so one bad row doesn't blank the rest.
            for inc_entry in result["incidents"][:30]:
                try:
                    first = store.get_first_analysis_by_state_key(
                        inc_entry["state_key"], max_age_hours=24)
                    if first and isinstance(first.get("analysis_json"), dict):
                        parsed = first["analysis_json"]
                        analyzed_at = datetime.fromtimestamp(
                            first["seen_at"], tz=timezone.utc,
                        ).isoformat()
                        inc_entry["initial_analysis"] = {
                            "reasoning": parsed.get("reasoning", ""),
                            "root_cause": parsed.get("root_cause", ""),
                            "confidence": parsed.get("confidence"),
                            "severity": parsed.get("severity"),
                            "hypotheses": (parsed.get("hypotheses") or [])[:3],
                            "impact": parsed.get("impact", ""),
                            "suggested_actions": (parsed.get("suggested_actions") or [])[:3],
                            "analyzed_at": analyzed_at,
                            "analyzed_by": first.get("llm_model", ""),
                        }
                        duration_s = max(0.0, inc_entry["_last_seen_ts"] - first["seen_at"])
                        # Count actual occurrences since the analyzed one
                        count_since = store.count_occurrences_since(
                            inc_entry["state_key"], since_ts=first["seen_at"]
                        )
                        # Subtract 1 to get count *after* the initial one
                        count_since = max(0, count_since - 1)
                        note = (
                            f"Initial LLM analysis at {analyzed_at}; "
                            f"incident recurred {count_since} times without re-analysis"
                            if count_since > 0
                            else "Single occurrence so far"
                        )
                        inc_entry["repetition"] = {
                            "count_since_initial": count_since,
                            "duration_minutes": round(duration_s / 60, 1),
                            "note": note,
                        }

                    latest = store.get_latest_raw_context_by_state_key(
                        inc_entry["state_key"], max_age_hours=24)
                    if latest and latest.get("raw_context"):
                        parsed_raw = latest["raw_context"]
                        if isinstance(parsed_raw, dict):
                            snap = _extract_current_snapshot(
                                parsed_raw, inc_entry["issue_type"])
                            if snap:
                                inc_entry["current_snapshot"] = snap
                except (AttributeError, KeyError, ValueError):
                    logger.warning("Failed to enrich incident %s with AI analysis",
                                   inc_entry.get("state_key", "?"), exc_info=True)

            # Strip internal sort keys before the data reaches the LLM payload.
            for inc_entry in result["incidents"]:
                inc_entry.pop("_last_seen_ts", None)
    except Exception:
        logger.debug("Failed to collect 24h incidents from SQLite", exc_info=True)

    # b) Pod restarts in last 24h from Prometheus
    try:
        ns_list = config.get_prod_namespaces()
        if ns_list and config.PROMETHEUS_URL:
            ns_regex = "|".join(ns_list)
            raw = prom_query(
                f'increase(kube_pod_container_status_restarts_total{{namespace=~"{ns_regex}"}}[24h]) > 0'
            )
            if raw:
                items = []
                for r in raw[:20]:
                    m = r["metric"]
                    items.append({
                        "namespace": m.get("namespace", "?"),
                        "pod": m.get("pod", "?"),
                        "container": m.get("container", "?"),
                        "restarts_24h": round(float(r["value"][1])),
                    })
                if items:
                    result["pod_restarts_24h"] = items
    except Exception:
        logger.debug("Failed to collect 24h pod restarts from Prometheus", exc_info=True)

    # c) OOMKill events in last 24h from Prometheus
    try:
        ns_list = config.get_prod_namespaces()
        if ns_list and config.PROMETHEUS_URL:
            ns_regex = "|".join(ns_list)
            raw = prom_query(
                f'increase(kube_pod_container_status_last_terminated_reason{{reason="OOMKilled",namespace=~"{ns_regex}"}}[24h]) > 0'
            )
            if raw:
                items = []
                for r in raw[:10]:
                    m = r["metric"]
                    items.append({
                        "namespace": m.get("namespace", "?"),
                        "pod": m.get("pod", "?"),
                        "container": m.get("container", "?"),
                        "oom_kills_24h": round(float(r["value"][1])),
                    })
                if items:
                    result["oom_kills_24h"] = items
    except Exception:
        logger.debug("Failed to collect 24h OOM kills from Prometheus", exc_info=True)

    return result


def _query_pvc_usage() -> list[dict]:
    try:
        raw = prom_query(
            '(kubelet_volume_stats_used_bytes / kubelet_volume_stats_capacity_bytes) > 0.8'
        )
        if not raw:
            return []
        items = []
        for r in raw:
            ns = r["metric"].get("namespace", "?")
            if ns in config.EXCLUDE_NAMESPACES:
                continue
            pvc = r["metric"].get("persistentvolumeclaim", "?")
            pct = round(float(r["value"][1]) * 100, 1)
            items.append({"namespace": ns, "pvc": pvc, "pct": pct})
        return items
    except Exception:
        return []


def _query_resource_pressure() -> list[dict]:
    try:
        query = (
            'sum by (namespace, pod) (container_memory_working_set_bytes{container!=""}) '
            '/ sum by (namespace, pod) (kube_pod_container_resource_limits{resource="memory"}) > 0.8'
        )
        raw = prom_query(query)
        if not raw:
            return []
        items = []
        for r in raw[:10]:
            ns = r["metric"].get("namespace", "?")
            if ns in config.EXCLUDE_NAMESPACES:
                continue
            pod = r["metric"].get("pod", "?")
            pct = round(float(r["value"][1]) * 100, 1)
            items.append({"namespace": ns, "pod": pod, "mem_pct": pct})
        return items
    except Exception:
        return []


def _collect_maintenance_events(hours: int) -> list[dict]:
    """Collect maintenance activation/deactivation events from store."""
    try:
        from src.handlers.startup import get_store
        store = get_store()
        events = store.get_maintenance_events(hours)
        result = []
        for ev in events:
            entry = {
                "event_type": ev["event_type"],
                "reason": ev["reason"],
                "source": ev["source"],
                "at": datetime.fromtimestamp(
                    ev["created_at"], tz=timezone.utc,
                ).isoformat(),
            }
            if ev.get("affected_nodes"):
                entry["affected_nodes"] = ev["affected_nodes"]
            result.append(entry)
        # Also check if maintenance is currently active
        if store.is_maintenance_active():
            window = store.get_maintenance_window()
            if window:
                result.insert(0, {
                    "event_type": "currently_active",
                    "reason": window.get("reason", ""),
                    "expires_at": datetime.fromtimestamp(
                        window["expires_at"], tz=timezone.utc,
                    ).isoformat() if window.get("expires_at") else None,
                })
        return result
    except Exception:
        logger.debug("Failed to collect maintenance events", exc_info=True)
        return []


def _query_cert_status(custom: k8s.CustomObjectsApi) -> list[dict]:
    try:
        certs = custom.list_cluster_custom_object("cert-manager.io", "v1", "certificates")
    except Exception:
        return []

    now = datetime.now(timezone.utc)
    issues = []

    for cert in certs.get("items", []):
        ns = cert["metadata"]["namespace"]
        if ns in config.EXCLUDE_NAMESPACES:
            continue
        name = cert["metadata"]["name"]
        status = cert.get("status", {})
        conditions = status.get("conditions", [])
        ready = next((c for c in conditions if c["type"] == "Ready"), None)
        not_after_str = status.get("notAfter", "")

        if ready and ready["status"] != "True":
            issues.append({
                "namespace": ns,
                "name": name,
                "status": f"NOT READY: {ready.get('reason', '?')}",
                "days_left": -1,
            })
            continue

        if not_after_str:
            try:
                not_after = datetime.fromisoformat(not_after_str.replace("Z", "+00:00"))
                days_left = (not_after - now).days
                if days_left <= 30:
                    issues.append({
                        "namespace": ns,
                        "name": name,
                        "status": f"expires in {days_left}d",
                        "days_left": days_left,
                    })
            except (ValueError, TypeError):
                logger.debug("Failed to parse cert expiry date %r for %s/%s", not_after_str, ns, name)

    issues.sort(key=lambda x: x["days_left"])
    return issues

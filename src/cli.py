"""CLI tool for managing k8s-ai-monitor from inside the container.

Usage:
    python -m src.cli <command> [options]

Commands:
    health          Show cluster health overview
    incidents       List incidents
    incident        Show/manage a specific incident
    suppressions    List active suppressions
    suppress        Create a suppression rule
    unsuppress      Delete a suppression rule
    reports         List daily reports
    report          Show a daily report
    run-report      Trigger a daily (or weekly) report now
    llm-usage       Show LLM usage stats
    llm-debug       Show LLM debug payloads (requires LLM_DEBUG=true)
    state           Show dedup state summary
    check-backups   Run backup storage verification now (S3)
    logs            Search Elasticsearch logs
    traces          Search Uptrace spans
    metrics         Query Prometheus metrics
    investigate     Multi-source investigation
    audit           Observability quality audit
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone


def _get_store():
    db_path = os.environ.get("SQLITE_PATH", "/data/k8s-ai-monitor.db")
    from src.engine.store.sqlite import SqliteStore
    return SqliteStore(db_path)


def _relative_time(ts: float) -> str:
    """Format timestamp as relative time string."""
    if not ts:
        return "-"
    delta = time.time() - ts
    if delta < 0:
        return "in the future"
    if delta < 60:
        return f"{int(delta)}s ago"
    if delta < 3600:
        return f"{int(delta / 60)}m ago"
    if delta < 86400:
        h = int(delta / 3600)
        return f"{h}h ago"
    d = int(delta / 86400)
    return f"{d}d ago"


def _format_duration(seconds: float) -> str:
    """Format seconds as human-readable duration."""
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds / 60)}m"
    if seconds < 86400:
        return f"{int(seconds / 3600)}h"
    return f"{int(seconds / 86400)}d"


def _absolute_time(ts: float) -> str:
    """Format timestamp as absolute UTC string."""
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _print_table(headers: list[str], rows: list[list[str]]):
    """Print aligned table."""
    if not rows:
        print("(no results)")
        return
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in widths]))
    for row in rows:
        print(fmt.format(*[str(c) for c in row]))


def cmd_health(args):
    """Show cluster health overview."""
    from kubernetes import client as k8s, config as k8s_config
    try:
        k8s_config.load_incluster_config()
    except Exception:
        k8s_config.load_kube_config()

    from src import config

    core = k8s.CoreV1Api()
    now = datetime.now(timezone.utc)
    ns_filter = args.ns

    # --- Nodes ---
    print("=== Nodes ===")
    try:
        nodes = core.list_node().items
        headers = ["Name", "Status", "Age", "Version"]
        rows = []
        for node in nodes:
            status = "NotReady"
            for cond in (node.status.conditions or []):
                if cond.type == "Ready" and cond.status == "True":
                    status = "Ready"
                    break
            created = node.metadata.creation_timestamp
            age = _format_duration((now - created).total_seconds()) if created else "-"
            version = node.status.node_info.kubelet_version if node.status.node_info else "-"
            rows.append([node.metadata.name, status, age, version])
        _print_table(headers, rows)
    except Exception as e:
        print(f"  Error listing nodes: {e}")
    print()

    # --- Pods with restarts (24h) ---
    print("=== Pods with Restarts (24h) ===")
    namespaces = [ns_filter] if ns_filter else config.get_namespaces()
    cutoff = now - timedelta(hours=24)
    restart_headers = ["Namespace", "Pod", "Container", "Restarts", "Last Reason"]
    restart_rows = []
    skipped_ns = []
    for ns in namespaces:
        try:
            pods = core.list_namespaced_pod(ns).items
            for pod in pods:
                for cs in (pod.status.container_statuses or []):
                    if cs.restart_count and cs.restart_count > 0:
                        recent = False
                        reason = "-"
                        if cs.last_state and cs.last_state.terminated:
                            term = cs.last_state.terminated
                            reason = term.reason or "-"
                            if term.finished_at and term.finished_at >= cutoff:
                                recent = True
                        if recent:
                            restart_rows.append([
                                ns,
                                pod.metadata.name[:50],
                                cs.name,
                                str(cs.restart_count),
                                reason,
                            ])
        except Exception as e:
            skipped_ns.append((ns, str(e)))
            continue
    restart_rows.sort(key=lambda r: int(r[3]), reverse=True)
    _print_table(restart_headers, restart_rows)
    if skipped_ns:
        print(f"  (skipped {len(skipped_ns)} namespace(s) due to errors: {', '.join(ns for ns, _ in skipped_ns)})")
    print()

    # --- Active incidents ---
    print("=== Active Incidents ===")
    try:
        store = _get_store()
        incidents = store.list_incidents(status="active")
        inc_headers = ["Severity", "Type", "State Key", "Count", "Last Seen"]
        inc_rows = []
        for inc in incidents:
            inc_rows.append([
                inc.severity,
                inc.issue_type,
                inc.state_key[:55],
                str(inc.occurrence_count),
                _relative_time(inc.last_seen_at),
            ])
        _print_table(inc_headers, inc_rows)
    except Exception as e:
        print(f"  Error loading incidents: {e}")
    print()

    # --- Backups (CloudNativePG) ---
    print("=== Backups (CloudNativePG) ===")
    from src.scanners.backup import BackupScanner
    cnpg_lines = BackupScanner()._daily_cnpg()
    print("\n".join(cnpg_lines) if cnpg_lines else "  (no CloudNativePG ScheduledBackups found)")
    print()

    # --- Warning events (last 1h) ---
    print("=== Warning Events (last 1h) ===")
    evt_counts: dict[str, int] = {}
    skipped_evt_ns = []
    for ns in namespaces:
        try:
            events = core.list_namespaced_event(
                ns, field_selector="type=Warning",
            ).items
        except Exception as e:
            skipped_evt_ns.append((ns, str(e)))
            continue
        for evt in events:
            last_ts = evt.last_timestamp or evt.event_time
            if last_ts and last_ts.tzinfo is None:
                last_ts = last_ts.replace(tzinfo=timezone.utc)
            if last_ts and last_ts >= now - timedelta(hours=1):
                key = f"{ns}/{evt.involved_object.name}: {evt.reason}"
                evt_counts[key] = evt_counts.get(key, 0) + (evt.count or 1)
    top_events = sorted(evt_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    if top_events:
        evt_headers = ["Event", "Count"]
        evt_rows = [[k[:70], str(v)] for k, v in top_events]
        _print_table(evt_headers, evt_rows)
    else:
        print("(no warning events)")
    if skipped_evt_ns:
        print(f"  (skipped {len(skipped_evt_ns)} namespace(s) due to errors: {', '.join(ns for ns, _ in skipped_evt_ns)})")
    print()

    # --- Latest daily report ---
    print("=== Latest Daily Report ===")
    try:
        store = _get_store()
        reports = store.list_daily_reports(limit=1)
        if reports:
            r = reports[0]
            age = _relative_time(r["created_at"])
            status = r.get("overall_status") or "-"
            summary = (r.get("summary") or "-")[:100]
            print(f"  Status: {status}  |  {age}  |  {summary}")
        else:
            print("  (no reports yet)")
    except Exception as e:
        print(f"  Error loading reports: {e}")


def cmd_incidents(args):
    store = _get_store()
    status = args.status if args.status != "all" else None
    incidents = store.list_incidents(status=status)
    if args.limit:
        incidents = incidents[:args.limit]
    headers = ["ID", "Status", "Severity", "Type", "State Key", "Count", "Last Seen"]
    rows = []
    for inc in incidents:
        rows.append([
            inc.id,
            inc.status,
            inc.severity,
            inc.issue_type,
            inc.state_key[:60],
            inc.occurrence_count,
            _relative_time(inc.last_seen_at),
        ])
    _print_table(headers, rows)
    print(f"\nTotal: {len(rows)} incident(s)")


def cmd_incident(args):
    store = _get_store()
    inc = store.get_incident_by_id(args.id)
    if not inc:
        print(f"Incident #{args.id} not found")
        sys.exit(1)

    if args.action == "ack":
        store.set_status(inc.id, "acknowledged")
        print(f"Incident #{inc.id} acknowledged")
        return
    if args.action == "resolve":
        store.set_status(inc.id, "resolved", clear_cooldown=True)
        store.set_resolved_by(inc.id, "operator")
        # Same as the HTTP/Slack resolve: tell the fleet board, or it keeps the
        # incident open until the periodic central sync catches it.
        from src.engine import central_push
        central_push.push_incident_status(inc, "resolved", "operator")
        print(f"Incident #{inc.id} resolved")
        return

    # Detail view
    print(f"Incident #{inc.id}")
    print(f"  State Key:    {inc.state_key}")
    print(f"  Status:       {inc.status}")
    print(f"  Severity:     {inc.severity}")
    print(f"  Type:         {inc.issue_type}")
    print(f"  Owner:        {inc.owner_ref or '-'}")
    print(f"  Fingerprint:  {inc.fingerprint or '-'}")
    print(f"  Occurrences:  {inc.occurrence_count}")
    print(f"  First Seen:   {_absolute_time(inc.first_seen_at)} ({_relative_time(inc.first_seen_at)})")
    print(f"  Last Seen:    {_absolute_time(inc.last_seen_at)} ({_relative_time(inc.last_seen_at)})")
    if inc.cooldown_until:
        remaining = inc.cooldown_until - time.time()
        if remaining > 0:
            print(f"  Cooldown:     until {_absolute_time(inc.cooldown_until)} ({_format_duration(remaining)} remaining)")
        else:
            print("  Cooldown:     expired")

    # Show recent occurrences
    occs = store.get_occurrences(inc.id)
    limit = args.occurrences if hasattr(args, "occurrences") else 5
    if occs:
        print(f"\n  Recent Occurrences (showing {min(limit, len(occs))} of {len(occs)}):")
        for o in occs[:limit]:
            ts = _absolute_time(o["seen_at"])
            rel = _relative_time(o["seen_at"])
            model = o.get("llm_model") or "-"
            cost = f"${o['cost_usd']:.4f}" if o.get("cost_usd") else "-"
            print(f"    [{o['id']}] {ts} ({rel})  model={model}  cost={cost}")
            if o.get("analysis_json"):
                try:
                    parsed = json.loads(o["analysis_json"])
                    summary = parsed.get("summary", parsed.get("root_cause", ""))
                    if summary:
                        # Truncate long summaries
                        if len(summary) > 120:
                            summary = summary[:117] + "..."
                        print(f"         {summary}")
                except (json.JSONDecodeError, TypeError):
                    pass


def cmd_suppressions(args):
    store = _get_store()
    suppressions = store.list_suppressions()
    headers = ["ID", "Type", "Namespace", "Pattern", "Reason", "Expires"]
    rows = []
    for s in suppressions:
        expires = _absolute_time(s["expires_at"]) if s.get("expires_at") else "never"
        rows.append([
            s["id"],
            s.get("resource_type") or "*",
            s.get("namespace") or "*",
            s.get("name_pattern") or "*",
            (s.get("reason") or "-")[:40],
            expires,
        ])
    _print_table(headers, rows)


def cmd_suppress(args):
    store = _get_store()
    expires_at = None
    if args.hours:
        expires_at = time.time() + args.hours * 3600
    sup_id = store.create_suppression(
        resource_type=args.type or "",
        namespace=args.ns or "",
        name_pattern=args.pattern or "",
        reason=args.reason or "",
        expires_at=expires_at,
    )
    print(f"Suppression #{sup_id} created")
    if expires_at:
        print(f"  Expires: {_absolute_time(expires_at)}")


def cmd_unsuppress(args):
    store = _get_store()
    deleted = store.delete_suppression(args.id)
    if deleted:
        print(f"Suppression #{args.id} deleted")
    else:
        print(f"Suppression #{args.id} not found")
        sys.exit(1)


def cmd_reports(args):
    store = _get_store()
    reports = store.list_daily_reports(limit=args.limit)
    headers = ["ID", "Created", "Cluster", "Status", "Model", "Cost", "Summary"]
    rows = []
    for r in reports:
        summary = (r.get("summary") or "-")[:50]
        cost = f"${r['cost_usd']:.4f}" if r.get("cost_usd") else "-"
        rows.append([
            r["id"],
            _relative_time(r["created_at"]),
            r.get("cluster") or "-",
            r.get("overall_status") or "-",
            r.get("model") or "-",
            cost,
            summary,
        ])
    _print_table(headers, rows)


def cmd_report(args):
    store = _get_store()
    report = store.get_daily_report(args.id)
    if not report:
        print(f"Report #{args.id} not found")
        sys.exit(1)

    print(f"Daily Report #{report['id']}")
    print(f"  Created:    {_absolute_time(report['created_at'])} ({_relative_time(report['created_at'])})")
    print(f"  Cluster:    {report.get('cluster') or '-'}")
    print(f"  Status:     {report.get('overall_status') or '-'}")
    print(f"  Model:      {report.get('model') or '-'}")
    cost = f"${report['cost_usd']:.4f}" if report.get("cost_usd") else "-"
    print(f"  Cost:       {cost}")
    print(f"  Tokens:     {report.get('tokens_in') or 0} in / {report.get('tokens_out') or 0} out")
    print(f"  Latency:    {report.get('latency_ms') or 0:.0f}ms")
    print(f"  Context:    {report.get('context_bytes') or 0} bytes")
    if report.get("parse_error"):
        print("  Parse Error: yes")

    if report.get("analysis"):
        analysis = report["analysis"]
        print(f"\n  Summary: {analysis.get('summary', '-')}")
        issues = analysis.get("issues", [])
        if issues:
            print(f"\n  Issues ({len(issues)}):")
            for issue in issues:
                sev = issue.get("severity", "?")
                title = issue.get("title", issue.get("description", "?"))
                print(f"    [{sev}] {title}")
        recs = analysis.get("recommendations", [])
        if recs:
            print(f"\n  Recommendations ({len(recs)}):")
            for rec in recs:
                if isinstance(rec, dict):
                    print(f"    - {rec.get('action', rec.get('description', str(rec)))}")
                else:
                    print(f"    - {rec}")
    elif report.get("analysis_raw"):
        print(f"\n  Raw Analysis:\n{report['analysis_raw'][:500]}")


def cmd_run_report(args):
    import logging
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="[%(asctime)s] %(name)s [%(levelname)-8s] %(message)s",
    )

    try:
        from kubernetes import config as k8s_config
        try:
            k8s_config.load_incluster_config()
        except k8s_config.ConfigException:
            k8s_config.load_kube_config()
    except Exception as e:
        print(f"Failed to load kubeconfig: {e}", file=sys.stderr)
        sys.exit(1)

    from src.reporter import run_daily_report, run_weekly_report
    runner = run_weekly_report if args.weekly else run_daily_report
    label = "weekly" if args.weekly else "daily"
    print(f"Running {label} report...")
    try:
        runner()
    except Exception as e:
        print(f"Report failed: {e}", file=sys.stderr)
        sys.exit(1)
    print("Done.")


def cmd_llm_usage(args):
    store = _get_store()
    summary = store.get_llm_usage_summary(args.hours)
    print(f"LLM Usage (last {args.hours}h)")
    print(f"  Total Calls:     {summary['total_calls']}")
    print(f"  Total Cost:      ${summary['total_cost_usd']:.4f}")
    print(f"  Total Tokens In: {summary['total_tokens_in']}")
    print(f"  Total Tokens Out:{summary['total_tokens_out']}")
    print(f"  Avg Tokens In:   {summary['avg_tokens_in']}")
    print(f"  Max Tokens In:   {summary['max_tokens_in']}")
    print(f"  Avg Latency:     {summary['avg_latency_ms']}ms")
    print(f"  Max Latency:     {summary['max_latency_ms']}ms")

    calls = store.get_llm_usage(args.hours)
    if calls:
        print(f"\n  Recent Calls ({len(calls)}):")
        headers = ["Time", "Type", "Model", "Tokens", "Cost", "Latency"]
        rows = []
        for c in calls[:20]:
            cost = f"${c['cost_usd']:.4f}" if c.get("cost_usd") else "-"
            latency = f"{c.get('latency_ms', 0):.0f}ms" if c.get("latency_ms") else "-"
            tokens = f"{c.get('tokens_in', 0)}/{c.get('tokens_out', 0)}"
            rows.append([
                _relative_time(c["called_at"]),
                c.get("call_type") or "-",
                c.get("model") or "-",
                tokens,
                cost,
                latency,
            ])
        _print_table(headers, rows)


def cmd_llm_debug(args):
    store = _get_store()
    if args.id:
        entry = store.get_llm_debug_detail(args.id)
        if not entry:
            print(f"LLM debug entry #{args.id} not found")
            sys.exit(1)
        print(f"LLM Debug #{entry['id']}")
        print(f"  Time:     {_absolute_time(entry['called_at'])} ({_relative_time(entry['called_at'])})")
        print(f"  Type:     {entry['call_type']}")
        print(f"  Resource: {entry.get('resource') or '-'}")
        print(f"\n{'='*60} SYSTEM PROMPT {'='*60}")
        print(entry["system_prompt"])
        print(f"\n{'='*60} USER CONTENT {'='*61}")
        print(entry["user_content"])
        print(f"\n{'='*60} RESPONSE {'='*65}")
        print(entry.get("response_text") or "(no response)")
        return

    entries = store.get_llm_debug(args.hours)
    headers = ["ID", "Time", "Type", "Resource", "Prompt", "Content", "Response", "Preview"]
    rows = []
    for e in entries:
        preview = (e.get("response_preview") or "")[:80]
        if preview and len(preview) >= 80:
            preview += "..."
        rows.append([
            e["id"],
            _relative_time(e["called_at"]),
            e["call_type"],
            (e.get("resource") or "-")[:30],
            f"{e.get('system_prompt_bytes', 0)}B",
            f"{e.get('user_content_bytes', 0)}B",
            f"{e.get('response_bytes', 0) or 0}B",
            preview,
        ])
    _print_table(headers, rows)
    if entries:
        print(f"\nTotal: {len(entries)} entries (use 'llm-debug <id>' for full payload)")


def cmd_maintenance(args):
    store = _get_store()
    if args.off:
        deleted = store.end_maintenance()
        if deleted:
            store.log_maintenance_event("deactivated", "CLI deactivation", source="cli")
            print(f"Maintenance mode ended ({deleted} window(s) removed)")
        else:
            print("No active maintenance window")
        return
    if args.hours:
        if args.hours <= 0:
            print("Error: hours must be > 0")
            sys.exit(1)
        expires_at = time.time() + args.hours * 3600
        reason = args.reason or ""
        sup_id = store.create_suppression(
            resource_type="__maintenance__",
            reason=reason,
            expires_at=expires_at,
        )
        store.log_maintenance_event("activated", reason, source="cli")
        print(f"Maintenance mode enabled (id={sup_id})")
        print(f"  Duration: {args.hours}h")
        print(f"  Expires:  {_absolute_time(expires_at)}")
        if reason:
            print(f"  Reason:   {reason}")
        return
    # Show status
    window = store.get_maintenance_window()
    if window:
        print("Maintenance mode: ACTIVE")
        print(f"  ID:      {window['id']}")
        print(f"  Reason:  {window.get('reason') or '-'}")
        print(f"  Started: {_absolute_time(window['created_at'])} ({_relative_time(window['created_at'])})")
        if window.get("expires_at"):
            remaining = window["expires_at"] - time.time()
            if remaining > 0:
                print(f"  Expires: {_absolute_time(window['expires_at'])} ({_format_duration(remaining)} remaining)")
            else:
                print(f"  Expires: {_absolute_time(window['expires_at'])} (expired)")
        else:
            print("  Expires: never")
    else:
        print("Maintenance mode: inactive")


def cmd_state(args):
    store = _get_store()
    data = store.read_all()
    seen = data.get("seen", {})
    if not seen:
        print("State is empty")
        return
    headers = ["State Key", "Count", "Status", "Severity", "Last Seen"]
    rows = []
    for key, entry in sorted(seen.items(), key=lambda x: x[1].get("ts", 0), reverse=True):
        rows.append([
            key[:60],
            entry.get("count", 0),
            entry.get("status", "-"),
            entry.get("severity", "-"),
            _relative_time(entry.get("ts", 0)),
        ])
    _print_table(headers, rows)
    print(f"\nTotal: {len(rows)} entries")






def _fmt_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f}KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f}MB"
    return f"{size_bytes / (1024 * 1024 * 1024):.2f}GB"


def cmd_logs(args):
    """Search Elasticsearch logs."""
    from src.collectors.elasticsearch import search_logs, search_error_logs

    ns = args.ns or "production"
    since = args.since

    if args.errors:
        print(f"=== Error Logs ({ns}, last {since}m) ===")
        results = search_error_logs(ns, since_minutes=since, limit=args.limit)
    else:
        print(f"=== Logs ({ns}, last {since}m) ===")
        results = search_logs(
            ns,
            pod_pattern=args.pod or "",
            query_string=args.query or "",
            since_minutes=since,
            limit=args.limit,
        )

    if results is None:
        print("Elasticsearch is not configured (ELASTICSEARCH_URL not set)")
        return
    if not results:
        print("(no matching logs)")
        return

    for entry in results:
        ts = entry.get("timestamp", "")[:19]
        pod = entry.get("pod", "")
        container = entry.get("container", "")
        msg = entry.get("message", "").rstrip()
        level = entry.get("level", "")
        level_str = f" [{level}]" if level else ""
        print(f"{ts} {pod}/{container}{level_str}: {msg}")
    print(f"\nTotal: {len(results)} log(s)")


def cmd_traces(args):
    """Search Uptrace spans."""
    from src.collectors.uptrace import search_spans, search_slow_spans, get_service_stats

    service = args.service
    since = args.since

    if args.stats:
        print(f"=== Service Stats: {service} (last {since}m) ===")
        stats = get_service_stats(service, since_minutes=since)
        if stats is None:
            print("Uptrace is not configured (UPTRACE_API_URL not set)")
            return
        print(f"  Spans:        {stats['span_count']}")
        print(f"  Errors:       {stats['error_count']} ({stats['error_rate']}%)")
        print(f"  Avg duration: {stats['avg_duration_ms']}ms")
        print(f"  P50 duration: {stats['p50_duration_ms']}ms")
        print(f"  P99 duration: {stats['p99_duration_ms']}ms")
        return

    if args.slow:
        min_dur = args.min_duration
        print(f"=== Slow Spans: {service} (last {since}m, >={min_dur}ms) ===")
        results = search_slow_spans(service, since_minutes=since,
                                    min_duration_ms=min_dur, limit=args.limit)
    elif args.errors:
        print(f"=== Error Spans: {service} (last {since}m) ===")
        results = search_spans(service, since_minutes=since,
                               limit=args.limit, status_code="error")
    else:
        print(f"=== Spans: {service} (last {since}m) ===")
        results = search_spans(service, since_minutes=since, limit=args.limit)

    if results is None:
        print("Uptrace is not configured (UPTRACE_API_URL not set)")
        return
    if not results:
        print("(no matching spans)")
        return

    headers = ["Time", "Name", "Duration", "Status", "Trace ID"]
    rows = []
    for span in results:
        rows.append([
            str(span.get("time", ""))[:19],
            span.get("name", "")[:40],
            f"{span.get('duration_ms', 0)}ms",
            span.get("status_code", "ok"),
            span.get("trace_id", "")[:16],
        ])
    _print_table(headers, rows)
    print(f"\nTotal: {len(results)} span(s)")


def cmd_metrics(args):
    """Query Prometheus metrics."""
    from src.collectors.metrics_range import prom_range_query
    from src.collectors.prometheus import prom_query as prom_instant

    since = args.since

    if args.query:
        print(f"=== Custom Query (last {since}m) ===")
        print(f"  Query: {args.query}")
        results = prom_range_query(args.query, since_minutes=since)
        if results is None:
            print("Prometheus is not configured or unreachable")
            return
        if not results:
            print("(no results)")
            return
        for r in results:
            metric = r.get("metric", {})
            label_str = ", ".join(f"{k}={v}" for k, v in metric.items() if k != "__name__")
            name = metric.get("__name__", "")
            values = r.get("values", [])
            if values:
                latest = values[-1][1]
                print(f"  {name}{{{label_str}}}: {latest} (latest of {len(values)} samples)")
        return

    # Preset battery for pod/namespace
    ns = args.ns or "production"
    pod = args.pod or ""

    print(f"=== Resource Metrics ({ns}{('/' + pod) if pod else ''}, last {since}m) ===")

    # CPU usage
    if pod:
        cpu_q = f'sum(rate(container_cpu_usage_seconds_total{{namespace="{ns}",pod=~"{pod}.*"}}[5m])) by (pod)'
    else:
        cpu_q = f'sum(rate(container_cpu_usage_seconds_total{{namespace="{ns}"}}[5m])) by (pod)'
    cpu = prom_instant(cpu_q)
    if cpu:
        print("\n  CPU Usage (cores):")
        for r in cpu[:10]:
            pod_name = r["metric"].get("pod", "?")
            val = float(r["value"][1])
            print(f"    {pod_name:50s} {val:.3f}")

    # Memory usage
    if pod:
        mem_q = f'sum(container_memory_working_set_bytes{{namespace="{ns}",pod=~"{pod}.*"}}) by (pod)'
    else:
        mem_q = f'sum(container_memory_working_set_bytes{{namespace="{ns}"}}) by (pod)'
    mem = prom_instant(mem_q)
    if mem:
        print("\n  Memory Usage:")
        for r in mem[:10]:
            pod_name = r["metric"].get("pod", "?")
            val = float(r["value"][1])
            mi = val / (1024 * 1024)
            print(f"    {pod_name:50s} {mi:.0f}Mi")

    # Restarts
    if pod:
        restart_q = f'sum(kube_pod_container_status_restarts_total{{namespace="{ns}",pod=~"{pod}.*"}}) by (pod)'
    else:
        restart_q = f'sum(kube_pod_container_status_restarts_total{{namespace="{ns}"}}) by (pod)'
    restarts = prom_instant(restart_q)
    if restarts:
        restart_list = [(r["metric"].get("pod", "?"), float(r["value"][1])) for r in restarts if float(r["value"][1]) > 0]
        if restart_list:
            restart_list.sort(key=lambda x: x[1], reverse=True)
            print("\n  Restarts:")
            for pod_name, count in restart_list[:10]:
                print(f"    {pod_name:50s} {count:.0f}")

    # HTTP request rate (if available)
    if pod:
        http_q = f'sum(rate(http_requests_total{{namespace="{ns}",pod=~"{pod}.*"}}[5m])) by (pod)'
    else:
        http_q = f'sum(rate(http_requests_total{{namespace="{ns}"}}[5m])) by (pod)'
    http_rate = prom_instant(http_q)
    if http_rate:
        print("\n  HTTP Request Rate (req/s):")
        for r in http_rate[:10]:
            pod_name = r["metric"].get("pod", "?")
            val = float(r["value"][1])
            if val > 0.001:
                print(f"    {pod_name:50s} {val:.2f}")

    if not cpu and not mem and not restarts:
        print("  (no metrics available — Prometheus may be unreachable)")


def cmd_investigate(args):
    """Multi-source investigation."""
    from kubernetes import client as k8s, config as k8s_config
    try:
        k8s_config.load_incluster_config()
    except Exception:
        k8s_config.load_kube_config()

    from src.collectors.prometheus import prom_query as prom_instant
    from src.collectors.elasticsearch import search_error_logs
    from src.collectors.uptrace import get_service_stats

    ns = args.ns or "production"
    since = args.since
    pod_filter = args.pod or ""
    context: dict = {}

    print(f"=== Investigation: {ns}{('/' + pod_filter) if pod_filter else ''} (last {since}m) ===\n")

    # --- Pod Status ---
    print("--- Pod Status ---")
    core = k8s.CoreV1Api()
    now = datetime.now(timezone.utc)
    pods: list = []
    try:
        pods = core.list_namespaced_pod(ns).items
        pod_data = []
        for pod in pods:
            if pod_filter and pod_filter not in pod.metadata.name:
                continue
            phase = pod.status.phase if pod.status else "Unknown"
            restarts = 0
            ready_count = 0
            total_count = 0
            for cs in (pod.status.container_statuses or []):
                restarts += cs.restart_count or 0
                total_count += 1
                if cs.ready:
                    ready_count += 1
            status_str = f"{phase} ({ready_count}/{total_count} ready)"
            if restarts > 0:
                status_str += f" [{restarts} restarts]"
            print(f"  {pod.metadata.name:50s} {status_str}")
            pod_data.append({
                "name": pod.metadata.name,
                "phase": phase,
                "ready": f"{ready_count}/{total_count}",
                "restarts": restarts,
            })
        context["pods"] = pod_data
    except Exception as e:
        print(f"  Error: {e}")
    print()

    # --- Node Health ---
    print("--- Node Health ---")
    try:
        from src.collectors._formatters import parse_cpu, parse_memory_mi
        nodes = core.list_node().items
        node_data: list[dict] = []
        node_alerts: list[str] = []
        versions: set[str] = set()
        young_count = 0
        metrics_api = k8s.CustomObjectsApi()
        # Fetch all node metrics in one call
        try:
            node_metrics_list = metrics_api.list_cluster_custom_object(
                "metrics.k8s.io", "v1beta1", "nodes"
            )
            node_metrics_map = {
                nm["metadata"]["name"]: nm.get("usage", {})
                for nm in node_metrics_list.get("items", [])
            }
        except Exception as e:
            print(f"  (node metrics unavailable: {e})")
            node_metrics_map = {}

        for node in nodes:
            name = node.metadata.name
            # Ready status
            ready = "NotReady"
            conditions_info: list[str] = []
            for cond in (node.status.conditions or []):
                if cond.type == "Ready":
                    ready = "Ready" if cond.status == "True" else "NotReady"
                elif cond.status == "True" and cond.type in (
                    "MemoryPressure", "DiskPressure", "PIDPressure"
                ):
                    conditions_info.append(cond.type)
            # Age
            created = node.metadata.creation_timestamp
            if created:
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                age_delta = now - created
                age_h = age_delta.total_seconds() / 3600
                if age_h < 1:
                    age_str = f"{int(age_delta.total_seconds() / 60)}m"
                elif age_h < 48:
                    mins = int((age_delta.total_seconds() % 3600) / 60)
                    age_str = f"{int(age_h)}h{mins:02d}m"
                else:
                    age_str = f"{int(age_h / 24)}d"
                if age_h < 12:
                    young_count += 1
            else:
                age_str = "?"
            # Kubelet version
            version = node.status.node_info.kubelet_version if node.status.node_info else "?"
            versions.add(version)
            # Resource usage
            alloc = node.status.allocatable or {}
            alloc_cpu_m = parse_cpu(alloc.get("cpu", ""))
            alloc_mem_mi = parse_memory_mi(alloc.get("memory", ""))
            usage = node_metrics_map.get(name, {})
            usage_cpu_m = parse_cpu(usage.get("cpu", ""))
            usage_mem_mi = parse_memory_mi(usage.get("memory", ""))
            cpu_pct_str = ""
            mem_pct_str = ""
            cpu_pct_val = None
            mem_pct_val = None
            if usage_cpu_m is not None and alloc_cpu_m:
                cpu_pct_val = usage_cpu_m / alloc_cpu_m * 100
                cpu_pct_str = f"CPU: {cpu_pct_val:.0f}%"
            if usage_mem_mi is not None and alloc_mem_mi:
                mem_pct_val = usage_mem_mi / alloc_mem_mi * 100
                mem_pct_str = f"Mem: {mem_pct_val:.0f}%"
            usage_str = "  ".join(filter(None, [cpu_pct_str, mem_pct_str]))

            line = f"  {name:40s} {ready:8s} {age_str:>7s}  {version:30s} {usage_str}"
            if conditions_info:
                line += f"  ⚠ {', '.join(conditions_info)}"
            print(line)

            node_data.append({
                "name": name, "ready": ready, "age": age_str,
                "version": version,
                "cpu_pct": round(cpu_pct_val, 1) if cpu_pct_val is not None else None,
                "mem_pct": round(mem_pct_val, 1) if mem_pct_val is not None else None,
                "conditions": conditions_info,
            })
        if young_count > 0:
            msg = f"⚠ {young_count} node(s) younger than 12h — possible node replacement/maintenance"
            print(f"  {msg}")
            node_alerts.append(msg)
        if len(versions) > 1:
            msg = f"⚠ Mixed versions: {', '.join(sorted(versions))} — rolling upgrade in progress"
            print(f"  {msg}")
            node_alerts.append(msg)
        context["nodes"] = node_data
        if node_alerts:
            context["node_alerts"] = node_alerts
    except Exception as e:
        print(f"  Error: {e}")
    print()

    # --- Warning Events ---
    print("--- Warning Events ---")
    try:
        events = core.list_namespaced_event(ns, field_selector="type=Warning").items
        evt_counts: dict[str, int] = {}
        cutoff = now - timedelta(minutes=since)
        for evt in events:
            if pod_filter and pod_filter not in (evt.involved_object.name or ""):
                continue
            last_ts = evt.last_timestamp or evt.event_time
            if last_ts and last_ts.tzinfo is None:
                last_ts = last_ts.replace(tzinfo=timezone.utc)
            if last_ts and last_ts >= cutoff:
                key = f"{evt.involved_object.name}: {evt.reason} — {evt.message or ''}"[:100]
                evt_counts[key] = evt_counts.get(key, 0) + (evt.count or 1)
        if evt_counts:
            for key, count in sorted(evt_counts.items(), key=lambda x: x[1], reverse=True)[:15]:
                print(f"  [{count:3d}x] {key}")
            context["warning_events"] = [{"event": k, "count": v} for k, v in evt_counts.items()]
        else:
            print("  (none)")
    except Exception as e:
        print(f"  Error: {e}")
    print()

    # --- Active Incidents ---
    print("--- Active Incidents ---")
    try:
        store = _get_store()
        incidents = store.list_incidents(status="active")
        ns_incidents = [i for i in incidents if ns in i.state_key]
        if pod_filter:
            ns_incidents = [i for i in ns_incidents if pod_filter in i.state_key]
        if ns_incidents:
            for inc in ns_incidents:
                print(f"  [{inc.severity}] {inc.issue_type}: {inc.state_key[:60]} ({inc.occurrence_count}x, {_relative_time(inc.last_seen_at)})")
            context["active_incidents"] = [
                {"severity": i.severity, "type": i.issue_type, "key": i.state_key,
                 "count": i.occurrence_count}
                for i in ns_incidents
            ]
        else:
            print("  (none)")
    except Exception as e:
        print(f"  Error: {e}")
    print()

    # --- Resource Metrics ---
    print("--- Resource Metrics ---")
    if pod_filter:
        cpu_q = f'sum(rate(container_cpu_usage_seconds_total{{namespace="{ns}",pod=~"{pod_filter}.*"}}[5m])) by (pod)'
        mem_q = f'sum(container_memory_working_set_bytes{{namespace="{ns}",pod=~"{pod_filter}.*"}}) by (pod)'
    else:
        cpu_q = f'topk(5, sum(rate(container_cpu_usage_seconds_total{{namespace="{ns}"}}[5m])) by (pod))'
        mem_q = f'topk(5, sum(container_memory_working_set_bytes{{namespace="{ns}"}}) by (pod))'

    cpu = prom_instant(cpu_q)
    mem = prom_instant(mem_q)
    metrics_data: list[dict] = []
    if cpu:
        for r in cpu[:5]:
            pod_name = r["metric"].get("pod", "?")
            val = float(r["value"][1])
            print(f"  CPU  {pod_name:45s} {val:.3f} cores")
            metrics_data.append({"pod": pod_name, "cpu_cores": round(val, 3)})
    if mem:
        for r in mem[:5]:
            pod_name = r["metric"].get("pod", "?")
            val = float(r["value"][1])
            mi = val / (1024 * 1024)
            print(f"  MEM  {pod_name:45s} {mi:.0f}Mi")
            for m in metrics_data:
                if m["pod"] == pod_name:
                    m["memory_mi"] = round(mi)
                    break
            else:
                metrics_data.append({"pod": pod_name, "memory_mi": round(mi)})
    if not cpu and not mem:
        print("  (Prometheus unavailable)")
    else:
        context["metrics"] = metrics_data
    print()

    # --- Resource Limits ---
    print("--- Resource Limits ---")
    try:
        from src.collectors._formatters import parse_memory_mi as _parse_mem_mi
        limits_data: list[dict] = []
        no_limit_count = 0
        for pod in pods:
            if pod_filter and pod_filter not in pod.metadata.name:
                continue
            # Skip completed pods (CronJobs)
            phase = pod.status.phase if pod.status else "Unknown"
            if phase in ("Succeeded", "Failed"):
                continue
            # Aggregate limits/requests across all containers in the pod
            pod_limit_total: float | None = None  # None = at least one container has no limit
            pod_request_total: float = 0
            any_container_unlimited = False
            for container in (pod.spec.containers or []):
                resources = container.resources or k8s.V1ResourceRequirements()
                c_limits = resources.limits or {}
                c_requests = resources.requests or {}
                mem_limit_str = c_limits.get("memory", "")
                mem_request_str = c_requests.get("memory", "")
                c_limit_mi = _parse_mem_mi(mem_limit_str) if mem_limit_str else None
                c_request_mi = _parse_mem_mi(mem_request_str) if mem_request_str else None
                if c_limit_mi is not None:
                    pod_limit_total = (pod_limit_total or 0) + c_limit_mi
                else:
                    any_container_unlimited = True
                if c_request_mi is not None:
                    pod_request_total += c_request_mi
            # If any container has no limit, treat the pod as unlimited
            if any_container_unlimited:
                pod_limit_total = None

            # Find current pod-level usage from metrics_data
            mem_usage_mi = None
            for m in metrics_data:
                if m.get("pod") == pod.metadata.name:
                    mem_usage_mi = m.get("memory_mi")
                    break

            pod_alerts: list[str] = []
            if mem_usage_mi is not None:
                if pod_limit_total is None:
                    usage_str = f"mem: {mem_usage_mi:.0f}Mi used / no limit"
                    pod_alerts.append("OOM RISK")
                elif pod_limit_total > 0:
                    pct = mem_usage_mi / pod_limit_total * 100
                    usage_str = f"mem: {mem_usage_mi:.0f}Mi / {pod_limit_total:.0f}Mi limit ({pct:.0f}%)"
                    if pct > 80:
                        pod_alerts.append("NEAR LIMIT")
                else:
                    usage_str = f"mem: {mem_usage_mi:.0f}Mi used / 0Mi limit"
                    pod_alerts.append("OOM RISK")
            else:
                if pod_limit_total is None:
                    # Count for summary, don't append per-pod entry
                    no_limit_count += 1
                    continue
                elif pod_limit_total > 0:
                    usage_str = f"mem: ? / {pod_limit_total:.0f}Mi limit"
                else:
                    continue  # no info at all, skip

            # Only show if there's something notable (has alerts or has usage)
            if pod_alerts or mem_usage_mi is not None:
                alert_str = f" ⚠ {', '.join(pod_alerts)}" if pod_alerts else ""
                print(f"  {pod.metadata.name:50s} {usage_str}{alert_str}")
                limits_data.append({
                    "pod": pod.metadata.name,
                    "mem_usage_mi": round(mem_usage_mi) if mem_usage_mi is not None else None,
                    "mem_limit_mi": round(pod_limit_total) if pod_limit_total is not None else None,
                    "mem_request_mi": round(pod_request_total) if pod_request_total else None,
                    "alerts": pod_alerts,
                })
        if no_limit_count > 0:
            print(f"  ⚠ {no_limit_count} pod(s) without memory limit (OOM RISK) — not shown individually")
            limits_data.append({
                "summary": f"{no_limit_count} pods without memory limit",
                "pod_count": no_limit_count,
                "alerts": ["OOM RISK"],
            })
        if limits_data:
            context["resource_limits"] = limits_data
        else:
            print("  (no resource data)")
    except Exception as e:
        print(f"  Error: {e}")
    print()

    # --- Ingress Traffic ---
    print("--- Ingress Traffic ---")
    ingress_q = f'sum(rate(nginx_ingress_controller_requests{{namespace="{ns}"}}[5m])) by (ingress)'
    ingress_data = prom_instant(ingress_q)
    if ingress_data:
        traffic_list: list[dict] = []
        for r in sorted(ingress_data, key=lambda x: float(x["value"][1]), reverse=True):
            ingress_name = r["metric"].get("ingress", "?")
            rps = float(r["value"][1])
            if rps < 0.001:
                continue
            print(f"  {ingress_name:50s} {rps:.2f} req/s")
            traffic_list.append({"ingress": ingress_name, "rps": round(rps, 2)})
        # Error rates per ingress
        err_q = f'sum(rate(nginx_ingress_controller_requests{{namespace="{ns}",status=~"5.."}}[5m])) by (ingress)'
        err_data = prom_instant(err_q)
        err_map: dict[str, float] = {}
        if err_data:
            for r in err_data:
                err_map[r["metric"].get("ingress", "?")] = float(r["value"][1])
        for t in traffic_list:
            err_rps = err_map.get(t["ingress"], 0)
            if err_rps > 0 and t["rps"] > 0:
                err_pct = err_rps / t["rps"] * 100
                t["error_rps"] = round(err_rps, 2)
                t["error_pct"] = round(err_pct, 1)
                print(f"    └─ 5xx: {err_rps:.2f} req/s ({err_pct:.1f}%)")
        if not traffic_list:
            print("  (no active traffic)")
        else:
            context["ingress_traffic"] = traffic_list
    elif ingress_data is None:
        print("  (Prometheus unavailable)")
    else:
        print("  (no ingress metrics)")
    print()

    # --- Error Logs (ES) ---
    print("--- Error Logs (Elasticsearch) ---")
    error_logs = search_error_logs(ns, since_minutes=since, limit=20)
    if error_logs is None:
        print("  (Elasticsearch not configured)")
    elif not error_logs:
        print("  (no error logs)")
    else:
        shown = error_logs
        if pod_filter:
            shown = [l for l in error_logs if pod_filter in l.get("pod", "")]
        for entry in shown[:10]:
            ts = entry.get("timestamp", "")[:19]
            pod_name = entry.get("pod", "")
            msg = entry.get("message", "").rstrip()[:120]
            print(f"  {ts} {pod_name}: {msg}")
        if len(shown) > 10:
            print(f"  ... and {len(shown) - 10} more")
        context["error_logs"] = [
            {"timestamp": l["timestamp"], "pod": l["pod"], "message": l["message"][:200]}
            for l in shown[:20]
        ]
    print()

    # --- Traces (Uptrace) ---
    print("--- Traces (Uptrace) ---")
    # Try to discover service names from pod names
    service_names: list[str] = []
    if pod_filter:
        service_names = [pod_filter]
    elif "pods" in context:
        seen: set[str] = set()
        for p in context["pods"]:
            # Derive service name: strip hash suffixes (deployment-hash-hash)
            parts = p["name"].rsplit("-", 2)
            if len(parts) >= 3:
                svc = parts[0]
            elif len(parts) >= 2:
                svc = parts[0]
            else:
                svc = p["name"]
            if svc not in seen:
                seen.add(svc)
                service_names.append(svc)

    trace_data: list[dict] = []
    for svc in service_names[:5]:
        stats = get_service_stats(svc, since_minutes=since)
        if stats and stats.get("span_count", 0) > 0:
            print(f"  {svc:30s} {stats['span_count']} spans, {stats['error_count']} errors ({stats['error_rate']}%), avg {stats['avg_duration_ms']}ms")
            trace_data.append({"service": svc, **stats})
    if not trace_data:
        if not service_names:
            print("  (no services found)")
        else:
            stats_check = get_service_stats(service_names[0], since_minutes=since) if service_names else None
            if stats_check is None:
                print("  (Uptrace not configured)")
            else:
                print("  (no spans found)")
    else:
        context["traces"] = trace_data
    print()

    # --- HPA Status ---
    print("--- HPA Status ---")
    try:
        autoscaling = k8s.AutoscalingV2Api()
        hpas = autoscaling.list_namespaced_horizontal_pod_autoscaler(ns).items
        hpa_data: list[dict] = []
        for hpa in hpas:
            if pod_filter and pod_filter not in hpa.metadata.name:
                continue
            current = hpa.status.current_replicas or 0
            desired = hpa.status.desired_replicas or 0
            min_r = hpa.spec.min_replicas or 0
            max_r = hpa.spec.max_replicas or 0
            print(f"  {hpa.metadata.name:40s} {current}/{desired} replicas (min={min_r}, max={max_r})")
            hpa_data.append({
                "name": hpa.metadata.name,
                "current": current, "desired": desired,
                "min": min_r, "max": max_r,
            })
        if not hpas:
            print("  (no HPAs)")
        elif hpa_data:
            context["hpa"] = hpa_data
    except Exception as e:
        print(f"  Error: {e}")
    print()

    # --- LLM Analysis ---
    if args.llm:
        if not context:
            print("No data collected for LLM analysis")
            return
        print("--- LLM Analysis ---")
        from src.engine.llm import analyze_investigation
        result = analyze_investigation(context, ns, since_minutes=since)
        if result.parsed and not result.parse_error:
            parsed = result.parsed
            print(f"\n  Summary: {parsed.get('summary', '-')}")
            print(f"  Root Cause: {parsed.get('root_cause', '-')}")
            print(f"  Confidence: {parsed.get('confidence', 0):.0%}")

            affected = parsed.get("affected_services", [])
            if affected:
                print(f"  Affected: {', '.join(affected)}")

            timeline = parsed.get("timeline", [])
            if timeline:
                print("\n  Timeline:")
                for evt in timeline[:10]:
                    print(f"    {evt.get('time', '?'):20s} {evt.get('event', '')}")

            correlations = parsed.get("correlations", [])
            if correlations:
                print("\n  Correlations:")
                for c in correlations:
                    sources = ", ".join(c.get("sources", []))
                    print(f"    [{sources}] {c.get('finding', '')}")

            actions = parsed.get("suggested_actions", [])
            if actions:
                print("\n  Actions:")
                for a in sorted(actions, key=lambda x: x.get("priority", 2)):
                    print(f"    P{a.get('priority', 2)}: {a.get('action', '')}")

            cost = f"${result.cost_usd:.4f}" if result.cost_usd else "?"
            print(f"\n  (model={result.model}, cost={cost}, latency={result.latency_ms:.0f}ms)")
        else:
            print(f"  {result.raw_text[:500]}")


def cmd_audit(args):
    """Observability quality audit."""
    from kubernetes import client as k8s, config as k8s_config
    try:
        k8s_config.load_incluster_config()
    except Exception:
        k8s_config.load_kube_config()

    from src.collectors.elasticsearch import search_logs
    from src.collectors.uptrace import get_service_stats
    from src.collectors.prometheus import prom_query as prom_instant

    ns = args.ns or "production"
    pod_filter = args.pod or ""

    print(f"=== Observability Audit: {ns} ===\n")

    apps = k8s.AppsV1Api()

    # Discover deployments
    try:
        deployments = apps.list_namespaced_deployment(ns).items
    except Exception as e:
        print(f"Error listing deployments: {e}")
        return

    if pod_filter:
        deployments = [d for d in deployments if pod_filter in d.metadata.name]

    total_critical = 0
    total_warning = 0
    total_ok = 0

    for deploy in deployments:
        name = deploy.metadata.name
        replicas = deploy.spec.replicas or 0
        print(f"--- {name} (Deployment, {replicas} replicas) ---")

        # --- Probes ---
        probe_issues: list[str] = []
        probe_ok: list[str] = []
        for container in (deploy.spec.template.spec.containers or []):
            if container.readiness_probe:
                probe_ok.append("readiness")
            else:
                probe_issues.append("NO readiness")
            if container.liveness_probe:
                probe_ok.append("liveness")
            else:
                probe_issues.append("NO liveness")
            if container.startup_probe:
                probe_ok.append("startup")
            # startup is optional, don't flag missing

        ok_str = "  ".join(f"\u2713 {p}" for p in probe_ok)
        issue_str = "  ".join(f"\u2717 {p}" for p in probe_issues)
        probe_line = f"  Probes:    {ok_str}"
        if issue_str:
            probe_line += f"  {issue_str}"
        print(probe_line)

        if probe_issues:
            total_critical += len([p for p in probe_issues if "readiness" in p or "liveness" in p])

        # --- Logging (ES sample) ---
        logs = search_logs(ns, pod_pattern=f"{name}*", since_minutes=1440, limit=200)
        if logs is None:
            print("  Logging:   - (Elasticsearch not configured)")
        elif not logs:
            print("  Logging:   \u26a0 no logs found in last 24h")
            total_warning += 1
        else:
            error_count = sum(
                1 for l in logs
                if l.get("stream") == "stderr"
                or (l.get("level") or "").upper() in ("ERROR", "FATAL", "CRITICAL")
            )
            total_logs = len(logs)
            error_pct = (error_count / total_logs * 100) if total_logs else 0
            if error_pct > 20:
                print(f"  Logging:   \u26a0 {error_pct:.0f}% error-level logs ({error_count}/{total_logs} sampled)")
                total_warning += 1
            elif error_pct > 0:
                print(f"  Logging:   \u2713 {total_logs} logs sampled, {error_pct:.0f}% errors")
                total_ok += 1
            else:
                print(f"  Logging:   \u2713 {total_logs} logs sampled, no errors")
                total_ok += 1

        # --- Traces (Uptrace) ---
        stats = get_service_stats(name, since_minutes=1440)
        if stats is None:
            print("  Traces:    - (Uptrace not configured)")
        elif stats.get("span_count", 0) == 0:
            print("  Traces:    \u2717 NO spans in last 24h")
            total_critical += 1
        else:
            span_count = stats["span_count"]
            error_rate = stats["error_rate"]
            avg_dur = stats["avg_duration_ms"]
            trace_line = f"  Traces:    \u2713 {span_count} spans (avg {avg_dur}ms)"
            if error_rate > 5:
                trace_line += f"  \u26a0 {error_rate}% error rate"
                total_warning += 1
            else:
                total_ok += 1
            print(trace_line)

        # --- Metrics (ServiceMonitor / scrape target) ---
        scrape_q = f'up{{namespace="{ns}",pod=~"{name}.*"}}'
        scrape = prom_instant(scrape_q)
        if scrape:
            print("  Metrics:   \u2713 Prometheus scrape target active")
            total_ok += 1
        else:
            # Check for ServiceMonitor CRD
            try:
                custom = k8s.CustomObjectsApi()
                sms = custom.list_namespaced_custom_object(
                    "monitoring.coreos.com", "v1", ns, "servicemonitors"
                )
                sm_names = [sm["metadata"]["name"] for sm in sms.get("items", [])]
                matching = [s for s in sm_names if name in s]
                if matching:
                    print(f"  Metrics:   \u2713 ServiceMonitor found ({', '.join(matching)})")
                    total_ok += 1
                else:
                    print("  Metrics:   \u2717 no ServiceMonitor, no Prometheus scrape")
                    total_warning += 1
            except Exception:
                # CRD may not be installed
                if scrape is None:
                    print("  Metrics:   - (Prometheus unavailable)")
                else:
                    print("  Metrics:   \u2717 no Prometheus scrape target")
                    total_warning += 1

        print()

    total_services = len(deployments)
    print(f"SUMMARY: {total_critical} critical, {total_warning} warnings, {total_ok} ok across {total_services} services")


def main():
    parser = argparse.ArgumentParser(
        prog="k8s-ai-monitor",
        description="k8s-ai-monitor CLI — manage incidents, suppressions, reports",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # health
    p = sub.add_parser("health", help="Show cluster health overview")
    p.add_argument("--ns", default="", help="Filter to specific namespace")
    p.set_defaults(func=cmd_health)

    # incidents
    p = sub.add_parser("incidents", help="List incidents")
    p.add_argument("--status", default="active", choices=["active", "resolved", "acknowledged", "all"])
    p.add_argument("--limit", type=int, default=None)
    p.set_defaults(func=cmd_incidents)

    # incident <id> [ack|resolve]
    p = sub.add_parser("incident", help="Show or manage a specific incident")
    p.add_argument("id", type=int, help="Incident ID")
    p.add_argument("action", nargs="?", choices=["ack", "resolve"], help="Action to perform")
    p.add_argument("--occurrences", type=int, default=5, help="Number of occurrences to show")
    p.set_defaults(func=cmd_incident)

    # suppressions
    p = sub.add_parser("suppressions", help="List active suppressions")
    p.set_defaults(func=cmd_suppressions)

    # suppress
    p = sub.add_parser("suppress", help="Create a suppression rule")
    p.add_argument("--type", dest="type", default="", help="Issue type to suppress (e.g. certificate)")
    p.add_argument("--ns", default="", help="Namespace to suppress")
    p.add_argument("--pattern", default="", help="Name pattern (glob, e.g. '*backend*')")
    p.add_argument("--reason", default="", help="Reason for suppression")
    p.add_argument("--hours", type=float, default=None, help="Expiry in hours (default: never)")
    p.set_defaults(func=cmd_suppress)

    # unsuppress
    p = sub.add_parser("unsuppress", help="Delete a suppression rule")
    p.add_argument("id", type=int, help="Suppression ID")
    p.set_defaults(func=cmd_unsuppress)

    # reports
    p = sub.add_parser("reports", help="List daily reports")
    p.add_argument("--limit", type=int, default=10)
    p.set_defaults(func=cmd_reports)

    # report <id>
    p = sub.add_parser("report", help="Show a daily report")
    p.add_argument("id", type=int, help="Report ID")
    p.set_defaults(func=cmd_report)

    # run-report
    p = sub.add_parser("run-report", help="Trigger a daily (or weekly) report now")
    p.add_argument("--weekly", action="store_true", help="Run the weekly report instead of the daily one")
    p.set_defaults(func=cmd_run_report)

    # llm-usage
    p = sub.add_parser("llm-usage", help="Show LLM usage statistics")
    p.add_argument("--hours", type=int, default=24)
    p.set_defaults(func=cmd_llm_usage)

    # llm-debug
    p = sub.add_parser("llm-debug", help="Show LLM debug payloads (requires LLM_DEBUG=true)")
    p.add_argument("id", nargs="?", type=int, default=None, help="Entry ID for full payload")
    p.add_argument("--hours", type=int, default=24)
    p.set_defaults(func=cmd_llm_debug)

    # maintenance
    p = sub.add_parser("maintenance", help="Show/manage maintenance mode")
    p.add_argument("--hours", type=float, default=None, help="Enable maintenance for N hours")
    p.add_argument("--reason", default="", help="Reason for maintenance")
    p.add_argument("--off", action="store_true", help="End maintenance mode")
    p.set_defaults(func=cmd_maintenance)

    # state
    p = sub.add_parser("state", help="Show dedup state summary")
    p.set_defaults(func=cmd_state)


    # logs
    p = sub.add_parser("logs", help="Search Elasticsearch logs")
    p.add_argument("--ns", default="", help="Namespace (default: production)")
    p.add_argument("--pod", default="", help="Pod name pattern (glob, e.g. '*backend*')")
    p.add_argument("--query", default="", help="Query string (e.g. 'timeout OR 503')")
    p.add_argument("--errors", action="store_true", help="Show only error logs")
    p.add_argument("--since", type=int, default=30, help="Look back minutes (default: 30)")
    p.add_argument("--limit", type=int, default=100, help="Max results (default: 100)")
    p.set_defaults(func=cmd_logs)

    # traces
    p = sub.add_parser("traces", help="Search Uptrace spans")
    p.add_argument("--service", required=True, help="Service name (OTel service.name)")
    p.add_argument("--errors", action="store_true", help="Show only error spans")
    p.add_argument("--slow", action="store_true", help="Show only slow spans")
    p.add_argument("--stats", action="store_true", help="Show aggregated service stats")
    p.add_argument("--min-duration", type=int, default=1000, help="Min duration for --slow (ms, default: 1000)")
    p.add_argument("--since", type=int, default=30, help="Look back minutes (default: 30)")
    p.add_argument("--limit", type=int, default=50, help="Max results (default: 50)")
    p.set_defaults(func=cmd_traces)

    # metrics
    p = sub.add_parser("metrics", help="Query Prometheus metrics")
    p.add_argument("--ns", default="", help="Namespace (default: production)")
    p.add_argument("--pod", default="", help="Pod name filter")
    p.add_argument("--query", default="", help="Custom PromQL query")
    p.add_argument("--since", type=int, default=30, help="Look back minutes (default: 30)")
    p.set_defaults(func=cmd_metrics)

    # investigate
    p = sub.add_parser("investigate", help="Multi-source investigation")
    p.add_argument("--ns", default="", help="Namespace (default: production)")
    p.add_argument("--pod", default="", help="Pod name filter")
    p.add_argument("--since", type=int, default=30, help="Look back minutes (default: 30)")
    p.add_argument("--llm", action="store_true", help="Run LLM analysis on collected data")
    p.set_defaults(func=cmd_investigate)

    # audit
    p = sub.add_parser("audit", help="Observability quality audit")
    p.add_argument("--ns", default="", help="Namespace (default: production)")
    p.add_argument("--pod", default="", help="Filter to specific deployment/pod name")
    p.set_defaults(func=cmd_audit)


    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()

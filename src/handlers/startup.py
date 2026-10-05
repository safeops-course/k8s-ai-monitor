"""Startup, cleanup, HTTP server, scanner loops — extracted from main.py."""
import asyncio
import json
import logging
import os
import time

import kopf
import requests
from aiohttp import web

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config

from src import config
from src.engine.notifier import post_maintenance_notice
from src.engine.store.sqlite import SqliteStore
from src.engine.pipeline import process_scan_results
from src.scanners import get_enabled_scanners, ALL_SCANNERS
from src.collectors import Collector
from src.collectors.node import get_node_metrics_summary
from src.collectors.app_metrics import get_app_metrics_summary
from src.reporter import run_daily_report, run_weekly_report
from src.engine.llm import _get_client, _get_model

logger = logging.getLogger(__name__)


def _parse_id(request, key="id") -> int | None:
    try:
        return int(request.match_info[key])
    except (ValueError, KeyError):
        return None


def _parse_int_param(request, key: str, default: int) -> int | None:
    raw = request.query.get(key, str(default))
    try:
        val = int(raw)
        return val if val > 0 else None
    except (ValueError, TypeError):
        return None

_HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))

# GKE node maintenance taints that indicate planned infrastructure work
_GKE_MAINTENANCE_TAINTS = {
    "cloud.google.com/impending-node-termination",
}

# Global store instance
_store = None


def get_store() -> SqliteStore:
    global _store
    if _store is None:
        _store = SqliteStore()
    return _store


def _check_auth(request) -> web.Response | None:
    """Fail closed: without INTERNAL_TOKEN the HTTP API is locked (401), not open.

    Before, an empty token meant no check at all - the whole management surface,
    including side effects such as POST /report (an LLM call), was open to anyone
    who could reach the pod.
    """
    if not config.INTERNAL_TOKEN:
        return web.Response(text="HTTP API disabled: set INTERNAL_TOKEN", status=401)
    token = request.headers.get("X-Internal-Token", "")
    if token != config.INTERNAL_TOKEN:
        return web.Response(text="Forbidden", status=403)
    return None


async def _handle_healthz(request):
    """Liveness: unhealthy (503) when the SQLite store cannot be reached.

    A store that wedges - "unable to open database file" on a stale volume, a disk
    that filled up or went read-only - does not recover by itself; a new process
    does. Failing /healthz lets the kubelet restart the pod.
    """
    try:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, lambda: get_store().ping())
    except Exception as e:
        logger.warning("healthz: store ping failed: %s", e)
        return web.Response(text="store unhealthy", status=503)
    return web.Response(text="ok")


@web.middleware
async def _auth_middleware(request, handler):
    """INTERNAL_TOKEN on every route except /healthz - one place, so no route is missed.

    Before, each handler called _check_auth itself, and eleven of them did not
    (reports, certs, state, incidents, LLM usage).
    """
    if request.path == "/healthz":
        return await handler(request)
    err = _check_auth(request)
    if err:
        return err
    return await handler(request)


async def _handle_report(request):
    loop = asyncio.get_running_loop()
    logger.info("Manual daily report triggered via HTTP")
    try:
        await loop.run_in_executor(None, run_daily_report)
        return web.Response(text="Report sent")
    except Exception as e:
        logger.exception("Manual report failed")
        return web.Response(text=f"Failed: {e}", status=500)


async def _handle_state(request):
    store = get_store()
    loop = asyncio.get_running_loop()
    data = await loop.run_in_executor(None, store.read_all)
    seen = data.get("seen", {})
    if not seen:
        return web.Response(text="State is empty")
    lines = []
    now = time.time()
    for key, entry in sorted(seen.items()):
        age_min = (now - entry.get("ts", 0)) / 60
        count = entry.get("count", 0)
        lines.append(f"  {key}: count={count}, age={age_min:.0f}m")
    return web.Response(text=f"State entries ({len(seen)}):\n" + "\n".join(lines))


async def _handle_state_clear(request):
    return web.Response(text="State clear not supported (use CLI to manage incidents)", status=501)


async def _handle_certs(request):
    from src.scanners.certificate import CertificateScanner
    loop = asyncio.get_running_loop()
    logger.info("Certificate scan triggered via HTTP")
    try:
        scanner = CertificateScanner()
        results = await loop.run_in_executor(None, scanner.scan)
        store = get_store()
        collector = Collector()
        await loop.run_in_executor(
            None, process_scan_results, results, store,
            collector.collect_pod_context_with_diagnostics,
            get_node_metrics_summary,
            get_app_metrics_summary,
        )
        return web.Response(text=f"Certificate scan completed: {len(results)} issues")
    except Exception as e:
        logger.exception("Certificate scan failed")
        return web.Response(text=f"Failed: {e}", status=500)


async def _handle_incidents_list(request):
    store = get_store()
    loop = asyncio.get_running_loop()
    status_filter = request.query.get("status", "active")
    if status_filter == "all":
        status_filter = None
    incidents = await loop.run_in_executor(None, store.list_incidents, status_filter)
    data = []
    for inc in incidents:
        data.append({
            "id": inc.id,
            "state_key": inc.state_key,
            "issue_type": inc.issue_type,
            "severity": inc.severity,
            "owner_ref": inc.owner_ref,
            "occurrence_count": inc.occurrence_count,
            "first_seen_at": inc.first_seen_at,
            "last_seen_at": inc.last_seen_at,
            "status": inc.status,
        })
    return web.json_response(data)


async def _handle_incident_detail(request):
    store = get_store()
    incident_id = _parse_id(request)
    if incident_id is None:
        return web.Response(text="Invalid ID", status=400)
    loop = asyncio.get_running_loop()
    inc = await loop.run_in_executor(None, store.get_incident_by_id, incident_id)
    if not inc:
        return web.Response(text="Not found", status=404)
    occs = await loop.run_in_executor(None, store.get_occurrences, incident_id)
    # Enrich occurrences with parsed analysis_json
    occ_data = []
    for o in occs:
        entry = {
            "id": o["id"],
            "seen_at": o["seen_at"],
            "context_hash": o["context_hash"],
            "llm_model": o.get("llm_model"),
            "tokens_in": o.get("tokens_in"),
            "tokens_out": o.get("tokens_out"),
            "cost_usd": o.get("cost_usd"),
            "analysis_error": bool(o.get("analysis_error")),
        }
        if o.get("analysis_json"):
            try:
                entry["analysis"] = json.loads(o["analysis_json"])
            except (json.JSONDecodeError, TypeError):
                entry["analysis"] = o.get("analysis")
        else:
            entry["analysis"] = o.get("analysis")
        occ_data.append(entry)
    return web.json_response({
        "id": inc.id,
        "state_key": inc.state_key,
        "fingerprint": inc.fingerprint,
        "issue_type": inc.issue_type,
        "severity": inc.severity,
        "owner_ref": inc.owner_ref,
        "occurrence_count": inc.occurrence_count,
        "first_seen_at": inc.first_seen_at,
        "last_seen_at": inc.last_seen_at,
        "status": inc.status,
        "cooldown_until": inc.cooldown_until,
        "occurrences": occ_data,
    })


async def _handle_llm_usage(request):
    store = get_store()
    hours = _parse_int_param(request, "hours", 24)
    if hours is None:
        return web.Response(text="Invalid 'hours' parameter", status=400)
    loop = asyncio.get_running_loop()
    calls = await loop.run_in_executor(None, store.get_llm_usage, hours)
    summary = await loop.run_in_executor(None, store.get_llm_usage_summary, hours)
    return web.json_response({"calls": calls, "summary": summary})


async def _handle_llm_debug_list(request):
    store = get_store()
    hours = _parse_int_param(request, "hours", 24)
    if hours is None:
        return web.Response(text="Invalid 'hours' parameter", status=400)
    loop = asyncio.get_running_loop()
    entries = await loop.run_in_executor(None, store.get_llm_debug, hours)
    return web.json_response(entries)


async def _handle_llm_debug_detail(request):
    store = get_store()
    debug_id = _parse_id(request)
    if debug_id is None:
        return web.Response(text="Invalid ID", status=400)
    loop = asyncio.get_running_loop()
    entry = await loop.run_in_executor(None, store.get_llm_debug_detail, debug_id)
    if not entry:
        return web.Response(text="Not found", status=404)
    return web.json_response(entry)


async def _handle_reports_list(request):
    store = get_store()
    limit = _parse_int_param(request, "limit", 30)
    if limit is None:
        return web.Response(text="Invalid 'limit' parameter", status=400)
    loop = asyncio.get_running_loop()
    reports = await loop.run_in_executor(None, store.list_daily_reports, limit)
    return web.json_response(reports)


async def _handle_report_detail(request):
    store = get_store()
    report_id = _parse_id(request)
    if report_id is None:
        return web.Response(text="Invalid ID", status=400)
    loop = asyncio.get_running_loop()
    report = await loop.run_in_executor(None, store.get_daily_report, report_id)
    if not report:
        return web.Response(text="Not found", status=404)
    return web.json_response(report)


async def _handle_incident_ack(request):
    store = get_store()
    incident_id = _parse_id(request)
    if incident_id is None:
        return web.Response(text="Invalid ID", status=400)
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, store.set_status, incident_id, "acknowledged")
    logger.info("Incident #%d acknowledged via HTTP", incident_id)
    return web.Response(text="Acknowledged")


async def _handle_incident_resolve(request):
    store = get_store()
    incident_id = _parse_id(request)
    if incident_id is None:
        return web.Response(text="Invalid ID", status=400)
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, store.set_status, incident_id, "resolved")
    logger.info("Incident #%d resolved via HTTP", incident_id)
    return web.Response(text="Resolved")


async def _handle_maintenance_get(request):
    store = get_store()
    loop = asyncio.get_running_loop()
    window = await loop.run_in_executor(None, store.get_maintenance_window)
    if window:
        return web.json_response({
            "active": True,
            "id": window["id"],
            "reason": window.get("reason") or "",
            "expires_at": window.get("expires_at"),
            "created_at": window["created_at"],
        })
    return web.json_response({"active": False})


async def _handle_maintenance_create(request):
    store = get_store()
    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError):
        return web.Response(text="Invalid JSON", status=400)
    except Exception:
        logger.exception("Unexpected error parsing request body")
        return web.Response(text="Internal server error", status=500)
    hours = body.get("hours")
    if hours is None:
        return web.Response(text="'hours' is required", status=400)
    try:
        hours = float(hours)
        if hours <= 0:
            raise ValueError
    except (ValueError, TypeError):
        return web.Response(text="Invalid 'hours' value", status=400)
    expires_at = time.time() + hours * 3600
    reason = body.get("reason", "")
    loop = asyncio.get_running_loop()
    sup_id = await loop.run_in_executor(
        None, lambda: store.create_suppression(
            resource_type="__maintenance__",
            reason=reason,
            expires_at=expires_at,
        )
    )
    await loop.run_in_executor(
        None, lambda: store.log_maintenance_event("activated", reason, source="manual")
    )
    logger.info("Maintenance mode enabled for %.1fh (reason: %s, id=%d)", hours, reason, sup_id)
    return web.json_response({"id": sup_id, "expires_at": expires_at}, status=201)


async def _handle_maintenance_delete(request):
    store = get_store()
    loop = asyncio.get_running_loop()
    deleted = await loop.run_in_executor(None, store.end_maintenance)
    if not deleted:
        return web.json_response({"message": "No active maintenance window"}, status=404)
    await loop.run_in_executor(
        None, lambda: store.log_maintenance_event("deactivated", "Manual deactivation via HTTP", source="manual")
    )
    logger.info("Maintenance mode ended (%d window(s) removed)", deleted)
    return web.json_response({"message": f"Maintenance ended ({deleted} window(s) removed)"})


async def _handle_suppressions_list(request):
    store = get_store()
    loop = asyncio.get_running_loop()
    suppressions = await loop.run_in_executor(None, store.list_suppressions)
    return web.json_response(suppressions)


async def _handle_suppression_create(request):
    store = get_store()
    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError):
        return web.Response(text="Invalid JSON", status=400)
    except Exception:
        logger.exception("Unexpected error parsing request body")
        return web.Response(text="Internal server error", status=500)
    expires_at = None
    expires_hours = body.get("expires_hours")
    if expires_hours is not None:
        try:
            expires_at = time.time() + float(expires_hours) * 3600
        except (ValueError, TypeError):
            return web.Response(text="Invalid expires_hours", status=400)
    loop = asyncio.get_running_loop()
    sup_id = await loop.run_in_executor(
        None, lambda: store.create_suppression(
            resource_type=body.get("resource_type", ""),
            namespace=body.get("namespace", ""),
            name_pattern=body.get("name_pattern", ""),
            reason=body.get("reason", ""),
            expires_at=expires_at,
        )
    )
    logger.info("Suppression #%d created via HTTP", sup_id)
    return web.json_response({"id": sup_id}, status=201)


async def _handle_suppression_delete(request):
    store = get_store()
    sup_id = _parse_id(request)
    if sup_id is None:
        return web.Response(text="Invalid ID", status=400)
    loop = asyncio.get_running_loop()
    deleted = await loop.run_in_executor(None, store.delete_suppression, sup_id)
    if not deleted:
        return web.Response(text="Not found", status=404)
    logger.info("Suppression #%d deleted via HTTP", sup_id)
    return web.Response(text="Deleted")


def _build_app() -> web.Application:
    """The HTTP API: every route behind _auth_middleware except /healthz."""
    app = web.Application(middlewares=[_auth_middleware])
    app.router.add_get("/healthz", _handle_healthz)
    app.router.add_get("/report", _handle_report)
    app.router.add_post("/report", _handle_report)
    app.router.add_get("/state", _handle_state)
    app.router.add_post("/state/clear", _handle_state_clear)
    app.router.add_get("/certs", _handle_certs)
    app.router.add_get("/llm-usage", _handle_llm_usage)
    app.router.add_get("/llm-debug", _handle_llm_debug_list)
    app.router.add_get("/llm-debug/{id}", _handle_llm_debug_detail)
    app.router.add_get("/incidents", _handle_incidents_list)
    app.router.add_get("/incidents/{id}", _handle_incident_detail)
    app.router.add_post("/incidents/{id}/ack", _handle_incident_ack)
    app.router.add_post("/incidents/{id}/resolve", _handle_incident_resolve)
    app.router.add_get("/reports", _handle_reports_list)
    app.router.add_get("/reports/{id}", _handle_report_detail)
    app.router.add_get("/maintenance", _handle_maintenance_get)
    app.router.add_post("/maintenance", _handle_maintenance_create)
    app.router.add_delete("/maintenance", _handle_maintenance_delete)
    app.router.add_get("/suppressions", _handle_suppressions_list)
    app.router.add_post("/suppressions", _handle_suppression_create)
    app.router.add_delete("/suppressions/{id}", _handle_suppression_delete)
    return app


async def _start_http_server():
    if not config.INTERNAL_TOKEN:
        logger.error("HTTP API is locked: INTERNAL_TOKEN is not set - every route except /healthz returns 401")
    runner = web.AppRunner(_build_app())
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", _HTTP_PORT)
    await site.start()
    endpoints = "/healthz, /report, /state, /certs, /llm-usage, /llm-debug, /incidents, /reports, /maintenance, /suppressions"
    logger.info("HTTP server listening on :%d (endpoints: %s)", _HTTP_PORT, endpoints)


# Scanner name → state_key prefixes used in ScanResults.
# Scanners without a fixed prefix (pod, reconcile) are excluded —
# their incidents are tied to generic resource types like Deployment:.
_SCANNER_STATE_KEY_PREFIXES: dict[str, list[str]] = {
    "certificate": ["Certificate:"],
    "pvc": ["PVC:"],
    "endpoint": ["Endpoint:", "EndpointBatch:"],
    "backup": ["Backup:"],
    "critical_endpoint": ["CriticalEndpoint:"],
}


def _resolve_disabled_scanner_incidents(store: SqliteStore, enabled: list) -> None:
    """Auto-resolve active incidents belonging to disabled scanners.

    When a scanner is disabled, it no longer runs and cannot emit
    auto_resolve=True results.  This leaves stale active incidents forever.
    """
    enabled_names = {s.name for s in enabled}
    disabled = [s for s in ALL_SCANNERS if s.name not in enabled_names]
    if not disabled:
        return

    for scanner in disabled:
        prefixes = _SCANNER_STATE_KEY_PREFIXES.get(scanner.name)
        if not prefixes:
            continue
        incidents = store.get_active_incidents_by_prefix(prefixes)
        for inc in incidents:
            store.set_status(inc.id, "resolved")
            logger.info("Auto-resolved stale incident #%d (%s) — scanner '%s' is disabled",
                        inc.id, inc.state_key, scanner.name)


async def _scanner_loop(scanner, store):
    """Generic scanner loop."""
    delay = scanner.startup_delay if scanner.startup_delay else scanner.interval_seconds
    await asyncio.sleep(delay)
    collector = Collector()
    while True:
        try:
            loop = asyncio.get_running_loop()
            results = await asyncio.wait_for(
                loop.run_in_executor(None, scanner.scan),
                timeout=300,
            )
            if results:
                await asyncio.wait_for(
                    loop.run_in_executor(
                        None, process_scan_results, results, store,
                        collector.collect_pod_context_with_diagnostics,
                        get_node_metrics_summary,
                        get_app_metrics_summary,
                    ),
                    timeout=300,
                )
            await loop.run_in_executor(None, store.cleanup)
        except asyncio.TimeoutError:
            logger.error("%s scanner timed out", scanner.name)
        except Exception:
            logger.exception("%s scanner error", scanner.name)
        await asyncio.sleep(scanner.interval_seconds)


def _check_node_maintenance(store: SqliteStore) -> None:
    """Check nodes for GKE maintenance taints and activate/deactivate maintenance mode."""
    try:
        core = k8s_client.CoreV1Api()
        nodes = core.list_node()
    except Exception:
        logger.warning("Maintenance detection: failed to list nodes", exc_info=True)
        return

    affected = 0
    affected_nodes: list[str] = []
    for node in nodes.items:
        spec = node.spec
        taints = (spec.taints or []) if spec else []
        taint_keys = {t.key for t in taints}
        has_maintenance_taint = bool(taint_keys & _GKE_MAINTENANCE_TAINTS)

        # Also count cordoned + NotReady nodes
        is_cordoned = bool(spec.unschedulable) if spec else False
        is_not_ready = False
        for cond in ((node.status.conditions or []) if node.status else []):
            if cond.type == "Ready":
                is_not_ready = cond.status != "True"
                break

        if has_maintenance_taint or (is_cordoned and is_not_ready):
            affected += 1
            affected_nodes.append(node.metadata.name)

    maintenance_window = store.get_maintenance_window()

    if affected >= config.AUTO_MAINTENANCE_NODE_THRESHOLD:
        reason = f"Auto-detected: {affected} nodes under maintenance ({', '.join(affected_nodes[:5])})"
        sup_id = store.activate_auto_maintenance(reason, config.AUTO_MAINTENANCE_DURATION_HOURS)
        if sup_id is not None:
            logger.info("Auto-maintenance activated: %s (id=%d)", reason, sup_id)
            store.log_maintenance_event(
                "activated", reason, source="auto",
                affected_nodes=affected_nodes[:10],
            )
            post_maintenance_notice(
                activated=True, reason=reason,
                duration_hours=config.AUTO_MAINTENANCE_DURATION_HOURS,
            )
    elif affected == 0 and maintenance_window:
        # Only auto-deactivate if it was auto-activated (name_pattern starts with "auto:")
        name_pattern = maintenance_window.get("name_pattern", "")
        if name_pattern.startswith("auto:"):
            store.end_maintenance()
            reason = "Auto-detected: all nodes healthy, maintenance complete"
            logger.info("Auto-maintenance deactivated: %s", reason)
            store.log_maintenance_event("deactivated", reason, source="auto")
            post_maintenance_notice(activated=False, reason=reason)


async def _maintenance_detection_loop() -> None:
    """Periodically check for GKE node maintenance."""
    await asyncio.sleep(60)  # startup grace
    store = get_store()
    while True:
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, _check_node_maintenance, store)
        except Exception:
            logger.exception("Maintenance detection loop error")
        await asyncio.sleep(config.AUTO_MAINTENANCE_CHECK_INTERVAL)


async def _daily_scheduler():
    from datetime import datetime, timedelta, timezone
    from zoneinfo import ZoneInfo

    tz = ZoneInfo(config.REPORT_TIMEZONE)

    while True:
        now_utc = datetime.now(timezone.utc)
        now_local = now_utc.astimezone(tz)
        target_local = now_local.replace(
            hour=config.DAILY_REPORT_HOUR, minute=0, second=0, microsecond=0,
        )

        # Catch-up: if today's scheduled time has passed, check if we missed it
        should_catch_up = False
        if target_local <= now_local:
            try:
                store = get_store()
                reports = store.list_daily_reports(limit=1, report_type="daily")
                if reports:
                    last_at = datetime.fromtimestamp(
                        reports[0]["created_at"], tz=timezone.utc,
                    ).astimezone(tz)
                    if last_at < target_local:
                        should_catch_up = True
                else:
                    should_catch_up = True  # no reports ever — run now
            except Exception:
                logger.debug("Failed to check last daily report for catch-up", exc_info=True)

        if should_catch_up:
            logger.info("Daily report catch-up: scheduled time %s already passed, running now",
                        target_local.strftime("%Y-%m-%d %H:%M %Z"))
            try:
                loop = asyncio.get_running_loop()
                await asyncio.wait_for(
                    loop.run_in_executor(None, run_daily_report),
                    timeout=300,
                )
            except asyncio.TimeoutError:
                logger.error("Daily report (catch-up) timed out")
            except Exception:
                logger.exception("Daily report (catch-up) error")
            # After catch-up, re-enter loop to compute tomorrow's target
            await asyncio.sleep(60)  # brief pause before re-checking
            continue

        # Schedule for next occurrence
        if target_local <= now_local:
            target_local += timedelta(days=1)

        target_utc = target_local.astimezone(timezone.utc)
        wait_seconds = (target_utc - now_utc).total_seconds()
        logger.info("Next daily report in %.0f seconds (at %s %s)",
                     wait_seconds, target_local.strftime("%Y-%m-%d %H:%M"), config.REPORT_TIMEZONE)
        await asyncio.sleep(wait_seconds)
        try:
            loop = asyncio.get_running_loop()
            await asyncio.wait_for(
                loop.run_in_executor(None, run_daily_report),
                timeout=300,
            )
        except asyncio.TimeoutError:
            logger.error("Daily report timed out")
        except Exception:
            logger.exception("Daily report error")


async def _weekly_scheduler():
    from datetime import datetime, timedelta, timezone
    from zoneinfo import ZoneInfo

    tz = ZoneInfo(config.REPORT_TIMEZONE)

    while True:
        now_utc = datetime.now(timezone.utc)
        now_local = now_utc.astimezone(tz)

        # Find next target: WEEKLY_REPORT_DAY at WEEKLY_REPORT_HOUR in local tz
        # isoweekday(): Monday=1 ... Sunday=7; config uses 0=Monday
        target_weekday = config.WEEKLY_REPORT_DAY + 1  # convert to isoweekday
        days_ahead = (target_weekday - now_local.isoweekday()) % 7
        target_local = (now_local + timedelta(days=days_ahead)).replace(
            hour=config.WEEKLY_REPORT_HOUR, minute=0, second=0, microsecond=0,
        )
        if target_local <= now_local:
            target_local += timedelta(weeks=1)

        target_utc = target_local.astimezone(timezone.utc)
        wait_seconds = (target_utc - now_utc).total_seconds()
        logger.info("Next weekly report in %.0f seconds (at %s %s)",
                     wait_seconds, target_local.strftime("%Y-%m-%d %H:%M"), config.REPORT_TIMEZONE)
        await asyncio.sleep(wait_seconds)
        try:
            loop = asyncio.get_running_loop()
            await asyncio.wait_for(
                loop.run_in_executor(None, run_weekly_report),
                timeout=600,
            )
        except asyncio.TimeoutError:
            logger.error("Weekly report timed out")
        except Exception:
            logger.exception("Weekly report error")


@kopf.on.startup()
async def on_startup(settings: kopf.OperatorSettings, **kwargs):
    settings.watching.server_timeout = 600

    # Apply LOG_LEVEL to kopf's internal loggers (they ignore basicConfig)
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    for name in ("kopf.activities", "httpcore", "httpx", "anthropic", "kubernetes"):
        logging.getLogger(name).setLevel(log_level)
    # kopf.objects is very noisy (logs every handler success), keep at WARNING
    logging.getLogger("kopf.objects").setLevel("WARNING")

    try:
        k8s_config.load_incluster_config()
    except k8s_config.ConfigException:
        k8s_config.load_kube_config()

    logger.info(
        "k8s-ai-monitor starting - cluster=%s, namespaces=%s, exclude_ns=%s, provider=%s, scanner_interval=%ds",
        config.CLUSTER_NAME, "*" if config.WATCH_ALL_NAMESPACES else config.NAMESPACES,
        config.EXCLUDE_NAMESPACES or "(none)",
        config.LLM_PROVIDER, config.SCANNER_INTERVAL_SECONDS,
    )

    # Prometheus connectivity check
    if config.PROMETHEUS_URL:
        try:
            resp = requests.get(f"{config.PROMETHEUS_URL}/api/v1/status/buildinfo", timeout=5)
            if resp.status_code == 200:
                version = resp.json().get("data", {}).get("version", "?")
                logger.info("Prometheus reachable at %s (version %s)", config.PROMETHEUS_URL, version)
            else:
                logger.warning("Prometheus at %s returned HTTP %s", config.PROMETHEUS_URL, resp.status_code)
        except Exception as e:
            logger.warning("Prometheus at %s is NOT reachable: %s", config.PROMETHEUS_URL, e)
    else:
        logger.warning("PROMETHEUS_URL not set — node metrics will use Metrics API only")
    # LLM connectivity check
    try:
        provider, client = _get_client()
        alert_model = _get_model(provider, "alert")
        report_model = _get_model(provider, "report")
        logger.info("LLM provider=%s, alert_model=%s, report_model=%s — testing...",
                     provider, alert_model, report_model)
        if provider == "openai":
            token_param = ("max_completion_tokens" if alert_model.startswith("gpt-5")
                           else "max_tokens")
            resp = client.chat.completions.create(
                model=alert_model,
                messages=[{"role": "user", "content": "Reply with just: ok"}],
                **{token_param: 3},
            )
            logger.info("LLM check OK: %s responded (%d tokens)", alert_model,
                         resp.usage.prompt_tokens + resp.usage.completion_tokens if resp.usage else 0)
        else:
            resp = client.messages.create(
                model=alert_model,
                messages=[{"role": "user", "content": "Reply with just: ok"}],
                max_tokens=3,
            )
            logger.info("LLM check OK: %s responded (%d tokens)", alert_model,
                         (resp.usage.input_tokens + resp.usage.output_tokens) if resp.usage else 0)
    except Exception as e:
        logger.error("LLM check FAILED for provider=%s: %s", config.LLM_PROVIDER, e)

    logger.info("HTTP auth: %s", "enabled (INTERNAL_TOKEN set)" if config.INTERNAL_TOKEN else "disabled")
    logger.info("State backend: sqlite (%s)", config.SQLITE_PATH)

    store = get_store()

    asyncio.create_task(_start_http_server())
    asyncio.create_task(_daily_scheduler())
    if config.WEEKLY_REPORT_ENABLED:
        asyncio.create_task(_weekly_scheduler())
        logger.info("Weekly report enabled: day=%d hour=%d tz=%s",
                     config.WEEKLY_REPORT_DAY, config.WEEKLY_REPORT_HOUR, config.REPORT_TIMEZONE)

    if config.AUTO_MAINTENANCE_ENABLED:
        asyncio.create_task(_maintenance_detection_loop())
        logger.info("Auto-maintenance detection enabled: threshold=%d nodes, check_interval=%ds",
                     config.AUTO_MAINTENANCE_NODE_THRESHOLD, config.AUTO_MAINTENANCE_CHECK_INTERVAL)

    enabled = get_enabled_scanners()
    for scanner in enabled:
        logger.info("Starting scanner: %s (interval=%ds, delay=%ds)",
                     scanner.name, scanner.interval_seconds, scanner.startup_delay or scanner.interval_seconds)
        asyncio.create_task(_scanner_loop(scanner, store))

    _resolve_disabled_scanner_incidents(store, enabled)

    if config.ENDPOINT_SCAN_ENABLED:
        logger.info("Endpoint scanner enabled, interval=%ds, ingress_service=%s",
                     config.ENDPOINT_SCAN_INTERVAL_SECONDS,
                     config.ENDPOINT_INGRESS_SERVICE or "(disabled)")


@kopf.on.cleanup()
async def on_cleanup(**kwargs):
    logger.info("k8s-ai-monitor shutting down")

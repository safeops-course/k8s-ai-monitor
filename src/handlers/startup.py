"""Startup, cleanup, HTTP server, scanner loops — extracted from main.py."""
import asyncio
import hmac
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
from src.handlers.alertmanager import handle_alertmanager_webhook
from src.engine.notifier import post_maintenance_notice
from src.engine import central_push
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

# Nodes the cluster autoscaler is removing carry one of these. A scale-down
# node is cordoned and goes NotReady while it is deleted — indistinguishable
# from a maintenance drain on those two facts alone — so the cordoned+NotReady
# heuristic below must exclude it, or routine autoscaling reads as maintenance
# and silences alerting cluster-wide. The taint is the discriminator: the
# autoscaler sets it before draining, so it is present throughout the window.
_AUTOSCALER_REMOVAL_TAINTS = {
    "ToBeDeletedByClusterAutoscaler",
    "DeletionCandidateOfClusterAutoscaler",
}

# Global store instance
_store = None


def get_store() -> SqliteStore:
    global _store
    if _store is None:
        _store = SqliteStore()
    return _store


def _check_auth(request) -> web.Response | None:
    """Gate every non-healthz endpoint behind INTERNAL_TOKEN.

    Previously returned None when INTERNAL_TOKEN was empty, which meant the
    whole management surface (including side-effect endpoints like /report,
    /certs) was open to anyone who could reach the pod.
    Now we reject with 401 when the token is unset (operator needs to
    configure one) and with 403 on mismatch.
    """
    if not config.INTERNAL_TOKEN:
        return web.Response(
            text="HTTP API disabled: set INTERNAL_TOKEN env var",
            status=401,
        )
    # X-Internal-Token, or "Authorization: Bearer <token>" - the form Alertmanager's
    # webhook http_config can send. Compared in constant time.
    token = request.headers.get("X-Internal-Token", "")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[len("Bearer "):].strip()
    if not hmac.compare_digest(token.encode(), config.INTERNAL_TOKEN.encode()):
        return web.Response(text="Forbidden", status=403)
    return None


async def _handle_healthz(request):
    """Liveness signal. Reports unhealthy when the SQLite store can't be
    reached so the kubelet restarts the pod.

    The store backend can wedge with no auto-recovery: at startup with
    "unable to open database file" on a stale RWO volume handle (real
    incident: a monitor sat Running but functionally dead for 72h while kopf
    retried on_startup forever), or mid-life on a disk-full / read-only
    remount. A fresh process is the only fix, so a liveness probe on
    /healthz lets Kubernetes self-heal. Always reachable: the HTTP server
    is started before store init in on_startup.
    """
    if _store is None:
        return web.Response(text="store uninitialized", status=503)
    try:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _store.ping)
    except Exception as e:
        logger.warning("healthz: store ping failed: %s", e)
        return web.Response(text=f"store unhealthy: {e}", status=503)
    return web.Response(text="ok")


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
    err = _check_auth(request)
    if err:
        return err
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
    err = _check_auth(request)
    if err:
        return err
    store = get_store()
    hours = _parse_int_param(request, "hours", 24)
    if hours is None:
        return web.Response(text="Invalid 'hours' parameter", status=400)
    loop = asyncio.get_running_loop()
    entries = await loop.run_in_executor(None, store.get_llm_debug, hours)
    return web.json_response(entries)


async def _handle_llm_debug_detail(request):
    err = _check_auth(request)
    if err:
        return err
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
    err = _check_auth(request)
    if err:
        return err
    store = get_store()
    incident_id = _parse_id(request)
    if incident_id is None:
        return web.Response(text="Invalid ID", status=400)
    loop = asyncio.get_running_loop()
    updated = await loop.run_in_executor(None, store.set_status, incident_id, "acknowledged")
    if not updated:
        return web.Response(text=f"Incident #{incident_id} not found", status=404)
    logger.info("Incident #%d acknowledged via HTTP", incident_id)
    return web.Response(text="Acknowledged")


async def _handle_incident_resolve(request):
    err = _check_auth(request)
    if err:
        return err
    store = get_store()
    incident_id = _parse_id(request)
    if incident_id is None:
        return web.Response(text="Invalid ID", status=400)
    loop = asyncio.get_running_loop()
    updated = await loop.run_in_executor(
        None, lambda: store.set_status(incident_id, "resolved", clear_cooldown=True)
    )
    if not updated:
        return web.Response(text=f"Incident #{incident_id} not found", status=404)
    await loop.run_in_executor(
        None, lambda: store.set_resolved_by(incident_id, "operator")
    )
    # Mirror the resolve to the central board — without this the central
    # dashboard keeps the incident "open" forever (the fossil problem).
    inc = await loop.run_in_executor(None, store.get_incident_by_id, incident_id)
    if inc is not None:
        await loop.run_in_executor(
            None, lambda: central_push.push_incident_status(inc, "resolved", "operator"))
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
    err = _check_auth(request)
    if err:
        return err
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
    err = _check_auth(request)
    if err:
        return err
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
    err = _check_auth(request)
    if err:
        return err
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
    err = _check_auth(request)
    if err:
        return err
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


@web.middleware
async def _auth_middleware(request, handler):
    """Require INTERNAL_TOKEN on every route except /healthz.

    Every control/read endpoint was audited — incidents list, LLM usage,
    reports, suppressions, maintenance — so nothing leaks sensitive data
    or exposes side-effect triggers when INTERNAL_TOKEN is not set.
    Middleware avoids 15 repetitive `_check_auth(request)` calls.
    """
    if request.path == "/healthz":
        return await handler(request)
    err = _check_auth(request)
    if err:
        return err
    return await handler(request)


def _build_app() -> web.Application:
    """The HTTP API: every route behind _auth_middleware except /healthz."""
    app = web.Application(middlewares=[_auth_middleware])
    app.router.add_get("/healthz", _handle_healthz)
    app.router.add_post("/alertmanager", handle_alertmanager_webhook)
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


_http_started = False


async def _start_http_server():
    # Idempotent: on_startup now starts the server before store init, and
    # kopf re-runs the whole on_startup activity if store init raises. Guard
    # against a second bind on retry (would fail with "address already in use").
    global _http_started
    if _http_started:
        return
    if not config.INTERNAL_TOKEN:
        # Fail loud but don't crash the whole process — scanners / daily
        # reports / Slack still work. Operators see this in logs and can
        # set INTERNAL_TOKEN via the ExternalSecret to unlock the HTTP API.
        logger.error(
            "HTTP API is locked: INTERNAL_TOKEN is not set. "
            "All routes except /healthz will return 401 until you set it."
        )
    runner = web.AppRunner(_build_app())
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", _HTTP_PORT)
    await site.start()
    _http_started = True
    endpoints = ("/healthz, /report, /state, /certs, /llm-usage, "
                 "/llm-debug, /incidents, /reports, /maintenance, /suppressions")
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
    "node": ["Node:"],
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
            store.set_resolved_by(inc.id, "sweep")
            logger.info("Auto-resolved stale incident #%d (%s) — scanner '%s' is disabled",
                        inc.id, inc.state_key, scanner.name)
        # One batched request — the loop must not pay per-incident HTTP.
        central_push.push_incident_statuses(incidents, "resolved", "sweep")


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
            # store.cleanup() is run by _store_cleanup_loop on a periodic
            # schedule — no per-scan call here. Multiple scanners running
            # in parallel were stepping on each other's SQLite cleanup.
        except asyncio.TimeoutError:
            logger.error("%s scanner timed out", scanner.name)
        except Exception:
            logger.exception("%s scanner error", scanner.name)
        await asyncio.sleep(scanner.interval_seconds)


async def _store_cleanup_loop(store):
    """Run store.cleanup() periodically instead of on every scan tick."""
    interval = config.STORE_CLEANUP_INTERVAL_SECONDS
    # Stagger first run a bit so we don't fight startup-time scans.
    await asyncio.sleep(min(interval, 120))
    loop = asyncio.get_running_loop()
    while True:
        try:
            reaped = await loop.run_in_executor(None, store.cleanup)
            # Mirror the reaper's resolves to the central board. The local DB is
            # the source of truth for the monitor's own decisions, but the central
            # board reads ClickHouse — an unpushed resolve leaves the incident
            # "active" there forever. Pushed in the executor: it is a blocking
            # HTTP call with a 10s timeout.
            if reaped:
                await loop.run_in_executor(
                    None,
                    lambda r=reaped: central_push.push_incident_statuses(
                        r, "resolved", "reaper"),
                )
            # Backstop for resolves the board never received (lost push, CLI
            # resolve): one SELECT, and a re-push only for keys that differ.
            await loop.run_in_executor(
                None, central_push.sync_resolved_to_central, store)
            logger.debug("store.cleanup tick complete")
        except Exception:
            logger.warning("store.cleanup failed", exc_info=True)
        await asyncio.sleep(interval)


async def _hourly_digest_loop(store):
    """Post the withheld-alert digest on an interval, and nothing when quiet.

    Modelled on _store_cleanup_loop rather than the wall-clock schedulers: this
    is a drain, not an appointment. It checks often and posts rarely — once the
    interval has elapsed AND there is something to say, or immediately when
    enough has piled up that waiting out the hour would be wrong.
    """
    from src.engine import digest

    interval = config.DIGEST_INTERVAL_SECONDS
    check = config.DIGEST_CHECK_INTERVAL_SECONDS
    await asyncio.sleep(min(check, 120))
    loop = asyncio.get_running_loop()
    last_post = time.time()
    # An executor future outlives the wait_for that timed out on it — the thread
    # keeps running, the wrapper is merely cancelled (see the same caveat in
    # reporter.py). Held here so a slow run cannot be joined by a second one
    # posting the same digest twice and double-marking the rows.
    inflight = None
    while True:
        try:
            if inflight is not None and not inflight.done():
                logger.warning("Hourly digest: previous run still in flight, skipping tick")
                await asyncio.sleep(check)
                continue
            inflight = None

            due = (time.time() - last_post) >= interval
            burst = await loop.run_in_executor(None, digest.pending_burst, store)
            if burst and not due:
                logger.info("Hourly digest: burst threshold reached, flushing early")
            if due or burst:
                inflight = loop.run_in_executor(None, digest.run_once, store)
                try:
                    # shield so the timeout cancels only our wait, leaving the
                    # future intact for the done() check above.
                    posted = await asyncio.wait_for(asyncio.shield(inflight), timeout=300)
                except asyncio.TimeoutError:
                    logger.warning("Hourly digest: run exceeded 300s, still running")
                    continue
                inflight = None
                # Only a delivered message restarts the clock — but a due tick
                # with nothing to say restarts it too, or a quiet cluster would
                # re-check every 5 minutes forever once the hour has elapsed.
                if posted or due:
                    last_post = time.time()
        except Exception:
            logger.warning("Hourly digest tick failed", exc_info=True)
        await asyncio.sleep(check)


def _spawn(coro, name: str):
    """Start a background task that cannot die quietly.

    Every loop here was registered with a bare create_task, so an exception
    escaping the loop body killed the task with no trace. That is tolerable for
    a cleanup pass; it is not for the digest, which is the only channel for
    alerts the pipeline withholds — a dead digest loop turns deferral into
    silence.
    """
    task = asyncio.create_task(coro)

    def _done(t: asyncio.Task) -> None:
        if t.cancelled():
            return
        exc = t.exception()
        if exc is not None:
            logger.error("Background task %s died: %s", name, exc, exc_info=exc)

    task.add_done_callback(_done)
    return task


async def _store_vacuum_loop(store):
    """Run store.full_vacuum() on a slow cadence (default weekly).

    cleanup() already handles WAL + incremental vacuum every 30 min; this
    is the heavier fragmentation pass that reclaims free pages on legacy
    DBs where auto_vacuum isn't active. Kept separate so the frequent
    cleanup tick doesn't block readers on a full rewrite.
    """
    interval_sec = config.DB_VACUUM_INTERVAL_HOURS * 3600
    # Delay first run so it doesn't collide with startup scans / initial
    # cleanup. A fresh full VACUUM at startup wastes IO — the interval
    # timer is the normal cadence.
    await asyncio.sleep(min(interval_sec, 3600))
    loop = asyncio.get_running_loop()
    while True:
        try:
            await loop.run_in_executor(None, store.full_vacuum)
        except Exception:
            logger.warning("store.full_vacuum failed", exc_info=True)
        await asyncio.sleep(interval_sec)


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
        # A node the autoscaler is scaling down is not under maintenance.
        being_scaled_down = bool(taint_keys & _AUTOSCALER_REMOVAL_TAINTS)

        # Also count cordoned + NotReady nodes — a manual drain or a genuinely
        # broken node that carries no maintenance taint. But not a scale-down,
        # which looks identical on these two conditions.
        is_cordoned = bool(spec.unschedulable) if spec else False
        is_not_ready = False
        for cond in ((node.status.conditions or []) if node.status else []):
            if cond.type == "Ready":
                is_not_ready = cond.status != "True"
                break

        if has_maintenance_taint or (
            is_cordoned and is_not_ready and not being_scaled_down
        ):
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


async def _run_daily_with_retries() -> bool:
    """Run the daily report, re-attempting on transient failure until a real
    report is produced or the retry window closes.

    The per-call backoff inside `_call_llm_with_retry` only spans seconds, so a
    multi-minute (or multi-hour) provider spike (observed: Gemini 503
    UNAVAILABLE / 504 DEADLINE_EXCEEDED) would otherwise drop the report until
    the next day. This keeps re-attempting the whole report every
    DAILY_REPORT_RETRY_INTERVAL_MINUTES for up to DAILY_REPORT_RETRY_MAX_HOURS —
    long enough to ride out any realistic outage, bounded so the loop can't
    bleed into the next day's scheduled run. Intermediate attempts suppress the
    error placeholder (no Slack spam / error report row); only the final attempt
    (the one made when retrying again would exceed the window) surfaces a
    sustained outage.

    Returns True if a real report was produced.
    """
    interval_sec = config.DAILY_REPORT_RETRY_INTERVAL_MINUTES * 60
    window_sec = config.DAILY_REPORT_RETRY_MAX_HOURS * 3600
    loop = asyncio.get_running_loop()
    start = loop.time()
    attempt = 0
    while True:
        attempt += 1
        # This is the final attempt once a further retry would land outside the
        # window (also true on the first attempt when the window is 0 — i.e.
        # single-shot). Only the final attempt surfaces the error placeholder.
        is_last = (loop.time() - start) + interval_sec > window_sec
        ok = False
        try:
            ok = await asyncio.wait_for(
                loop.run_in_executor(
                    None, lambda last=is_last: run_daily_report(suppress_error_output=not last)),
                timeout=300,
            )
        except asyncio.TimeoutError:
            logger.error("Daily report timed out (attempt %d)", attempt)
            # ok stays False — a timeout is a transient stall, eligible for retry.
        except Exception:
            # Failure outside the transient-LLM path (collector / Slack post /
            # central push). analyze_daily_report never raises — it returns
            # llm_error=True — so an exception here is NOT the retryable signal.
            # Retrying could re-run side effects and double-publish, so log once
            # and stop. Only the explicit ok=False LLM signal drives retries.
            logger.exception("Daily report unexpected error — not retrying")
            return False
        if ok:
            if attempt > 1:
                logger.info("Daily report succeeded on attempt %d", attempt)
            return True
        if is_last:
            break
        delay_min = config.DAILY_REPORT_RETRY_INTERVAL_MINUTES
        logger.warning("Daily report attempt %d failed — retrying in %d min",
                       attempt, delay_min)
        await asyncio.sleep(interval_sec)
    logger.error("Daily report failed after %d attempts (%.1fh window) — giving up until next scheduled run",
                 attempt, config.DAILY_REPORT_RETRY_MAX_HOURS)
    return False


async def _daily_scheduler():
    from datetime import datetime, timedelta, timezone
    from zoneinfo import ZoneInfo

    tz = ZoneInfo(config.REPORT_TIMEZONE)

    # The scheduler state is stored in a dedicated table that is updated only
    # AFTER a successful run, so it survives across restarts and is independent
    # of whether `_save_report` succeeded or not.
    last_run_date = None
    try:
        store = get_store()
        checkpoint = store.get_last_daily_run()
        if checkpoint:
            last_run_date = datetime.strptime(checkpoint, "%Y-%m-%d").date()
            logger.info("Daily scheduler: last successful run was %s", last_run_date)
        else:
            # First boot with no checkpoint — bootstrap from the most recent
            # report row so we don't replay yesterday's report.
            reports = store.list_daily_reports(limit=1, report_type="daily")
            if reports:
                last_run_date = datetime.fromtimestamp(
                    reports[0]["created_at"], tz=timezone.utc,
                ).astimezone(tz).date()
                logger.info("Daily scheduler: bootstrapped checkpoint from last report (%s)",
                            last_run_date)
    except Exception:
        logger.warning("Daily scheduler: failed to read checkpoint", exc_info=True)

    while True:
        now_utc = datetime.now(timezone.utc)
        now_local = now_utc.astimezone(tz)
        target_local = now_local.replace(
            hour=config.DAILY_REPORT_HOUR, minute=0, second=0, microsecond=0,
        )
        today_local = now_local.date()

        # Catch-up: today's scheduled time has passed and we haven't run yet today.
        if target_local <= now_local and last_run_date != today_local:
            logger.info(
                "Daily report catch-up: scheduled time %s already passed, running now (last_run_date=%s)",
                target_local.strftime("%Y-%m-%d %H:%M %Z"), last_run_date,
            )
            daily_succeeded = await _run_daily_with_retries()
            # Always advance the in-memory marker so the loop doesn't spin in
            # a tight retry, but only persist the checkpoint on a successful
            # daily report. A persistent checkpoint claims "last successful
            # run" — see SqliteStore.save_last_daily_run.
            last_run_date = today_local
            if daily_succeeded:
                try:
                    get_store().save_last_daily_run(today_local.isoformat())
                except Exception:
                    logger.warning("Failed to persist scheduler checkpoint", exc_info=True)

        # Compute the next target time we should sleep until.
        next_target_local = target_local
        if next_target_local <= now_local or last_run_date == today_local:
            next_target_local = next_target_local + timedelta(days=1)

        next_target_utc = next_target_local.astimezone(timezone.utc)
        wait_seconds = max(0.0, (next_target_utc - now_utc).total_seconds())
        logger.info("Next daily report in %.0f seconds (at %s %s)",
                    wait_seconds, next_target_local.strftime("%Y-%m-%d %H:%M"),
                    config.REPORT_TIMEZONE)
        await asyncio.sleep(wait_seconds)

        run_date_local = datetime.now(timezone.utc).astimezone(tz).date()
        if last_run_date == run_date_local:
            # Already ran for this date (e.g. via catch-up). Skip and re-loop
            # to compute the next target.
            logger.debug("Skipping scheduled daily report — already ran for %s", run_date_local)
            continue

        daily_succeeded = await _run_daily_with_retries()
        last_run_date = run_date_local
        if daily_succeeded:
            try:
                get_store().save_last_daily_run(run_date_local.isoformat())
            except Exception:
                logger.warning("Failed to persist scheduler checkpoint", exc_info=True)


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


async def _open_digest_scheduler(store):
    """Post the open-incident snapshot at each OPEN_DIGEST_HOURS local hour.

    No checkpoint on purpose: a restart landing exactly on an hour costs at
    most one snapshot, and the next slot self-heals. Simpler beats a replay
    table for a message that is only ever a point-in-time view.
    """
    from datetime import datetime, timedelta, timezone
    from zoneinfo import ZoneInfo

    from src.engine import open_digest

    tz = ZoneInfo(config.REPORT_TIMEZONE)
    hours = config.OPEN_DIGEST_HOURS
    if not hours:
        # Registration is guarded on the same condition; reaching this is a bug.
        logger.error("Open digest scheduler started without OPEN_DIGEST_HOURS set")
        return

    loop = asyncio.get_running_loop()
    # Kept across iterations: run_once runs in an executor thread, and a
    # timeout below abandons (not stops) that thread. Holding the Future lets
    # the next slot detect a still-running digest and skip instead of starting
    # an overlapping one (which would double-post to Slack).
    digest_future: asyncio.Future | None = None
    while True:
        now_utc = datetime.now(timezone.utc)
        now_local = now_utc.astimezone(tz)
        candidates = [
            now_local.replace(hour=h, minute=0, second=0, microsecond=0)
            for h in hours
        ]
        upcoming = [t for t in candidates if t > now_local]
        target_local = min(upcoming) if upcoming else min(candidates) + timedelta(days=1)

        wait_seconds = (target_local.astimezone(timezone.utc) - now_utc).total_seconds()
        logger.info("Next open-incidents digest in %.0f seconds (at %s %s)",
                     wait_seconds, target_local.strftime("%Y-%m-%d %H:%M"),
                     config.REPORT_TIMEZONE)
        await asyncio.sleep(wait_seconds)
        if digest_future is not None and not digest_future.done():
            logger.error(
                "Previous open digest still running — skipping this slot")
            continue
        try:
            digest_future = loop.run_in_executor(
                None, open_digest.run_once, store)
            # shield: on timeout only the wait is cancelled, the Future keeps
            # reflecting the thread's real state for the skip check above.
            await asyncio.wait_for(asyncio.shield(digest_future), timeout=120)
        except asyncio.TimeoutError:
            logger.error("Open digest timed out (executor thread may still "
                         "be running; overlapping slots will be skipped)")
        except Exception:
            logger.exception("Open digest error")


def _startup_cleanup(store):
    """Resolve stale incidents at boot.

    1. Non-prod incidents: develop/staging scanning is now off by default.
       Active incidents from before the disable would never auto-resolve
       because no scanner sees them. Resolve them all.
    2. Stale incidents: anything with last_seen > 7 days and still active
       is clearly not a current problem. Resolve it.
    """
    resolved = 0
    swept: list = []
    for inc in store.list_incidents("active"):
        # Non-prod namespace incidents
        if config.is_nonprod_namespace(getattr(inc, 'namespace', '') or ''):
            store.set_status(inc.id, "resolved")
            store.set_resolved_by(inc.id, "sweep")
            swept.append(inc)
            resolved += 1
            continue
        # Also catch non-prod by state_key pattern for incidents without namespace
        for ns in config.NON_PROD_NAMESPACES:
            if f":{ns}/" in inc.state_key or inc.state_key.endswith(f":{ns}"):
                store.set_status(inc.id, "resolved")
                store.set_resolved_by(inc.id, "sweep")
                swept.append(inc)
                resolved += 1
                break
        else:
            # Stale: last_seen > 7 days
            import time
            if (time.time() - inc.last_seen_at) > 7 * 86400:
                store.set_status(inc.id, "resolved")
                store.set_resolved_by(inc.id, "sweep")
                swept.append(inc)
                resolved += 1
    # One batched request for the whole sweep — startup must not pay
    # per-incident HTTP round-trips (worst case 10s timeout each with the
    # central ClickHouse down).
    central_push.push_incident_statuses(swept, "resolved", "sweep")
    if resolved:
        logger.info("Startup cleanup: resolved %d stale/non-prod incidents", resolved)


@kopf.on.startup()
async def on_startup(settings: kopf.OperatorSettings, **kwargs):
    settings.watching.server_timeout = 600
    # The monitor only reads the cluster: no Kubernetes Events of its own (kopf posts its
    # per-object log lines as Events by default, which needs events create - not granted).
    settings.posting.enabled = False

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
        elif provider == "gemini":
            from google.genai import types as _genai_types
            resp = client.models.generate_content(
                model=alert_model,
                contents="Reply with just: ok",
                config=_genai_types.GenerateContentConfig(
                    system_instruction="Reply with just the word ok",
                    max_output_tokens=8,
                ),
            )
            usage = getattr(resp, "usage_metadata", None)
            total = ((getattr(usage, "prompt_token_count", 0) or 0)
                     + (getattr(usage, "candidates_token_count", 0) or 0))
            logger.info("LLM check OK: %s responded (%d tokens)", alert_model, total)
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

    # Start the HTTP server FIRST, before store init. get_store() can raise
    # (e.g. "unable to open database file" on a stale RWO volume handle), and
    # kopf retries on_startup forever while the pod stays Running. With the
    # server already up, /healthz stays reachable and reports 503 on the dead
    # store so a liveness probe can restart the pod. Idempotent, so the retry
    # doesn't double-bind. Awaited (not create_task) so the listener is up
    # before store init is attempted — otherwise a synchronous get_store()
    # failure could pre-empt the bind and /healthz would be unreachable.
    await _start_http_server()

    store = get_store()

    # Startup cleanup: resolve stale incidents
    try:
        _startup_cleanup(store)
    except Exception:
        logger.warning("Startup cleanup failed", exc_info=True)

    _spawn(_daily_scheduler(), "daily_scheduler")
    _spawn(_store_cleanup_loop(store), "store_cleanup")
    _spawn(_store_vacuum_loop(store), "store_vacuum")
    if config.hourly_digest_enabled():
        _spawn(_hourly_digest_loop(store), "hourly_digest")
        logger.info("Hourly digest enabled: interval=%ds check=%ds burst=%d",
                     config.DIGEST_INTERVAL_SECONDS,
                     config.DIGEST_CHECK_INTERVAL_SECONDS,
                     config.DIGEST_BURST_THRESHOLD)
    if config.OPEN_DIGEST_HOURS:
        _spawn(_open_digest_scheduler(store), "open_digest")
        logger.info("Open-incidents digest enabled: hours=%s tz=%s",
                     config.OPEN_DIGEST_HOURS, config.REPORT_TIMEZONE)
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

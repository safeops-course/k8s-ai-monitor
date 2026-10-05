"""Alertmanager webhook input - Prometheus alerts become incidents in the shared pipeline.

Alertmanager routes an alert group here (a webhook receiver, POST /alertmanager); each
alert becomes one ScanResult and goes through the same pipeline as scanner results and
Kubernetes events: fingerprint, dedup, escalation, enrichment, the LLM for production,
one Slack message per incident. A `resolved` alert closes its incident.

The alert's own severity is final (never_promote): the PrometheusRule already decided
how urgent it is - novelty or persistence must not turn a warning into a page.

Payload format (Alertmanager webhook v4):
    {"status": "firing"|"resolved", "alerts": [
        {"status": ..., "labels": {"alertname", "namespace", "severity", ...},
         "annotations": {"summary", "description", "runbook_url"},
         "startsAt", "endsAt", "generatorURL", "fingerprint"}]}
"""
import asyncio
import json
import logging

from aiohttp import web

from src.engine.sanitizer import sanitize_value
from src.scanners._base import ScanResult

logger = logging.getLogger(__name__)

# Alerts that are not about a problem: the heartbeat, and the inhibitor of info alerts.
IGNORED_ALERTS = frozenset({"Watchdog", "InfoInhibitor"})
# A webhook payload larger than this is refused - a normal group is a few KB.
MAX_PAYLOAD_BYTES = 1_000_000


def _watched(namespace: str) -> bool:
    """The namespace filters of the event handler; a cluster-scoped alert (no namespace,
    e.g. a node) is always tracked."""
    if not namespace:
        return True
    from src.handlers.events import _in_watched_namespace
    return _in_watched_namespace(namespace)


def alert_to_result(alert: dict) -> ScanResult | None:
    """One Alertmanager alert -> one ScanResult, or None when it is not ours to track.
    Raises ValueError for a malformed alert (labels or annotations that are not objects)."""
    labels = alert.get("labels") or {}
    annotations = alert.get("annotations") or {}
    if not isinstance(labels, dict) or not isinstance(annotations, dict):
        raise ValueError("alert labels and annotations must be objects")
    alertname = labels.get("alertname", "")
    if not alertname or alertname in IGNORED_ALERTS:
        return None
    namespace = labels.get("namespace", "")
    if not _watched(namespace):
        return None

    fingerprint = alert.get("fingerprint", "")
    severity = labels.get("severity", "warning")
    if severity not in ("critical", "warning"):
        severity = "warning"
    resolved = alert.get("status") == "resolved"
    scope = namespace or "cluster"

    context = {
        "source": "alertmanager",
        "alertname": alertname,
        "status": alert.get("status", ""),
        "severity": severity,
        "namespace": namespace,
        "summary": annotations.get("summary", ""),
        "description": annotations.get("description", ""),
        "runbook_url": annotations.get("runbook_url", ""),
        "labels": labels,
        "starts_at": alert.get("startsAt", ""),
        "generator_url": alert.get("generatorURL", ""),
    }
    return ScanResult(
        state_key=f"Alert:{scope}/{alertname}:{fingerprint or 'none'}",
        # The title goes to Slack as is (the pipeline sanitizes the context, not the title)
        title=sanitize_value(annotations.get("summary") or f"Alert {alertname}"),
        severity=severity,
        resource=f"Alert/{alertname}",
        namespace=namespace,
        issue_type="alert",
        pod_name=labels.get("pod", ""),
        context_override=context,
        event_reason=alertname,
        auto_resolve=resolved,
        never_promote=True,
        metadata={"alertname": alertname, "fingerprint": fingerprint},
    )


def payload_to_results(payload: dict) -> list[ScanResult]:
    """The alerts of one webhook payload that become ScanResults.
    Raises ValueError when the payload is not an object with an 'alerts' list."""
    if not isinstance(payload, dict):
        raise ValueError("payload is not a JSON object")
    alerts = payload.get("alerts")
    if not isinstance(alerts, list):
        raise ValueError("payload has no 'alerts' list")
    results = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        result = alert_to_result(alert)
        if result is not None:
            results.append(result)
    return results


async def handle_alertmanager_webhook(request: web.Request) -> web.Response:
    """POST /alertmanager - authenticated by _auth_middleware like every other route."""
    if request.content_length and request.content_length > MAX_PAYLOAD_BYTES:
        return web.Response(text="payload too large", status=413)
    try:
        payload = json.loads(await request.text())
        results = payload_to_results(payload)
    except (ValueError, TypeError) as e:
        logger.warning("Alertmanager webhook: bad payload: %s", e)
        return web.Response(text=f"bad payload: {e}", status=400)

    received = len(payload["alerts"])  # payload_to_results checked it is a list
    if not results:
        return web.json_response({"received": received, "processed": 0})

    from src.collectors.app_metrics import get_app_metrics_summary
    from src.collectors.node import get_node_metrics_summary
    from src.engine.pipeline import process_scan_results
    from src.handlers.startup import get_store

    store = get_store()
    loop = asyncio.get_running_loop()
    fired = await loop.run_in_executor(
        None,
        lambda: process_scan_results(results, store, None,
                                     get_node_metrics_summary, get_app_metrics_summary),
    )
    logger.info("Alertmanager webhook: %d alerts received, %d tracked, %d posted",
                received, len(results), fired)
    return web.json_response({"received": received, "processed": len(results), "posted": fired})

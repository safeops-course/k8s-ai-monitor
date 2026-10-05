"""Flux Kustomization/HelmRelease handlers — extracted from handlers.py.

Sprint 9 — migrated to the shared pipeline. Stalled conditions emit a
`ScanResult` that flows through `process_scan_results`, so flux alerts
now get fingerprinting, escalation, enrichment, root-cause correlation
and Slack threading — features the direct `post_alert` path bypassed.

Kopf-specific concerns stay here: startup grace, `_in_flight` dedup
across concurrent kopf invocations for the same CR, and the CR-level
namespace filters. Context collection (`collect_flux_context`) is also
still done in the handler; the dict is handed to the pipeline via
`ScanResult.context_override` so the pipeline doesn't try to collect
pod context for a non-pod resource.
"""
import asyncio
import logging
import time

import kopf

from src import config
from src.collectors import Collector
from src.collectors.app_metrics import get_app_metrics_summary
from src.collectors.node import get_node_metrics_summary
from src.engine.pipeline import process_scan_results
from src.scanners._base import ScanResult

logger = logging.getLogger(__name__)

_startup_time = time.time()
_STARTUP_GRACE_SECONDS = 30

# In-flight state keys to prevent duplicate concurrent alerts.
# Covers the whole processing window (context collection + pipeline
# invocation) so a duplicate kopf event for the same CR skips work the
# pipeline would anyway de-dedupe via incident cooldown.
_in_flight: set[str] = set()

_collector: Collector | None = None


def _get_collector() -> Collector:
    global _collector
    if _collector is None:
        _collector = Collector()
    return _collector


@kopf.on.event("kustomizations", group="kustomize.toolkit.fluxcd.io", version="v1")
async def on_kustomization_event(event, logger, **kwargs):
    await _handle_flux_event(event, "Kustomization", logger)


@kopf.on.event("helmreleases", group="helm.toolkit.fluxcd.io", version="v2")
async def on_helmrelease_event(event, logger, **kwargs):
    await _handle_flux_event(event, "HelmRelease", logger)


async def _handle_flux_event(event, kind: str, logger):
    """Handle Flux Kustomization/HelmRelease stalled events.

    Like `events.py`, this handler bypasses the hot/cold router on purpose:
    Flux stalls block deployments and need immediate surface-level alerting
    regardless of the hot/cold batching policy that scanners go through.
    """
    if event.get("type") is None:
        return
    if time.time() - _startup_time < _STARTUP_GRACE_SECONDS:
        return

    obj = event.get("object")
    if not obj:
        return

    name = obj.get("metadata", {}).get("name", "")
    namespace = obj.get("metadata", {}).get("namespace", "")

    # Respect EXCLUDE_NAMESPACES / WATCH_NAMESPACES / NON_PROD_SCANNER_ENABLED
    if namespace in config.EXCLUDE_NAMESPACES:
        return
    if config.is_nonprod_namespace(namespace) and not config.NON_PROD_SCANNER_ENABLED:
        return
    if not config.WATCH_ALL_NAMESPACES and namespace not in config.NAMESPACES:
        return

    conditions = obj.get("status", {}).get("conditions", [])
    cond_map = {c.get("type"): c for c in conditions}
    stalled = cond_map.get("Stalled", {})
    if stalled.get("status") != "True":
        return

    from src.handlers.startup import get_store
    store = get_store()

    state_key = f"Flux:{kind}:{namespace}/{name}:stalled"

    if state_key in _in_flight:
        return
    _in_flight.add(state_key)

    try:
        loop = asyncio.get_running_loop()

        # Respect maintenance mode — skip emission entirely, same as the
        # pod event handler in events.py. Previously flux.py had no such
        # check (confirmed by v4 SRE review).
        if await loop.run_in_executor(None, store.is_maintenance_active):
            logger.debug(
                "Flux %s stall ignored during maintenance: %s/%s",
                kind, namespace, name,
            )
            return

        message = stalled.get("message", "")
        logger.info("Flux %s stalled: %s/%s \u2014 %s", kind, namespace, name, message)

        collector = _get_collector()
        flux_context = await loop.run_in_executor(
            None, collector.collect_flux_context, name, namespace, kind,
        )

        result = ScanResult(
            state_key=state_key,
            title=f"Flux {kind} Stalled",
            severity="critical",
            resource=f"{kind}/{name}",
            namespace=namespace,
            issue_type="stalled",
            context_override=flux_context,
            event_reason="Stalled",
            skip_llm=True,
            metadata={"kind": kind, "name": name},
        )

        # Pipeline handles: fingerprinting, dedup/cooldown, escalation,
        # enrichment, root-cause correlation, Slack post + threading,
        # central ClickHouse push. collect_context_fn stays None because
        # context_override is already set — the pipeline uses it as-is
        # instead of attempting pod-context collection.
        await loop.run_in_executor(
            None,
            lambda: process_scan_results(
                [result], store, None,
                get_node_metrics_summary,
                get_app_metrics_summary,
            ),
        )
    finally:
        _in_flight.discard(state_key)

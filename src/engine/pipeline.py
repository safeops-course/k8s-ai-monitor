"""Shared detect -> dedup -> collect -> analyze -> alert pipeline.

Uses SqliteStore for full incident lifecycle with escalation and structured JSON.
"""
import json
import logging
import time

from src import config
from src.engine import central_push
from src.engine.escalation import check_escalation
from src.engine.fingerprint import compute_fingerprint
from src.engine.llm import analyze_alert, AnalysisResult
from src.engine.notifier import post_alert, post_resolved, format_structured_analysis, get_webhook_for_namespace
from src.engine.store import Incident
from src.engine.store.sqlite import SqliteStore

logger = logging.getLogger(__name__)


def _format_analysis(ar: AnalysisResult) -> str:
    """Format AnalysisResult for Slack: structured JSON if available, raw text otherwise."""
    if ar.parsed and not ar.parse_error:
        return format_structured_analysis(ar.parsed)
    return ar.raw_text or "Analysis unavailable"


def _effective_debounce(namespace: str) -> int:
    base = config.DEBOUNCE_SECONDS
    if config.is_nonprod_namespace(namespace):
        return base * config.NON_PROD_DEBOUNCE_MULTIPLIER
    return base


def process_scan_results(results: list, store: SqliteStore,
                         collect_context_fn=None,
                         get_node_metrics_fn=None,
                         get_app_metrics_fn=None) -> int:
    """Process scan results: dedup -> context -> LLM -> Slack. Returns alert count."""
    fired = 0
    maintenance = store.is_maintenance_active()
    for r in results:
        # Auto-resolve path — always process even in maintenance
        if r.auto_resolve:
            existing = store.get_incident(r.state_key)
            if existing and existing.status == "active":
                store.set_status(existing.id, "resolved")
                logger.info("Auto-resolved: %s", r.state_key)
                central_push.push_incident({
                    "state_key": existing.state_key,
                    "fingerprint": existing.fingerprint,
                    "issue_type": existing.issue_type,
                    "severity": existing.severity,
                    "owner_ref": existing.owner_ref,
                    "namespace": r.namespace,
                    "resource": r.resource,
                    "title": r.title,
                    "status": "resolved",
                    "event_type": "resolved",
                    "auto_resolved": True,
                    "occurrence_count": existing.occurrence_count,
                    "first_seen_at": existing.first_seen_at,
                    "last_seen_at": existing.last_seen_at,
                    "resolved_at": time.time(),
                    "analysis_json": "",
                    "llm_model": "",
                })
                # Notify Slack for critical incidents
                if existing.severity == "critical":
                    duration_min = (time.time() - existing.last_seen_at) / 60
                    post_resolved(
                        state_key=existing.state_key,
                        namespace=r.namespace,
                        resource=r.resource,
                        duration_min=duration_min,
                        last_seen_at=existing.last_seen_at,
                        webhook_url=get_webhook_for_namespace(r.namespace),
                    )
            continue

        if maintenance and not r.skip_llm:
            r.skip_llm = True
            r.context_override = r.context_override or f"LLM analysis skipped — maintenance mode active.\n{r.title}"
            r.title = f"[Maintenance] {r.title}"

        # Non-prod: LLM only for critical_endpoint scanner
        if not r.skip_llm and config.is_nonprod_namespace(r.namespace) and r.issue_type != "critical_endpoint":
            r.skip_llm = True
            r.context_override = r.context_override or r.title
            r.title = f"{config.nonprod_title_prefix(r.namespace)} {r.title}"

        # Check existing incident
        incident = store.get_incident(r.state_key)

        if store.is_suppressed(r.state_key, r.namespace, r.issue_type):
            if incident and incident.status == "active":
                _record_silent_occurrence(store, incident, r, collect_context_fn)
            continue

        if incident:
            # Skip resolved/acknowledged
            if incident.status in ("resolved", "acknowledged"):
                if incident.status == "resolved":
                    # Reoccurrence after resolution → reopen and alert immediately
                    store.set_status(incident.id, "active")
                    store.bump_incident(incident.id, cooldown_until=0)  # reset cooldown
                    logger.info("Reopened resolved incident: %s", r.state_key)
                    # Refresh incident so check_escalation sees updated state
                    incident = store.get_incident(r.state_key)
                    if not incident:
                        continue
                else:
                    # Acknowledged → still track but don't alert
                    _record_silent_occurrence(store, incident, r, collect_context_fn)
                    continue

            # The current occurrence is recorded below, after this check.
            esc = check_escalation(incident, count_offset=1)
            if not esc.should_alert:
                # Still track the detection (bumps count for future escalation)
                context = _collect_context(r, collect_context_fn)
                raw_context = json.dumps(context) if isinstance(context, dict) else context
                ctx_hash = store.store_context(raw_context)
                store.record_occurrence(incident.id, context_hash=ctx_hash)
                new_count = incident.occurrence_count + 1
                cooldown = min(_effective_debounce(r.namespace) * (2 ** min(new_count, 10)), 43200)
                store.bump_incident(incident.id, cooldown_until=time.time() + cooldown)
                logger.debug("Skipped alert for %s (incident #%d, count=%d, cooldown=%ds): %s",
                             r.state_key, incident.id, new_count, cooldown, esc)
                continue

            # Collect context + LLM (or skip LLM)
            context = _collect_context(r, collect_context_fn)
            raw_context = json.dumps(context) if isinstance(context, dict) else context
            ctx_hash = store.store_context(raw_context)

            if r.skip_llm:
                ar = None
                analysis_text = r.context_override or r.title
            else:
                ar = analyze_alert(context, resource=f"{r.namespace}/{r.resource}")
                analysis_text = _format_analysis(ar)

            store.record_occurrence(
                incident.id,
                context_hash=ctx_hash,
                raw_context=raw_context,
                analysis=ar.raw_text if ar else "",
                analysis_json=json.dumps(ar.parsed) if ar and ar.parsed else None,
                analysis_error=ar.parse_error if ar else False,
                llm_model=ar.model if ar else "",
                tokens_in=ar.tokens_in if ar else 0,
                tokens_out=ar.tokens_out if ar else 0,
                cost_usd=ar.cost_usd if ar else None,
            )

            # Update cooldown (exponential backoff based on new count)
            new_count = incident.occurrence_count + 1  # incident object is stale; +1 accounts for the occurrence just recorded
            cooldown = min(_effective_debounce(r.namespace) * (2 ** min(new_count, 10)), 43200)
            store.bump_incident(incident.id, cooldown_until=time.time() + cooldown)

            # Alert with escalation prefix
            title = f"{esc.prefix}{r.title}"
            node_metrics, app_metrics = _get_metrics(r, get_node_metrics_fn, get_app_metrics_fn)

            webhook_url = get_webhook_for_namespace(r.namespace)
            post_alert(
                title=title, analysis=analysis_text, severity=r.severity,
                resource=r.resource, namespace=r.namespace,
                event_reason=r.event_reason, node=r.node_name,
                node_metrics=node_metrics, app_metrics=app_metrics,
                model=ar.model if ar else "",
                webhook_url=webhook_url,
            )
            central_push.push_incident({
                "state_key": r.state_key,
                "fingerprint": incident.fingerprint,
                "issue_type": r.issue_type,
                "severity": r.severity,
                "owner_ref": incident.owner_ref,
                "namespace": r.namespace,
                "resource": r.resource,
                "title": r.title,
                "status": incident.status,
                "event_type": "escalation",
                "auto_resolved": False,
                "occurrence_count": incident.occurrence_count + 1,
                "first_seen_at": incident.first_seen_at,
                "last_seen_at": incident.last_seen_at,
                "analysis_json": json.dumps(ar.parsed) if ar and ar.parsed else "",
                "llm_model": ar.model if ar else "",
            })
            fired += 1

        else:
            # New incident
            fp = compute_fingerprint(r.state_key, r.issue_type, r.metadata)
            incident = store.create_incident(
                state_key=r.state_key, fingerprint=fp,
                issue_type=r.issue_type, severity=r.severity,
                owner_ref=r.metadata.get("owner_ref", ""),
            )

            context = _collect_context(r, collect_context_fn)
            raw_context = json.dumps(context) if isinstance(context, dict) else context
            ctx_hash = store.store_context(raw_context)

            if r.skip_llm:
                ar = None
                analysis_text = r.context_override or r.title
            else:
                ar = analyze_alert(context, resource=f"{r.namespace}/{r.resource}")
                analysis_text = _format_analysis(ar)

            store.record_occurrence(
                incident.id,
                context_hash=ctx_hash,
                raw_context=raw_context,
                analysis=ar.raw_text if ar else "",
                analysis_json=json.dumps(ar.parsed) if ar and ar.parsed else None,
                analysis_error=ar.parse_error if ar else False,
                llm_model=ar.model if ar else "",
                tokens_in=ar.tokens_in if ar else 0,
                tokens_out=ar.tokens_out if ar else 0,
                cost_usd=ar.cost_usd if ar else None,
            )

            cooldown = _effective_debounce(r.namespace)
            store.bump_incident(incident.id, cooldown_until=time.time() + cooldown)

            node_metrics, app_metrics = _get_metrics(r, get_node_metrics_fn, get_app_metrics_fn)

            webhook_url = get_webhook_for_namespace(r.namespace)
            post_alert(
                title=r.title, analysis=analysis_text, severity=r.severity,
                resource=r.resource, namespace=r.namespace,
                event_reason=r.event_reason, node=r.node_name,
                node_metrics=node_metrics, app_metrics=app_metrics,
                model=ar.model if ar else "",
                webhook_url=webhook_url,
            )
            central_push.push_incident({
                "state_key": r.state_key,
                "fingerprint": incident.fingerprint,
                "issue_type": r.issue_type,
                "severity": r.severity,
                "owner_ref": incident.owner_ref,
                "namespace": r.namespace,
                "resource": r.resource,
                "title": r.title,
                "status": incident.status,
                "event_type": "new",
                "auto_resolved": False,
                "occurrence_count": incident.occurrence_count,
                "first_seen_at": incident.first_seen_at,
                "last_seen_at": incident.last_seen_at,
                "analysis_json": json.dumps(ar.parsed) if ar and ar.parsed else "",
                "llm_model": ar.model if ar else "",
            })
            fired += 1
            logger.info("New incident: %s (id=%d)", r.state_key, incident.id)

    return fired


def _collect_context(r, collect_context_fn) -> dict:
    """Collect context for a scan result. Returns dict."""
    if r.context_override:
        # context_override could be dict or str
        if isinstance(r.context_override, dict):
            return r.context_override
        return {"raw": r.context_override}

    if collect_context_fn:
        result = collect_context_fn(r.pod_name, r.namespace, r.issue_type)
        if isinstance(result, dict):
            return result
        if result:
            return {"raw": result}

    return {
        "event": {
            "title": r.title,
            "resource": f"{r.namespace}/{r.resource}",
            "issue_type": r.issue_type,
        }
    }


def _get_metrics(r, get_node_metrics_fn, get_app_metrics_fn) -> tuple[str, str]:
    node_metrics = ""
    if r.node_name and get_node_metrics_fn:
        node_metrics = get_node_metrics_fn(r.node_name)
    app_metrics = ""
    if r.pod_name and get_app_metrics_fn:
        app_metrics = get_app_metrics_fn(r.pod_name, r.namespace)
    return node_metrics, app_metrics


def _record_silent_occurrence(store: SqliteStore, incident: Incident, r, collect_context_fn):
    """Record occurrence for acknowledged incident without alerting or calling LLM."""
    context = _collect_context(r, collect_context_fn)
    raw_context = json.dumps(context) if isinstance(context, dict) else context
    ctx_hash = store.store_context(raw_context)
    store.record_occurrence(
        incident.id,
        context_hash=ctx_hash,
        raw_context=raw_context,
    )
    logger.debug("Silent occurrence for acknowledged incident: %s", r.state_key)

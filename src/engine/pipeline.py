"""Shared detect -> dedup -> collect -> analyze -> alert pipeline.

Uses SqliteStore for full incident lifecycle with escalation and structured JSON.
"""
from dataclasses import replace
import json
import logging
import time

from src import config
from src.engine import central_push
from src.engine.critical import (
    matches_critical_service as _matches_critical_service,
    matches_important as _matches_important,
    matches_infra_critical as _matches_infra_critical,
)
from src.engine.enrichment import build_enrichment_blocks
from src.engine.escalation import EscalationResult, check_escalation
from src.engine.fingerprint import compute_fingerprint
from src.engine.llm import analyze_alert, AnalysisResult, llm_configured
from src.engine.notifier import (
    post_alert, post_resolved,
    format_structured_analysis, format_context_summary, get_webhook_for_namespace,
)
from src.engine.sanitizer import sanitize_dict
from src.engine.store import Incident
from src.engine.store.sqlite import SqliteStore

logger = logging.getLogger(__name__)


def _format_analysis(ar: AnalysisResult) -> str:
    """Format AnalysisResult for Slack: structured JSON if available, raw text otherwise."""
    if ar.parsed and not ar.parse_error:
        return format_structured_analysis(ar.parsed)
    return ar.raw_text or "Analysis unavailable"


def _should_skip_ai_mention(incident: Incident, reopened: bool) -> bool:
    """Decide whether to suppress the @ai mention on this re-fire.

    The @ai bot analyses an alert once; subsequent re-tags on chronic
    incidents only burn its context window without adding signal.
    This gate enforces a configurable cooldown
    (`AI_MENTION_REMINDER_HOURS`, default 6h) between @ai mentions for
    the same incident. The alert itself still posts with severity
    critical — the operator sees it in Slack — only the bot tag is
    skipped.

    A reopened incident (resolved → active transition) is treated as a
    fresh incident: even if we tagged @ai within the window for the
    previous active cycle, the new active cycle deserves a fresh
    analysis (the underlying cause may be different).

    Returns True when the mention should be SKIPPED.
    """
    if config.AI_MENTION_REMINDER_HOURS <= 0:
        return False
    if reopened:
        return False
    last = incident.last_ai_mention_at or 0.0
    if last <= 0:
        return False
    window_seconds = config.AI_MENTION_REMINDER_HOURS * 3600
    return (time.time() - last) < window_seconds


def _maybe_record_root_cause(store: SqliteStore, r, incident: Incident) -> None:
    """After a successful Slack post for a critical-service incident,
    register it as the active root-cause marker for its namespace.

    Subsequent non-critical alerts in the same namespace STILL post
    normally (intentional — cascade alerts expose services that aren't
    resilient to dep outages), but gain a correlation hint block
    pointing at the root. See `_root_cause_correlation` in
    engine/enrichment.py.
    """
    if not config.ROOT_CAUSE_CORRELATION_ENABLED:
        return
    if config.ROOT_CAUSE_CORRELATION_SECONDS <= 0:
        return
    # Only infra-tier services are treated as root causes. Business
    # apps (frontend, backend) fail BECAUSE their deps fail; they
    # are symptoms, not roots.
    if not _matches_infra_critical(r.resource, r.pod_name):
        return
    if config.is_nonprod_namespace(r.namespace):
        return
    # Best-effort: Slack post already went out above, so a DB hiccup
    # must not abort the rest of process_scan_results. Dependent alerts
    # will simply miss their correlation hint this cycle.
    try:
        store.record_root_cause(
            namespace=r.namespace,
            root_fingerprint=incident.fingerprint,
            root_state_key=r.state_key,
            root_incident_id=incident.id,
            ttl_seconds=config.ROOT_CAUSE_CORRELATION_SECONDS,
        )
    except Exception:
        logger.error(
            "record_root_cause failed for %s in %s (alert already posted)",
            r.state_key, r.namespace, exc_info=True,
        )
        return
    logger.info(
        "Recorded root cause %s in namespace %s (TTL %ds)",
        r.state_key, r.namespace, config.ROOT_CAUSE_CORRELATION_SECONDS,
    )


def _should_post_slack(ar: AnalysisResult | None, r, is_collective: bool,
                       store=None) -> tuple[bool, str, str]:
    """Determine if an alert should be posted to Slack.

    Routing contract:
      - `critical` → Slack (immediately paging path)
      - `warning` → storage + daily report; Slack ONLY if LLM explicitly set
        `human_needed=True` (which today means a critical_endpoint RCA
        concluded the operator must act despite non-critical classification)
      - `collective_incident` → always Slack (5+ simultaneous issues in one
        namespace is almost always a real outage)

    Earlier behaviour defaulted `human_needed=True` when no LLM verdict was
    available, turning Slack into the default sink for every warning from
    pod / cert / backup / node / endpoint scanners. That also defeated
    `skip_llm=True` protections (rolling-update downgrade in endpoint.py
    never actually suppressed). Warnings now go to storage by default;
    the daily report surfaces them once per day, and the
    persistent-promotion path (3+ occur, age >1h) still auto-upgrades
    chronic warnings into paging-critical so nothing rots forever.

    PVC is NOT on the forced-critical list anymore — the PVC scanner
    already assigns severity by threshold (80%→warning, 90%→critical).
    The blanket promotion made every 82%-full volume page the on-call.
    """
    severity = ar.parsed.get("severity", r.severity) if ar and ar.parsed else r.severity

    # Forced-critical classes. Match on stable identifiers only: resource
    # + pod_name — state_key would mix namespace/reason tokens into the
    # subset match, e.g. ns="api-backend" + workload="gateway-worker"
    # would spuriously match svc "api-gateway". Only INFRA-tier services
    # force critical; business services (frontend, backend, ...)
    # use their scanner-assigned severity.
    if r.issue_type == "critical_endpoint":
        severity = "critical"
    elif _matches_infra_critical(r.resource, r.pod_name):
        severity = "critical"

    # Non-prod: always post to the non-prod webhook. The non-prod Slack
    # channel is by design a lower-priority lane that absorbs develop/
    # staging noise — silencing warnings here would make it useless.
    # The 2x debounce multiplier (NON_PROD_DEBOUNCE_MULTIPLIER) already
    # limits repetition; the Slack gate isn't the right layer to filter
    # further. Routes via get_webhook_for_namespace() at post time.
    if config.is_nonprod_namespace(r.namespace):
        return True, "non-prod → non-prod webhook", severity

    if is_collective:
        return True, "collective incident", severity
    if severity == "critical":
        return True, "critical severity", severity

    # No LLM key: nothing can say human_needed, and there is no daily report to
    # carry the warning either - post it, unanalysed, or nobody ever sees it.
    if ar is None and not r.skip_llm and not llm_configured():
        return True, "no LLM key → posted unanalysed", severity

    # Warning / info path: only post if LLM explicitly said human_needed.
    # This is currently only reachable via critical_endpoint (the one
    # analysis path that runs LLM); every other scanner has ar=None and
    # falls through to the daily-report path below.
    if ar and ar.parsed and ar.parsed.get("human_needed") is True:
        return True, "LLM requested human attention", severity

    return False, f"non-critical (severity={severity}) → daily report", severity


def _max_cooldown(resource: str = "", pod_name: str = "",
                  incident_age_hours: float = 0) -> int:
    """Hard ceiling for exponential cooldown, progressive with incident age.

    Fresh critical incidents fire frequently (30-min cap) so operators
    notice quickly. As the incident ages without resolution, the cap
    grows so a 5-day-old redis OOM doesn't Slack-spam every 30 min:

        age < 1h  → CRITICAL_ALERT_MAX_COOLDOWN_SECONDS (default 30m)
        1–6h      → 2h
        6–24h     → 6h
        > 24h     → 12h

    Non-critical services always decay to 24h (unchanged).
    """
    if _matches_critical_service(resource, pod_name):
        base_cap = config.CRITICAL_ALERT_MAX_COOLDOWN_SECONDS
        if incident_age_hours > 24:
            return max(base_cap, 43200)   # 12h
        if incident_age_hours > 6:
            return max(base_cap, 21600)   # 6h
        if incident_age_hours > 1:
            return max(base_cap, 7200)    # 2h
        return base_cap
    return 86400


def _effective_debounce(namespace: str, resource: str = "", pod_name: str = "") -> int:
    """Base debounce seconds before exponential backoff is applied.

    Three tiers:
      - INFRA_CRITICAL → CRITICAL_ALERT_COOLDOWN_SECONDS (300s default):
        stateful deps, first couple of alerts fire quickly
      - IMPORTANT → IMPORTANT_ALERT_COOLDOWN_SECONDS (600s default):
        business services, faster than default but slower than infra
      - Default → DEBOUNCE_SECONDS (1800s)

    Exponential backoff stacks on top so a long outage doesn't burn
    LLM calls every few minutes forever.
    """
    if _matches_infra_critical(resource, pod_name):
        return config.CRITICAL_ALERT_COOLDOWN_SECONDS
    if _matches_important(resource, pod_name):
        return config.IMPORTANT_ALERT_COOLDOWN_SECONDS
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
    suppressed_noise = 0
    suppressed_cooldown = 0
    maintenance = store.is_maintenance_active()

    # Detect mass events per namespace (likely node maintenance or cluster issue)
    from collections import Counter
    active_results = [r for r in results if not r.auto_resolve and not r.skip_llm]
    ns_counts = Counter(r.namespace for r in active_results)
    mass_ns = {ns for ns, count in ns_counts.items()
               if count >= config.MASS_EVENT_THRESHOLD}

    processed_results = []
    mass_by_ns = {}
    for r in results:
        if r.namespace in mass_ns and not r.auto_resolve and not r.skip_llm:
            mass_by_ns.setdefault(r.namespace, []).append(r)
        else:
            processed_results.append(r)

    for ns, res_list in mass_by_ns.items():
        # Create a representative "Collective" result (Fix 6: replace)
        collective = replace(res_list[0])
        collective.title = f"[Batch] {len(res_list)} incidents in {ns}"
        collective.resource = f"multiple ({len(res_list)})"
        collective.issue_type = "collective_incident"
        collective.severity = "warning"  # LLM will re-evaluate
        # Stable state_key for the batch to allow deduplication via cooldown
        collective.state_key = f"Collective:{ns}"

        # Build collective context as raw text (Fix 1: raw payload)
        lines = [
            f"Collective Incident in namespace: {ns}",
            f"Total events: {len(res_list)}",
            "Affected resources: " + ", ".join(r.resource for r in res_list[:10]),
            "",
            "Recent events in this batch (max 10):"
        ]
        # Fix 7: Cap context gathering
        for r in res_list[:10]:
            ctx = _collect_context(r, collect_context_fn)
            lines.append(f"- {r.resource}: {r.title}")
            if isinstance(ctx, dict):
                # Fix N6: Extract more signal from context
                if "pod" in ctx and isinstance(ctx["pod"], dict):
                    p = ctx["pod"]
                    cs = (p.get("containers") or [{}])[0]
                    lines.append(f"  Pod: {p.get('phase')} ({cs.get('reason', 'N/A')})")
                elif "event" in ctx:
                    lines.append(f"  Info: {ctx['event'].get('resource', '')}")

                logs = ctx.get("logs")
                if logs:
                    lines.append(f"  Last log: {logs[-1][:100]}")

        collective.context_override = {"raw": "\n".join(lines)}
        processed_results.append(collective)

    results = processed_results

    for r in results:
        # Auto-resolve path — always process even in maintenance
        if r.auto_resolve:
            existing = store.get_incident(r.state_key)
            # Acknowledged means a person owns it - not that it stays open once the
            # cause is gone (a resolved alert, a healthy scan).
            if existing and existing.status in ("active", "acknowledged"):
                if not store.set_status(existing.id, "resolved"):
                    # Row disappeared mid-flight (e.g. manual delete via CLI).
                    # Don't emit resolved Slack or ClickHouse push — the
                    # transition didn't actually happen.
                    logger.warning(
                        "Auto-resolve aborted: incident %s not in DB anymore",
                        r.state_key,
                    )
                    continue
                # A scanner closed this, not a person. If it turns out the
                # problem never went away, the reopen must not announce itself
                # as news — see the reopen branch below.
                store.set_resolved_by(existing.id, "auto")
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
                    "active_since": existing.active_since or existing.first_seen_at,
                    "last_seen_at": existing.last_seen_at,
                    "resolved_at": time.time(),
                    "analysis_json": "",
                    "llm_model": "",
                })
                # Notify Slack for critical incidents. Use active_since (start
                # of CURRENT active cycle) so a long-standing flappy state_key
                # doesn't report months of "recovery time" every time it
                # auto-resolves.
                if existing.severity == "critical":
                    duration_min = (time.time() - existing.active_since) / 60
                    post_resolved(
                        state_key=existing.state_key,
                        namespace=r.namespace,
                        resource=r.resource,
                        duration_min=duration_min,
                        last_seen_at=existing.last_seen_at,
                        webhook_url=get_webhook_for_namespace(r.namespace),
                        thread_ts=existing.last_slack_ts or None,
                    )
                # If the resolving incident was a root-cause marker,
                # clear it so dependent alerts in this namespace stop
                # being tagged with the stale correlation. Clear is
                # idempotent — no-op if the incident was never a root.
                # Best-effort: a DB error here must not derail the
                # auto-resolve flow which has already run set_status +
                # central_push + (optionally) Slack recovery post.
                if config.ROOT_CAUSE_CORRELATION_ENABLED:
                    try:
                        store.clear_root_cause(r.namespace, existing.fingerprint)
                    except Exception:
                        logger.error(
                            "clear_root_cause failed for %s in %s",
                            r.state_key, r.namespace, exc_info=True,
                        )
            continue

        if any(w in r.state_key for w in config.ALERT_EXCLUDE_WORKLOADS):
            logger.debug("Skipping excluded workload: %s", r.state_key)
            continue

        if maintenance and not r.skip_llm:
            r.skip_llm = True
            r.context_override = r.context_override or f"LLM analysis skipped — maintenance mode active.\n{r.title}"
            r.title = f"[Maintenance] {r.title}"

        # Non-prod: always the prefix, never the LLM - its cost is kept for production
        if config.is_nonprod_namespace(r.namespace):
            r.context_override = r.context_override or r.title
            prefix = config.nonprod_title_prefix(r.namespace)
            if prefix not in r.title:
                r.title = f"{prefix} {r.title}"
            r.skip_llm = True

        # Owner-level cooldown: if ANY reason for this owner is in cooldown,
        # silently record and skip — except when a new event is critical OR
        # brings a state_key we've never tracked before.
        #
        # Rationale: the owner cooldown exists to dedupe 4-5x LLM calls when
        # one outage surfaces as several state_keys ("backend:crash" +
        # "backend:unhealthy" + "backend:error") within a minute.
        # But it MUST NOT mute a later, severity-escalating event on the
        # same owner. Example: image-pull warning (30 min cooldown) followed
        # by OOMKilled critical five minutes later — the critical must still
        # alert. Likewise a brand-new state_key we've never seen is a
        # distinct incident and deserves first-alert treatment.
        #
        # Bypass predicates mirror `is_hot_path` below so an alert that would
        # route to the hot path on its own merits is never silently muted by
        # a cooldown triggered by some unrelated warning on the same owner.
        # state_key format: "Deployment:ns/name:reason" -> owner_key = "Deployment:ns/name"
        owner_key = r.state_key.rsplit(":", 1)[0] if ":" in r.state_key else r.state_key
        if store.is_owner_in_cooldown(owner_key):
            incident = store.get_incident(r.state_key)
            # "pvc" dropped from this list along with Г — PVC severity is
            # assigned by the scanner's threshold (80%→warning, 90%→critical)
            # and flows through _should_post_slack normally now.
            is_promoted_critical = (
                r.issue_type in ("critical_endpoint", "collective_incident")
                or _matches_critical_service(r.resource, r.pod_name)
            )
            # Also bypass for persistent incidents — a chronic warning that
            # has been firing for hours should not be silently muted by the
            # owner cooldown. check_escalation is a pure function over the
            # incident fields, cheap to call.
            is_persistent_prod = False
            if (incident and not config.is_nonprod_namespace(r.namespace)
                    and not maintenance):
                esc_pre = check_escalation(incident, count_offset=1)
                is_persistent_prod = esc_pre.level == "persistent"
            bypass_for_escalation = (
                r.severity == "critical"
                or is_promoted_critical
                or incident is None
                or is_persistent_prod
            )
            if bypass_for_escalation:
                logger.info(
                    "Bypassing owner cooldown for %s (severity=%s, promoted=%s, new_state_key=%s)",
                    r.state_key, r.severity, is_promoted_critical, incident is None,
                )
            else:
                if incident:
                    # If the stored incident is already resolved but the issue
                    # just came back, flip its status to active *now* so
                    # occurrence_count / last_seen_at don't advance on a
                    # resolved row (which would otherwise surface as a
                    # "resolved incident with 4 recent occurrences" oddity in
                    # the CLI / ClickHouse until the owner cooldown expires
                    # and the main reopen path finally runs).
                    if incident.status == "resolved":
                        if not store.set_status(incident.id, "active",
                                                reset_active_since=True):
                            logger.warning(
                                "Silent reopen failed for %s (row vanished) — "
                                "skipping silent occurrence this tick",
                                r.state_key,
                            )
                            continue
                        # Same provenance rule as the main reopen path: only an
                        # operator resolve earns a cleared cooldown, because only
                        # it claims the problem had actually gone away.
                        if (not config.reopen_provenance_enabled()
                                or (incident.resolved_by or "operator") == "operator"):
                            store.bump_incident(incident.id, cooldown_until=0)
                        refreshed = store.get_incident(r.state_key)
                        if refreshed is None:
                            # Row was deleted between set_status and the refresh
                            # read (cleanup race / operator delete). Don't write
                            # an occurrence against the stale in-memory
                            # incident — next tick will recreate cleanly.
                            logger.warning(
                                "Silent reopen refresh failed for %s (row vanished) — "
                                "skipping silent occurrence this tick",
                                r.state_key,
                            )
                            continue
                        incident = refreshed
                        logger.info(
                            "Silently reopened resolved incident %s during owner cooldown; "
                            "formal re-alert deferred until cooldown clears",
                            r.state_key,
                        )
                    _record_silent_occurrence(store, incident, r, collect_context_fn)
                continue

        # Check existing incident
        incident = store.get_incident(r.state_key)

        if store.is_suppressed(r.state_key, r.namespace, r.issue_type):
            if incident and incident.status == "active":
                _record_silent_occurrence(store, incident, r, collect_context_fn)
            continue

        reopened = False
        if incident:
            # Skip resolved/acknowledged
            if incident.status in ("resolved", "acknowledged"):
                if incident.status == "resolved":
                    # Who closed it decides whether coming back is news.
                    #
                    # An operator resolve means "I fixed this — tell me if it
                    # returns", so a reoccurrence is genuinely new information
                    # and forces a post. A scanner resolve carries no such
                    # claim: a StatefulSet's `mount` incident was closed and reopened
                    # 111/110 times in 48h on one unchanging fingerprint while
                    # the volume stayed locked the whole time, and each reopen
                    # forced a Slack message that no debounce could suppress.
                    #
                    # Empty means legacy or unmigrated, and is read as operator
                    # so an old row keeps behaving exactly as it does today.
                    announce = (
                        not config.reopen_provenance_enabled()
                        or (incident.resolved_by or "operator") == "operator"
                    )
                    # Reoccurrence after resolution → reopen. reset_active_since
                    # so MTTR on the NEXT auto-resolve reports the duration of
                    # this flap, not the lifetime of the state_key (can be
                    # months for recurring flappy incidents like public
                    # endpoints). It also drops the cooldown ceiling back to the
                    # 30-minute tier, which bounds how long a genuinely
                    # worsening incident can stay quiet below.
                    if not store.set_status(incident.id, "active",
                                             reset_active_since=True):
                        # Row gone (e.g. cleanup raced or operator deleted).
                        # Skip this scan tick — the next tick (≤ scanner
                        # interval seconds away) will see no incident for
                        # this state_key and create a brand-new one through
                        # the else-branch below. Forcing the fall-through
                        # here would require restructuring the if/else and
                        # losing the read-once-and-act pattern, so we accept
                        # the one-tick delay.
                        logger.warning(
                            "Reopen skipped: incident %s disappeared before reactivation; "
                            "next scan tick will recreate it",
                            r.state_key,
                        )
                        continue
                    if announce:
                        store.bump_incident(incident.id, cooldown_until=0)  # reset cooldown
                        # Clear the previous active cycle's Slack ts — the fresh
                        # reopen post starts a new top-level thread, not a reply
                        # buried under the long-ago original.
                        try:
                            store.clear_last_slack_ts(incident.id)
                        except Exception:
                            logger.warning("clear_last_slack_ts failed for %s",
                                           r.state_key, exc_info=True)
                        logger.info("Reopened resolved incident: %s", r.state_key)
                    else:
                        # Keep the cooldown and the thread: this is the same
                        # problem we already reported, re-entering its normal
                        # age-decayed reminder schedule rather than announcing
                        # itself as new.
                        logger.info(
                            "Reopened %s (closed by %s) — not announcing, cooldown kept",
                            r.state_key, incident.resolved_by,
                        )
                    # Refresh incident so check_escalation sees updated state
                    incident = store.get_incident(r.state_key)
                    if not incident:
                        continue
                    # `reopened` is what forces the post below; a scanner-closed
                    # incident goes through normal escalation instead.
                    reopened = announce
                else:
                    # Acknowledged → still track but don't alert
                    _record_silent_occurrence(store, incident, r, collect_context_fn)
                    continue

            # Escalation decides whether this occurrence should post to
            # Slack (`should_alert`) and carries the RECURRING/PERSISTENT
            # title prefix. Pure function over the incident fields.
            esc = check_escalation(incident, count_offset=1)
            if reopened:
                # Operator explicitly resolved this — the next occurrence
                # alerts as a fresh incident, not buried by escalation /
                # cooldown logic that is tuned for auto-flow.
                esc = EscalationResult(level=None, should_alert=True, prefix="")

            # Persistent promotion: if the incident has been firing for hours
            # without resolution, promote to critical so @ai is tagged and
            # an operator gets a fresh investigation. Without this, a chronic
            # warning would stay at warning severity forever.
            # Skip non-prod / maintenance — don't tag @ai on staging noise.
            if (esc.level == "persistent"
                    and r.severity != "critical"
                    and not r.never_promote
                    and not config.is_nonprod_namespace(r.namespace)
                    and not maintenance):
                r.severity = "critical"
                logger.info("Persistent incident promoted to critical: %s", r.state_key)

            if not esc.should_alert:
                # Still track the detection (bumps count for future escalation).
                # Pass raw_context so get_latest_raw_context_by_state_key can
                # find it — daily-enrichment current_snapshot depends on this.
                context = _collect_context(r, collect_context_fn)
                raw_context = json.dumps(context) if isinstance(context, dict) else context
                ctx_hash = store.store_context(raw_context)
                _record_occurrence(store, incident.id, r.state_key,
                                   context_hash=ctx_hash, raw_context=raw_context,
                                   batch_status="immediate")
                new_count = incident.occurrence_count + 1
                base_debounce = _effective_debounce(r.namespace, r.resource, r.pod_name)
                age_h = (time.time() - incident.active_since) / 3600
                cooldown = min(base_debounce * (2 ** min(new_count, 10)),
                               _max_cooldown(r.resource, r.pod_name, age_h))
                store.bump_incident(incident.id, cooldown_until=time.time() + cooldown)
                logger.debug("Skipped alert for %s (incident #%d, count=%d, cooldown=%ds): %s",
                             r.state_key, incident.id, new_count, cooldown, esc)
                suppressed_cooldown += 1
                continue

            # Single unified alert path: collect context, analyze (unless
            # r.skip_llm - non-prod, maintenance - or no LLM key), render, post.
            context = _collect_context(r, collect_context_fn)
            raw_context = json.dumps(context) if isinstance(context, dict) else context
            ctx_hash = store.store_context(raw_context)

            if r.skip_llm or not llm_configured():
                ar = None
                analysis_text = (
                    format_context_summary(context) if isinstance(context, dict)
                    else (r.context_override or r.title)
                )
            else:
                ar = analyze_alert(context, resource=owner_key)
                analysis_text = _format_analysis(ar)

            # Enrichment: flap history, blast radius, deploy info, directives
            enrichment = build_enrichment_blocks(store, incident, r, context)
            if enrichment:
                analysis_text = f"{analysis_text}\n\n{enrichment}"

            occurrence_id = _record_occurrence(
                store, incident.id, r.state_key,
                context_hash=ctx_hash,
                raw_context=raw_context,
                analysis=ar.raw_text if ar else "",
                analysis_json=json.dumps(ar.parsed) if ar and ar.parsed else None,
                analysis_error=ar.parse_error if ar else False,
                llm_model=ar.model if ar else "",
                tokens_in=ar.tokens_in if ar else None,
                tokens_out=ar.tokens_out if ar else None,
                cost_usd=ar.cost_usd if ar else None,
                batch_status="immediate",
            )

            new_count = incident.occurrence_count + 1
            base_debounce = _effective_debounce(r.namespace, r.resource, r.pod_name)
            age_h = (time.time() - incident.active_since) / 3600
            cooldown = min(base_debounce * (2 ** min(new_count, 10)),
                           _max_cooldown(r.resource, r.pod_name, age_h))
            store.bump_incident(incident.id, cooldown_until=time.time() + cooldown)

            title = f"{esc.prefix}{r.title}"

            webhook_url = get_webhook_for_namespace(r.namespace)

            # Smart Noise Reduction (Fix 10: unified helper)
            is_collective = r.issue_type == "collective_incident"
            should_post, reason, final_sev = _should_post_slack(ar, r, is_collective, store)

            # Sync severity if re-evaluated (Source of truth fix N4)
            if final_sev != incident.severity:
                store.set_severity(incident.id, final_sev)
                logger.info("Incident severity re-evaluated for %s: %s -> %s", r.state_key, incident.severity, final_sev)

            # Refresh incident from DB — record_occurrence() and bump_incident()
            # updated last_seen_at (and set_severity may have touched severity)
            # since we last read it. Using the stale in-memory copy would push
            # wrong last_seen_at / status to ClickHouse.
            refreshed = store.get_incident(r.state_key)
            if refreshed is None:
                # Row was deleted between our writes and this refresh
                # (manual cleanup or another concurrent writer). Skip the
                # ClickHouse push so we don't store inconsistent state, but
                # the Slack post still goes out below — the operator already
                # got the alert through the in-memory analysis.
                logger.warning(
                    "Skipping central_push for %s: incident row vanished after writes",
                    r.state_key,
                )
            else:
                incident = refreshed
                # Push to central ClickHouse AFTER severity re-evaluation so the
                # central aggregator sees the same severity that operators see
                # in Slack — not the pre-LLM scanner severity.
                central_push.push_incident({
                    "state_key": r.state_key,
                    "fingerprint": incident.fingerprint,
                    "issue_type": r.issue_type,
                    "severity": final_sev,
                    "owner_ref": incident.owner_ref,
                    "namespace": r.namespace,
                    "resource": r.resource,
                    "title": r.title,
                    "status": incident.status,
                    "event_type": "escalation",
                    "auto_resolved": False,
                    "occurrence_count": incident.occurrence_count,
                    "first_seen_at": incident.first_seen_at,
                    "active_since": incident.active_since or incident.first_seen_at,
                    "last_seen_at": incident.last_seen_at,
                    "analysis_json": json.dumps(ar.parsed) if ar and ar.parsed else "",
                    "llm_model": ar.model if ar else "",
                })


            if not should_post:
                logger.info("Skipping Slack alert for %s: %s", r.state_key, reason)
                suppressed_noise += 1
                # Hand it to the hourly digest. Withheld is not the same as
                # discarded — without this the gates above would be silencing.
                if config.hourly_digest_enabled():
                    store.mark_occurrence_pending(occurrence_id)
            else:
                node_metrics, app_metrics = _get_metrics(r, get_node_metrics_fn, get_app_metrics_fn)
                # @ai mention cooldown (AI_MENTION_REMINDER_HOURS): for
                # chronic critical re-fires, skip the @ai tag if we
                # already tagged it recently — the bot already analysed
                # this incident, re-tagging every cooldown cycle burns
                # its context and adds no new signal. First fire of a
                # reopened incident always re-tags (it's effectively a
                # new incident from the bot's POV).
                skip_ai = _should_skip_ai_mention(incident, reopened)
                # Thread recurring/persistent alerts under the original
                # first-fire message (bot API path only; empty last_slack_ts
                # = no ts stored = webhook path or pre-bot deployment →
                # normal top-level post).
                posted_ts = post_alert(
                    title=title, analysis=analysis_text, severity=final_sev,
                    resource=r.resource, namespace=r.namespace,
                    event_reason=r.event_reason, node=r.node_name,
                    node_metrics=node_metrics, app_metrics=app_metrics,
                    model=ar.model if ar else "",
                    webhook_url=webhook_url,
                    thread_ts=(incident.last_slack_ts or None) if not reopened else None,
                    skip_ai_mention=skip_ai,
                )
                # Record the @ai mention timestamp for cooldown gating
                # on future re-fires. Only bump when:
                #   (a) the mention was actually included in the payload
                #       (critical severity + not skipped + mention set),
                #   (b) AND Slack delivery succeeded (posted_ts is not None).
                # post_alert returns None on total delivery failure
                # (no transport OR both bot+webhook failed → console only);
                # we must not lock in cooldown on an alert nobody saw.
                delivered = posted_ts is not None
                if (delivered and final_sev == "critical"
                        and not skip_ai and config.SLACK_CRITICAL_MENTION):
                    try:
                        store.bump_ai_mention(incident.id)
                    except Exception:
                        logger.warning("bump_ai_mention failed for %s",
                                       r.state_key, exc_info=True)
                # Persist the returned ts whenever this post established a
                # fresh thread root — i.e. the bot API returned a
                # top-level (non-thread) ts. That happens when:
                #   (a) reopened: we explicitly cleared last_slack_ts above
                #       and the post goes top-level; OR
                #   (b) pre-existing incident with empty last_slack_ts
                #       (e.g. created before bot API was rolled out, or
                #       first successful bot post after webhook era). Without
                #       stashing here, future recurrences of this incident
                #       would ALSO go top-level instead of threading.
                # When last_slack_ts is already set AND not reopened, the
                # posted_ts is a thread-reply ts — must NOT overwrite the
                # root ts with the reply ts (future recurrences would then
                # thread under the reply instead of the root).
                if posted_ts and (reopened or not incident.last_slack_ts):
                    try:
                        store.set_last_slack_ts(incident.id, posted_ts)
                    except Exception:
                        logger.warning("set_last_slack_ts failed for %s",
                                       r.state_key, exc_info=True)
                fired += 1
                _maybe_record_root_cause(store, r, incident)

        else:
            # New incident
            fp = compute_fingerprint(r.state_key, r.issue_type, r.metadata)

            # Net-new fingerprint: a failure mode we've never seen before.
            # Promote to critical so @ai gets tagged and investigates the
            # unknown. Known fingerprints (even from resolved incidents) are
            # not promoted — we've seen that pattern before and the operator
            # already handled it at least once.
            # Skip non-prod / maintenance — don't tag @ai on staging noise.
            is_net_new = not store.is_fingerprint_known(fp)
            if (is_net_new
                    and r.severity != "critical"
                    and not r.never_promote
                    and not config.is_nonprod_namespace(r.namespace)
                    and not maintenance):
                logger.info("Net-new fingerprint %s promoted to critical: %s",
                            fp[:12], r.state_key)
                r.severity = "critical"
                r.title = f"\U0001f195 {r.title}"

            incident = store.create_incident(
                state_key=r.state_key, fingerprint=fp,
                issue_type=r.issue_type, severity=r.severity,
                namespace=r.namespace,
                owner_ref=r.metadata.get("owner_ref", ""),
            )

            # Single unified alert path for new incidents: the LLM analyzes
            # unless r.skip_llm (non-prod, maintenance) or there is no LLM key.
            context = _collect_context(r, collect_context_fn)
            raw_context = json.dumps(context) if isinstance(context, dict) else context
            ctx_hash = store.store_context(raw_context)

            if r.skip_llm or not llm_configured():
                ar = None
                analysis_text = (
                    format_context_summary(context) if isinstance(context, dict)
                    else (r.context_override or r.title)
                )
            else:
                ar = analyze_alert(context, resource=owner_key)
                analysis_text = _format_analysis(ar)

            # Enrichment: blast radius, deploy info, directives (flap history
            # will show "First occurrence" for a brand-new incident).
            enrichment = build_enrichment_blocks(store, incident, r, context)
            if enrichment:
                analysis_text = f"{analysis_text}\n\n{enrichment}"

            occurrence_id = _record_occurrence(
                store, incident.id, r.state_key,
                context_hash=ctx_hash,
                raw_context=raw_context,
                analysis=ar.raw_text if ar else "",
                analysis_json=json.dumps(ar.parsed) if ar and ar.parsed else None,
                analysis_error=ar.parse_error if ar else False,
                llm_model=ar.model if ar else "",
                tokens_in=ar.tokens_in if ar else None,
                tokens_out=ar.tokens_out if ar else None,
                cost_usd=ar.cost_usd if ar else None,
                batch_status="immediate",
            )

            cooldown = _effective_debounce(r.namespace, r.resource, r.pod_name)
            store.bump_incident(incident.id, cooldown_until=time.time() + cooldown)

            webhook_url = get_webhook_for_namespace(r.namespace)

            # Smart Noise Reduction (Fix 10: unified helper)
            is_collective = r.issue_type == "collective_incident"
            should_post, reason, severity = _should_post_slack(ar, r, is_collective, store)

            # Sync severity if re-evaluated (Source of truth fix N4)
            if severity != incident.severity:
                store.set_severity(incident.id, severity)
                logger.info("Incident severity re-evaluated for %s: %s -> %s", r.state_key, incident.severity, severity)

            # Refresh incident from DB — record_occurrence() and bump_incident()
            # updated last_seen_at (and set_severity may have touched severity)
            # since we created it. If the row vanished between writes (rare:
            # manual cleanup, concurrent writer), skip the central push so we
            # don't store stale state.
            refreshed = store.get_incident(r.state_key)
            if refreshed is None:
                logger.warning(
                    "Skipping central_push for new incident %s: row vanished after writes",
                    r.state_key,
                )
            else:
                incident = refreshed
                # Push to central ClickHouse AFTER severity re-evaluation.
                # occurrence_count comes from the refreshed row (which is 1
                # for a brand-new incident that just had its first occurrence
                # recorded).
                central_push.push_incident({
                    "state_key": r.state_key,
                    "fingerprint": incident.fingerprint,
                    "issue_type": r.issue_type,
                    "severity": severity,
                    "owner_ref": incident.owner_ref,
                    "namespace": r.namespace,
                    "resource": r.resource,
                    "title": r.title,
                    "status": incident.status,
                    "event_type": "new",
                    "auto_resolved": False,
                    "occurrence_count": incident.occurrence_count,
                    "first_seen_at": incident.first_seen_at,
                    "active_since": incident.active_since or incident.first_seen_at,
                    "last_seen_at": incident.last_seen_at,
                    "analysis_json": json.dumps(ar.parsed) if ar and ar.parsed else "",
                    "llm_model": ar.model if ar else "",
                })


            if not should_post:
                logger.info("Skipping Slack alert for new incident %s: %s", r.state_key, reason)
                suppressed_noise += 1
                if config.hourly_digest_enabled():
                    store.mark_occurrence_pending(occurrence_id)
            else:
                node_metrics, app_metrics = _get_metrics(r, get_node_metrics_fn, get_app_metrics_fn)
                # First fire — no thread yet, no prior @ai mention to
                # cooldown against. Capture the posted ts so future
                # recurrences of this same state_key can reply to this
                # message rather than spamming new top-level ones.
                posted_ts = post_alert(
                    title=r.title, analysis=analysis_text, severity=severity,
                    resource=r.resource, namespace=r.namespace,
                    event_reason=r.event_reason, node=r.node_name,
                    node_metrics=node_metrics, app_metrics=app_metrics,
                    model=ar.model if ar else "",
                    webhook_url=webhook_url,
                    # First fire — @ai gets its initial analysis
                    # opportunity, regardless of any cooldown state
                    # that migrated in from an old row.
                    skip_ai_mention=False,
                )
                if posted_ts:
                    try:
                        store.set_last_slack_ts(incident.id, posted_ts)
                    except Exception:
                        logger.warning("set_last_slack_ts failed for %s",
                                       r.state_key, exc_info=True)
                # Bump @ai mention timestamp only when Slack delivery
                # actually succeeded — otherwise we'd lock in cooldown
                # for an alert that fell through to console only.
                delivered = posted_ts is not None
                if delivered and severity == "critical" and config.SLACK_CRITICAL_MENTION:
                    try:
                        store.bump_ai_mention(incident.id)
                    except Exception:
                        logger.warning("bump_ai_mention failed for %s",
                                       r.state_key, exc_info=True)
                fired += 1
                _maybe_record_root_cause(store, r, incident)
            logger.info("New incident: %s (id=%d)", r.state_key, incident.id)

    if fired > 0 or suppressed_noise > 0 or suppressed_cooldown > 0:
        logger.info("Scan cycle complete: fired=%d, suppressed_noise=%d, suppressed_cooldown=%d",
                    fired, suppressed_noise, suppressed_cooldown)

    return fired


def _collect_context(r, collect_context_fn) -> dict:
    """Collect context for a scan result. Returns dict.

    Sanitizes the result — on the `skip_llm=True` path the pipeline
    renders context directly via `format_context_summary` and writes it
    to `context_store`; the LLM path (`analyze_alert`) re-sanitizes
    idempotently. Centralising sanitization here guarantees that every
    `context_override` payload (e.g. flux_context, endpoint probe
    details, backup manifests) is redacted before it reaches Slack or
    the SQLite store, regardless of which scanner produced it.
    """
    if r.context_override:
        # context_override could be dict or str
        ctx = r.context_override if isinstance(r.context_override, dict) else {"raw": r.context_override}
        return sanitize_dict(ctx)

    if collect_context_fn:
        result = collect_context_fn(r.pod_name, r.namespace, r.issue_type)
        if isinstance(result, dict):
            return sanitize_dict(result)
        if result:
            return sanitize_dict({"raw": result})

    # Final fallback — minimal event payload built from ScanResult
    # metadata (title / resource / namespace / issue_type). These
    # fields are K8s object names and scanner-controlled strings, so
    # in practice they don't contain secrets — but sanitize defensively
    # so every return path from this function passes through the same
    # redaction filter, no exceptions.
    return sanitize_dict({
        "event": {
            "title": r.title,
            "resource": f"{r.namespace}/{r.resource}",
            "issue_type": r.issue_type,
        }
    })


def _get_metrics(r, get_node_metrics_fn, get_app_metrics_fn) -> tuple[str, str]:
    node_metrics = ""
    if r.node_name and get_node_metrics_fn:
        node_metrics = get_node_metrics_fn(r.node_name)
    app_metrics = ""
    if r.pod_name and get_app_metrics_fn:
        app_metrics = get_app_metrics_fn(r.pod_name, r.namespace)
    return node_metrics, app_metrics


def _record_occurrence(store: SqliteStore, incident_id: int, state_key: str,
                       **kw) -> int | None:
    """Record the occurrence locally AND mirror it into its hour bucket.

    The two halves have to describe the same set of events. occurrence_count is
    what the board shows as the lifetime total; the hour buckets are what it
    shows as Today / 7d. Push from only some of the recording paths — the
    alerting ones, say, but not the cooldown-suppressed or acknowledged ones —
    and the windows silently undercount against the total sitting in the
    tooltip beside them, which is worse than having no windows at all.

    Every caller that records goes through here, so there is one place to be
    wrong rather than four.

    The return type is declared rather than inferred on purpose: leaving it off
    makes this return Any, which silently swallows the two long-standing
    `int | None` -> `int` errors mypy reports at the mark_occurrence_pending
    calls downstream. Hiding existing debt behind a new helper is not the same
    as paying it.
    """
    occurrence_id = store.record_occurrence(incident_id, **kw)
    central_push.push_occurrence_hour(state_key)
    return occurrence_id


# Last central heartbeat per state_key. In-memory on purpose: losing it costs
# one extra push after a restart, which is the harmless direction. Persisting a
# "recently pushed" marker that outlives the process would recreate the very
# staleness this heartbeat exists to prevent.
_last_heartbeat_push: dict[str, float] = {}


def _evict_stale_heartbeats(now: float, interval: int) -> None:
    """Drop entries that no longer throttle anything.

    An entry at least `interval` old already fails the throttle check, so
    removing it changes no behaviour — it only stops the map growing for the
    life of the process. That matters because a `Pod:{ns}/{name}` state_key
    carries a pod name, and pod names churn without bound: a long-lived monitor
    on a cluster with rolling deploys would accumulate an entry per pod that
    was ever suppressed, forever.
    """
    stale = [k for k, ts in _last_heartbeat_push.items() if now - ts >= interval]
    for key in stale:
        del _last_heartbeat_push[key]


def _push_central_heartbeat(store: SqliteStore, r) -> None:
    """Keep the central row's clock honest while an incident is suppressed.

    A suppressed occurrence updates SQLite and nothing else, so ClickHouse kept
    whatever was last pushed - for an incident the scanner was still
    detecting on every cycle, the central copy fell days and thousands of
    occurrences behind. On the dashboard that live outage was
    indistinguishable from a fossil — an incident whose condition is long gone
    but which nothing ever closed. Telling those two apart is the whole job of
    the dashboard, and a frozen timestamp makes it impossible.

    Throttled to CENTRAL_HEARTBEAT_INTERVAL_SECONDS per incident: the scan loop
    runs every few minutes and a chronic incident would otherwise write a row
    per cycle forever. Sends no Slack, calls no LLM, changes no severity.
    """
    interval = config.CENTRAL_HEARTBEAT_INTERVAL_SECONDS
    if interval <= 0:
        return
    now = time.time()
    _evict_stale_heartbeats(now, interval)
    if now - _last_heartbeat_push.get(r.state_key, 0.0) < interval:
        return

    # Re-read: the occurrence was just recorded, so the caller's copy is stale
    # by exactly the two fields this push exists to carry. Guarded like the push
    # below, and for the same reason: SQLite raises on lock contention and disk
    # errors, and a heartbeat is the last thing _record_silent_occurrence does,
    # so an escaping OperationalError would abort the scan cycle mid-way through
    # incidents that still need handling.
    try:
        fresh = store.get_incident(r.state_key)
    except Exception:
        logger.warning(
            "Central heartbeat refresh failed for %s", r.state_key, exc_info=True,
        )
        return
    if fresh is None or fresh.status != "active":
        return

    try:
        central_push.push_incident({
            "state_key": r.state_key,
            "fingerprint": fresh.fingerprint,
            "issue_type": r.issue_type,
            "severity": fresh.severity,
            "owner_ref": fresh.owner_ref,
            "namespace": r.namespace,
            "resource": r.resource,
            "title": r.title,
            "status": fresh.status,
            # Not an alert. Nothing filters on event_type, and collectors/daily
            # already writes its own value ("currently_active"), so a distinct
            # label keeps heartbeats greppable without changing any behaviour.
            "event_type": "heartbeat",
            "auto_resolved": False,
            "occurrence_count": fresh.occurrence_count,
            "first_seen_at": fresh.first_seen_at,
            # Every other push_incident call carries this, and omitting it is
            # not neutral: the column DEFAULTs to first_seen_at, so under
            # ReplacingMergeTree a heartbeat row would REPLACE a good one and
            # silently reset the start of the current active cycle on any
            # incident that had been reopened.
            "active_since": fresh.active_since or fresh.first_seen_at,
            "last_seen_at": fresh.last_seen_at,
            "analysis_json": "",
            "llm_model": "",
        })
    except Exception:
        # Best-effort. Failing to refresh a timestamp must never take down the
        # scan cycle that is still handling real incidents.
        logger.warning(
            "Central heartbeat push failed for %s", r.state_key, exc_info=True,
        )
        return

    _last_heartbeat_push[r.state_key] = now
    logger.debug("Central heartbeat for suppressed incident: %s", r.state_key)


def _record_silent_occurrence(store: SqliteStore, incident: Incident, r, collect_context_fn):
    """Record occurrence for acknowledged incident without alerting or calling LLM."""
    context = _collect_context(r, collect_context_fn)
    raw_context = json.dumps(context) if isinstance(context, dict) else context
    ctx_hash = store.store_context(raw_context)
    _record_occurrence(
        store, incident.id, r.state_key,
        context_hash=ctx_hash,
        raw_context=raw_context,
    )
    logger.debug("Silent occurrence for acknowledged incident: %s", r.state_key)
    _push_central_heartbeat(store, r)

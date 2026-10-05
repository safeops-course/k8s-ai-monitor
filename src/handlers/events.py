"""Warning K8s event handler — extracted from handlers.py."""
import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone

import kopf
from kubernetes import client as k8s

from src import config
from src.engine.constants import IMPORTANT_EVENT_REASONS, PROBLEM_ALIASES, CONTAINER_STATUS_REASONS
from src.engine.critical import matches_critical_service
from src.engine.owner import owner_fully_available, resolve_owner_key_by_name
from src.engine.pipeline import process_scan_results
from src.engine.sanitizer import sanitize_value
from src.collectors import Collector
from src.collectors.node import get_node_metrics_summary
from src.collectors.app_metrics import get_app_metrics_summary
from src.scanners._base import ScanResult

logger = logging.getLogger(__name__)

_startup_time = time.time()
_STARTUP_GRACE_SECONDS = 30

# In-flight state keys to prevent duplicate concurrent alerts
_in_flight: set[str] = set()

# Cap raw event messages before they land in context_override (SQLite / Slack /
# ClickHouse). Shared by the Elasticsearch and general Warning-event paths.
_MESSAGE_CAP = 1024

_collector: Collector | None = None

# Batching for all pod Warning events (groups by namespace, flushes after window)
_pod_event_batch: dict[str, list] = {}   # ns -> [(pod_name, owner_key, state_key, node, display_reason)]
_pod_event_batch_lock = asyncio.Lock()
_pod_event_batch_task: dict[str, asyncio.Task] = {}  # ns -> pending flush task
_BATCH_WINDOW_SECONDS = 30
_BATCH_THRESHOLD = 3  # min events to trigger batch mode

# Flux resource kinds — source-level (informational only, skip) and deployment-level (grace period)
_FLUX_SOURCE_KINDS = {"HelmRepository", "HelmChart", "GitRepository", "OCIRepository"}
_FLUX_KINDS = {"HelmRelease", "Kustomization"}

# Transient infra reasons: CNI/sandbox errors that often self-resolve within seconds
_TRANSIENT_INFRA_REASONS = {
    "FailedCreatePodSandBox", "FailedCreatePodContainer",
    "NetworkNotReady", "FailedSync",
}
_TRANSIENT_GRACE_SECONDS = 90

# Image pull errors: often transient (DNS blip, registry throttle, network hiccup)
_IMAGE_PULL_REASONS = {"ErrImagePull", "ImagePullBackOff"}
_IMAGE_PULL_GRACE_SECONDS = config.IMAGE_PULL_GRACE_SECONDS

# Deferred auto-resolve: after alerting on a pod event, wait a short
# grace and check if the owner deployment recovered — emit an
# auto_resolve ScanResult so the pipeline flips the incident to
# resolved + posts a Slack recovery. Much faster than waiting for the
# pod scanner's 1800s tick; pipeline handles the Slack post + central
# push + root-cause clearing automatically.
_AUTO_RESOLVE_DELAY = config.EVENT_AUTO_RESOLVE_DELAY_SECONDS


# Moved to src/engine/owner.py so the engine layer can use it without importing
# from handlers. Kept under the old private name because this module's callers
# and their tests patch `src.handlers.events._is_owner_healthy`.
_is_owner_healthy = owner_fully_available


async def _deferred_auto_resolve(alerted: list[tuple[str, str, str]]):
    """Wait, then emit auto_resolve ScanResults for owners that recovered.

    The pipeline consumes auto_resolve=True ScanResults in its existing
    path (`pipeline.py:_process_auto_resolve_results`): flips incident
    status to resolved, posts `post_resolved` for critical severity,
    clears root-cause marker, and pushes the resolved event to central
    ClickHouse. Before the shared pipeline this function called
    `store.set_status` + `post_resolved` directly; post-migration it
    funnels through the same pipeline branch that scanner-emitted
    auto-resolves use.

    Args:
        alerted: list of (state_key, namespace, owner_key) for fired alerts.
    """
    await asyncio.sleep(_AUTO_RESOLVE_DELAY)
    from src.handlers.startup import get_store
    store = get_store()
    loop = asyncio.get_running_loop()

    to_resolve: list[ScanResult] = []
    for state_key, namespace, owner_key in alerted:
        try:
            incident = await loop.run_in_executor(None, store.get_incident, state_key)
            if not incident or incident.status not in ("active", "acknowledged"):
                continue
            healthy = await loop.run_in_executor(None, _is_owner_healthy, owner_key, namespace)
            if not healthy:
                continue
            resource = owner_key.split(":", 1)[-1] if ":" in owner_key else owner_key
            to_resolve.append(ScanResult(
                state_key=state_key,
                title=f"Resolved: {state_key}",
                severity="info",
                resource=resource,
                namespace=namespace,
                issue_type=incident.issue_type,
                auto_resolve=True,
            ))
        except Exception:
            logger.warning("Deferred auto-resolve check failed for %s", state_key, exc_info=True)

    if to_resolve:
        try:
            await loop.run_in_executor(
                None, lambda: process_scan_results(
                    to_resolve, store, None,
                    get_node_metrics_summary, get_app_metrics_summary,
                ),
            )
        except Exception:
            logger.warning("Deferred auto-resolve pipeline dispatch failed", exc_info=True)


def _log_task_exception(task: asyncio.Task) -> None:
    """Done-callback for fire-and-forget tasks — surface any unretrieved
    exception in our own logger rather than letting asyncio emit a
    terse "Task exception was never retrieved" default warning.

    Cancellation is expected during shutdown and not an error.
    """
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.error("Background task %r failed", task.get_name(), exc_info=exc)


def _get_collector() -> Collector:
    global _collector
    if _collector is None:
        _collector = Collector()
    return _collector


def _infer_reason_from_message(event_reason: str, message: str) -> str:
    msg = message.lower()
    if event_reason == "BackOff":
        if "pulling image" in msg or "image" in msg:
            return "ImagePullBackOff"
        if "restarting failed container" in msg:
            return "CrashLoopBackOff"
    elif event_reason == "Failed":
        if "failed to pull image" in msg or "pull image" in msg:
            return "ErrImagePull"
        if "not found" in msg and "configmap" in msg:
            return "CreateContainerConfigError"
        if "not found" in msg and "secret" in msg:
            return "CreateContainerConfigError"
        if "failed to create" in msg:
            return "CreateContainerError"
    return event_reason


def _get_pod_status_reason(namespace: str, pod_name: str) -> tuple[str, str]:
    try:
        core = k8s.CoreV1Api()
        pod = core.read_namespaced_pod(pod_name, namespace)
        node = pod.spec.node_name or ""

        for cs in (pod.status.container_statuses or []):
            if cs.state and cs.state.waiting and cs.state.waiting.reason in CONTAINER_STATUS_REASONS:
                return cs.state.waiting.reason, node
            if cs.state and cs.state.terminated and cs.state.terminated.reason in CONTAINER_STATUS_REASONS:
                return cs.state.terminated.reason, node
            if cs.last_state and cs.last_state.terminated and cs.last_state.terminated.reason == "OOMKilled":
                finished = cs.last_state.terminated.finished_at
                if finished:
                    from datetime import datetime, timezone
                    age_h = (datetime.now(timezone.utc) - finished).total_seconds() / 3600
                    if age_h > 12:
                        continue  # Stale OOMKill — pod has recovered
                return "OOMKilled", node

        return "", node
    except Exception:
        return "", ""


def _is_pod_still_pending(namespace: str, pod_name: str) -> bool:
    try:
        core = k8s.CoreV1Api()
        pod = core.read_namespaced_pod(pod_name, namespace)
        return pod.status.phase == "Pending"
    except k8s.ApiException as e:
        if e.status == 404:
            return False
        return True
    except Exception:
        logger.error("_is_pod_still_pending failed for %s/%s", namespace, pod_name, exc_info=True)
        return True


def _get_elasticsearch_health(namespace: str, name: str) -> str:
    """Read the ECK Elasticsearch status.health, normalized to one of:
    "yellow"/"red" (actionable), "unknown" (green/empty/missing/404 — benign,
    skip), or "error" (read failed — do NOT treat as recovered).

    Used to re-check whether an "Unhealthy: cluster health degraded" event was a
    transient blip (recovered to green) or a persistent degrade worth alerting.
    """
    try:
        custom = k8s.CustomObjectsApi()
        obj = custom.get_namespaced_custom_object(
            "elasticsearch.k8s.elastic.co", "v1", namespace, "elasticsearches", name,
        )
        health = ((obj.get("status") or {}).get("health") or "").lower()
        # Only yellow/red are actionable; collapse green/empty/unknown/anything
        # unexpected to "unknown" (the caller skips on both green and unknown).
        return health if health in ("yellow", "red") else "unknown"
    except k8s.ApiException as e:
        if e.status == 404:
            # CR is gone — genuinely nothing to alert on, treat as resolved.
            logger.debug("_get_elasticsearch_health: %s/%s not found (404) — treating as resolved", namespace, name)
            return "unknown"
        # A failed read must NOT be mistaken for "recovered" — return a distinct
        # sentinel so the caller forwards the Unhealthy event instead of skipping.
        logger.warning("_get_elasticsearch_health read failed for %s/%s: %s", namespace, name, e.reason)
        return "error"
    except Exception:
        logger.error("_get_elasticsearch_health read failed for %s/%s", namespace, name, exc_info=True)
        return "error"


def _pod_exists(namespace: str, pod_name: str) -> bool:
    """Return True only if pod exists and is NOT being terminated."""
    try:
        core = k8s.CoreV1Api()
        pod = core.read_namespaced_pod(pod_name, namespace)
        if pod.metadata.deletion_timestamp is not None:
            return False  # Terminating — treat as gone
        return True
    except k8s.ApiException as e:
        if e.status == 404:
            return False
        return True
    except Exception:
        logger.error("_pod_exists failed for %s/%s", namespace, pod_name, exc_info=True)
        return True


_MIN_UNHEALTHY_GRACE = 30
_MAX_UNHEALTHY_GRACE = 600


def _get_probe_grace_seconds(namespace: str, pod_name: str) -> tuple[int, float | None]:
    """Calculate grace period from pod probe config.

    Returns (grace_seconds, pod_age_seconds) where grace_seconds is the max
    startup budget across all containers/probes, and pod_age_seconds is the
    pod's age (None when the pod cannot be read — caller treats that as "not
    young" and alerts immediately, fail-loud).
    """
    try:
        core = k8s.CoreV1Api()
        pod = core.read_namespaced_pod(pod_name, namespace)
    except k8s.ApiException as e:
        if e.status == 404:
            # Pod already gone (rollout replaced it) — routine, not a failure.
            logger.debug("Probe grace: pod %s/%s not found", namespace, pod_name)
        else:
            logger.warning("Probe grace: pod read failed for %s/%s: %s",
                           namespace, pod_name, e)
        return _MIN_UNHEALTHY_GRACE, None
    except Exception:
        logger.warning("Probe grace: unexpected error reading pod %s/%s",
                       namespace, pod_name, exc_info=True)
        return _MIN_UNHEALTHY_GRACE, None

    # Calculate max probe startup budget across all containers
    max_budget = _MIN_UNHEALTHY_GRACE
    for c in (pod.spec.containers or []):
        if c.startup_probe:
            p = c.startup_probe
            budget = (p.initial_delay_seconds or 0) + \
                     (p.failure_threshold or 3) * (p.period_seconds or 10)
            max_budget = max(max_budget, budget)
        else:
            # No startup probe: liveness/readiness start immediately
            for probe in (c.liveness_probe, c.readiness_probe):
                if probe:
                    budget = (probe.initial_delay_seconds or 0) + \
                             (probe.failure_threshold or 3) * (probe.period_seconds or 10)
                    max_budget = max(max_budget, budget)

    grace = min(max_budget + 10, _MAX_UNHEALTHY_GRACE)  # +10s buffer, cap at 10 min

    created = pod.metadata.creation_timestamp
    if created:
        if hasattr(created, 'tzinfo') and created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - created).total_seconds()
        return grace, age

    return grace, None


def _is_pod_ready_now(namespace: str, pod_name: str) -> bool:
    """Return True if all containers in the pod are Ready."""
    try:
        core = k8s.CoreV1Api()
        pod = core.read_namespaced_pod(pod_name, namespace)
        statuses = pod.status.container_statuses if pod.status else None
        if not statuses:
            return False
        return all(cs.ready for cs in statuses)
    except Exception:
        return False


def _is_node_not_ready(node_name: str) -> bool:
    """Return True if node exists and has Ready condition != True."""
    try:
        core = k8s.CoreV1Api()
        node = core.read_node(node_name)
        for cond in (node.status.conditions or []):
            if cond.type == "Ready":
                return cond.status != "True"
        return True  # no Ready condition found — treat as not ready
    except Exception:
        return False  # node gone or API error — don't block alert


def _is_node_being_deleted(node_name: str) -> tuple[bool, bool, bool]:
    """Check node state. Returns (exists, is_ready, marked_for_deletion)."""
    try:
        core = k8s.CoreV1Api()
        node = core.read_node(node_name)
        is_ready = True
        for cond in (node.status.conditions or []):
            if cond.type == "Ready":
                is_ready = cond.status == "True"
                break
        marked = False
        for taint in (node.spec.taints or []):
            if taint.key == "ToBeDeletedByClusterAutoscaler":
                marked = True
                break
        if node.metadata.deletion_timestamp is not None:
            marked = True
        return True, is_ready, marked
    except k8s.ApiException as e:
        if e.status == 404:
            return False, False, True  # node gone
        return True, False, False  # API error, assume exists
    except Exception:
        return True, False, False


def _is_autoscaler_scaling_up() -> bool:
    """Return True if cluster autoscaler is actively scaling up.

    Checks two signals:
    - Recent scale-up events in kube-system (last 10 min)
    - New NotReady nodes younger than 10 min (being provisioned)
    """
    core = k8s.CoreV1Api()
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=10)
    scale_up_reasons = {"TriggeredScaleUp", "ScaledUpGroup", "ScaleUp"}

    # Check recent scale-up events in kube-system
    try:
        events = core.list_namespaced_event("kube-system")
        for ev in events.items:
            if ev.reason in scale_up_reasons:
                ts = ev.last_timestamp or ev.metadata.creation_timestamp
                if ts and ts >= cutoff:
                    return True
    except Exception:
        logger.warning("Failed to check scale-up events in kube-system", exc_info=True)

    # Check for new NotReady nodes (being provisioned)
    try:
        nodes = core.list_node()
        for node in nodes.items:
            age = (now - node.metadata.creation_timestamp).total_seconds()
            if age < 600:  # younger than 10 min
                is_ready = False
                for cond in (node.status.conditions or []):
                    if cond.type == "Ready":
                        is_ready = cond.status == "True"
                        break
                if not is_ready:
                    return True
    except Exception:
        logger.warning("Failed to check new node status for scale-up detection", exc_info=True)

    return False


def _in_watched_namespace(namespace: str) -> bool:
    if namespace in config.EXCLUDE_NAMESPACES:
        return False
    if namespace in config._SYSTEM_NAMESPACES:
        return False
    if config.is_nonprod_namespace(namespace):
        return config.NON_PROD_SCANNER_ENABLED
    if config.WATCH_ALL_NAMESPACES:
        return True
    return namespace in config.NAMESPACES


def _make_state_key(owner_key: str, reason: str) -> str:
    alias = PROBLEM_ALIASES.get(reason, reason.lower())
    return f"{owner_key}:{alias}"


def _titled_for_routing(base: str, namespace: str, maintenance: bool) -> str:
    """Prefix maintenance / non-prod tags onto an alert title.

    The pipeline re-applies the non-prod prefix idempotently; the
    maintenance prefix is only added by the pipeline when `skip_llm` is
    still False, so we apply it here before setting `skip_llm=True`.
    """
    if maintenance:
        return f"[Maintenance] {base}"
    if config.is_nonprod_namespace(namespace):
        return f"{config.nonprod_title_prefix(namespace)} {base}"
    return base


async def _flush_pod_event_batch(ns: str, **_kwargs):
    """Process accumulated pod Warning events for a namespace after the batch window."""
    try:
        await asyncio.sleep(_BATCH_WINDOW_SECONDS)
    except asyncio.CancelledError:
        # Clean up stale state so future flushes aren't blocked
        async with _pod_event_batch_lock:
            _pod_event_batch.pop(ns, None)
            current = _pod_event_batch_task.get(ns)
            if current is asyncio.current_task():
                _pod_event_batch_task.pop(ns, None)
        raise

    async with _pod_event_batch_lock:
        events = _pod_event_batch.pop(ns, [])
        current = _pod_event_batch_task.get(ns)
        if current is asyncio.current_task():
            _pod_event_batch_task.pop(ns, None)

    if not events:
        return

    loop = asyncio.get_running_loop()
    from src.handlers.startup import get_store
    store = get_store()

    # Read maintenance state NOW (not from snapshot at scheduling time).
    # The pipeline won't add the [Maintenance] title prefix once we set
    # skip_llm=True below, so we read the flag here and fold it into the
    # title via `_titled_for_routing`.
    maintenance = await loop.run_in_executor(None, store.is_maintenance_active)

    # Kopf-specific early filter: drop recovered pods, deleted pods, and
    # collapse duplicate (owner_key, display_reason) events within this
    # same batch. Pipeline-side dedup (incident cooldown, suppressions,
    # owner cooldown) is re-applied in `process_scan_results`, so the
    # old is_seen / is_suppressed / is_owner_in_cooldown guards are no
    # longer re-implemented here.
    pending = []
    batch_seen: set[tuple[str, str]] = set()
    for pod_name, owner_key, state_key, node, display_reason in events:
        if any(w in owner_key for w in config.ALERT_EXCLUDE_WORKLOADS):
            continue
        dedup_key = (owner_key, display_reason)
        if dedup_key in batch_seen:
            continue
        ready = await loop.run_in_executor(None, _is_pod_ready_now, ns, pod_name)
        if ready:
            continue
        exists = await loop.run_in_executor(None, _pod_exists, ns, pod_name)
        if not exists:
            continue
        batch_seen.add(dedup_key)
        pending.append((pod_name, owner_key, state_key, node, display_reason))

    if not pending:
        return

    collector = _get_collector()

    if len(pending) < _BATCH_THRESHOLD:
        # Individual mode — one ScanResult per pod event, all dispatched
        # in a single process_scan_results call. Pipeline handles
        # fingerprinting + dedup + enrichment + Slack + threading +
        # central push.
        results: list[ScanResult] = []
        for pod_name, _owner_key, state_key, node, display_reason in pending:
            alias = PROBLEM_ALIASES.get(display_reason, display_reason.lower())
            severity = "critical" if display_reason == "OOMKilled" else "warning"
            try:
                pod_context = await loop.run_in_executor(
                    None, collector.collect_pod_context_with_diagnostics,
                    pod_name, ns, alias,
                )
            except Exception:
                logger.warning(
                    "Pod context collection failed for %s/%s (%s); "
                    "emitting ScanResult with minimal context",
                    ns, pod_name, alias, exc_info=True,
                )
                pod_context = {"event": {"pod": pod_name, "reason": display_reason}}
            results.append(ScanResult(
                state_key=state_key,
                title=_titled_for_routing(f"Warning: {display_reason}", ns, maintenance),
                severity=severity,
                resource=f"Pod/{pod_name}",
                namespace=ns,
                issue_type=alias,
                pod_name=pod_name,
                node_name=node or "",
                context_override=pod_context,
                event_reason=display_reason,
                skip_llm=True,
                metadata={"reason": display_reason, "source": "event"},
            ))
        await loop.run_in_executor(
            None, lambda: process_scan_results(
                results, store, None,
                get_node_metrics_summary, get_app_metrics_summary,
            ),
        )
        _alerted = [(sk, ns, ok) for _, ok, sk, _, _ in pending]
        if _alerted:
            task = asyncio.create_task(_deferred_auto_resolve(_alerted))
            task.add_done_callback(_log_task_exception)
        return

    # Batch mode — single collective ScanResult for ≥ _BATCH_THRESHOLD
    # events. The pipeline's `_should_post_slack` special-cases
    # `issue_type == "collective_incident"` to always post, and its
    # collective-incident branch at process start skips doing its OWN
    # aggregation since we pre-batched here.
    svc_names = [owner_key.split("/")[-1] for _, owner_key, _, _, _ in pending]
    reasons = sorted({dr for _, _, _, _, dr in pending})
    nodes = {p[3] for p in pending if p[3]}

    # Cap both lists before folding them into the rendered context.
    # A rolling-restart cascade can dump 40+ pod names here; without a
    # cap the body balloons past Slack block limits and wastes SQLite /
    # ClickHouse bandwidth with a redundant pod roster that the operator
    # will never read line-by-line anyway.
    _SVC_CAP = 5
    _REASON_CAP = 10
    svc_summary = ", ".join(svc_names[:_SVC_CAP])
    if len(svc_names) > _SVC_CAP:
        svc_summary += f"… +{len(svc_names) - _SVC_CAP} more"
    reasons_str = ", ".join(reasons[:_REASON_CAP])
    if len(reasons) > _REASON_CAP:
        reasons_str += f"… +{len(reasons) - _REASON_CAP} more"

    context_lines = [f"Multiple pod issues detected: {len(pending)} events in {ns}"]
    context_lines.append(f"Affected ({len(svc_names)}): {svc_summary}")
    context_lines.append(f"Reasons: {reasons_str}")
    node_name = ""
    for n in sorted(nodes):
        nm = await loop.run_in_executor(None, get_node_metrics_summary, n)
        if nm:
            context_lines.append(f"Node ({n}): {nm}")
            if not node_name:
                node_name = n
    context_lines.append(
        "Multiple warnings fired within a short window — likely related to "
        "the same underlying issue or a rolling update."
    )

    has_oom = any(dr == "OOMKilled" for _, _, _, _, dr in pending)
    has_critical_svc = any(
        matches_critical_service(owner_key.rsplit("/", 1)[-1] if owner_key else "", pod_name)
        for pod_name, owner_key, _sk, _node, _reason in pending
    )
    # Severity escalates to critical when OOM is involved OR any affected
    # service matches the infra/important tiers; otherwise warning. The
    # pipeline respects this directly (collective_incident always posts),
    # so the old in-handler "is_critical" gate is collapsed into severity.
    batch_severity = "critical" if (has_oom or has_critical_svc) else "warning"

    collective = ScanResult(
        state_key=f"Collective:{ns}",
        title=_titled_for_routing(
            f"Warning: {len(pending)} pod issues — {reasons_str}", ns, maintenance,
        ),
        severity=batch_severity,
        resource=f"BatchAlert/{len(pending)}-events",
        namespace=ns,
        issue_type="collective_incident",
        node_name=node_name,
        context_override={"raw": "\n".join(context_lines)},
        event_reason=f"{reasons_str}: {svc_summary}",
        skip_llm=True,
        metadata={
            "event_count": len(pending),
            # Capped samples + total counts. Unbounded lists here were
            # redundant with context_override (already rendered + capped
            # via svc_summary/reasons_str) and just added payload bloat
            # for pipelines/consumers that read ScanResult.metadata.
            "reasons_sample": reasons[:_REASON_CAP],
            "reasons_total": len(reasons),
            "services_sample": svc_names[:_SVC_CAP],
            "services_total": len(svc_names),
            "source": "event",
        },
    )
    await loop.run_in_executor(
        None, lambda: process_scan_results(
            [collective], store, None,
            get_node_metrics_summary, get_app_metrics_summary,
        ),
    )

    # No deferred auto-resolve here. Batch mode persists a single
    # `Collective:{ns}` incident instead of one incident per pod, so the
    # per-owner state_keys in `pending` have no incident rows to flip — calling
    # _deferred_auto_resolve with them was a silent no-op that left every
    # collective incident active forever. The pod scanner's sweep closes
    # `Collective:{ns}` once the namespace is clean again (src/scanners/pod.py).


@kopf.on.event("events")
async def on_warning_event(event, logger, **kwargs):
    if event.get("type") is None:
        return
    if time.time() - _startup_time < _STARTUP_GRACE_SECONDS:
        return

    obj = event.get("object")
    if not obj:
        return

    if obj.get("type") != "Warning":
        return

    metadata = obj.get("metadata", {})
    namespace = metadata.get("namespace", "")

    if not _in_watched_namespace(namespace):
        return

    # Check maintenance mode — still process events for dedup, but skip LLM
    from src.handlers.startup import get_store as _get_store
    _loop = asyncio.get_running_loop()
    _maintenance_active = await _loop.run_in_executor(None, _get_store().is_maintenance_active)

    reason = obj.get("reason") or ""
    if reason not in IMPORTANT_EVENT_REASONS:
        return

    involved = obj.get("involvedObject", {})
    obj_name = involved.get("name", "unknown")
    obj_kind = involved.get("kind", "unknown")

    # Import store lazily to avoid circular imports
    from src.handlers.startup import get_store

    store = get_store()

    # Unhealthy grace: probe flaps early in a pod's life are startup churn
    # until proven otherwise. Wait out the remainder of the settle window
    # (max of the probe-config budget and UNHEALTHY_STARTUP_SETTLE_SECONDS)
    # and alert only if the pod is STILL not ready — recovered pods exit
    # silently. Pods older than the window alert immediately, as before.
    if reason in ("Unhealthy", "ProbeWarning") and obj_kind == "Pod":
        grace, pod_age = await asyncio.get_running_loop().run_in_executor(
            None, _get_probe_grace_seconds, namespace, obj_name,
        )
        settle = max(grace, config.UNHEALTHY_STARTUP_SETTLE_SECONDS)
        if pod_age is not None and pod_age <= settle:
            wait = max(settle - pod_age, 1)
            logger.debug("Unhealthy for %s/%s — pod is %.0fs old, waiting %.0fs (startup settle)",
                         namespace, obj_name, pod_age, wait)
            await asyncio.sleep(wait)
            ready_now = await asyncio.get_running_loop().run_in_executor(
                None, _is_pod_ready_now, namespace, obj_name,
            )
            if ready_now:
                logger.info("Skipping Unhealthy for %s/%s — recovered within startup settle (%.0fs)",
                            namespace, obj_name, settle)
                return

        # After grace: add to batch instead of immediate alert
        owner_key = await asyncio.get_running_loop().run_in_executor(
            None, resolve_owner_key_by_name, namespace, obj_name,
        )
        message = obj.get("message", "")
        pod_status_reason, node_name = await asyncio.get_running_loop().run_in_executor(
            None, _get_pod_status_reason, namespace, obj_name,
        )
        display_reason = pod_status_reason if pod_status_reason else reason
        state_key = _make_state_key(owner_key, display_reason)

        async with _pod_event_batch_lock:
            _pod_event_batch.setdefault(namespace, []).append(
                (obj_name, owner_key, state_key, node_name, display_reason)
            )
            if namespace not in _pod_event_batch_task:
                _pod_event_batch_task[namespace] = asyncio.create_task(
                    _flush_pod_event_batch(namespace, maintenance=_maintenance_active)
                )
        return  # Don't fall through to individual alert flow

    # Elasticsearch Unhealthy: ECK fires "cluster health degraded" on any
    # non-green blip. On a single-node cluster the daily index rollover briefly
    # initializes new primary shards (transient yellow) that recovers in seconds.
    # Wait, then re-read status.health: green/unknown => benign transient (skip),
    # yellow/red => a persistent degrade worth an alert (tagged with the colour).
    if reason == "Unhealthy" and obj_kind == "Elasticsearch" and config.ELASTICSEARCH_HEALTH_CHECK_ENABLED:
        state_key = f"Elasticsearch:{namespace}/{obj_name}:unhealthy"
        if state_key in _in_flight:
            return
        _in_flight.add(state_key)
        try:
            grace = config.ELASTICSEARCH_HEALTH_GRACE_SECONDS
            if grace > 0:
                logger.debug("Unhealthy for Elasticsearch %s/%s — waiting %ds for health to settle",
                             namespace, obj_name, grace)
                await asyncio.sleep(grace)
            health = await asyncio.get_running_loop().run_in_executor(
                None, _get_elasticsearch_health, namespace, obj_name,
            )
            if health in ("green", "unknown"):
                logger.info("Skipping Unhealthy for Elasticsearch %s/%s — health=%s after %ds (transient)",
                            namespace, obj_name, health, grace)
                return
            # Persistent yellow/red — actionable degrade. "error" means the
            # re-read itself failed: we can't confirm recovery, so fail loud and
            # forward the Unhealthy event as a warning rather than swallow it.
            severity = "critical" if health == "red" else "warning"
            if health == "error":
                event_reason = (
                    f"Elasticsearch {obj_name} health could not be re-read after "
                    f"{grace}s — forwarding Unhealthy event (fail-loud)"
                )
            else:
                event_reason = f"Elasticsearch cluster health {health} sustained {grace}s (not a transient blip)"
            es_message = sanitize_value((obj.get("message", "") or "")[:_MESSAGE_CAP])
            result = ScanResult(
                state_key=state_key,
                title=_titled_for_routing(f"Warning: Elasticsearch health {health}", namespace, _maintenance_active),
                severity=severity,
                resource=f"Elasticsearch/{obj_name}",
                namespace=namespace,
                issue_type="unhealthy",
                context_override={"event": {
                    "elasticsearch": obj_name, "health": health,
                    "message": es_message, "grace_seconds": grace,
                }},
                event_reason=event_reason,
                skip_llm=True,
                metadata={"resource": obj_name, "health": health, "reason": "Unhealthy", "source": "event"},
            )
            await asyncio.get_running_loop().run_in_executor(
                None, lambda: process_scan_results(
                    [result], store, None,
                    get_node_metrics_summary, get_app_metrics_summary,
                ),
            )
        finally:
            _in_flight.discard(state_key)
        return

    if reason == "FailedScheduling" and obj_kind == "Pod":
        await asyncio.sleep(300)
        still_pending = await asyncio.get_running_loop().run_in_executor(
            None, _is_pod_still_pending, namespace, obj_name,
        )
        if not still_pending:
            logger.debug("Skipping FailedScheduling for %s/%s \u2014 pod no longer Pending", namespace, obj_name)
            return

        # Extended grace period when autoscaler is actively scaling up
        scaling_up = await asyncio.get_running_loop().run_in_executor(
            None, _is_autoscaler_scaling_up,
        )
        if scaling_up:
            logger.info("FailedScheduling for %s/%s \u2014 autoscaler scaling up, waiting another 300s", namespace, obj_name)
            await asyncio.sleep(300)
            still_pending = await asyncio.get_running_loop().run_in_executor(
                None, _is_pod_still_pending, namespace, obj_name,
            )
            if not still_pending:
                logger.info("FailedScheduling for %s/%s \u2014 pod scheduled after autoscaler grace period", namespace, obj_name)
                return

    if reason == "NodeNotReady" and obj_kind == "Pod":
        loop = asyncio.get_running_loop()
        # Resolve node name
        try:
            core = k8s.CoreV1Api()
            pod = await loop.run_in_executor(
                None, core.read_namespaced_pod, obj_name, namespace,
            )
            nr_node = pod.spec.node_name or ""
        except Exception:
            nr_node = ""
        if not nr_node:
            return

        # Node-level dedup (not per-pod) — `_in_flight` covers the whole
        # grace-period sleep + post-wait checks + emission. Pipeline's
        # incident cooldown handles the "don't re-fire too soon" case
        # AFTER we emit the ScanResult.
        node_state_key = f"Node:{nr_node}:notready"
        if node_state_key in _in_flight:
            return
        _in_flight.add(node_state_key)
        try:
            # Determine wait time
            try:
                node_obj = await loop.run_in_executor(None, core.read_node, nr_node)
                age = (datetime.now(timezone.utc) - node_obj.metadata.creation_timestamp).total_seconds()
            except Exception:
                age = None

            if age is not None and age < config.NODE_READY_GRACE_SECONDS:
                wait = config.NODE_READY_GRACE_SECONDS - age
                logger.info("NodeNotReady on new node %s (age=%ds), waiting %ds", nr_node, int(age), int(wait))
            else:
                wait = config.NODE_NOT_READY_GRACE_SECONDS
                logger.info("NodeNotReady on node %s, waiting %ds for potential autoscaler deletion", nr_node, int(wait))
            await asyncio.sleep(wait)

            # Post-wait checks: node gone / being drained / now Ready
            exists, is_ready, marked = await loop.run_in_executor(None, _is_node_being_deleted, nr_node)
            if not exists:
                logger.info("Node %s deleted (autoscaler scale-down), skipping alert", nr_node)
                return
            if marked:
                logger.info("Node %s marked for deletion, skipping alert", nr_node)
                return
            if is_ready:
                logger.info("Node %s is now Ready, skipping alert", nr_node)
                return

            # Still NotReady — emit ScanResult through the pipeline.
            logger.info("Warning event: %s — NodeNotReady (%s/%s)", node_state_key, namespace, obj_name)
            collector = _get_collector()
            try:
                node_context = await loop.run_in_executor(
                    None, collector.collect_pod_context_with_diagnostics,
                    obj_name, namespace, "notready",
                )
            except Exception:
                logger.warning(
                    "Pod context collection failed for %s/%s (notready); "
                    "emitting with minimal context",
                    namespace, obj_name, exc_info=True,
                )
                node_context = {"event": {"pod": obj_name, "node": nr_node, "reason": "NodeNotReady"}}

            result = ScanResult(
                state_key=node_state_key,
                title=_titled_for_routing("Warning: NodeNotReady", namespace, _maintenance_active),
                severity="warning",
                resource=f"Node/{nr_node}",
                namespace=namespace,
                issue_type="notready",
                pod_name=obj_name,
                node_name=nr_node,
                context_override=node_context,
                event_reason=f"NodeNotReady: Node {nr_node} is not ready",
                skip_llm=True,
                metadata={"node": nr_node, "reason": "NodeNotReady", "source": "event"},
            )
            await loop.run_in_executor(
                None, lambda: process_scan_results(
                    [result], store, None,
                    get_node_metrics_summary, get_app_metrics_summary,
                ),
            )
        finally:
            _in_flight.discard(node_state_key)
        return  # early return — skip the general flow

    # Transient infra errors (sandbox, CNI): grace period, then check if resolved
    if reason in _TRANSIENT_INFRA_REASONS and obj_kind == "Pod":
        logger.debug("Transient %s for %s/%s — waiting %ds", reason, namespace, obj_name, _TRANSIENT_GRACE_SECONDS)
        await asyncio.sleep(_TRANSIENT_GRACE_SECONDS)
        exists = await asyncio.get_running_loop().run_in_executor(
            None, _pod_exists, namespace, obj_name,
        )
        if not exists:
            logger.info("Skipping %s for %s/%s — pod no longer exists (transient)", reason, namespace, obj_name)
            return
        ready = await asyncio.get_running_loop().run_in_executor(
            None, _is_pod_ready_now, namespace, obj_name,
        )
        if ready:
            logger.info("Skipping %s for %s/%s — pod recovered within grace period", reason, namespace, obj_name)
            return
        # Still failing — fall through to normal pod batch flow

    # Image pull errors: grace period for transient DNS/registry issues
    if reason in ("Failed", "BackOff") and obj_kind == "Pod":
        message = obj.get("message", "")
        inferred = _infer_reason_from_message(reason, message)
        if inferred in _IMAGE_PULL_REASONS:
            logger.debug("Image pull error for %s/%s — waiting %ds for retry",
                         namespace, obj_name, _IMAGE_PULL_GRACE_SECONDS)
            await asyncio.sleep(_IMAGE_PULL_GRACE_SECONDS)
            exists = await asyncio.get_running_loop().run_in_executor(
                None, _pod_exists, namespace, obj_name,
            )
            if not exists:
                logger.info("Skipping image pull for %s/%s — pod gone (transient)", namespace, obj_name)
                return
            ready = await asyncio.get_running_loop().run_in_executor(
                None, _is_pod_ready_now, namespace, obj_name,
            )
            if ready:
                logger.info("Skipping image pull for %s/%s — recovered within grace period", namespace, obj_name)
                return
            # Check if still an image pull issue (might have progressed to CrashLoop etc.)
            status_reason, _ = await asyncio.get_running_loop().run_in_executor(
                None, _get_pod_status_reason, namespace, obj_name,
            )
            if status_reason and status_reason not in _IMAGE_PULL_REASONS:
                logger.info("Skipping image pull for %s/%s — no longer image pull (now %s)",
                            namespace, obj_name, status_reason)
                return
            # Still failing — fall through to pod batch flow

    # Flux source-level resources: skip entirely — they don't impact running workloads
    if obj_kind in _FLUX_SOURCE_KINDS:
        logger.debug("Skipping source-level Flux %s/%s event — informational only", obj_kind, obj_name)
        return

    # Flux deployment resources: grace period for transient failures
    if obj_kind in _FLUX_KINDS:
        await asyncio.sleep(120)  # wait 2 min for Flux retry
        # Re-check if resource is now healthy
        try:
            api = k8s.CustomObjectsApi()
            _flux_group_version = {
                "HelmRelease": ("helm.toolkit.fluxcd.io", "v2"),
                "Kustomization": ("kustomize.toolkit.fluxcd.io", "v1"),
            }
            group, version = _flux_group_version.get(obj_kind, ("", ""))
            if group:
                plural = obj_kind.lower() + "s"
                flux_obj = await asyncio.get_running_loop().run_in_executor(
                    None, api.get_namespaced_custom_object, group, version, namespace, plural, obj_name,
                )
                conditions = flux_obj.get("status", {}).get("conditions", [])
                ready_cond = next((c for c in conditions if c.get("type") == "Ready"), None)
                if ready_cond and ready_cond.get("status") == "True":
                    logger.info("Skipping Flux %s/%s alert — recovered after grace period", obj_kind, obj_name)
                    return
        except Exception:
            logger.debug("Failed to check Flux %s/%s status after grace", obj_kind, obj_name)

    # --- Pod events: batch to prevent duplicate alerts for the same pod/deployment ---
    if obj_kind == "Pod":
        owner_key = await asyncio.get_running_loop().run_in_executor(
            None, resolve_owner_key_by_name, namespace, obj_name,
        )
        exists = await asyncio.get_running_loop().run_in_executor(
            None, _pod_exists, namespace, obj_name,
        )
        if not exists:
            logger.info("Skipping alert for deleted pod %s/%s (reason=%s)", namespace, obj_name, reason)
            return

        message = obj.get("message", "")
        pod_status_reason, node_name = await asyncio.get_running_loop().run_in_executor(
            None, _get_pod_status_reason, namespace, obj_name,
        )
        display_reason = pod_status_reason if pod_status_reason else reason
        if not pod_status_reason and display_reason in ("BackOff", "Failed"):
            display_reason = _infer_reason_from_message(reason, message)

        state_key = _make_state_key(owner_key, display_reason)

        async with _pod_event_batch_lock:
            _pod_event_batch.setdefault(namespace, []).append(
                (obj_name, owner_key, state_key, node_name, display_reason)
            )
            if namespace not in _pod_event_batch_task:
                _pod_event_batch_task[namespace] = asyncio.create_task(
                    _flush_pod_event_batch(namespace, maintenance=_maintenance_active)
                )
        return

    # --- Non-pod events: immediate emission via pipeline ---
    owner_key = f"{obj_kind}:{namespace}/{obj_name}"
    message = obj.get("message", "")
    display_reason = reason

    alias = PROBLEM_ALIASES.get(display_reason, PROBLEM_ALIASES.get(reason, reason.lower()))
    state_key = _make_state_key(owner_key, display_reason)

    if state_key in _in_flight:
        return
    _in_flight.add(state_key)

    try:
        loop = asyncio.get_running_loop()
        logger.info("Warning event: %s \u2014 %s (%s)", state_key, reason, obj_name)

        # Size-bound + sanitize raw event messages before they land in
        # context_override. The pipeline's _collect_context already
        # re-runs sanitize_dict idempotently, but applying sanitize_value
        # at source means a hypothetical pipeline regression can't leak
        # raw credentials from a kubernetes Warning event into Slack /
        # SQLite / ClickHouse. Cap at 1KB so a pathologically long event
        # message (e.g. verbose kubelet probe failure dumps) doesn't
        # bloat context_store rows or the central push payload.
        raw_msg = message or ""
        sanitized_msg = sanitize_value(raw_msg[:_MESSAGE_CAP])
        if len(raw_msg) > _MESSAGE_CAP:
            sanitized_msg += f"…(truncated, {len(raw_msg)} bytes total)"

        short_message = sanitized_msg.split("\n")[0][:80] if sanitized_msg else ""
        event_label = f"{display_reason}: {short_message}" if short_message else display_reason

        non_pod_context = {
            "event": {
                "kind": obj_kind,
                "name": obj_name,
                "namespace": namespace,
                "reason": reason,
                "message": sanitized_msg,
            }
        }

        result = ScanResult(
            state_key=state_key,
            title=_titled_for_routing(f"Warning: {display_reason}", namespace, _maintenance_active),
            severity="warning",
            resource=f"{obj_kind}/{obj_name}",
            namespace=namespace,
            issue_type=alias,
            context_override=non_pod_context,
            event_reason=event_label,
            skip_llm=True,
            metadata={"reason": reason, "kind": obj_kind, "source": "event"},
        )
        await loop.run_in_executor(
            None, lambda: process_scan_results(
                [result], store, None,
                get_node_metrics_summary, get_app_metrics_summary,
            ),
        )
    finally:
        _in_flight.discard(state_key)

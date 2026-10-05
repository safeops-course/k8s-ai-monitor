"""Pod scanner — extracted from main._scan_pods."""
import logging

from kubernetes import client as k8s

from src import config
from src.engine.constants import PROBLEM_STATES, POD_PROBLEM_REASONS, PROBLEM_ALIASES
from src.engine.owner import resolve_owner_key
from src.scanners._base import ScanResult

logger = logging.getLogger(__name__)

# Aliases this scanner can produce, derived from the same constants the loop
# below uses rather than listed by hand, so the two cannot drift apart.
#
# The trailing auto-resolve sweep closes any active incident whose state_key is
# absent from `problem_keys`, and `problem_keys` holds only what THIS scanner
# saw this tick. An alias it can never emit is therefore absent on every pass
# and gets resolved every time, no matter how broken the resource is.
#
# A real case: a `StatefulSet:production/<db>:mount` incident was auto-resolved
# 111 times and reopened 110 times in 48h, on one unchanging fingerprint, while
# its volume sat locked in the cloud provider's API throughout. `mount` comes from
# FailedMount / FailedAttachVolume / FailedMapVolume — events, handled
# elsewhere — while this scanner reads only pod.status.reason and container
# states, so the key could never appear in `problem_keys`. Each false resolve
# cost a Slack message, because the reopen path deliberately forces
# should_alert to bypass cooldown for what it takes to be a fixed incident.
#
# Aliases both sources emit (error, scheduling, evicted, oom) stay in scope:
# separating those two origins needs provenance recorded on the incident, which
# this does not add.
_SCANNER_ALIASES: frozenset[str] = frozenset(
    {PROBLEM_ALIASES.get(reason, reason.lower())
     for reason in (POD_PROBLEM_REASONS | PROBLEM_STATES)}
)


def _owner_is_healthy(pod, namespace: str) -> bool:
    """True if this pod is terminal but its owning workload is fully available.

    Only meaningful for pods in a terminal phase — a Running pod's own state is
    the signal, regardless of its owner. Returns False when the owner cannot be
    determined, so an unknown case still alerts rather than being swallowed.
    """
    phase = (pod.status.phase or "") if pod.status else ""
    if phase not in ("Failed", "Succeeded"):
        return False
    try:
        apps = k8s.AppsV1Api()
        for owner in (pod.metadata.owner_references or []):
            if owner.kind == "ReplicaSet":
                rs = apps.read_namespaced_replica_set(owner.name, namespace)
                for rs_owner in (rs.metadata.owner_references or []):
                    if rs_owner.kind == "Deployment":
                        dep = apps.read_namespaced_deployment(rs_owner.name, namespace)
                        want = dep.spec.replicas if dep.spec.replicas is not None else 1
                        have = dep.status.ready_replicas or 0
                        return have >= want and want > 0
                return False
            if owner.kind == "StatefulSet":
                sts = apps.read_namespaced_stateful_set(owner.name, namespace)
                want = sts.spec.replicas if sts.spec.replicas is not None else 1
                have = sts.status.ready_replicas or 0
                return have >= want and want > 0
    except Exception:
        logger.debug("Could not check owner health for %s/%s",
                     namespace, pod.metadata.name, exc_info=True)
    return False


class PodScanner:
    name = "pod"
    startup_delay = 30  # quick first scan after startup

    @property
    def enabled(self):
        return config.SCANNER_POD_ENABLED

    @property
    def interval_seconds(self):
        return config.SCANNER_INTERVAL_SECONDS

    def scan(self) -> list[ScanResult]:
        core = k8s.CoreV1Api()
        results = []
        problem_keys: set[str] = set()
        # Namespaces holding a Running-but-NotReady pod. Tracked separately
        # because none of the checks below fire for one — see the comment at the
        # top of the pod loop.
        unready_namespaces: set[str] = set()

        for ns in config.get_namespaces():
            try:
                pods = core.list_namespaced_pod(ns)
            except Exception:
                logger.exception("Pod scanner: failed to list pods in %s", ns)
                continue

            for pod in pods.items:
                # A pod failing its readiness probe stays Running with an empty
                # status.reason and a `running` container state, so none of the
                # checks below flag it and it never reaches `results`. But the
                # `Unhealthy`/`ProbeWarning` events it emits ARE in
                # IMPORTANT_EVENT_REASONS and do raise Collective:{ns} incidents
                # through on_warning_event. Track the namespace here, or a
                # namespace whose only fault is failing probes looks clean and
                # the sweep below resolves its collective mid-incident.
                if pod.status and pod.status.phase == "Running" and not any(
                    c.type == "Ready" and c.status == "True"
                    for c in (pod.status.conditions or [])
                ):
                    unready_namespaces.add(ns)

                # A terminal pod whose owner is healthy is a corpse, not an
                # incident. Kubernetes keeps Evicted/Failed pods in the API
                # until the GC threshold is hit (12500 by default), so on a
                # cluster that evicts rarely they stay forever — and every scan
                # rediscovers them.
                #
                # One Evicted pod alerted 1495 times over 11 days.
                # The deployment had been 1/1 Available throughout; the cause
                # was fixed the day after the eviction. The pod was still
                # shouting the original message, `request is 0`, which had
                # stopped being true.
                #
                # Gated here rather than inside the pod-reason branch below so
                # the rule is a property of the pod, not of whichever check
                # happens to run first. A terminal pod also carries terminated
                # container states, and those are read further down; keeping
                # the gate ahead of every check means a corpse cannot re-enter
                # through a path added later. `_owner_is_healthy` returns False
                # for a Running pod, so live pods are untouched, and False for
                # any owner it cannot resolve, so unknown still alerts.
                if _owner_is_healthy(pod, ns):
                    continue

                # Pod-level reasons
                pod_reason = (pod.status.reason or "") if pod.status else ""
                if pod_reason in POD_PROBLEM_REASONS:
                    severity = "critical" if pod_reason in ("OutOfmemory", "OutOfcpu") else "warning"
                    owner_key = resolve_owner_key(pod)
                    alias = PROBLEM_ALIASES.get(pod_reason, pod_reason.lower())
                    state_key = f"{owner_key}:{alias}"
                    problem_keys.add(state_key)
                    results.append(ScanResult(
                        state_key=state_key,
                        title=f"Pod Issue: {pod_reason}",
                        severity=severity,
                        resource=pod.metadata.name,
                        namespace=ns,
                        issue_type=alias,
                        pod_name=pod.metadata.name,
                        node_name=pod.spec.node_name or "",
                    ))
                    continue

                # Container-level states
                for cs in (pod.status.container_statuses or []):
                    reason = None
                    severity = "warning"

                    if cs.state and cs.state.waiting and cs.state.waiting.reason in PROBLEM_STATES:
                        reason = cs.state.waiting.reason
                    if not reason and cs.state and cs.state.terminated:
                        if cs.state.terminated.reason == "OOMKilled":
                            reason = "OOMKilled"
                            severity = "critical"
                    if not reason and cs.last_state and cs.last_state.terminated:
                        if cs.last_state.terminated.reason == "OOMKilled":
                            from datetime import datetime, timezone
                            now_utc = datetime.now(timezone.utc)
                            finished = cs.last_state.terminated.finished_at
                            if finished:
                                age_h = (now_utc - finished).total_seconds() / 3600
                                if age_h > 12:
                                    continue  # Very old OOMKill — fully stale
                            pod_ready_cond = any(
                                c.type == "Ready" and c.status == "True"
                                for c in (pod.status.conditions or [])
                            )
                            is_running_ready = (
                                cs.state and cs.state.running
                                and cs.ready
                                and pod.status.phase == "Running"
                                and pod_ready_cond
                            )
                            # Stability check: a snapshot of Running+Ready isn't
                            # enough — the pod may be mid-crash-loop. uptime_s is
                            # measured from the CURRENT container's start, so it is
                            # precisely "time since the last restart", and
                            # Kubernetes caps CrashLoopBackOff at 5 minutes: a
                            # container up for longer than that cap is provably not
                            # in a restart-backoff loop.
                            #
                            # restart_count used to gate this as well (<= 1). It is
                            # cumulative over the container's lifetime, so it says
                            # nothing about now, and it never falls. uptrace-0 sat
                            # at 16 restarts accumulated over months while 1/1 Ready
                            # and serving: permanently ineligible for recovery, so
                            # its key stayed in problem_keys and the sweep below
                            # could never close the incident. An alert that cannot
                            # clear while the thing it describes is healthy stops
                            # being an alert.
                            uptime_s = 0.0
                            if cs.state and cs.state.running and cs.state.running.started_at:
                                uptime_s = (now_utc - cs.state.running.started_at).total_seconds()
                            # Still read for the alert title — "restart #16" is
                            # useful context — but it no longer decides anything.
                            restart_count = cs.restart_count or 0
                            stable_recovered = (
                                is_running_ready
                                and uptime_s >= config.POD_OOM_RECOVERY_STABLE_SECONDS
                            )
                            owner_key = resolve_owner_key(pod)
                            alias = PROBLEM_ALIASES.get("OOMKilled", "oom")
                            state_key = f"{owner_key}:{alias}"
                            if stable_recovered:
                                # Truly recovered — single OOM, ≥5min stable.
                                # Mark auto_resolve so the pipeline clears the
                                # active incident and posts a single "Resolved"
                                # message instead of yet another "(recovered)"
                                # alert that gets shadowed by the auto-resolve
                                # loop a few lines below (which would also emit
                                # an auto_resolve ScanResult for the same key).
                                results.append(ScanResult(
                                    state_key=state_key,
                                    title="Pod Issue: OOMKilled (recovered)",
                                    severity="critical",
                                    resource=pod.metadata.name,
                                    namespace=ns,
                                    issue_type=alias,
                                    pod_name=pod.metadata.name,
                                    node_name=pod.spec.node_name or "",
                                    auto_resolve=True,
                                ))
                                # Also add to problem_keys so the trailing
                                # auto-resolve loop doesn't enqueue a duplicate
                                # ScanResult for the same state_key.
                                problem_keys.add(state_key)
                                continue
                            # Not stable: the container restarted inside the
                            # window, or the pod is not Ready. Either way it may
                            # still be looping — active incident, no auto-resolve.
                            problem_keys.add(state_key)
                            label = "crashed again" if restart_count > 1 else "may not be stable"
                            results.append(ScanResult(
                                state_key=state_key,
                                title=f"Pod Issue: OOMKilled ({label}, restart #{restart_count})",
                                severity="critical",
                                resource=pod.metadata.name,
                                namespace=ns,
                                issue_type=alias,
                                pod_name=pod.metadata.name,
                                node_name=pod.spec.node_name or "",
                            ))
                            continue

                    if not reason:
                        continue

                    owner_key = resolve_owner_key(pod)
                    alias = PROBLEM_ALIASES.get(reason, reason.lower())
                    state_key = f"{owner_key}:{alias}"
                    problem_keys.add(state_key)
                    results.append(ScanResult(
                        state_key=state_key,
                        title=f"Pod Issue: {reason}",
                        severity=severity,
                        resource=pod.metadata.name,
                        namespace=ns,
                        issue_type=alias,
                        pod_name=pod.metadata.name,
                        node_name=pod.spec.node_name or "",
                    ))

        # Namespaces that still have at least one live pod problem this tick.
        # A `Collective:{ns}` incident summarises a whole namespace rather than a
        # single owner, so it can never appear in `problem_keys` — it has to be
        # held open while its namespace is still affected and resolved only once
        # that namespace comes back clean. Union in the probe-failure namespaces:
        # collectives are raised from events, which cover more failure modes than
        # this scanner detects on its own.
        problem_namespaces = {
            r.namespace for r in results if not r.auto_resolve
        } | unready_namespaces

        # Auto-resolve: check active pod/deployment incidents against current state
        try:
            from src.handlers.startup import get_store
            store = get_store()
            active = store.get_active_incidents_by_prefix(
                ["Deployment:", "StatefulSet:", "DaemonSet:", "Job:", "Pod:", "Collective:"]
            )
            for incident in active:
                if incident.state_key in problem_keys:
                    continue
                if (
                    incident.state_key.startswith("Collective:")
                    and (incident.namespace or incident.state_key.split(":", 1)[1])
                    in problem_namespaces
                ):
                    continue
                # Only close what this scanner could have found. An event-only
                # alias is missing from problem_keys on every pass, so sweeping
                # it resolves a live problem — see _SCANNER_ALIASES.
                if not incident.state_key.startswith("Collective:"):
                    alias = incident.state_key.rsplit(":", 1)[-1]
                    if alias not in _SCANNER_ALIASES:
                        continue
                # Prefer the authoritative incident.namespace column; fall back
                # to parsing the state_key only for legacy rows written before
                # that column existed (state_key format:
                # "Kind:namespace/name:alias").
                parts = incident.state_key.split(":")
                ns_resource = parts[1] if len(parts) > 1 else ""
                ns = incident.namespace or (
                    ns_resource.split("/")[0] if "/" in ns_resource else ""
                )
                results.append(ScanResult(
                    state_key=incident.state_key,
                    title=f"Resolved: {incident.state_key}",
                    severity="info",
                    resource=ns_resource,
                    namespace=ns,
                    issue_type=incident.issue_type,
                    auto_resolve=True,
                ))
            resolved_count = len(results) - len(problem_keys)
            if resolved_count > 0:
                logger.info("Pod scanner: %d incidents auto-resolved", resolved_count)
        except Exception:
            logger.warning("Pod scanner: failed to check for auto-resolve", exc_info=True)

        issues = [r for r in results if not r.auto_resolve]
        if issues:
            details = "; ".join(f"{r.namespace}/{r.resource}: {r.issue_type}" for r in issues)
            logger.info("Pod scanner: %d issues found: %s", len(issues), details)
        else:
            logger.info("Pod scanner: no issues found")
        return results

    def collect_daily_data(self) -> str | None:
        return None  # daily pod data handled by collectors/daily.py

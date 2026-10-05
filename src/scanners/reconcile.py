"""Reconciliation scanner — auto-resolves stale active incidents.

Periodically checks active incidents in the store against current K8s state
and emits auto_resolve ScanResults for incidents whose underlying issue is gone.

Covers:
- Node:* incidents — checks if node is Ready
- Flux:* incidents — checks Ready condition on Flux resources
- HelmRepository/HelmChart/GitRepository/OCIRepository event incidents
- Elasticsearch/Kibana/ApmServer:* incidents — checks the ECK CR's
  status.health; nothing else closes these, so before this they lived forever
- Certificate/CertificateRequest/Order/Challenge:* event incidents — checks
  the cert-manager resource is Ready/valid or gone; the certificate scanner's
  own auto-resolve uses a different state_key, so it never matched these
- Event-only workload incidents (an alias the pod scanner refuses to sweep,
  e.g. `unhealthy` from a probe event) — verified against the owner's real
  readiness, the durable backstop for events.py's in-memory deferred check.
  Jobs included: a FailedMount on a CronJob run stays "active" long after the
  Job finished or its TTL deleted it, unless something here closes it

Absence is not a signal. A scanner that stops iterating a resource emits
nothing about it, so an incident raised while it existed stays active forever.
The store's stale reaper closes untouched incidents after 7 days, but that is
a backstop measured in days — this scanner turns "the resource is gone" into
an explicit close on the next pass.
"""
import logging
import re
import time

from kubernetes import client as k8s

from src import config
from src.engine.owner import owner_fully_available
from src.scanners._base import ScanResult
# Deliberate coupling: this sweeper exists to cover exactly the COMPLEMENT of
# what the pod scanner will sweep. pod.py skips any alias outside this set
# because it cannot confirm an event-only condition from pod state alone (see
# its `_SCANNER_ALIASES` comment) — which left those incidents with no closer
# at all. Importing the set keeps the two halves from drifting apart silently.
from src.scanners.pod import _SCANNER_ALIASES as _POD_SWEPT_ALIASES

logger = logging.getLogger(__name__)

# Flux CRD group/version/plural mappings
_FLUX_RESOURCES: dict[str, tuple[str, str, str]] = {
    "HelmRelease": ("helm.toolkit.fluxcd.io", "v2", "helmreleases"),
    "Kustomization": ("kustomize.toolkit.fluxcd.io", "v1", "kustomizations"),
    "HelmRepository": ("source.toolkit.fluxcd.io", "v1", "helmrepositories"),
    "HelmChart": ("source.toolkit.fluxcd.io", "v1", "helmcharts"),
    "GitRepository": ("source.toolkit.fluxcd.io", "v1", "gitrepositories"),
    "OCIRepository": ("source.toolkit.fluxcd.io", "v1", "ocirepositories"),
}

# ECK CRD group/version/plural mappings. These incidents are raised by the
# event handler (`handlers/events.py`) and, until this scanner, were closed by
# nothing: every other sweeper keys off a prefix none of these match. devops
# carried a Kibana incident opened 2026-03-06 that was still active six months
# later while the CR read green the whole time.
_ECK_RESOURCES: dict[str, tuple[str, str, str]] = {
    "Elasticsearch": ("elasticsearch.k8s.elastic.co", "v1", "elasticsearches"),
    "Kibana": ("kibana.k8s.elastic.co", "v1", "kibanas"),
    "ApmServer": ("apm.k8s.elastic.co", "v1", "apmservers"),
}

# cert-manager CRD group/version/plural mappings. A failed ACME renewal raises
# `Failed` Warning events on the Certificate and on each Challenge, and
# `handlers/events.py` turns those into `Certificate:ns/name:error` /
# `Challenge:ns/name:error` incidents. The certificate scanner auto-resolves
# under `Certificate:ns/name` — no alias suffix — so its close never matched
# the event-born key, and Challenge/Order objects are deleted by cert-manager
# once the Order completes, so no event ever announced their recovery. Six
# clusters carried the same three fossils for a week after `project-tls` had
# renewed fine; only the 7-day stale reaper ever closed them.
# Orders and Challenges live in a separate API group — the RBAC has to grant
# `acme.cert-manager.io`, not just `cert-manager.io`, or these reads are
# Forbidden and the incidents stay exactly as they were.
_CERT_MANAGER_RESOURCES: dict[str, tuple[str, str, str]] = {
    "Certificate": ("cert-manager.io", "v1", "certificates"),
    "CertificateRequest": ("cert-manager.io", "v1", "certificaterequests"),
    "Order": ("acme.cert-manager.io", "v1", "orders"),
    "Challenge": ("acme.cert-manager.io", "v1", "challenges"),
}

# ACME Order/Challenge `status.state` values. "valid" is the ACME server's
# final acceptance; "ready" on a Challenge only means the self-check passed
# and the server has not yet been asked to verify it, so it stays in-flight.
_ACME_STATE_DONE = {"valid"}
_ACME_STATE_FAILED = {"errored", "invalid", "expired"}

# Ready=False reasons that mean in-flight rather than failed, per kind.
_READY_FALSE_IN_FLIGHT: dict[str, frozenset[str]] = {
    "CertificateRequest": frozenset({"Pending"}),
    "Certificate": frozenset({"DoesNotExist"}),
}
# CertificateRequest conditions that are terminal failures on their own.
_CR_TERMINAL_CONDITIONS = frozenset({"Denied", "InvalidRequest"})

# Workload kinds whose readiness we can verify authoritatively.
_WORKLOAD_PREFIXES = ["Deployment:", "StatefulSet:", "DaemonSet:", "Pod:", "Job:"]



def _eck_resource_state(kind: str, namespace: str, name: str) -> str:
    """One of "ready", "failing", "gone", "unknown" for an ECK resource.

    ECK publishes `status.health` as green/yellow/red on all three kinds, which
    makes this the same shape as `_flux_resource_state`: green is recovered,
    yellow/red is still broken and must hold the incident open, 404 means the
    resource was removed, and anything unreadable is "unknown" so the caller
    leaves the incident exactly as it found it.
    """
    group, version, plural = _ECK_RESOURCES[kind]
    try:
        obj = k8s.CustomObjectsApi().get_namespaced_custom_object(
            group, version, namespace, plural, name,
        )
    except k8s.ApiException as e:
        if e.status == 404:
            return "gone"
        logger.warning(
            "Reconcile: could not read %s %s/%s: %s", kind, namespace, name, e.reason,
        )
        return "unknown"
    except Exception:
        logger.debug(
            "Reconcile: %s read failed for %s/%s", kind, namespace, name, exc_info=True,
        )
        return "unknown"

    health = ((obj.get("status") or {}).get("health") or "").lower()
    if health == "green":
        return "ready"
    if health in ("yellow", "red"):
        return "failing"
    return "unknown"


def _cert_manager_resource_state(kind: str, namespace: str, name: str) -> str:
    """One of "ready", "failing", "gone", "unknown" for a cert-manager resource.

    Certificate and CertificateRequest publish a Ready condition like Flux.
    Order and Challenge publish `status.state` instead; only "valid" counts as
    done, the terminal failure states hold the incident open, and anything
    in-flight (pending/processing/ready) is "unknown" so nothing is decided
    while cert-manager is still working. 404 is the normal end of a Challenge
    or Order — cert-manager garbage-collects them once the Certificate is
    issued — and a failed read is "unknown", never recovery.
    """
    group, version, plural = _CERT_MANAGER_RESOURCES[kind]
    try:
        obj = k8s.CustomObjectsApi().get_namespaced_custom_object(
            group, version, namespace, plural, name,
        )
    except k8s.ApiException as e:
        if e.status == 404:
            return "gone"
        logger.warning(
            "Reconcile: could not read %s %s/%s: %s", kind, namespace, name, e.reason,
        )
        return "unknown"
    except Exception:
        logger.debug(
            "Reconcile: %s read failed for %s/%s", kind, namespace, name, exc_info=True,
        )
        return "unknown"

    status = obj.get("status") or {}
    if kind in ("Order", "Challenge"):
        state = (status.get("state") or "").lower()
        if state in _ACME_STATE_DONE:
            return "ready"
        if state in _ACME_STATE_FAILED:
            return "failing"
        return "unknown"

    conditions = status.get("conditions") or []
    # A CertificateRequest that was denied by an approver or rejected as
    # malformed is terminal regardless of what Ready says at that moment.
    if kind == "CertificateRequest" and any(
        c.get("type") in _CR_TERMINAL_CONDITIONS and c.get("status") == "True"
        for c in conditions
    ):
        return "failing"
    ready = next((c for c in conditions if c.get("type") == "Ready"), None)
    if ready is None:
        return "unknown"
    if ready.get("status") == "True":
        return "ready"
    if ready.get("status") != "False":
        return "unknown"
    # Ready=False is also how cert-manager reports "still working on it":
    # a CertificateRequest waiting on its issuer, a Certificate whose Secret
    # has not been written yet. Same treatment as a pending ACME Order —
    # nothing is decided until cert-manager is.
    if ready.get("reason") in _READY_FALSE_IN_FLIGHT.get(kind, ()):
        return "unknown"
    return "failing"


def _flux_resource_state(kind: str, namespace: str, name: str) -> str:
    """One of "ready", "failing", "gone", "unknown".

    `_is_flux_resource_ready` collapses this to a boolean, which is enough to
    decide whether to close an incident but loses the distinction that matters
    for keeping one open: a resource that is still failing is not the same as
    one we could not read.
    """
    spec = _FLUX_RESOURCES.get(kind)
    if not spec:
        return "unknown"
    group, version, plural = spec

    try:
        api = k8s.CustomObjectsApi()
        obj = api.get_namespaced_custom_object(group, version, namespace, plural, name)
    except k8s.ApiException as e:
        if e.status == 404:
            logger.debug("Reconcile: %s %s/%s not found (deleted)", kind, namespace, name)
            return "gone"
        logger.warning("Reconcile: API error checking %s %s/%s: %s", kind, namespace, name, e.reason)
        return "unknown"
    except Exception:
        logger.debug("Reconcile: failed to check %s %s/%s", kind, namespace, name, exc_info=True)
        return "unknown"

    conditions = obj.get("status", {}).get("conditions", [])
    ready = next((c for c in conditions if c.get("type") == "Ready"), None)
    if ready is None:
        # No Ready condition yet — mid-first-reconcile, nothing decided.
        return "unknown"
    return "ready" if ready.get("status") == "True" else "failing"


class ReconcileScanner:
    """Periodic reconciliation: auto-resolve stale active incidents."""

    name = "reconcile"
    startup_delay = 120  # let other scanners run first

    @property
    def enabled(self) -> bool:
        return True  # always enabled — core correctness feature

    @property
    def interval_seconds(self) -> int:
        return config.SCANNER_INTERVAL_SECONDS

    def scan(self) -> list[ScanResult]:
        from src.handlers.startup import get_store
        store = get_store()
        results: list[ScanResult] = []

        results.extend(self._reconcile_nodes(store))
        results.extend(self._reconcile_flux(store))
        results.extend(self._reconcile_eck(store))
        results.extend(self._reconcile_cert_manager(store))
        results.extend(self._reconcile_event_only_workloads(store))

        if results:
            logger.info("Reconcile scanner: %d incidents auto-resolved", len(results))
        else:
            logger.debug("Reconcile scanner: nothing to resolve")
        return results

    def _reconcile_nodes(self, store) -> list[ScanResult]:
        """Auto-resolve Node:* incidents where the node is now Ready."""
        results: list[ScanResult] = []
        active = store.get_active_incidents_by_prefix(["Node:"])
        if not active:
            return results

        core = k8s.CoreV1Api()
        for incident in active:
            # Parse node name from state_key "Node:{node_name}:notready"
            match = re.match(r"^Node:([^:]+):", incident.state_key)
            if not match:
                continue
            node_name = match.group(1)

            try:
                node = core.read_node(node_name)
                is_ready = any(
                    c.type == "Ready" and c.status == "True"
                    for c in (node.status.conditions or [])
                )
                if not is_ready:
                    continue
            except k8s.ApiException as e:
                if e.status == 404:
                    logger.debug("Reconcile: node %s not found (deleted), resolving", node_name)
                else:
                    logger.warning("Reconcile: API error checking node %s: %s", node_name, e.reason)
                    continue
            except Exception:
                logger.debug("Reconcile: failed to check node %s", node_name, exc_info=True)
                continue

            results.append(ScanResult(
                state_key=incident.state_key,
                title=f"Resolved: Node {node_name} is Ready",
                severity="info",
                resource=f"Node/{node_name}",
                namespace="",
                issue_type=incident.issue_type,
                auto_resolve=True,
            ))

        return results

    def _reconcile_flux(self, store) -> list[ScanResult]:
        """Auto-resolve Flux resource incidents where the resource is now Ready."""
        results: list[ScanResult] = []

        # Flux handler incidents: "Flux:{Kind}:{ns}/{name}:stalled"
        flux_handler_active = store.get_active_incidents_by_prefix(
            ["Flux:HelmRelease:", "Flux:Kustomization:"]
        )
        for incident in flux_handler_active:
            match = re.match(r"^Flux:(\w+):([^/]+)/([^:]+):", incident.state_key)
            if not match:
                continue
            kind, ns, name = match.group(1), match.group(2), match.group(3)
            state = _flux_resource_state(kind, ns, name)
            if state == "failing":
                # Still broken, and nothing will say so again. These incidents
                # are raised only by kopf events on the Flux resource; once Flux
                # exhausts its retries it stops writing to the object, the
                # events stop, and the incident goes silent while the problem
                # remains. Seen in practice: a HelmRelease frozen at 11
                # occurrences with last_seen 22.8h old and climbing, on a chart
                # 290h out of date that Flux had permanently given up on. At 7
                # days the stale reaper would have closed it as recovered.
                self._keep_alive(store, incident, f"{kind} {ns}/{name}")
                continue
            if state in ("ready", "gone"):
                results.append(ScanResult(
                    state_key=incident.state_key,
                    title=f"Resolved: Flux {kind} {ns}/{name}",
                    severity="info",
                    resource=f"{kind}/{name}",
                    namespace=ns,
                    issue_type=incident.issue_type,
                    auto_resolve=True,
                ))

        # Event handler incidents: "{Kind}:{ns}/{name}:{alias}"
        event_flux_active = store.get_active_incidents_by_prefix(
            ["HelmRepository:", "HelmChart:", "GitRepository:", "OCIRepository:",
             "HelmRelease:", "Kustomization:"]
        )
        for incident in event_flux_active:
            match = re.match(r"^(\w+):([^/]+)/([^:]+):", incident.state_key)
            if not match:
                continue
            kind, ns, name = match.group(1), match.group(2), match.group(3)
            if kind not in _FLUX_RESOURCES:
                continue
            state = _flux_resource_state(kind, ns, name)
            if state == "failing":
                self._keep_alive(store, incident, f"{kind} {ns}/{name}")
                continue
            if state in ("ready", "gone"):
                results.append(ScanResult(
                    state_key=incident.state_key,
                    title=f"Resolved: {kind} {ns}/{name}",
                    severity="info",
                    resource=f"{kind}/{name}",
                    namespace=ns,
                    issue_type=incident.issue_type,
                    auto_resolve=True,
                ))

        return results

    def _reconcile_eck(self, store) -> list[ScanResult]:
        """Auto-resolve Elasticsearch/Kibana/ApmServer incidents that read green.

        These are raised by the event handler on an ECK "Unhealthy" event. No
        other sweeper matches their prefix, so nothing ever closed them: across
        the whole fleet history every Elasticsearch and Kibana incident was
        closed by hand, none automatically.

        Mirrors `_reconcile_flux`: a resource that is still degraded is kept
        alive rather than left to the stale reaper, and only green-or-gone
        closes the incident. An unreadable CR is "unknown" and changes nothing —
        a failed read must never be mistaken for recovery.
        """
        results: list[ScanResult] = []
        active = store.get_active_incidents_by_prefix(
            [f"{kind}:" for kind in _ECK_RESOURCES]
        )
        if not active:
            return results

        for incident in active:
            match = re.match(r"^(\w+):([^/]+)/([^:]+):", incident.state_key)
            if not match:
                continue
            kind, ns, name = match.group(1), match.group(2), match.group(3)
            if kind not in _ECK_RESOURCES:
                continue
            state = _eck_resource_state(kind, ns, name)
            if state == "failing":
                self._keep_alive(store, incident, f"{kind} {ns}/{name}")
                continue
            if state in ("ready", "gone"):
                results.append(ScanResult(
                    state_key=incident.state_key,
                    title=f"Resolved: {kind} {ns}/{name}",
                    severity="info",
                    resource=f"{kind}/{name}",
                    namespace=ns,
                    issue_type=incident.issue_type,
                    auto_resolve=True,
                ))

        return results

    def _reconcile_cert_manager(self, store) -> list[ScanResult]:
        """Auto-resolve cert-manager incidents whose renewal has since succeeded.

        Only event-born keys (`Kind:ns/name:alias`) are touched. The certificate
        scanner's own `Certificate:ns/name` incidents carry no alias suffix,
        fail the regex below, and stay that scanner's to close — it re-lists
        every Certificate on each pass and already does.

        Mirrors `_reconcile_eck`: a resource that is still failing is kept
        alive rather than left to the stale reaper, ready-or-gone closes the
        incident, and an unreadable or in-flight resource changes nothing.
        """
        results: list[ScanResult] = []
        active = store.get_active_incidents_by_prefix(
            [f"{kind}:" for kind in _CERT_MANAGER_RESOURCES]
        )
        if not active:
            return results

        for incident in active:
            match = re.match(r"^(\w+):([^/]+)/([^:]+):", incident.state_key)
            if not match:
                continue
            kind, ns, name = match.group(1), match.group(2), match.group(3)
            if kind not in _CERT_MANAGER_RESOURCES:
                continue
            state = _cert_manager_resource_state(kind, ns, name)
            if state == "failing":
                self._keep_alive(store, incident, f"{kind} {ns}/{name}")
                continue
            if state in ("ready", "gone"):
                results.append(ScanResult(
                    state_key=incident.state_key,
                    title=f"Resolved: {kind} {ns}/{name}",
                    severity="info",
                    resource=f"{kind}/{name}",
                    namespace=ns,
                    issue_type=incident.issue_type,
                    auto_resolve=True,
                ))

        return results

    def _reconcile_event_only_workloads(self, store) -> list[ScanResult]:
        """Close workload incidents the pod scanner is not allowed to sweep.

        `events.py` raises these from Kubernetes events (probe failures land as
        the `unhealthy` alias) and schedules an in-memory deferred check to
        close them. That check is the fast path and it is not durable:

        * it lives in an asyncio task, so a monitor restart between the alert
          and the check orphans the incident - a monitor that came up at
          07:32 and three incidents raised at 07:26-07:27 by the previous pod
          were still active hours later;
        * it runs exactly once, so an owner that is not yet healthy at
          T+EVENT_AUTO_RESOLVE_DELAY_SECONDS is never looked at again.

        The pod scanner then refuses to sweep them by design, because it cannot
        confirm a probe-level condition from pod state. This method can: it asks
        the same authority the deferred check does, on every pass.

        Only incidents with no fresh event for EVENT_ONLY_RESOLVE_GRACE_SECONDS
        are eligible, so a genuinely flapping probe stays open and the deferred
        path always gets to go first.
        """
        results: list[ScanResult] = []
        active = store.get_active_incidents_by_prefix(_WORKLOAD_PREFIXES)
        if not active:
            return results

        cutoff = time.time() - config.EVENT_ONLY_RESOLVE_GRACE_SECONDS
        for incident in active:
            alias = incident.state_key.rsplit(":", 1)[-1]
            # Anything the pod scanner already sweeps is not ours to touch.
            if alias in _POD_SWEPT_ALIASES:
                continue
            if incident.last_seen_at > cutoff:
                continue
            match = re.match(r"^(\w+):([^/]+)/([^:]+):", incident.state_key)
            if not match:
                continue
            kind, ns, name = match.group(1), match.group(2), match.group(3)
            ns = incident.namespace or ns
            if not self._workload_recovered(kind, ns, name):
                # Not confirmed healthy — hold it open, and refresh last_seen_at
                # so the 7-day stale reaper does not read "no fresh event" as
                # "it went away". Same treatment the ECK path gives a red CR:
                # this branch is reached only for an incident already past its
                # grace window, so without the touch an incident whose owner is
                # quietly down (scaled to zero, stuck mid-rollout) and therefore
                # emitting no new events would be reaped as if recovered.
                self._keep_alive(store, incident, f"{kind} {ns}/{name}")
                continue
            results.append(ScanResult(
                state_key=incident.state_key,
                title=f"Resolved: {kind} {ns}/{name} healthy",
                severity="info",
                resource=f"{kind}/{name}",
                namespace=ns,
                issue_type=incident.issue_type,
                auto_resolve=True,
            ))

        return results

    def _workload_recovered(self, kind: str, namespace: str, name: str) -> bool:
        """True only when this workload is provably healthy again.

        Fails CLOSED everywhere, like `owner_fully_available`: an unknown kind
        or a failed read returns False, so an incident we cannot judge stays
        open instead of being closed on a guess.
        """
        if kind in ("Deployment", "StatefulSet", "DaemonSet"):
            return owner_fully_available(f"{kind}:{namespace}/{name}", namespace)
        if kind == "Job":
            # A Job is done, not "available": it has recovered once it is Complete,
            # or once it is gone (CronJob history limit / TTL) —
            # a deleted Job cannot still be failing to mount. One that is still
            # running or ended Failed stays open. Mount events on CronJob runs
            # (scheduled jobs, a database init job)
            # otherwise sat "active" for days with nothing to close them.
            try:
                job = k8s.BatchV1Api().read_namespaced_job(name, namespace)
            except k8s.ApiException as e:
                if e.status == 404:
                    return True
                logger.warning(
                    "Reconcile: could not read job %s/%s: %s", namespace, name, e.reason,
                )
                return False
            except Exception:
                logger.debug(
                    "Reconcile: job read failed for %s/%s", namespace, name, exc_info=True,
                )
                return False
            # The Complete condition, not status.succeeded: with completions > 1
            # one succeeded pod does not make the Job done.
            return any(
                c.type == "Complete" and c.status == "True"
                for c in ((job.status.conditions or []) if job.status else [])
            )
        if kind == "Pod":
            # owner_fully_available returns False for bare Pod keys by design,
            # so the pod is read directly. A deleted pod cannot still be
            # unhealthy - that case used to leave a fossil incident behind.
            try:
                pod = k8s.CoreV1Api().read_namespaced_pod(name, namespace)
            except k8s.ApiException as e:
                if e.status == 404:
                    return True
                logger.warning(
                    "Reconcile: could not read pod %s/%s: %s", namespace, name, e.reason,
                )
                return False
            except Exception:
                logger.debug(
                    "Reconcile: pod read failed for %s/%s", namespace, name, exc_info=True,
                )
                return False
            if (pod.status.phase if pod.status else "") != "Running":
                return False
            return any(
                c.type == "Ready" and c.status == "True"
                for c in ((pod.status.conditions or []) if pod.status else [])
            )
        return False

    def _keep_alive(self, store, incident, what: str) -> None:
        """Record that a still-broken incident is still broken.

        Deliberately silent: no occurrence, no Slack, no escalation. The only
        thing this changes is last_seen_at, so the stale reaper stops treating
        "nobody mentioned it for a week" as "it went away". Everything else
        about the incident — cooldown, severity, escalation — is untouched.
        """
        try:
            store.touch_incident(incident.id)
            logger.debug("Reconcile: %s still failing, incident kept alive", what)
        except Exception:
            logger.warning("Reconcile: could not keep %s alive", what, exc_info=True)

    def _is_flux_resource_ready(self, kind: str, namespace: str, name: str) -> bool:
        """True when the incident for this resource should be closed.

        That is either state — a resource reporting Ready, or one that no longer
        exists. Kind validation lives in `_flux_resource_state`, which returns
        "unknown" for anything it does not recognise.
        """
        return _flux_resource_state(kind, namespace, name) in ("ready", "gone")

    def collect_daily_data(self) -> str | None:
        return None

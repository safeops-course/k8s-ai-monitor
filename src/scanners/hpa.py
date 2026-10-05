"""HPA scanner — an autoscaler that wants more replicas than it may have.

The gap this fills. An HPA that hits its ceiling is silent: it keeps
recommending a higher count, Kubernetes keeps clamping it, and nothing is
logged, no event fires, and the pods that do exist stay Ready. The service is
served by fewer replicas than its own metrics say it needs, and the first
visible symptom is latency.

Seen in practice before this existed: a ceiling of 15 for a service whose pods
peaked at 0.56 cores, and others at ceilings their nodes could not physically
honour. Neither state was detectable except by reading `kubectl get hpa` by hand.

**The trap, and it is the whole reason this file is careful.** The obvious
predicate — `ScalingLimited == True` — is wrong. Kubernetes sets that condition
True at *both* ends of the range:

    production/backend  ScalingLimited True   TooFewReplicas     <- resting on its floor
    production/frontend ScalingLimited False  DesiredWithinRange
    (saturated)         ScalingLimited True   TooManyReplicas    <- the one we want

Resting on the floor (minReplicas) is where most HPAs spend most of their time:
it is the normal, healthy state - so matching on status alone would alert
on nearly every HPA in production. The reason has to be matched too.

What this deliberately does not cover: an HPA that scaled up but whose new pods
cannot be scheduled. There `currentReplicas` includes the Pending pod, the HPA
is content, and `ScalingLimited` stays False. That is `FailedScheduling`, which
the event handler already raises.

Severity is warning, never critical. Being at the ceiling means the shop is
serving on fewer pods than it wants, not that it is down — the same reasoning
that keeps plugin failures off the pager while `critical_endpoint` decides what
an outage is.
"""
import logging
from datetime import datetime, timezone

from kubernetes import client as k8s

from src import config
from src.scanners._base import ScanResult

logger = logging.getLogger(__name__)

# Kubernetes' own word for "I recommended more than maxReplicas allows".
_SATURATED_REASON = "TooManyReplicas"


def _utilisation(hpa) -> list[str]:
    """Render "cpu 82%/70%" per metric, matching what `kubectl get hpa` shows.

    Targets come from the spec and current values from the status; the two lists
    are correlated by resource name rather than by position, because neither API
    promises they are ordered the same way.
    """
    targets: dict[str, int] = {}
    for m in (getattr(hpa.spec, "metrics", None) or []):
        res = getattr(m, "resource", None)
        if res is None or getattr(res, "target", None) is None:
            continue
        if res.target.average_utilization is not None:
            targets[res.name] = res.target.average_utilization

    out = []
    for m in (getattr(hpa.status, "current_metrics", None) or []):
        res = getattr(m, "resource", None)
        if res is None or getattr(res, "current", None) is None:
            continue
        cur = res.current.average_utilization
        if cur is None or res.name not in targets:
            continue
        out.append(f"{res.name} {cur}%/{targets[res.name]}%")
    return out


def _saturated_since(hpa) -> datetime | None:
    """When the autoscaler last became ceiling-bound, or None if it is not.

    Read from the condition rather than tracked here on purpose: it survives a
    monitor restart, and it means a brief spike cannot raise an incident. A
    deploy alone can move a replica count 3 -> 6 -> 3 inside ten minutes while
    CPU never left 0.2 cores; nothing that short should reach Slack.
    """
    for c in (getattr(hpa.status, "conditions", None) or []):
        if c.type != "ScalingLimited":
            continue
        if str(c.status) != "True" or c.reason != _SATURATED_REASON:
            return None
        return c.last_transition_time
    return None


class HpaScanner:
    name = "hpa"
    startup_delay = 120

    @property
    def enabled(self):
        return config.SCANNER_HPA_ENABLED

    @property
    def interval_seconds(self):
        return config.HPA_SCAN_INTERVAL_SECONDS

    def scan(self) -> list[ScanResult]:
        api = k8s.AutoscalingV2Api()
        results: list[ScanResult] = []
        problem_keys: set[str] = set()
        # Namespaces the API actually answered for. Auto-resolve reads this and
        # not the configured list: a namespace whose call raised is still
        # configured, so checking configuration would clear its incidents on the
        # strength of an answer we never got.
        listed: set[str] = set()
        checked = 0

        for ns in config.get_namespaces():
            try:
                hpas = api.list_namespaced_horizontal_pod_autoscaler(ns).items
            except Exception:
                # One unreadable namespace must not cost the others. Nothing is
                # resolved on this path either — see the auto-resolve note below.
                logger.warning("HPA scanner: could not list HPAs in %s", ns, exc_info=True)
                continue
            listed.add(ns)

            for hpa in hpas:
                checked += 1
                name = hpa.metadata.name
                since = _saturated_since(hpa)
                if since is None:
                    continue

                current = hpa.status.current_replicas or 0
                maximum = hpa.spec.max_replicas
                if current < maximum:
                    # Clamped but still climbing — it has room to reach the
                    # ceiling on its own. Reporting now would be premature.
                    continue

                age_min = (datetime.now(timezone.utc) - since).total_seconds() / 60
                if age_min < config.HPA_SATURATED_MIN_MINUTES:
                    logger.debug("HPA scanner: %s/%s at ceiling for %.0fm, below the %dm floor",
                                 ns, name, age_min, config.HPA_SATURATED_MIN_MINUTES)
                    continue

                metrics = _utilisation(hpa)
                desired = hpa.status.desired_replicas or current
                target_ref = getattr(hpa.spec.scale_target_ref, "name", name)

                context = "\n".join([
                    "## Autoscaler at its ceiling",
                    f"HPA: {ns}/{name} -> {hpa.spec.scale_target_ref.kind}/{target_ref}",
                    f"Replicas: {current} running, ceiling {maximum} "
                    f"(floor {hpa.spec.min_replicas or 1})",
                    f"Metrics: {', '.join(metrics) if metrics else 'none reported'}",
                    f"Ceiling-bound for: {age_min / 60:.1f}h",
                    "",
                    "Kubernetes recommended more replicas than maxReplicas allows "
                    f"({_SATURATED_REASON}). The workload is serving on fewer pods "
                    "than its own metrics ask for.",
                    "",
                    "Either the ceiling is too low for real demand, or the metric "
                    "driving it is the wrong one — a Node.js heap grows into "
                    "whatever it is given, so a memory target can pin a replica "
                    "count that CPU does not justify. Check which metric is over "
                    "its target before raising the ceiling.",
                    "",
                    "Raising maxReplicas is only useful if the node can hold the "
                    "extra pods; if it cannot, the next replica goes Pending and "
                    "FailedScheduling reports that instead.",
                ]) + "\n"

                state_key = f"HPA:{ns}/{name}:saturated"
                problem_keys.add(state_key)
                results.append(ScanResult(
                    state_key=state_key,
                    title=f"HPA at ceiling: {name} ({current}/{maximum})",
                    severity="warning",
                    # Never critical, and the pipeline must not decide otherwise.
                    # Both promoters would: the fingerprint is new to every
                    # cluster on the day this scanner ships, and an autoscaler
                    # capped for days is the definition of persistent. Neither
                    # makes it an outage — the workload is serving, on fewer
                    # pods than it asked for.
                    never_promote=True,
                    resource=f"HorizontalPodAutoscaler/{name}",
                    namespace=ns,
                    issue_type="hpa",
                    context_override=context,
                    metadata={
                        "current_replicas": current,
                        "desired_replicas": desired,
                        "max_replicas": maximum,
                        "metrics": metrics,
                        "saturated_minutes": round(age_min),
                    },
                ))

        # Auto-resolve. Only incidents whose namespace we successfully listed can
        # be cleared: a namespace that raised above is absent from problem_keys
        # for lack of an answer, not because it recovered, and closing on that
        # would be the "silence means healthy" mistake.
        try:
            from src.handlers.startup import get_store
            store = get_store()
            for incident in store.get_active_incidents_by_prefix(["HPA:"]):
                if incident.state_key in problem_keys:
                    continue
                ns = incident.state_key.split(":")[1].split("/")[0]
                if ns not in listed:
                    continue
                name = incident.state_key.split(":")[1].split("/")[-1]
                results.append(ScanResult(
                    state_key=incident.state_key,
                    title=f"HPA back within range: {name}",
                    severity="info",
                    resource=f"HorizontalPodAutoscaler/{name}",
                    namespace=ns,
                    issue_type="hpa",
                    auto_resolve=True,
                ))
        except Exception:
            logger.warning("HPA scanner: failed to check for auto-resolve", exc_info=True)

        logger.info("HPA scanner completed: %d autoscalers checked, %d at their ceiling",
                    checked, len(problem_keys))
        return results

    def collect_daily_data(self) -> str | None:
        return None

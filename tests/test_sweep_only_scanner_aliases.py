"""The pod scanner must not resolve incidents it cannot detect.

Its trailing sweep closes any active incident whose state_key is missing from
`problem_keys`, and `problem_keys` holds only what the scanner itself saw this
tick. Aliases that arrive as Events — `mount` from FailedAttachVolume,
`unhealthy` from Unhealthy/ProbeWarning — are handled elsewhere and can never
land there, so the sweep resolved them on every pass.

echo, 48h, one unchanging fingerprint (119bf2e98b21):

    111  Auto-resolved: StatefulSet:production/db-rs0:mount
    110  Reopened resolved incident: ...
      1  New incident: ... (id=30)

The volume was locked in the Hetzner API the whole time — the mount never
recovered for even one second. Every reopen posted to Slack, because the reopen
path forces should_alert to bypass cooldown for what it takes to be a fixed
incident. 179 of the cluster's 197 alerts over those two days were reopens.
"""
from unittest.mock import MagicMock, patch

from src.engine.constants import POD_PROBLEM_REASONS, PROBLEM_STATES
from src.scanners.pod import _SCANNER_ALIASES, PodScanner


def _incident(state_key, issue_type="mount", namespace="production"):
    inc = MagicMock()
    inc.state_key = state_key
    inc.issue_type = issue_type
    inc.namespace = namespace
    return inc


def _sweep(active):
    """Run a scan over an empty cluster, so results are sweep decisions only."""
    core = MagicMock()
    core.list_namespaced_pod.return_value = MagicMock(items=[])
    store = MagicMock()
    store.get_active_incidents_by_prefix.return_value = active
    with patch("src.scanners.pod.k8s.CoreV1Api", return_value=core), \
         patch("src.scanners.pod.config.get_namespaces", return_value=["production"]), \
         patch("src.handlers.startup.get_store", return_value=store):
        return {r.state_key for r in PodScanner().scan() if r.auto_resolve}


def test_mount_incident_is_not_swept():
    """The echo case. FailedAttachVolume is an Event; this scanner reads
    pod.status.reason and container states, so it can never observe it."""
    key = "StatefulSet:production/db-rs0:mount"
    assert _sweep([_incident(key)]) == set()


def test_unhealthy_incident_is_not_swept():
    """Unhealthy/ProbeWarning are Events too. A pod failing its readiness probe
    stays Running with an empty status.reason and a `running` container state,
    which is exactly why the scanner cannot see it."""
    key = "Deployment:production/db-admin:unhealthy"
    assert _sweep([_incident(key, issue_type="unhealthy")]) == set()


def test_crash_incident_is_still_swept():
    """The guard must not become a blanket amnesty. CrashLoopBackOff is a
    container waiting state the scanner reads directly, so its absence is
    real evidence the pod recovered."""
    key = "Deployment:production/api-gateway:crash"
    assert _sweep([_incident(key, issue_type="crash")]) == {key}


def test_oom_and_evicted_are_still_swept():
    keys = {
        "Deployment:production/asset-service:oom",
        "Deployment:production/worker-history:evicted",
    }
    assert _sweep([_incident(k) for k in keys]) == keys


def test_collective_is_unaffected_by_the_alias_guard():
    """Collective keys carry a namespace, not an alias — `Collective:production`
    would otherwise be read as alias 'production' and never resolve, leaking
    every collective incident forever."""
    assert _sweep([_incident("Collective:production",
                             issue_type="collective_incident")]) == {"Collective:production"}


def test_alias_set_is_derived_not_hardcoded():
    """It must track the constants the scan loop reads, or the two drift and the
    guard silently starts suppressing real resolutions."""
    assert "crash" in _SCANNER_ALIASES          # CrashLoopBackOff
    assert "oom" in _SCANNER_ALIASES            # OOMKilled
    assert "evicted" in _SCANNER_ALIASES        # Evicted
    assert "image-pull" in _SCANNER_ALIASES     # ImagePullBackOff
    assert "mount" not in _SCANNER_ALIASES      # event-only
    assert "unhealthy" not in _SCANNER_ALIASES  # event-only
    assert "notready" not in _SCANNER_ALIASES   # node event
    # Every reason the loop can encounter must map into the set.
    assert len(_SCANNER_ALIASES) >= 1
    for reason in POD_PROBLEM_REASONS | PROBLEM_STATES:
        from src.engine.constants import PROBLEM_ALIASES
        assert PROBLEM_ALIASES.get(reason, reason.lower()) in _SCANNER_ALIASES

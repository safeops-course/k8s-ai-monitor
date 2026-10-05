"""Pod scanner: `Collective:{ns}` incidents must not outlive their namespace.

Batch mode (src/handlers/events.py) persists ONE `Collective:{ns}` incident for a
burst of pod events instead of one incident per owner. That state_key can never
appear in the scanner's `problem_keys`, which cuts both ways: without the prefix
the sweep never sees it and the incident stays active forever, and with the
prefix but no namespace guard the sweep would close it on the very next tick —
even mid-outage.
"""
import unittest
from unittest.mock import MagicMock, patch

from src.engine.store import Incident
from src.scanners.pod import PodScanner


def _make_pod(name: str, *, reason: str = "", ready: bool = True) -> MagicMock:
    """A pod the scanner sees as healthy unless told otherwise.

    `ready=False` models the case the scanner is blind to on its own: a pod
    Running with a `running` container state and an empty status.reason, held
    NotReady by a failing readiness probe.
    """
    pod = MagicMock()
    pod.metadata.name = name
    pod.status.reason = reason
    pod.status.phase = "Running"
    pod.status.container_statuses = []
    cond = MagicMock()
    cond.type = "Ready"
    cond.status = "True" if ready else "False"
    pod.status.conditions = [cond]
    pod.spec.node_name = "node-1"
    return pod


def _collective(ns: str) -> Incident:
    return Incident(
        id=1,
        state_key=f"Collective:{ns}",
        fingerprint="",
        issue_type="collective_incident",
        severity="critical",
        owner_ref="",
        first_seen_at=0.0,
        last_seen_at=0.0,
        active_since=0.0,
        occurrence_count=1,
        cooldown_until=None,
        last_slack_ts="",
        status="active",
        namespace=ns,
    )


class CollectiveAutoResolveTest(unittest.TestCase):
    def _scan(self, pods, active, store=None):
        core = MagicMock()
        core.list_namespaced_pod.return_value = MagicMock(items=pods)
        store = store or MagicMock()
        store.get_active_incidents_by_prefix.return_value = active
        with patch("src.scanners.pod.k8s.CoreV1Api", return_value=core), \
             patch("src.scanners.pod.config.get_namespaces", return_value=["production"]), \
             patch("src.scanners.pod.resolve_owner_key", return_value="Deployment:production/api"), \
             patch("src.handlers.startup.get_store", return_value=store):
            return PodScanner().scan()

    def test_collective_held_open_while_namespace_still_broken(self):
        results = self._scan(
            [_make_pod("api-1", reason="Evicted")], [_collective("production")],
        )
        resolved = [r.state_key for r in results if r.auto_resolve]
        self.assertEqual(
            resolved, [],
            "collective must stay active while its namespace still has a problem pod",
        )

    def test_collective_resolved_once_namespace_is_clean(self):
        results = self._scan([_make_pod("api-1")], [_collective("production")])
        resolved = [r.state_key for r in results if r.auto_resolve]
        self.assertEqual(resolved, ["Collective:production"])

    def test_collective_held_open_while_probes_still_failing(self):
        """A probe-failing pod is invisible to this scanner but not to events.

        Nothing here lands in `results`: the pod is Running, its container state
        is `running`, and status.reason is empty. The Unhealthy/ProbeWarning
        events it emits still raise a Collective incident, so resolving on a
        clean `results` would close it while the outage is ongoing.
        """
        results = self._scan(
            [_make_pod("api-1", ready=False)], [_collective("production")],
        )
        self.assertEqual(
            [r.state_key for r in results if not r.auto_resolve], [],
            "probe failure must not itself raise a pod incident",
        )
        self.assertEqual(
            [r.state_key for r in results if r.auto_resolve], [],
            "collective must stay active while a pod is Running but NotReady",
        )

    def test_collective_resolves_once_probes_recover(self):
        """The auto_resolve emission must survive the probe-aware guard."""
        results = self._scan([_make_pod("api-1", ready=True)], [_collective("production")])
        self.assertEqual(
            [r.state_key for r in results if r.auto_resolve], ["Collective:production"],
        )

    def test_sweep_asks_the_store_for_collective_keys(self):
        """Regression guard: dropping the prefix silently resurrects the leak."""
        store = MagicMock()
        self._scan([], [], store=store)
        prefixes = store.get_active_incidents_by_prefix.call_args[0][0]
        self.assertIn("Collective:", prefixes)


if __name__ == "__main__":
    unittest.main()

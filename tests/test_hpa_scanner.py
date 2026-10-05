"""Tests for the HPA scanner.

The scanner exists to catch an autoscaler that wants more replicas than its
ceiling allows — a state Kubernetes reports and then never mentions again.

Almost every test here is about *not* alerting. The signal is rare; the ways to
report it spuriously are not, and two of them were found in live objects before
a line was written:

  - `ScalingLimited` is True at both ends of the range. An HPA resting on its
    floor carries `ScalingLimited=True, reason=TooFewReplicas`, and that is the
    normal state of nearly every HPA in production.
  - Being briefly clamped is ordinary. A deploy alone moved one frontend
    3 -> 6 -> 3 in ten minutes while its CPU never left 0.2 cores.
"""
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from src.scanners.hpa import HpaScanner, _saturated_since, _utilisation


def _condition(ctype, status, reason, age_minutes=60):
    c = MagicMock()
    c.type = ctype
    c.status = status
    c.reason = reason
    c.last_transition_time = datetime.now(timezone.utc) - timedelta(minutes=age_minutes)
    return c


def _metric(name, current=None, target=None):
    m = MagicMock()
    if current is None and target is None:
        m.resource = None
        return m
    m.resource = MagicMock()
    m.resource.name = name
    if target is not None:
        m.resource.target = MagicMock()
        m.resource.target.average_utilization = target
    else:
        m.resource.target = None
    if current is not None:
        m.resource.current = MagicMock()
        m.resource.current.average_utilization = current
    else:
        m.resource.current = None
    return m


def _hpa(name="frontend-alpha", *, current=6, maximum=6, minimum=3,
         reason="TooManyReplicas", status="True", age_minutes=60,
         metrics=(("cpu", 82, 70),), conditions=None):
    h = MagicMock()
    h.metadata.name = name
    h.spec.max_replicas = maximum
    h.spec.min_replicas = minimum
    h.spec.scale_target_ref.kind = "Deployment"
    h.spec.scale_target_ref.name = name
    h.spec.metrics = [_metric(n, target=t) for n, _, t in metrics]
    h.status.current_replicas = current
    h.status.desired_replicas = current
    h.status.current_metrics = [_metric(n, current=c) for n, c, _ in metrics]
    h.status.conditions = conditions if conditions is not None else [
        _condition("AbleToScale", "True", "ReadyForNewScale"),
        _condition("ScalingLimited", status, reason, age_minutes),
    ]
    return h


def _run(hpas, namespaces=("production",)):
    api = MagicMock()
    api.list_namespaced_horizontal_pod_autoscaler.return_value = MagicMock(items=hpas)
    store = MagicMock()
    store.get_active_incidents_by_prefix.return_value = []
    with patch("src.scanners.hpa.k8s.AutoscalingV2Api", return_value=api), \
         patch("src.config.get_namespaces", return_value=list(namespaces)), \
         patch("src.handlers.startup.get_store", return_value=store):
        return HpaScanner().scan(), store


# --- the signal -------------------------------------------------------------

class TestSaturated(unittest.TestCase):

    def test_ceiling_bound_autoscaler_is_reported(self):
        results, _ = _run([_hpa()])
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r.state_key, "HPA:production/frontend-alpha:saturated")
        self.assertEqual(r.issue_type, "hpa")
        self.assertFalse(r.auto_resolve)
        self.assertIn("6/6", r.title)

    def test_severity_is_warning_never_critical(self):
        """At the ceiling means serving on fewer pods than wanted, not down."""
        results, _ = _run([_hpa()])
        self.assertEqual(results[0].severity, "warning")

    def test_the_pipeline_is_told_not_to_promote(self):
        """warning alone is not enough — the promoters override it.

        A net-new fingerprint becomes critical and tags @ai, and every
        fingerprint is net-new on the day a scanner ships; a persistent
        incident becomes critical too, and an autoscaler capped for days is
        exactly that. Both fired on the first wave of this scanner in
        production: golf, bravo and hotel all arrived as CRITICAL
        with a new-marker, for shops that were serving.
        """
        results, _ = _run([_hpa()])
        self.assertTrue(results[0].never_promote)

    def test_context_carries_the_metric_readings(self):
        results, _ = _run([_hpa(metrics=(("cpu", 82, 70), ("memory", 94, 90)))])
        ctx = results[0].context_override
        self.assertIn("cpu 82%/70%", ctx)
        self.assertIn("memory 94%/90%", ctx)

    def test_metadata_carries_the_numbers(self):
        results, _ = _run([_hpa(current=6, maximum=6)])
        md = results[0].metadata
        self.assertEqual(md["current_replicas"], 6)
        self.assertEqual(md["max_replicas"], 6)
        self.assertGreaterEqual(md["saturated_minutes"], 59)


# --- everything that must stay quiet ----------------------------------------

class TestQuiet(unittest.TestCase):

    def test_autoscaler_resting_on_its_floor_is_not_reported(self):
        """The trap. Post pre-warm this is the normal state of most HPAs:

            alpha/backend  ScalingLimited True  TooFewReplicas

        Matching on status alone would alert on nearly every HPA in production.
        """
        results, _ = _run([_hpa(current=3, maximum=6, reason="TooFewReplicas")])
        self.assertEqual(results, [])

    def test_desired_within_range_is_not_reported(self):
        results, _ = _run([_hpa(current=4, maximum=6, status="False",
                                reason="DesiredWithinRange")])
        self.assertEqual(results, [])

    def test_brief_saturation_is_not_reported(self):
        """Ten minutes of it is a deploy, not a capacity problem."""
        results, _ = _run([_hpa(age_minutes=10)])
        self.assertEqual(results, [])

    def test_saturation_just_past_the_floor_is_reported(self):
        results, _ = _run([_hpa(age_minutes=16)])
        self.assertEqual(len(results), 1)

    def test_clamped_but_still_climbing_is_not_reported(self):
        """TooManyReplicas while below the ceiling: it can still get there on
        its own, and saying so now would be premature."""
        results, _ = _run([_hpa(current=4, maximum=6)])
        self.assertEqual(results, [])

    def test_missing_scaling_limited_condition_is_not_reported(self):
        results, _ = _run([_hpa(conditions=[_condition("AbleToScale", "True", "ReadyForNewScale")])])
        self.assertEqual(results, [])

    def test_no_conditions_at_all_is_not_reported(self):
        results, _ = _run([_hpa(conditions=[])])
        self.assertEqual(results, [])


# --- reading the metrics ----------------------------------------------------

class TestUtilisation(unittest.TestCase):

    def test_pairs_are_matched_by_name_not_position(self):
        """Neither list promises an order, so position would silently mislabel."""
        h = _hpa()
        h.spec.metrics = [_metric("memory", target=90), _metric("cpu", target=70)]
        h.status.current_metrics = [_metric("cpu", current=82), _metric("memory", current=94)]
        self.assertEqual(_utilisation(h), ["cpu 82%/70%", "memory 94%/90%"])

    def test_metric_without_a_target_is_skipped(self):
        h = _hpa()
        h.spec.metrics = [_metric("cpu", target=70)]
        h.status.current_metrics = [_metric("cpu", current=82), _metric("memory", current=94)]
        self.assertEqual(_utilisation(h), ["cpu 82%/70%"])

    def test_absent_metrics_render_as_none_rather_than_crashing(self):
        h = _hpa()
        h.spec.metrics = None
        h.status.current_metrics = None
        self.assertEqual(_utilisation(h), [])
        results, _ = _run([h])
        self.assertIn("none reported", results[0].context_override)


# --- failure directions -----------------------------------------------------

class TestFailureModes(unittest.TestCase):

    def test_unreadable_namespace_does_not_stop_the_others(self):
        api = MagicMock()
        api.list_namespaced_horizontal_pod_autoscaler.side_effect = [
            RuntimeError("forbidden"),
            MagicMock(items=[_hpa()]),
        ]
        store = MagicMock()
        store.get_active_incidents_by_prefix.return_value = []
        with patch("src.scanners.hpa.k8s.AutoscalingV2Api", return_value=api), \
             patch("src.config.get_namespaces", return_value=["broken", "production"]), \
             patch("src.handlers.startup.get_store", return_value=store):
            results = HpaScanner().scan()
        self.assertEqual(len(results), 1)

    def test_store_failure_does_not_break_the_scan(self):
        api = MagicMock()
        api.list_namespaced_horizontal_pod_autoscaler.return_value = MagicMock(items=[_hpa()])
        with patch("src.scanners.hpa.k8s.AutoscalingV2Api", return_value=api), \
             patch("src.config.get_namespaces", return_value=["production"]), \
             patch("src.handlers.startup.get_store", side_effect=RuntimeError("db locked")):
            results = HpaScanner().scan()
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].auto_resolve)


# --- auto-resolve -----------------------------------------------------------

class TestAutoResolve(unittest.TestCase):

    def _incident(self, state_key):
        inc = MagicMock()
        inc.state_key = state_key
        return inc

    def test_recovered_autoscaler_is_resolved(self):
        api = MagicMock()
        api.list_namespaced_horizontal_pod_autoscaler.return_value = MagicMock(items=[])
        store = MagicMock()
        store.get_active_incidents_by_prefix.return_value = [
            self._incident("HPA:production/frontend-alpha:saturated")]
        with patch("src.scanners.hpa.k8s.AutoscalingV2Api", return_value=api), \
             patch("src.config.get_namespaces", return_value=["production"]), \
             patch("src.handlers.startup.get_store", return_value=store):
            results = HpaScanner().scan()
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].auto_resolve)

    def test_still_saturated_is_not_resolved(self):
        api = MagicMock()
        api.list_namespaced_horizontal_pod_autoscaler.return_value = MagicMock(items=[_hpa()])
        store = MagicMock()
        store.get_active_incidents_by_prefix.return_value = [
            self._incident("HPA:production/frontend-alpha:saturated")]
        with patch("src.scanners.hpa.k8s.AutoscalingV2Api", return_value=api), \
             patch("src.config.get_namespaces", return_value=["production"]), \
             patch("src.handlers.startup.get_store", return_value=store):
            results = HpaScanner().scan()
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].auto_resolve)

    def test_incident_in_an_unlisted_namespace_is_not_resolved(self):
        """A namespace we never queried says nothing about its incidents.
        Closing on that would be reading silence as recovery — the same mistake
        that closed a HelmRelease nobody was talking about any more.
        """
        api = MagicMock()
        api.list_namespaced_horizontal_pod_autoscaler.return_value = MagicMock(items=[])
        store = MagicMock()
        store.get_active_incidents_by_prefix.return_value = [
            self._incident("HPA:staging/frontend-alpha:saturated")]
        with patch("src.scanners.hpa.k8s.AutoscalingV2Api", return_value=api), \
             patch("src.config.get_namespaces", return_value=["production"]), \
             patch("src.handlers.startup.get_store", return_value=store):
            results = HpaScanner().scan()
        self.assertEqual(results, [])

    def test_incident_is_not_resolved_when_its_namespace_could_not_be_listed(self):
        """The configured/answered distinction, and the reason it is not
        cosmetic.

        `production` is configured and its call raises, so it contributes
        nothing to problem_keys — for lack of an answer, not because the
        autoscaler recovered. Checking membership of the configured list would
        find it there and close the incident anyway. Only the set of namespaces
        the API actually answered for may clear anything.
        """
        api = MagicMock()
        api.list_namespaced_horizontal_pod_autoscaler.side_effect = RuntimeError("forbidden")
        store = MagicMock()
        store.get_active_incidents_by_prefix.return_value = [
            self._incident("HPA:production/frontend-alpha:saturated")]
        with patch("src.scanners.hpa.k8s.AutoscalingV2Api", return_value=api), \
             patch("src.config.get_namespaces", return_value=["production"]), \
             patch("src.handlers.startup.get_store", return_value=store):
            results = HpaScanner().scan()
        self.assertEqual(results, [], "an incident was closed on an answer we never received")

    def test_a_readable_namespace_still_resolves_when_another_one_fails(self):
        """The fix must not make one broken namespace freeze the whole cluster."""
        api = MagicMock()
        api.list_namespaced_horizontal_pod_autoscaler.side_effect = [
            RuntimeError("forbidden"),
            MagicMock(items=[]),
        ]
        store = MagicMock()
        store.get_active_incidents_by_prefix.return_value = [
            self._incident("HPA:broken/frontend-a:saturated"),
            self._incident("HPA:production/frontend-b:saturated"),
        ]
        with patch("src.scanners.hpa.k8s.AutoscalingV2Api", return_value=api), \
             patch("src.config.get_namespaces", return_value=["broken", "production"]), \
             patch("src.handlers.startup.get_store", return_value=store):
            results = HpaScanner().scan()
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].auto_resolve)
        self.assertEqual(results[0].namespace, "production")


# --- the flag ---------------------------------------------------------------

class TestFlag(unittest.TestCase):

    def test_disabled_scanner_reports_disabled(self):
        with patch("src.config.SCANNER_HPA_ENABLED", False):
            self.assertFalse(HpaScanner().enabled)

    def test_enabled_by_default(self):
        from src import config
        self.assertTrue(config.SCANNER_HPA_ENABLED)


class TestSaturatedSince(unittest.TestCase):

    def test_reads_the_transition_time_rather_than_tracking_state(self):
        """Duration comes from the condition so it survives a monitor restart."""
        h = _hpa(age_minutes=45)
        since = _saturated_since(h)
        self.assertIsNotNone(since)
        age = (datetime.now(timezone.utc) - since).total_seconds() / 60
        self.assertAlmostEqual(age, 45, delta=1)

    def test_returns_none_for_the_floor_reason(self):
        self.assertIsNone(_saturated_since(_hpa(reason="TooFewReplicas")))


if __name__ == "__main__":
    unittest.main()

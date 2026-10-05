"""Tests for the critical-endpoint cross-cycle flap damping (_flap_gate).

Reproduces the production incident that motivated the hysteresis: a frontend
backend flapping during GKE node upgrades emitted a NEW critical incident every
scan cycle (952 Down + 952 Recovered pairs in one maintenance window), because
a single healthy probe closed the incident and the next failure reopened it.
"""
import unittest

import src.config as config
from src.scanners.critical_endpoint import CriticalEndpointScanner

KEY = "CriticalEndpoint:production/frontend-shop:shop.example.com"


class FlapGateTest(unittest.TestCase):
    def setUp(self):
        self.scanner = CriticalEndpointScanner()
        self._orig = (
            config.CRITICAL_ENDPOINT_DOWN_CYCLES,
            config.CRITICAL_ENDPOINT_RECOVER_CYCLES,
        )
        config.CRITICAL_ENDPOINT_DOWN_CYCLES = 1
        config.CRITICAL_ENDPOINT_RECOVER_CYCLES = 3

    def tearDown(self):
        (config.CRITICAL_ENDPOINT_DOWN_CYCLES,
         config.CRITICAL_ENDPOINT_RECOVER_CYCLES) = self._orig

    def _run(self, sequence):
        """Feed a probe sequence ('F'/'O') and return the emitted decisions."""
        out = []
        for probe in sequence:
            out.append(self.scanner._flap_gate(KEY, healthy=(probe == "O")))
        return out

    def test_steady_failure_fires_down_on_first_cycle(self):
        # DOWN_CYCLES=1 keeps detection immediate (current behavior).
        self.assertEqual(self._run("F"), ["down"])

    def test_steady_failure_keeps_emitting_down(self):
        # The pipeline dedups repeated Down results into one incident's
        # occurrence count — the gate must not withhold them.
        self.assertEqual(self._run("FFF"), ["down", "down", "down"])

    def test_flap_emits_single_down_and_no_recovered(self):
        # The 952x2 scenario: alternate fail/ok. Single healthy cycles must NOT
        # emit Recovered (which would close and later reopen the incident).
        decisions = self._run("FOFOFOFO")
        self.assertEqual(decisions.count("recovered"), 0)
        self.assertEqual(decisions, ["down", None] * 4)

    def test_recovery_after_three_consecutive_ok(self):
        decisions = self._run("FOOO")
        self.assertEqual(decisions, ["down", None, None, "recovered"])

    def test_flap_then_stable_recovery(self):
        decisions = self._run("FOFOOO")
        self.assertEqual(decisions, ["down", None, "down", None, None, "recovered"])

    def test_steady_healthy_keeps_emitting_recovered(self):
        # Pre-hysteresis behavior: healthy frontends emit Recovered every
        # cycle (a no-op downstream unless an incident is active). After the
        # threshold is reached the counter keeps growing, so emission resumes
        # permanently.
        decisions = self._run("OOOOO")
        self.assertEqual(decisions, [None, None, "recovered", "recovered", "recovered"])

    def test_down_cycles_two_delays_detection(self):
        config.CRITICAL_ENDPOINT_DOWN_CYCLES = 2
        decisions = self._run("FF")
        self.assertEqual(decisions, [None, "down"])

    def test_counters_are_per_state_key(self):
        other = "CriticalEndpoint:production/frontend-other:other.example.com"
        self.assertEqual(self.scanner._flap_gate(KEY, healthy=False), "down")
        # Independent endpoint: its ok-counter is unaffected by KEY's failure.
        for _ in range(3):
            last = self.scanner._flap_gate(other, healthy=True)
        self.assertEqual(last, "recovered")
        # KEY still needs its own three healthy cycles.
        self.assertEqual(self.scanner._flap_gate(KEY, healthy=True), None)


if __name__ == "__main__":
    unittest.main()

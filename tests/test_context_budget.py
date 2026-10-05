"""Tests for src.engine.context_budget — dict-based alert payload and report payload."""
import json
import unittest

from src.engine.context_budget import (
    measure_context,
    build_alert_payload,
    build_report_payload,
    measure_report_data,
    _prioritize_log_lines,
    _section_slug,
)


class TestSectionSlug(unittest.TestCase):
    """Header -> slug mapping (kept for daily report markdown parsing)."""

    def test_pod_status(self):
        self.assertEqual(_section_slug("## Pod: production/my-app"), "pod_status")

    def test_logs(self):
        self.assertEqual(_section_slug("## Pod Logs (last 50 lines)"), "logs")

    def test_events(self):
        self.assertEqual(_section_slug("## Events"), "events")

    def test_deployment(self):
        self.assertEqual(_section_slug("## Deployment: production/my-app"), "deployment")

    def test_statefulset(self):
        self.assertEqual(_section_slug("## StatefulSet: production/redis"), "statefulset")

    def test_hpa(self):
        self.assertEqual(_section_slug("## HPA: production/my-app"), "hpa")

    def test_node_metrics(self):
        self.assertEqual(_section_slug("## Node Metrics Summary"), "node_metrics")

    def test_app_metrics(self):
        self.assertEqual(_section_slug("## Application Metrics"), "app_metrics")

    def test_prom_metrics(self):
        self.assertEqual(_section_slug("## Pod Metrics (Prometheus)"), "prom_metrics")

    def test_diagnostics(self):
        self.assertEqual(_section_slug("## Extended Diagnostics"), "diagnostics")

    def test_endpoint(self):
        self.assertEqual(_section_slug("## Endpoint Health Check"), "endpoint")

    def test_backend(self):
        self.assertEqual(_section_slug("## Backend Services"), "backend")

    def test_unknown_header(self):
        slug = _section_slug("## Something Else")
        self.assertEqual(slug, "something_else")


class TestMeasureContext(unittest.TestCase):
    """measure_context correctly parses markdown sections and counts bytes."""

    SAMPLE = (
        "## Pod: production/my-app\n"
        "Phase: Running\n"
        "restarts=5\n"
        "## Pod Logs (last 50 lines)\n"
        "log line 1\n"
        "log line 2\n"
        "## Events\n"
        "event 1\n"
        "event 2\n"
    )

    def test_sections_detected(self):
        result = measure_context(self.SAMPLE)
        self.assertIn("pod_status", result["sections"])
        self.assertIn("logs", result["sections"])
        self.assertIn("events", result["sections"])

    def test_total_bytes(self):
        result = measure_context(self.SAMPLE)
        self.assertEqual(result["total_bytes"], len(self.SAMPLE.encode("utf-8")))

    def test_empty_context(self):
        result = measure_context("")
        self.assertEqual(result["total_bytes"], 0)
        self.assertEqual(result["sections"], [])

    def test_no_sections(self):
        result = measure_context("just plain text\nno headers")
        self.assertEqual(result["sections"], ["_preamble"])
        self.assertEqual(result["total_bytes"], len("just plain text\nno headers".encode()))


class TestPrioritizeLogLines(unittest.TestCase):
    """Error lines prioritized, tail fill, omission note."""

    def test_under_limit_returns_all(self):
        lines = ["INFO hello", "ERROR bad", "DEBUG trace"]
        result = _prioritize_log_lines(lines, 10)
        self.assertEqual(result, lines)

    def test_error_lines_kept(self):
        lines = [f"INFO line {i}" for i in range(50)]
        lines[10] = "ERROR something bad"
        lines[30] = "FATAL crash"
        result = _prioritize_log_lines(lines, 10)
        self.assertIn("ERROR something bad", result)
        self.assertIn("FATAL crash", result)
        self.assertTrue(any("omitted" in l for l in result))

    def test_omission_note_present(self):
        lines = [f"INFO line {i}" for i in range(100)]
        result = _prioritize_log_lines(lines, 30)
        self.assertTrue(any("omitted" in l for l in result))
        self.assertLessEqual(len(result), 31)  # 30 + omission note

    def test_all_errors_many(self):
        lines = [f"ERROR error {i}" for i in range(50)]
        result = _prioritize_log_lines(lines, 10)
        self.assertLessEqual(len(result), 11)


class TestBuildAlertPayload(unittest.TestCase):
    """build_alert_payload creates valid JSON under byte cap."""

    def _make_data(self, log_count=100, event_count=30):
        return {
            "pod": {
                "name": "my-app-abc123",
                "namespace": "production",
                "phase": "CrashLoopBackOff",
                "node": "worker-1",
                "containers": [{
                    "name": "app",
                    "state": "waiting",
                    "reason": "CrashLoopBackOff",
                    "restarts": 5,
                    "exit_code": 137,
                    "image": "registry/app:v1.2",
                    "resources": {"cpu_req": "100m", "cpu_lim": "500m", "mem_req": "128Mi", "mem_lim": "256Mi"},
                }],
                "node_ready": True,
            },
            "logs": [f"ERROR error line {i}" if i % 10 == 0 else f"INFO info line {i}" for i in range(log_count)],
            "events": [
                {"type": "Warning", "reason": "BackOff", "message": f"Back-off restarting {i}", "count": i}
                for i in range(event_count)
            ],
            "owner": {"kind": "Deployment", "name": "my-app", "desired": 3, "ready": 2, "unavailable": 1},
            "node_metrics": {"cpu_pct": 45.2, "mem_pct": 72.3, "mem_used": "11.2Gi", "mem_total": "15.5Gi"},
            "diagnostics": {
                "current_usage": [{"container": "app", "cpu": "450m", "mem": "180Mi"}],
                "previous_logs": [f"ERROR prev line {i}" for i in range(20)],
                "resource_limits": [{"container": "app", "cpu_req": "100m", "cpu_lim": "500m"}],
            },
        }

    def test_valid_json_output(self):
        data = self._make_data()
        json_str, _, _ = build_alert_payload(data, "production/Pod/my-app", "example", 24000)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["cluster"], "example")
        self.assertEqual(parsed["resource"], "production/Pod/my-app")
        self.assertIn("pod", parsed)

    def test_under_cap(self):
        data = self._make_data()
        json_str, _, _ = build_alert_payload(data, "res", "cluster", 24000)
        self.assertLessEqual(len(json_str.encode("utf-8")), 24000)

    def test_logs_capped_at_30(self):
        data = self._make_data(log_count=200)
        json_str, _, notes = build_alert_payload(data, "res", "cluster", 24000)
        parsed = json.loads(json_str)
        self.assertLessEqual(len(parsed["logs"]), 31)  # 30 + omission note
        self.assertTrue(any("logs" in n for n in notes))

    def test_events_capped_at_15(self):
        data = self._make_data(event_count=50)
        json_str, _, notes = build_alert_payload(data, "res", "cluster", 24000)
        parsed = json.loads(json_str)
        self.assertLessEqual(len(parsed["events"]), 15)

    def test_pod_preserved(self):
        data = self._make_data()
        json_str, _, _ = build_alert_payload(data, "res", "cluster", 24000)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["pod"]["phase"], "CrashLoopBackOff")
        self.assertEqual(parsed["pod"]["containers"][0]["restarts"], 5)

    def test_error_lines_in_output(self):
        data = self._make_data(log_count=200)
        json_str, _, _ = build_alert_payload(data, "res", "cluster", 24000)
        parsed = json.loads(json_str)
        error_lines = [l for l in parsed["logs"] if "ERROR" in l]
        self.assertGreater(len(error_lines), 0)

    def test_small_context_not_truncated(self):
        data = {"pod": {"name": "x", "phase": "Running"}}
        json_str, truncated, notes = build_alert_payload(data, "res", "cluster", 24000)
        self.assertFalse(truncated)
        self.assertEqual(notes, [])

    def test_progressive_trim_under_tight_cap(self):
        """With very tight cap, logs are progressively trimmed; structured
        sections are preserved even if the result stays over budget."""
        data = self._make_data()
        json_str, truncated, notes = build_alert_payload(data, "res", "cluster", 2000)
        self.assertTrue(truncated)
        parsed = json.loads(json_str)
        # Structured sections must remain — they're the LLM's root-cause signal.
        self.assertIn("pod", parsed)
        self.assertIn("owner", parsed)
        self.assertIn("node_metrics", parsed)
        self.assertIn("diagnostics", parsed)
        self.assertIn("events", parsed)

    def test_trim_preserves_diagnostics_when_logs_fit_budget(self):
        """If dropping / trimming logs brings us under the cap, the structured
        sections all survive untouched."""
        # Oversized log section forces the trim loop; cap is large enough that
        # the structured sections themselves fit comfortably, so the only
        # thing that needs to shrink is `logs`.
        data = self._make_data(log_count=500)
        # Tight cap so even the 30-line-capped log section pushes us over,
        # but structured sections alone fit comfortably.
        json_str, truncated, notes = build_alert_payload(data, "res", "cluster", 2800)
        self.assertTrue(truncated)
        self.assertLessEqual(len(json_str.encode("utf-8")), 2800)
        parsed = json.loads(json_str)
        self.assertIn("diagnostics", parsed)
        self.assertIn("node_metrics", parsed)
        self.assertIn("events", parsed)
        self.assertIn("owner", parsed)
        self.assertIn("pod", parsed)

    def test_trim_never_drops_structured_sections(self):
        """Synthetic payload that stays over budget even after dropping logs
        entirely — we still return pod/owner/events/diagnostics intact."""
        data = self._make_data()
        # Force the structured sections to exceed an absurdly tight cap.
        json_str, truncated, notes = build_alert_payload(data, "res", "cluster", 500)
        self.assertTrue(truncated)
        parsed = json.loads(json_str)
        # Even though the payload is over budget, the structured sections
        # survive — the OVER_BUDGET note is added but nothing else is dropped.
        self.assertIn("pod", parsed)
        self.assertIn("diagnostics", parsed)
        self.assertIn("node_metrics", parsed)
        self.assertIn("events", parsed)
        self.assertIn("owner", parsed)
        self.assertNotIn("logs", parsed)
        self.assertTrue(any("OVER_BUDGET" in n for n in notes))

    def test_initial_log_cap_is_30_lines(self):
        """Under a generous budget the log section is capped at 30 lines."""
        data = self._make_data(log_count=200)
        json_str, _, notes = build_alert_payload(data, "res", "cluster", 80000)
        parsed = json.loads(json_str)
        # 30 retained + 1 omission marker line
        self.assertLessEqual(len(parsed["logs"]), 31)
        self.assertTrue(any("-> 30" in n for n in notes))

    def test_flux_context(self):
        data = {
            "flux_resource": {"kind": "Kustomization", "name": "app", "namespace": "flux-system"},
            "conditions": [{"type": "Ready", "status": "False", "message": "failed"}],
        }
        json_str, _, _ = build_alert_payload(data, "res", "cluster", 24000)
        parsed = json.loads(json_str)
        self.assertIn("flux_resource", parsed)
        self.assertIn("conditions", parsed)

    def test_event_context(self):
        data = {"event": {"kind": "Service", "name": "my-svc", "reason": "BackOff"}}
        json_str, _, _ = build_alert_payload(data, "res", "cluster", 24000)
        parsed = json.loads(json_str)
        self.assertIn("event", parsed)


class TestBuildReportPayload(unittest.TestCase):
    """build_report_payload creates valid JSON from dict input with section limits."""

    def _make_report_data(self, pod_restarts=5, warning_events=5,
                          pvc_count=3, pressure_count=3):
        return {
            "pod_restarts": [
                {"namespace": "prod", "pod": f"app-{i}", "container": "app",
                 "restarts": i + 1, "last_reason": "OOMKilled"}
                for i in range(pod_restarts)
            ],
            "warning_events": [
                {"namespace": "prod", "key": f"BackOff: Pod/app-{i}", "count": i + 1}
                for i in range(warning_events)
            ],
            "flux_failures": [],
            "node_issues": [],
            "nodes": [
                {"name": "worker-1", "ready": True, "schedulable": True,
                 "cpu_pct": 45.2, "mem_pct": 72.3, "mem_detail": "11.2Gi/15.5Gi", "disk_pct": 38.1}
            ],
            "pvc_usage": [
                {"namespace": "prod", "pvc": f"data-db-{i}", "pct": 85.0 + i}
                for i in range(pvc_count)
            ],
            "cert_issues": [],
            "resource_pressure": [
                {"namespace": "prod", "pod": f"app-{i}", "mem_pct": 90.0 + i}
                for i in range(pressure_count)
            ],
        }

    def test_valid_json(self):
        data = self._make_report_data()
        json_str, _, _ = build_report_payload(data, "cluster", 80000)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["cluster"], "cluster")
        self.assertIn("pod_restarts", parsed)
        self.assertIn("nodes", parsed)

    def test_under_cap(self):
        data = self._make_report_data(pod_restarts=50, warning_events=50)
        json_str, _, _ = build_report_payload(data, "cluster", 80000)
        self.assertLessEqual(len(json_str.encode("utf-8")), 80000)

    def test_small_not_truncated(self):
        data = self._make_report_data()
        json_str, truncated, notes = build_report_payload(data, "cluster", 80000)
        self.assertFalse(truncated)

    def test_pod_restarts_capped_at_20(self):
        data = self._make_report_data(pod_restarts=30)
        json_str, _, notes = build_report_payload(data, "cluster", 80000)
        parsed = json.loads(json_str)
        self.assertLessEqual(len(parsed["pod_restarts"]), 20)
        self.assertTrue(any("pod_restarts" in n for n in notes))

    def test_warning_events_capped_at_15(self):
        data = self._make_report_data(warning_events=25)
        json_str, _, notes = build_report_payload(data, "cluster", 80000)
        parsed = json.loads(json_str)
        self.assertLessEqual(len(parsed["warning_events"]), 15)
        self.assertTrue(any("warning_events" in n for n in notes))

    def test_pvc_usage_capped_at_10(self):
        data = self._make_report_data(pvc_count=15)
        json_str, _, notes = build_report_payload(data, "cluster", 80000)
        parsed = json.loads(json_str)
        self.assertLessEqual(len(parsed["pvc_usage"]), 10)

    def test_resource_pressure_capped_at_10(self):
        data = self._make_report_data(pressure_count=15)
        json_str, _, notes = build_report_payload(data, "cluster", 80000)
        parsed = json.loads(json_str)
        self.assertLessEqual(len(parsed["resource_pressure"]), 10)

    def test_progressive_trim_under_tight_cap(self):
        """With very tight cap, sections are progressively trimmed/dropped."""
        data = self._make_report_data(pod_restarts=20, warning_events=15,
                                      pvc_count=10, pressure_count=10)
        json_str, truncated, notes = build_report_payload(data, "cluster", 1500)
        self.assertTrue(truncated)
        parsed = json.loads(json_str)
        # resource_pressure and/or pvc_usage should be dropped
        dropped = "resource_pressure" not in parsed or "pvc_usage" not in parsed
        trimmed = any("budget" in n for n in notes)
        self.assertTrue(dropped or trimmed)

    def test_empty_data(self):
        data = {
            "pod_restarts": [], "warning_events": [], "flux_failures": [],
            "node_issues": [], "nodes": [], "pvc_usage": [],
            "cert_issues": [], "resource_pressure": [],
        }
        json_str, truncated, _ = build_report_payload(data, "cluster", 80000)
        self.assertFalse(truncated)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["pod_restarts"], [])


class TestMeasureReportData(unittest.TestCase):
    """measure_report_data returns byte sizes per section."""

    def test_basic(self):
        data = {
            "pod_restarts": [{"namespace": "prod", "pod": "app", "restarts": 5}],
            "nodes": [{"name": "w1", "cpu_pct": 45.2}],
        }
        result = measure_report_data(data)
        self.assertIn("total_bytes", result)
        self.assertIn("section_bytes", result)
        self.assertIn("sections", result)
        self.assertIn("pod_restarts", result["section_bytes"])
        self.assertIn("nodes", result["section_bytes"])
        self.assertEqual(result["sections"], ["pod_restarts", "nodes"])
        self.assertGreater(result["total_bytes"], 0)

    def test_empty(self):
        result = measure_report_data({})
        self.assertEqual(result["total_bytes"], 0)
        self.assertEqual(result["sections"], [])


if __name__ == "__main__":
    unittest.main()


class TestPassThroughSections(unittest.TestCase):
    """Sections the payload builder does not know by name reach the LLM (found on kind:
    an Alertmanager alert arrived as 71 bytes - only cluster and resource)."""

    def test_alert_fields_reach_the_payload(self):
        alert = {"source": "alertmanager", "alertname": "BackendErrorBudgetBurnFast",
                 "summary": "production: backend users are failing", "labels": {"severity": "critical"}}
        payload, truncated, _ = build_alert_payload(alert, "Alert/X", "safeops", 16000)
        self.assertIn("backend users are failing", payload)
        self.assertIn('"alertname": "BackendErrorBudgetBurnFast"', payload)
        self.assertFalse(truncated)

    def test_pass_through_sections_are_dropped_after_the_logs(self):
        data = {"logs": ["error: x"] * 5, "description": "d" * 3000}
        payload, truncated, notes = build_alert_payload(data, "Alert/X", "safeops", 1024)
        self.assertTrue(truncated)
        self.assertNotIn("ddd", payload)
        self.assertIn("logs: dropped (budget)", notes)
        self.assertEqual(notes[-1], "description: dropped (budget)")

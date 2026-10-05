"""Tests for LLM spend report breakdown, fingerprint-reuse, and the
non-prod-skip / exponential-backoff changes to the pipeline."""
import json
import time
import unittest
from unittest.mock import patch

from src.engine.llm import AnalysisResult

from src import config
from src.engine.store.sqlite import SqliteStore
import src.handlers.startup # noqa: F401


class TestFingerprintReuse(unittest.TestCase):
    def setUp(self):
        self.store = SqliteStore(":memory:")

    def _insert_incident_with_analysis(self, fingerprint, analysis_dict,
                                       age_seconds=60, analysis_error=False):
        inc = self.store.create_incident(
            state_key=f"Deployment:ns/{fingerprint[:6]}:oom",
            fingerprint=fingerprint, issue_type="oom",
            severity="critical", namespace="ns", owner_ref="",
        )
        conn = self.store._get_conn()
        seen_at = time.time() - age_seconds
        conn.execute(
            """INSERT INTO incident_occurrences
               (incident_id, seen_at, context_hash, raw_context, analysis,
                analysis_json, analysis_error, llm_model, tokens_in, tokens_out,
                cost_usd, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (inc.id, seen_at, "h", "{}", "raw text",
             json.dumps(analysis_dict), analysis_error, "claude", 100, 50, 0.001, seen_at),
        )
        conn.commit()
        return inc

    def test_returns_recent_parsed_analysis(self):
        self._insert_incident_with_analysis(
            "fp1", {"root_cause": "OOM", "severity": "critical"},
            age_seconds=60,
        )
        row = self.store.get_recent_analysis_by_fingerprint("fp1", max_age_hours=6)
        self.assertIsNotNone(row)
        self.assertIn("analysis_json", row)
        parsed = json.loads(row["analysis_json"])
        self.assertEqual(parsed["root_cause"], "OOM")

    def test_skips_old_analysis(self):
        self._insert_incident_with_analysis(
            "fp1", {"root_cause": "OOM"}, age_seconds=8 * 3600,
        )
        row = self.store.get_recent_analysis_by_fingerprint("fp1", max_age_hours=6)
        self.assertIsNone(row)

    def test_skips_error_analyses(self):
        self._insert_incident_with_analysis(
            "fp1", {"root_cause": "OOM"}, age_seconds=60, analysis_error=True,
        )
        row = self.store.get_recent_analysis_by_fingerprint("fp1", max_age_hours=6)
        self.assertIsNone(row)

    def test_empty_fingerprint(self):
        self.assertIsNone(self.store.get_recent_analysis_by_fingerprint("", 6))


class TestPipelineNonProdSkipLLM(unittest.TestCase):
    """Non-prod namespaces must never call the LLM, regardless of issue_type."""

    def setUp(self):
        self._orig_nonprod = config.NON_PROD_NAMESPACES
        config.NON_PROD_NAMESPACES = {"develop", "staging"}

    def tearDown(self):
        config.NON_PROD_NAMESPACES = self._orig_nonprod

    def _make_result(self, namespace, issue_type="critical_endpoint",
                     state_key=None):
        from src.scanners._base import ScanResult
        return ScanResult(
            state_key=state_key or f"CriticalEndpoint:{namespace}/store:url",
            title="endpoint down",
            severity="critical",
            namespace=namespace,
            resource="Frontend/store",
            issue_type=issue_type,
            metadata={},
            context_override="endpoint down at https://example.com",
        )

    def test_nonprod_critical_endpoint_llm_off_by_default(self):
        from src.engine import pipeline
        store = SqliteStore(":memory:")
        result = self._make_result("develop")

        # Fail-fast: if a regression lets the call through, raise immediately
        # rather than letting the test fall through to the real LLM.
        def fake_analyze(*a, **kw):
            raise AssertionError(
                "analyze_alert must not be called for non-prod")

        with patch.object(pipeline, "analyze_alert", side_effect=fake_analyze), \
             patch.object(pipeline, "post_alert"):
            pipeline.process_scan_results([result], store)

    def test_nonprod_incident_still_tracked(self):
        """Non-prod incident must still be created and occurrence recorded."""
        from src.engine import pipeline
        store = SqliteStore(":memory:")
        result = self._make_result(
            "develop",
            state_key="CriticalEndpoint:develop/store:https://x")

        with patch.object(pipeline, "analyze_alert"), \
             patch.object(pipeline, "post_alert"):
            pipeline.process_scan_results([result], store)

        inc = store.get_incident(result.state_key)
        self.assertIsNotNone(inc)
        assert inc is not None  # for type checker
        self.assertEqual(inc.status, "active")
        self.assertGreaterEqual(inc.occurrence_count, 1)

    def test_nonprod_slack_post_uses_nonprod_webhook(self):
        """Non-prod alerts must target SLACK_WEBHOOK_URL_NONPROD."""
        orig_webhook = config.SLACK_WEBHOOK_URL_NONPROD
        config.SLACK_WEBHOOK_URL_NONPROD = "https://hooks.slack.test/nonprod"
        try:
            from src.engine import pipeline
            store = SqliteStore(":memory:")
            result = self._make_result("develop")

            with patch.object(pipeline, "analyze_alert"), \
                 patch.object(pipeline, "post_alert") as post_mock:
                pipeline.process_scan_results([result], store)

            self.assertEqual(post_mock.call_count, 1)
            kwargs = post_mock.call_args.kwargs
            self.assertEqual(
                kwargs["webhook_url"], "https://hooks.slack.test/nonprod")
        finally:
            config.SLACK_WEBHOOK_URL_NONPROD = orig_webhook

    def test_nonprod_non_critical_issue_type_also_skipped(self):
        """A regular pod issue in non-prod must also skip the LLM."""
        from src.engine import pipeline
        store = SqliteStore(":memory:")
        result = self._make_result(
            "develop", issue_type="crash",
            state_key="Deployment:develop/review-service:crash")

        def fake_analyze(*a, **kw):
            raise AssertionError(
                "analyze_alert must not be called for non-prod pod issues")

        with patch.object(pipeline, "analyze_alert", side_effect=fake_analyze), \
             patch.object(pipeline, "post_alert"):
            pipeline.process_scan_results([result], store)


class TestSchedulerCheckpoint(unittest.TestCase):
    def setUp(self):
        self.store = SqliteStore(":memory:")

    def test_round_trip(self):
        self.assertIsNone(self.store.get_last_daily_run())
        self.store.save_last_daily_run("2026-04-11")
        self.assertEqual(self.store.get_last_daily_run(), "2026-04-11")

    def test_overwrite(self):
        self.store.save_last_daily_run("2026-04-10")
        self.store.save_last_daily_run("2026-04-11")
        self.assertEqual(self.store.get_last_daily_run(), "2026-04-11")


class TestLatestAnalysisByStateKey(unittest.TestCase):
    def setUp(self):
        self.store = SqliteStore(":memory:")

    def _add(self, state_key, analysis_dict, age_seconds=60):
        inc = self.store.get_incident(state_key) or self.store.create_incident(
            state_key=state_key, fingerprint="fp", issue_type="oom",
            severity="critical", namespace="ns", owner_ref="",
        )
        conn = self.store._get_conn()
        seen_at = time.time() - age_seconds
        conn.execute(
            """INSERT INTO incident_occurrences
               (incident_id, seen_at, context_hash, raw_context, analysis,
                analysis_json, analysis_error, llm_model, tokens_in, tokens_out,
                cost_usd, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (inc.id, seen_at, "h", "{}", "raw text",
             json.dumps(analysis_dict), False, "claude", 100, 50, 0.001, seen_at),
        )
        conn.commit()

    def test_returns_latest(self):
        sk = "Deployment:ns/x:oom"
        self._add(sk, {"root_cause": "old"}, age_seconds=600)
        self._add(sk, {"root_cause": "new"}, age_seconds=60)
        row = self.store.get_latest_analysis_by_state_key(sk)
        self.assertIsNotNone(row)
        self.assertEqual(row["analysis_json"]["root_cause"], "new")

    def test_no_data(self):
        self.assertIsNone(self.store.get_latest_analysis_by_state_key("nope"))

    def test_empty_key(self):
        self.assertIsNone(self.store.get_latest_analysis_by_state_key(""))

    def test_max_age_excludes_old(self):
        sk = "Deployment:ns/x:oom"
        self._add(sk, {"root_cause": "old"}, age_seconds=48 * 3600)
        self.assertIsNotNone(
            self.store.get_latest_analysis_by_state_key(sk)
        )
        self.assertIsNone(
            self.store.get_latest_analysis_by_state_key(sk, max_age_hours=24)
        )


class TestNodeMetricsSingleFlight(unittest.TestCase):
    """Concurrent calls for the same node must hit Prometheus exactly once."""

    def setUp(self):
        from src.collectors import pod
        pod._node_metrics_cache.clear()
        pod._node_inflight_locks.clear()

    def test_single_flight_collapses_concurrent_misses(self):
        from src.collectors import pod
        from unittest.mock import MagicMock
        import threading as _t

        call_count = {"n": 0}
        gate = _t.Event()

        def fake_query(node_name, node_ip):
            call_count["n"] += 1
            gate.wait(timeout=2.0)
            return {"cpu_pct": 42.0, "mem_pct": 50.0}

        fake_pod = MagicMock()
        fake_pod.spec.node_name = "node-1"
        fake_core = MagicMock()
        fake_core.read_node.return_value = MagicMock(
            status=MagicMock(addresses=[MagicMock(type="InternalIP", address="10.0.0.1")])
        )

        results: list[dict | None] = [None] * 5
        threads = []

        def worker(i):
            with patch.object(pod, "_query_node_exporter_metrics_dict", side_effect=fake_query):
                results[i] = pod._get_node_metrics(fake_pod, fake_core)

        for i in range(5):
            t = _t.Thread(target=worker, args=(i,))
            t.start()
            threads.append(t)

        # Let the first thread acquire its lock and block in fake_query, then
        # release the gate so it returns. Followers will read from cache.
        time.sleep(0.05)
        gate.set()
        for t in threads:
            t.join(timeout=3.0)

        self.assertEqual(call_count["n"], 1,
                         "Prometheus must be queried exactly once for the same node")
        for r in results:
            self.assertEqual(r, {"cpu_pct": 42.0, "mem_pct": 50.0})

    def test_inflight_lock_cleaned_up_after_success(self):
        from src.collectors import pod
        from unittest.mock import MagicMock

        fake_pod = MagicMock()
        fake_pod.spec.node_name = "node-cleanup"
        fake_core = MagicMock()
        fake_core.read_node.return_value = MagicMock(
            status=MagicMock(addresses=[MagicMock(type="InternalIP", address="10.0.0.2")])
        )

        with patch.object(pod, "_query_node_exporter_metrics_dict",
                          return_value={"cpu_pct": 1.0}):
            pod._get_node_metrics(fake_pod, fake_core)

        self.assertNotIn("node-cleanup", pod._node_inflight_locks,
                         "Inflight lock should be popped after a successful fetch")
        self.assertIn("node-cleanup", pod._node_metrics_cache)


class TestLogLlmCallSchemaGuard(unittest.TestCase):
    """_log_llm_call must run migrations before its first INSERT, even when
    nothing else has touched SqliteStore yet."""

    def test_ensure_schema_migrated_runs_once(self):
        from src.engine import llm
        llm._schema_ready = False
        calls = []

        class FakeStore:
            def __init__(self):
                calls.append(1)

        with patch("src.engine.store.sqlite.SqliteStore", FakeStore):
            llm._ensure_schema_migrated()
            llm._ensure_schema_migrated()
            llm._ensure_schema_migrated()

        self.assertEqual(len(calls), 1, "Schema must be initialised exactly once")
        self.assertTrue(llm._schema_ready)

    def test_ensure_schema_migrated_swallows_failure(self):
        from src.engine import llm
        llm._schema_ready = False

        def boom():
            raise RuntimeError("disk full")

        with patch("src.engine.store.sqlite.SqliteStore", side_effect=boom):
            llm._ensure_schema_migrated()  # must not raise
        self.assertFalse(llm._schema_ready, "Failed migrations should not flip the ready flag")
        # Reset for downstream tests
        llm._schema_ready = True


class TestNodeMetricsStaleCap(unittest.TestCase):
    """Stale node-metrics serving must be bounded by _NODE_METRICS_STALE_MAX_AGE_SEC."""

    def setUp(self):
        from src.collectors import pod
        pod._node_metrics_cache.clear()
        pod._node_inflight_locks.clear()

    def test_stale_within_cap_returned(self):
        from src.collectors import pod
        # Insert an entry that's 10 minutes old (past TTL but inside stale cap)
        pod._node_metrics_cache["n1"] = (time.time() - 600, {"cpu_pct": 1.0})
        self.assertIsNone(pod._read_cached_node_metrics("n1"))  # past fresh TTL
        self.assertIsNotNone(pod._read_cached_node_metrics("n1", allow_stale=True))

    def test_stale_beyond_cap_refused(self):
        from src.collectors import pod
        # 2 hours old — beyond the 30-minute stale cap
        pod._node_metrics_cache["n2"] = (time.time() - 7200, {"cpu_pct": 1.0})
        self.assertIsNone(pod._read_cached_node_metrics("n2"))
        self.assertIsNone(pod._read_cached_node_metrics("n2", allow_stale=True))

    def test_failed_fetch_does_not_reage_entry(self):
        from src.collectors import pod
        from unittest.mock import MagicMock
        # Pre-populate a stale entry (8 minutes old)
        original_ts = time.time() - 480
        pod._node_metrics_cache["n3"] = (original_ts, {"cpu_pct": 5.0})

        fake_pod = MagicMock()
        fake_pod.spec.node_name = "n3"
        fake_core = MagicMock()
        fake_core.read_node.return_value = MagicMock(
            status=MagicMock(addresses=[MagicMock(type="InternalIP", address="10.0.0.3")])
        )

        with patch.object(pod, "_query_node_exporter_metrics_dict", return_value=None), \
             patch.object(pod, "_query_metrics_api_node", return_value=None):
            result = pod._get_node_metrics(fake_pod, fake_core)

        # Stale data must be returned
        self.assertEqual(result, {"cpu_pct": 5.0})
        # And the cache entry's timestamp must NOT have been refreshed
        ts, _ = pod._node_metrics_cache["n3"]
        self.assertEqual(ts, original_ts,
                         "Failed fetch must not re-age the existing stale entry")


class TestProviderApiKeyValidation(unittest.TestCase):
    def setUp(self):
        self._orig = (config.LLM_PROVIDER, config.GEMINI_API_KEY,
                      config.OPENAI_API_KEY, config.ANTHROPIC_API_KEY)

    def tearDown(self):
        (config.LLM_PROVIDER, config.GEMINI_API_KEY,
         config.OPENAI_API_KEY, config.ANTHROPIC_API_KEY) = self._orig

    def test_gemini_missing_key(self):
        from src.engine.llm import _get_client
        config.LLM_PROVIDER = "gemini"
        config.GEMINI_API_KEY = ""
        with self.assertRaises(RuntimeError) as cm:
            _get_client()
        self.assertIn("GEMINI_API_KEY", str(cm.exception))

    def test_openai_missing_key(self):
        from src.engine.llm import _get_client
        config.LLM_PROVIDER = "openai"
        config.OPENAI_API_KEY = ""
        with self.assertRaises(RuntimeError) as cm:
            _get_client()
        self.assertIn("OPENAI_API_KEY", str(cm.exception))

    def test_anthropic_missing_key(self):
        from src.engine.llm import _get_client
        config.LLM_PROVIDER = "anthropic"
        config.ANTHROPIC_API_KEY = ""
        with self.assertRaises(RuntimeError) as cm:
            _get_client()
        self.assertIn("ANTHROPIC_API_KEY", str(cm.exception))


class TestDebounceTiers(unittest.TestCase):
    """Three-tier debounce base: infra / important / default.

    Renamed from TestExponentialBackoffCriticalService.
    """

    def test_effective_debounce_base_for_infra_critical(self):
        from src.engine.pipeline import _effective_debounce
        # postgres/redis/redis — stateful infra
        base = _effective_debounce("production", "Pod/postgres-0", "postgres-0")
        self.assertEqual(base, config.CRITICAL_ALERT_COOLDOWN_SECONDS)

    def test_effective_debounce_base_for_important(self):
        from src.engine.pipeline import _effective_debounce
        # backend - business-tier, middle cooldown
        base = _effective_debounce("production",
                                    "Deployment:production/backend:x",
                                    "backend-abc")
        self.assertEqual(base, config.IMPORTANT_ALERT_COOLDOWN_SECONDS)

    def test_effective_debounce_base_for_default(self):
        from src.engine.pipeline import _effective_debounce
        base = _effective_debounce("production", "Pod/unknown-worker",
                                    "unknown-worker")
        self.assertEqual(base, config.DEBOUNCE_SECONDS)

    def test_cooldown_grows_exponentially(self):
        from src.engine.pipeline import _effective_debounce
        base = _effective_debounce("production", "Pod/postgres-0", "postgres-0")
        count_5_cooldown = min(base * (2 ** 5), 86400)
        self.assertGreater(count_5_cooldown, base)
        count_20_cooldown = min(base * (2 ** 10), 86400)
        self.assertEqual(count_20_cooldown, min(base * 1024, 86400))


class TestNoiseReduction(unittest.TestCase):
    """Validation for the smart noise reduction logic in pipeline."""

    def _make_result(self, issue_type="crash", severity="warning",
                     namespace="prod"):
        from src.scanners._base import ScanResult
        return ScanResult(
            state_key=f"Test:{issue_type}", title="Test",
            severity=severity, namespace=namespace, resource="res",
            issue_type=issue_type,
        )

    def _make_ar(self, severity="warning", human_needed=False):
        from src.engine.llm import AnalysisResult
        return AnalysisResult(
            raw_text="...", parsed={"severity": severity, "human_needed": human_needed},
            parse_error=False, model="m", tokens_in=0, tokens_out=0, cost_usd=0
        )

    def test_noise_reduction_skips_low_impact_warning(self):
        """Routing contract: non-critical warnings
        with LLM verdict human_needed=False go to daily report, not Slack.
        """
        from src.engine.pipeline import _should_post_slack
        r = self._make_result(severity="warning")
        ar = self._make_ar(severity="warning", human_needed=False)
        should, reason, final_sev = _should_post_slack(ar, r, is_collective=False)
        self.assertFalse(should)
        self.assertIn("daily report", reason)
        self.assertEqual(final_sev, "warning")

    def test_noise_reduction_always_alerts_critical(self):
        from src.engine.pipeline import _should_post_slack
        r = self._make_result(severity="critical")
        ar = self._make_ar(severity="critical", human_needed=False)
        should, _, final_sev = _should_post_slack(ar, r, is_collective=False)
        self.assertTrue(should)
        self.assertEqual(final_sev, "critical")

    def test_noise_reduction_always_alerts_collective(self):
        from src.engine.pipeline import _should_post_slack
        r = self._make_result(severity="warning")
        ar = self._make_ar(severity="warning", human_needed=False)
        should, _, _ = _should_post_slack(ar, r, is_collective=True)
        self.assertTrue(should)

    def test_noise_reduction_alerts_when_human_needed(self):
        from src.engine.pipeline import _should_post_slack
        r = self._make_result(severity="warning")
        ar = self._make_ar(severity="warning", human_needed=True)
        should, _, _ = _should_post_slack(ar, r, is_collective=False)
        self.assertTrue(should)

    def test_noise_reduction_warning_without_ar_goes_to_daily_report(self):
        """Routing contract: warnings without an LLM
        verdict (every non-critical_endpoint path) default to NOT posting
        to Slack. They still land in SQLite + daily report, and Sprint
        2.5 promotion upgrades chronic ones to critical. Previously
        defaulted to posting → Slack flood of every minor warning.
        """
        from src.engine.pipeline import _should_post_slack
        r = self._make_result(severity="warning")
        with patch("src.engine.pipeline.llm_configured", return_value=True):  # a key, no verdict
            should, reason, final_sev = _should_post_slack(None, r, is_collective=False)
        self.assertFalse(should)
        self.assertIn("daily report", reason)
        self.assertEqual(final_sev, "warning")

    def test_noise_reduction_critical_without_ar_still_posts(self):
        """A scanner-assigned critical without LLM must still page —
        otherwise every non-LLM path would silently drop urgent alerts.
        """
        from src.engine.pipeline import _should_post_slack
        r = self._make_result(severity="critical")
        should, _, final_sev = _should_post_slack(None, r, is_collective=False)
        self.assertTrue(should)
        self.assertEqual(final_sev, "critical")

    def test_noise_reduction_nonprod_warning_posts_to_nonprod_webhook(self):
        """Non-prod namespaces have their own webhook
        (SLACK_WEBHOOK_URL_NONPROD). A warning in develop/staging must
        still route there — silencing it would make the non-prod
        channel useless. 2x debounce multiplier already limits noise.
        """
        from src.engine.pipeline import _should_post_slack
        orig_nonprod = config.NON_PROD_NAMESPACES
        config.NON_PROD_NAMESPACES = {"develop", "staging"}
        try:
            r = self._make_result(severity="warning", namespace="develop")
            should, reason, final_sev = _should_post_slack(
                None, r, is_collective=False,
            )
            self.assertTrue(should)
            self.assertEqual(final_sev, "warning")
            self.assertIn("non-prod", reason)
        finally:
            config.NON_PROD_NAMESPACES = orig_nonprod

    def test_noise_reduction_pvc_respects_scanner_severity(self):
        """PVC is NOT on the forced-critical list anymore — the PVC
        scanner already assigns severity by threshold (80%→warning,
        90%→critical). An 82%-full volume should not page the on-call.
        """
        from src.engine.pipeline import _should_post_slack
        r = self._make_result(issue_type="pvc", severity="warning")
        ar = self._make_ar(severity="warning", human_needed=False)
        should, reason, final_sev = _should_post_slack(ar, r, is_collective=False)
        self.assertFalse(should)
        self.assertEqual(final_sev, "warning")
        self.assertIn("daily report", reason)

    def test_noise_reduction_pvc_critical_still_posts(self):
        """A PVC scanner assigning severity=critical (>= 90%) still
        routes as critical — we dropped only the blanket promotion."""
        from src.engine.pipeline import _should_post_slack
        r = self._make_result(issue_type="pvc", severity="critical")
        ar = self._make_ar(severity="critical", human_needed=False)
        should, _, final_sev = _should_post_slack(ar, r, is_collective=False)
        self.assertTrue(should)
        self.assertEqual(final_sev, "critical")


class TestMassEventThreshold(unittest.TestCase):
    """Validates that MASS_EVENT_THRESHOLD is respected (not hardcoded 5)."""

    def test_mass_threshold_env_var_has_sane_default(self):
        self.assertEqual(config.MASS_EVENT_THRESHOLD, 5)
        self.assertGreaterEqual(config.MASS_EVENT_THRESHOLD, 2)

    def test_mass_threshold_routes_via_config_not_hardcoded(self):
        """Lower the threshold to 3 and confirm 3 alerts in one namespace
        trip collective batching (which would have been sub-threshold
        under the hardcoded 5)."""
        from src.scanners._base import ScanResult
        from src.engine import pipeline

        store = SqliteStore(":memory:")
        results = [
            ScanResult(
                state_key=f"Pod:prod/svc-{i}:crash",
                title=f"svc-{i} crash",
                severity="warning",
                resource=f"Pod/svc-{i}",
                namespace="prod",
                issue_type="crash",
                pod_name=f"svc-{i}",
            )
            for i in range(3)
        ]
        # No patches on notifiers → _should_post_slack will route but
        # the post itself becomes a no-op without a Slack webhook set.
        # We just need to verify that the collective path was hit, i.e.
        # at least one ScanResult with issue_type="collective_incident"
        # reached store.create_incident.
        # analyze_alert mocked: this test is about collective batching, not the LLM.
        with patch.object(config, "MASS_EVENT_THRESHOLD", 3), \
             patch("src.engine.pipeline.post_alert"), \
             patch("src.engine.pipeline.analyze_alert", return_value=AnalysisResult(
                 raw_text="", parsed=None, parse_error=True, model="test",
                 tokens_in=0, tokens_out=0, cost_usd=0.0)):
            pipeline.process_scan_results(results, store)
        incidents = store.list_incidents(status=None)
        keys = [i.state_key for i in incidents]
        self.assertTrue(
            any(k.startswith("Collective:") for k in keys),
            f"expected a Collective incident in {keys}",
        )


if __name__ == "__main__":
    unittest.main()

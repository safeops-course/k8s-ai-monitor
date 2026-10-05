"""Tests for daily report persistence in SqliteStore."""
import json
import time
import unittest
import src.handlers.startup # noqa: F401
from dataclasses import dataclass

from src.engine.store.sqlite import SqliteStore


@dataclass
class FakeAnalysisResult:
    raw_text: str
    parsed: dict | None
    parse_error: bool
    model: str
    tokens_in: int
    tokens_out: int
    cost_usd: float | None
    latency_ms: float = 0.0


def _make_result(*, parsed=None, raw_text="raw llm output", parse_error=False,
                 model="claude-haiku-3", tokens_in=500, tokens_out=200,
                 cost_usd=0.001, latency_ms=450.0):
    if parsed is None and not parse_error:
        parsed = {
            "overall_status": "healthy",
            "confidence": 0.9,
            "summary": "All systems operational",
            "issues": [],
            "trends": [],
            "recommendations": [],
        }
    return FakeAnalysisResult(
        raw_text=raw_text, parsed=parsed, parse_error=parse_error,
        model=model, tokens_in=tokens_in, tokens_out=tokens_out,
        cost_usd=cost_usd, latency_ms=latency_ms,
    )


def _make_collector_data():
    return {
        "pods": [{"name": "web-1", "status": "Running"}],
        "nodes": [{"name": "node-1", "ready": True}],
        "events": [],
    }


class TestSaveDailyReport(unittest.TestCase):
    """Save + retrieve round-trip."""

    def setUp(self):
        self.store = SqliteStore(":memory:")

    def test_save_returns_id(self):
        rid = self.store.save_daily_report(
            cluster="test-cluster",
            collector_data=_make_collector_data(),
            result=_make_result(),
        )
        self.assertIsInstance(rid, int)
        self.assertGreater(rid, 0)

    def test_round_trip(self):
        data = _make_collector_data()
        result = _make_result()
        rid = self.store.save_daily_report(
            cluster="test-cluster", collector_data=data, result=result,
        )
        report = self.store.get_daily_report(rid)
        self.assertIsNotNone(report)
        self.assertEqual(report["id"], rid)
        self.assertEqual(report["cluster"], "test-cluster")
        self.assertEqual(report["overall_status"], "healthy")
        self.assertEqual(report["model"], "claude-haiku-3")
        self.assertEqual(report["tokens_in"], 500)
        self.assertEqual(report["tokens_out"], 200)
        self.assertAlmostEqual(report["cost_usd"], 0.001)
        self.assertAlmostEqual(report["latency_ms"], 450.0)
        self.assertFalse(report["parse_error"])
        self.assertEqual(report["collector_data"], data)
        self.assertEqual(report["analysis"]["overall_status"], "healthy")
        self.assertEqual(report["summary"], "All systems operational")
        self.assertEqual(report["analysis_raw"], "raw llm output")


class TestListDailyReports(unittest.TestCase):
    """List returns summaries without heavy fields, ordered DESC."""

    def setUp(self):
        self.store = SqliteStore(":memory:")

    def test_list_ordered_desc(self):
        for i in range(3):
            self.store.save_daily_report(
                cluster="c", collector_data=_make_collector_data(),
                result=_make_result(),
            )
        reports = self.store.list_daily_reports()
        self.assertEqual(len(reports), 3)
        # Newest first
        self.assertGreaterEqual(reports[0]["created_at"], reports[1]["created_at"])
        self.assertGreaterEqual(reports[1]["created_at"], reports[2]["created_at"])

    def test_list_respects_limit(self):
        for _ in range(5):
            self.store.save_daily_report(
                cluster="c", collector_data=_make_collector_data(),
                result=_make_result(),
            )
        reports = self.store.list_daily_reports(limit=2)
        self.assertEqual(len(reports), 2)

    def test_list_has_summary_no_heavy_fields(self):
        self.store.save_daily_report(
            cluster="c", collector_data=_make_collector_data(),
            result=_make_result(),
        )
        reports = self.store.list_daily_reports()
        r = reports[0]
        # Should have summary fields
        self.assertIn("id", r)
        self.assertIn("summary", r)
        self.assertIn("overall_status", r)
        self.assertIn("model", r)
        self.assertIn("cost_usd", r)
        self.assertIn("parse_error", r)
        # Should NOT have heavy fields
        self.assertNotIn("collector_data", r)
        self.assertNotIn("analysis_raw", r)
        self.assertNotIn("collector_data_json", r)


class TestGetDailyReport(unittest.TestCase):
    """Full detail with parsed JSON fields."""

    def setUp(self):
        self.store = SqliteStore(":memory:")

    def test_get_returns_all_fields(self):
        rid = self.store.save_daily_report(
            cluster="prod", collector_data=_make_collector_data(),
            result=_make_result(),
        )
        report = self.store.get_daily_report(rid)
        expected_keys = {
            "id", "created_at", "cluster", "overall_status", "summary",
            "model", "cost_usd", "parse_error", "report_type", "collector_data",
            "analysis", "analysis_raw", "tokens_in", "tokens_out", "latency_ms",
            "context_bytes", "truncated",
        }
        self.assertEqual(set(report.keys()), expected_keys)

    def test_get_nonexistent_returns_none(self):
        self.assertIsNone(self.store.get_daily_report(999))

    def test_collector_data_is_parsed_dict(self):
        data = _make_collector_data()
        rid = self.store.save_daily_report(
            cluster="c", collector_data=data, result=_make_result(),
        )
        report = self.store.get_daily_report(rid)
        self.assertIsInstance(report["collector_data"], dict)
        self.assertEqual(report["collector_data"]["pods"][0]["name"], "web-1")

    def test_context_bytes_set(self):
        data = _make_collector_data()
        rid = self.store.save_daily_report(
            cluster="c", collector_data=data, result=_make_result(),
        )
        report = self.store.get_daily_report(rid)
        expected = len(json.dumps(data, default=str).encode("utf-8"))
        self.assertEqual(report["context_bytes"], expected)


class TestCleanupDailyReports(unittest.TestCase):
    """Old records deleted, recent kept."""

    def setUp(self):
        self.store = SqliteStore(":memory:")

    def test_cleanup_removes_old(self):
        # Insert a record with old timestamp
        conn = self.store._get_conn()
        old_ts = time.time() - (31 * 86400)  # 31 days ago
        conn.execute(
            """INSERT INTO daily_reports
               (created_at, cluster, collector_data_json, overall_status,
                analysis_json, analysis_raw, parse_error,
                llm_model, tokens_in, tokens_out, cost_usd,
                latency_ms, context_bytes, truncated)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (old_ts, "c", "{}", "healthy", "{}", "raw", False,
             "m", 0, 0, 0, 0, 0, False),
        )
        conn.commit()

        # Insert a recent record
        self.store.save_daily_report(
            cluster="c", collector_data=_make_collector_data(),
            result=_make_result(),
        )

        deleted = self.store.cleanup_daily_reports()
        self.assertEqual(deleted, 1)
        reports = self.store.list_daily_reports()
        self.assertEqual(len(reports), 1)

    def test_cleanup_keeps_recent(self):
        self.store.save_daily_report(
            cluster="c", collector_data=_make_collector_data(),
            result=_make_result(),
        )
        deleted = self.store.cleanup_daily_reports()
        self.assertEqual(deleted, 0)
        reports = self.store.list_daily_reports()
        self.assertEqual(len(reports), 1)


class TestSaveWithParseError(unittest.TestCase):
    """AnalysisResult with parsed=None, parse_error=True."""

    def setUp(self):
        self.store = SqliteStore(":memory:")

    def test_save_parse_error(self):
        result = _make_result(
            parsed=None, parse_error=True,
            raw_text="invalid json from LLM",
        )
        rid = self.store.save_daily_report(
            cluster="c", collector_data=_make_collector_data(),
            result=result,
        )
        report = self.store.get_daily_report(rid)
        self.assertTrue(report["parse_error"])
        self.assertIsNone(report["overall_status"])
        self.assertIsNone(report["analysis"])
        self.assertEqual(report["analysis_raw"], "invalid json from LLM")

    def test_list_shows_parse_error(self):
        result = _make_result(parsed=None, parse_error=True)
        self.store.save_daily_report(
            cluster="c", collector_data=_make_collector_data(),
            result=result,
        )
        reports = self.store.list_daily_reports()
        self.assertTrue(reports[0]["parse_error"])
        self.assertIsNone(reports[0]["summary"])


class TestGetFirstAnalysisByStateKey(unittest.TestCase):
    """Daily report enrichment needs the *first* (oldest) analysis in the
    window — `get_latest_analysis_by_state_key` flipped ORDER BY."""

    def setUp(self):
        self.store = SqliteStore(":memory:")

    def _add_occurrence(self, state_key, analysis_dict, age_seconds=60, error=False):
        inc = self.store.get_incident(state_key) or self.store.create_incident(
            state_key=state_key, fingerprint="fp", issue_type="oom",
            severity="critical", namespace="production", owner_ref="",
        )

        conn = self.store._get_conn()
        seen_at = time.time() - age_seconds
        conn.execute(
            """INSERT INTO incident_occurrences
               (incident_id, seen_at, context_hash, raw_context, analysis,
                analysis_json, analysis_error, llm_model, tokens_in, tokens_out,
                cost_usd, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (inc.id, seen_at, "h", None, "raw",
             json.dumps(analysis_dict), error,
             "gemini-test", 100, 50, 0.001, seen_at),
        )
        conn.commit()

    def test_returns_earliest_within_window(self):
        sk = "Deployment:production/frontend:oom"
        self._add_occurrence(sk, {"root_cause": "first"}, age_seconds=3600)
        self._add_occurrence(sk, {"root_cause": "second"}, age_seconds=600)
        self._add_occurrence(sk, {"root_cause": "third"}, age_seconds=60)
        row = self.store.get_first_analysis_by_state_key(sk, max_age_hours=24)
        self.assertIsNotNone(row)
        assert row is not None  # type checker
        self.assertEqual(row["analysis_json"]["root_cause"], "first")

    def test_ignores_errored_analyses(self):
        sk = "Deployment:production/frontend:oom"
        self._add_occurrence(sk, {"root_cause": "broken"},
                             age_seconds=3600, error=True)
        self._add_occurrence(sk, {"root_cause": "good"}, age_seconds=60)
        row = self.store.get_first_analysis_by_state_key(sk, max_age_hours=24)
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(row["analysis_json"]["root_cause"], "good")

    def test_respects_max_age_hours(self):
        sk = "Deployment:production/frontend:oom"
        self._add_occurrence(sk, {"root_cause": "very old"},
                             age_seconds=48 * 3600)
        self._add_occurrence(sk, {"root_cause": "recent"}, age_seconds=60)
        row = self.store.get_first_analysis_by_state_key(sk, max_age_hours=24)
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(row["analysis_json"]["root_cause"], "recent")

    def test_returns_none_for_unknown_state_key(self):
        self.assertIsNone(self.store.get_first_analysis_by_state_key("none"))

    def test_empty_state_key(self):
        self.assertIsNone(self.store.get_first_analysis_by_state_key(""))


class TestGetLatestRawContextByStateKey(unittest.TestCase):
    """Daily report enrichment needs the most recent raw_context for a
    state_key, even when no LLM analysis was attached."""

    def setUp(self):
        self.store = SqliteStore(":memory:")

    def _add(self, state_key, context_json, age_seconds=60):
        inc = self.store.get_incident(state_key) or self.store.create_incident(
            state_key=state_key, fingerprint="fp", issue_type="oom",
            severity="critical", namespace="production", owner_ref="",
        )

        conn = self.store._get_conn()
        seen_at = time.time() - age_seconds
        try:
            raw_context = json.loads(context_json) if isinstance(context_json, str) else context_json
        except (json.JSONDecodeError, TypeError):
            raw_context = context_json

        conn.execute(
            """INSERT INTO incident_occurrences
               (incident_id, seen_at, context_hash, raw_context, analysis,
                analysis_json, analysis_error, llm_model, tokens_in, tokens_out,
                cost_usd, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (inc.id, seen_at, "h", json.dumps(raw_context), None, None, False,
             None, None, None, None, seen_at),
        )
        conn.commit()

    def test_returns_most_recent(self):
        sk = "Deployment:production/frontend:crash"
        self._add(sk, '{"phase": "CrashLoopBackOff", "old": true}', age_seconds=600)
        self._add(sk, '{"phase": "CrashLoopBackOff", "new": true}', age_seconds=30)
        row = self.store.get_latest_raw_context_by_state_key(sk, max_age_hours=24)
        self.assertIsNotNone(row)
        assert row is not None
        self.assertTrue(row["raw_context"].get("new"))

    def test_ignores_occurrences_without_raw_context(self):
        sk = "Deployment:production/frontend:crash"
        self._add(sk, '{"phase": "Running"}', age_seconds=300)
        # Insert an analysis-only row (raw_context NULL) — must be skipped.
        inc = self.store.get_incident(sk)
        assert inc is not None
        conn = self.store._get_conn()
        conn.execute(
            """INSERT INTO incident_occurrences
               (incident_id, seen_at, context_hash, raw_context, analysis,
                analysis_json, analysis_error, llm_model, tokens_in, tokens_out,
                cost_usd, created_at)
               VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (inc.id, time.time() - 30, "h2", "raw",
             '{"root_cause":"x"}', False, "gemini", 1, 1, 0.0, time.time() - 30),
        )
        conn.commit()
        row = self.store.get_latest_raw_context_by_state_key(sk, max_age_hours=24)
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(row["raw_context"].get("phase"), "Running")

    def test_respects_max_age(self):
        sk = "Deployment:production/frontend:crash"
        self._add(sk, '{"phase": "CrashLoopBackOff"}', age_seconds=48 * 3600)
        self.assertIsNone(
            self.store.get_latest_raw_context_by_state_key(sk, max_age_hours=24))

    def test_empty_state_key(self):
        self.assertIsNone(self.store.get_latest_raw_context_by_state_key(""))


class TestExtractCurrentSnapshot(unittest.TestCase):
    def test_pod_issue_returns_container_state(self):
        from src.collectors.daily import _extract_current_snapshot
        raw = {
            "pod": {
                "phase": "CrashLoopBackOff",
                "node_ready": True,
                "containers": [
                    {"name": "app", "restarts": 7, "reason": "OOMKilled",
                     "exit_code": 137},
                ],
            },
        }
        snap = _extract_current_snapshot(raw, "crash")
        self.assertIsNotNone(snap)
        assert snap is not None
        self.assertEqual(snap["phase"], "CrashLoopBackOff")
        self.assertEqual(snap["restart_count"], 7)
        self.assertEqual(snap["last_reason"], "OOMKilled")
        self.assertEqual(snap["last_exit_code"], 137)

    def test_oom_issue_uses_pod_shape(self):
        from src.collectors.daily import _extract_current_snapshot
        raw = {"pod": {"phase": "Running", "containers": [
            {"restarts": 3, "reason": "OOMKilled"}]}}
        snap = _extract_current_snapshot(raw, "oom")
        self.assertIsNotNone(snap)
        assert snap is not None
        self.assertEqual(snap["restart_count"], 3)

    def test_endpoint_issue(self):
        from src.collectors.daily import _extract_current_snapshot
        raw = {"context": "endpoint down at https://example.com (status 503)"}
        snap = _extract_current_snapshot(raw, "critical_endpoint")
        self.assertIsNotNone(snap)
        assert snap is not None
        self.assertIn("status 503", snap["context"])

    def test_flux_issue(self):
        from src.collectors.daily import _extract_current_snapshot
        raw = {
            "flux_resource": {"kind": "HelmRelease", "generation": 42,
                              "last_applied_revision": "abcd"},
            "conditions": [{"type": "Ready", "status": "False",
                            "message": "chart fetch failed"}],
        }
        snap = _extract_current_snapshot(raw, "flux")
        self.assertIsNotNone(snap)
        assert snap is not None
        self.assertEqual(snap["generation"], 42)
        self.assertEqual(snap["last_applied_revision"], "abcd")
        self.assertIn("chart fetch", snap["condition_message"])

    def test_unknown_issue_type_returns_none(self):
        from src.collectors.daily import _extract_current_snapshot
        raw = {"something": "irrelevant"}
        self.assertIsNone(_extract_current_snapshot(raw, "unknown_type"))

    def test_non_dict_input(self):
        from src.collectors.daily import _extract_current_snapshot
        self.assertIsNone(_extract_current_snapshot("not a dict", "crash"))  # type: ignore[arg-type]


class TestGetRecentProdIncidents(unittest.TestCase):
    """Daily reports must only see prod incidents."""

    def setUp(self):
        self.store = SqliteStore(":memory:")

    def _insert(self, state_key: str, severity: str = "warning",
                age_hours: float = 1.0, namespace: str = "production"):
        inc = self.store.create_incident(
            state_key=state_key, fingerprint="fp",
            issue_type="oom", severity=severity,
            namespace=namespace, owner_ref="",
        )
        # Backdate last_seen_at so we can test cutoff behaviour.
        conn = self.store._get_conn()
        ts = time.time() - age_hours * 3600
        conn.execute(
            "UPDATE incidents SET last_seen_at = ?, first_seen_at = ? WHERE id = ?",
            (ts, ts, inc.id),
        )
        conn.commit()
        return inc

    def test_excludes_nonprod_state_keys(self):
        self._insert("Deployment:production/frontend:oom", "critical")
        self._insert("Deployment:staging/frontend:oom", "critical", namespace="staging")
        self._insert("Deployment:develop/review-service:crash", namespace="develop")
        self._insert("CriticalEndpoint:staging/frontend-x:https://x", namespace="staging")
        self._insert("PVC:production/postgres-data:warning")

        result = self.store.get_recent_prod_incidents(
            hours=24, exclude_namespaces={"staging", "develop"})

        keys = {r["state_key"] for r in result}
        self.assertEqual(
            keys,
            {
                "Deployment:production/frontend:oom",
                "PVC:production/postgres-data:warning",
            },
        )

    def test_no_filter_returns_all(self):
        self._insert("Deployment:production/frontend:oom")
        self._insert("Deployment:staging/frontend:oom", namespace="staging")
        result = self.store.get_recent_prod_incidents(
            hours=24, exclude_namespaces=None)
        self.assertEqual(len(result), 2)

    def test_handles_custom_state_key_shapes(self):
        """Must filter Flux:HelmRelease:<ns>/..., Certificate:<ns>/...,
        CriticalEndpoint:<ns>/..., Endpoint:<ns>/... and EndpointBatch:<ns>."""
        self._insert("Flux:HelmRelease:staging/foo:stalled", namespace="staging")
        self._insert("Flux:Kustomization:production/foo:stalled")
        self._insert("Certificate:develop/wildcard", namespace="develop")
        self._insert("Certificate:production/wildcard")
        self._insert("CriticalEndpoint:staging/frontend-x:https://x", namespace="staging")
        self._insert("Endpoint:develop/ingress:host", namespace="develop")
        self._insert("EndpointBatch:staging", namespace="staging")
        self._insert("EndpointBatch:production")

        result = self.store.get_recent_prod_incidents(
            hours=24, exclude_namespaces={"staging", "develop"})
        keys = {r["state_key"] for r in result}
        self.assertEqual(
            keys,
            {
                "Flux:Kustomization:production/foo:stalled",
                "Certificate:production/wildcard",
                "EndpointBatch:production",
            },
        )

    def test_honours_hours_cutoff(self):
        self._insert("Deployment:production/old:oom", age_hours=48)
        self._insert("Deployment:production/fresh:oom", age_hours=1)
        result = self.store.get_recent_prod_incidents(
            hours=24, exclude_namespaces={"staging"})
        keys = {r["state_key"] for r in result}
        self.assertEqual(keys, {"Deployment:production/fresh:oom"})


class TestLlmCallsRetention(unittest.TestCase):
    """cleanup_llm_calls / cleanup_llm_debug + integration via cleanup()."""

    def setUp(self):
        self.store = SqliteStore(":memory:")

    def _insert_call(self, called_at: float):
        conn = self.store._get_conn()
        conn.execute(
            """INSERT INTO llm_calls
               (called_at, call_type, provider, model, resource,
                context_bytes, section_bytes_json, sections_json,
                tokens_in, tokens_out, cached_tokens, cost_usd, latency_ms,
                truncated, truncation_notes, error, created_at)
               VALUES (?, 'alert', 'gemini', 'test', 'x', 0, '{}', '[]',
                       1, 1, 0, 0.0, 0, 0, NULL, 0, ?)""",
            (called_at, called_at),
        )
        conn.commit()

    def _insert_debug(self, called_at: float):
        self.store.log_llm_debug(
            called_at=called_at, call_type="alert", resource="x",
            system_prompt="sys", user_content="usr", response_text="resp",
        )
        # Backdate the created_at / called_at so retention kicks in.
        conn = self.store._get_conn()
        conn.execute(
            "UPDATE llm_debug_payloads SET called_at = ?, created_at = ? "
            "WHERE id = (SELECT MAX(id) FROM llm_debug_payloads)",
            (called_at, called_at),
        )
        conn.commit()

    def test_cleanup_llm_calls_deletes_old_rows(self):
        now = time.time()
        self._insert_call(now - 40 * 86400)  # old
        self._insert_call(now - 5 * 86400)   # recent
        deleted = self.store.cleanup_llm_calls(max_age_days=30)
        self.assertEqual(deleted, 1)
        conn = self.store._get_conn()
        remaining = conn.execute("SELECT COUNT(*) FROM llm_calls").fetchone()[0]
        self.assertEqual(remaining, 1)

    def test_cleanup_llm_calls_zero_retention_is_noop(self):
        now = time.time()
        self._insert_call(now - 40 * 86400)
        self.assertEqual(self.store.cleanup_llm_calls(max_age_days=0), 0)
        conn = self.store._get_conn()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM llm_calls").fetchone()[0], 1)

    def test_cleanup_llm_debug_deletes_old_rows(self):
        now = time.time()
        self._insert_debug(now - 10 * 86400)  # old
        self._insert_debug(now - 1 * 86400)   # recent
        deleted = self.store.cleanup_llm_debug(max_age_days=7)
        self.assertEqual(deleted, 1)
        conn = self.store._get_conn()
        remaining = conn.execute("SELECT COUNT(*) FROM llm_debug_payloads").fetchone()[0]
        self.assertEqual(remaining, 1)

    def test_cleanup_integrates_llm_tables(self):
        """Store.cleanup() must apply llm_calls + llm_debug retention."""
        from src import config as cfg
        orig = (cfg.LLM_CALLS_RETENTION_DAYS, cfg.LLM_DEBUG_RETENTION_DAYS)
        cfg.LLM_CALLS_RETENTION_DAYS = 30
        cfg.LLM_DEBUG_RETENTION_DAYS = 7
        try:
            now = time.time()
            self._insert_call(now - 90 * 86400)
            self._insert_call(now - 1 * 86400)
            self._insert_debug(now - 30 * 86400)
            self._insert_debug(now - 1 * 86400)

            self.store.cleanup(max_age_hours=168)

            conn = self.store._get_conn()
            calls = conn.execute("SELECT COUNT(*) FROM llm_calls").fetchone()[0]
            debug = conn.execute("SELECT COUNT(*) FROM llm_debug_payloads").fetchone()[0]
            self.assertEqual(calls, 1)
            self.assertEqual(debug, 1)
        finally:
            cfg.LLM_CALLS_RETENTION_DAYS, cfg.LLM_DEBUG_RETENTION_DAYS = orig


class TestCollect24hHistoryEnrichment(unittest.TestCase):
    """_collect_24h_history attaches initial_analysis / repetition /
    current_snapshot per incident for the daily LLM."""

    def setUp(self):
        self.store = SqliteStore(":memory:")

    def test_enrichment_end_to_end(self):
        from unittest.mock import patch
        from src.collectors.daily import _collect_24h_history

        sk = "Deployment:production/frontend:crash"
        inc = self.store.create_incident(
            state_key=sk, fingerprint="fp", issue_type="crash",
            severity="warning", namespace="production", owner_ref="",
        )
        conn = self.store._get_conn()

        # First (oldest) occurrence with full LLM analysis.
        first_seen_at = time.time() - 2 * 3600
        initial = {
            "root_cause": "Memory limit too low — pod hits 256Mi during warm-up",
            "confidence": 0.85,
            "severity": "warning",
            "hypotheses": [
                {"h": "JVM heap too small"},
                {"h": "Startup probe too aggressive"},
            ],
            "impact": "frontend temporarily unavailable during cold start",
            "suggested_actions": [{"action": "raise mem limit to 512Mi"}],
        }
        conn.execute(
            """INSERT INTO incident_occurrences
               (incident_id, seen_at, context_hash, raw_context, analysis,
                analysis_json, analysis_error, llm_model, tokens_in, tokens_out,
                cost_usd, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (inc.id, first_seen_at, "h1",
             '{"pod": {"phase": "CrashLoopBackOff", "containers": [{"restarts": 2, "reason": "Error", "exit_code": 1}]}}',
             "raw1", json.dumps(initial), False,
             "gemini-3.1-flash", 1000, 200, 0.001, first_seen_at),
        )
        # A later silent occurrence with a fresher snapshot (more restarts).
        latest_seen_at = time.time() - 120
        conn.execute(
            """INSERT INTO incident_occurrences
               (incident_id, seen_at, context_hash, raw_context, analysis,
                analysis_json, analysis_error, llm_model, tokens_in, tokens_out,
                cost_usd, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (inc.id, latest_seen_at, "h2",
             '{"pod": {"phase": "CrashLoopBackOff", "containers": [{"restarts": 9, "reason": "OOMKilled", "exit_code": 137}]}}',
             None, None, False, None, None, None, None, latest_seen_at),
        )
        # Insert 7 more occurrences to reach count=9 (Fix N2: count actual rows)
        for i in range(7):
            ts = first_seen_at + 60 * (i + 1)
            conn.execute(
                "INSERT INTO incident_occurrences (incident_id, seen_at, context_hash, created_at) VALUES (?, ?, ?, ?)",
                (inc.id, ts, f"h-extra-{i}", ts)
            )

        # Sync the main incident table timestamps
        conn.execute(
            "UPDATE incidents SET occurrence_count = 9, last_seen_at = ?, first_seen_at = ? WHERE id = ?",
            (latest_seen_at, first_seen_at, inc.id)
        )

        conn.commit()

        with patch("src.handlers.startup.get_store", return_value=self.store), \
             patch("src.collectors.daily.prom_query", return_value=None):
            history = _collect_24h_history()

        self.assertIn("incidents", history)
        self.assertEqual(len(history["incidents"]), 1)
        entry = history["incidents"][0]
        self.assertEqual(entry["state_key"], sk)
        # Internal sort key must be stripped before leaving the collector.
        self.assertNotIn("_last_seen_ts", entry)

        ia = entry.get("initial_analysis")
        self.assertIsNotNone(ia, "initial_analysis must be attached")
        assert ia is not None
        self.assertIn("Memory limit too low", ia["root_cause"])
        self.assertEqual(ia["analyzed_by"], "gemini-3.1-flash")
        self.assertLessEqual(len(ia["hypotheses"]), 3)
        self.assertLessEqual(len(ia["suggested_actions"]), 3)

        rep = entry.get("repetition")
        self.assertIsNotNone(rep)
        assert rep is not None
        self.assertEqual(rep["count_since_initial"], 8)
        self.assertGreater(rep["duration_minutes"], 100)
        self.assertIn("recurred 8 times", rep["note"])

        snap = entry.get("current_snapshot")
        self.assertIsNotNone(snap)
        assert snap is not None
        # Snapshot must reflect the *latest* raw_context, not the initial one.
        self.assertEqual(snap["restart_count"], 9)
        self.assertEqual(snap["last_reason"], "OOMKilled")
        self.assertEqual(snap["phase"], "CrashLoopBackOff")

    def test_enrichment_skips_nonprod(self):
        from unittest.mock import patch
        from src import config as cfg
        from src.collectors.daily import _collect_24h_history

        orig = cfg.NON_PROD_NAMESPACES
        cfg.NON_PROD_NAMESPACES = {"staging", "develop"}
        try:
            for sk in (
                "Deployment:production/frontend:crash",
                "Deployment:staging/frontend:crash",
                "Deployment:develop/frontend:crash",
            ):
                ns = sk.split(":")[1].split("/")[0]
                self.store.create_incident(
                    state_key=sk, fingerprint="fp",
                    issue_type="crash", severity="warning", namespace=ns, owner_ref="",
                )

            with patch("src.handlers.startup.get_store", return_value=self.store), \
                 patch("src.collectors.daily.prom_query", return_value=None):
                history = _collect_24h_history()

            keys = {i["state_key"] for i in history.get("incidents", [])}
            self.assertEqual(keys, {"Deployment:production/frontend:crash"})
        finally:
            cfg.NON_PROD_NAMESPACES = orig


class TestCooldownBranchPersistsRawContext(unittest.TestCase):
    """F0.2: the pipeline cooldown branch used to drop raw_context at the
    occurrence level (only storing it in the context_store deduplication
    table). `get_latest_raw_context_by_state_key` filters by
    `raw_context IS NOT NULL` so daily enrichment lost visibility into
    cooldown-suppressed occurrences."""

    def setUp(self):
        self._orig = (
            __import__("src", fromlist=["config"]).config.NON_PROD_NAMESPACES,
            __import__("src", fromlist=["config"]).config.DEBOUNCE_SECONDS,
            __import__("src", fromlist=["config"]).config.ESCALATION_RECURRING_WINDOW_H,
        )
        from src import config
        config.NON_PROD_NAMESPACES = set()
        config.DEBOUNCE_SECONDS = 3600  # long cooldown so 2nd occurrence is suppressed
        config.ESCALATION_RECURRING_WINDOW_H = 6
        self.store = SqliteStore(":memory:")

    def tearDown(self):
        from src import config
        (config.NON_PROD_NAMESPACES,
         config.DEBOUNCE_SECONDS, config.ESCALATION_RECURRING_WINDOW_H) = self._orig

    def test_cooldown_occurrence_persists_raw_context(self):
        from unittest.mock import patch
        from src.engine import pipeline
        from src.engine.llm import AnalysisResult
        from src.scanners._base import ScanResult

        # Seed an incident directly so the 2nd process_scan_results pass
        # enters the cooldown branch (escalation.should_alert=False).
        inc = self.store.create_incident(
            state_key="Deployment:production/frontend:oom",
            fingerprint="fp", issue_type="oom",
            severity="critical", namespace="production", owner_ref="",
        )
        # Long cooldown so the next pass is "not should_alert".
        self.store.bump_incident(inc.id, cooldown_until=time.time() + 86400)
        # Pretend one occurrence has already fired (so the 2nd is suppressed
        # by cooldown, not promoted to "recurring" escalation).
        conn = self.store._get_conn()
        conn.execute(
            "UPDATE incidents SET occurrence_count = ?, last_seen_at = ? WHERE id = ?",
            (5, time.time() - 60, inc.id),
        )
        conn.commit()

        result = ScanResult(
            state_key="Deployment:production/frontend:oom",
            title="OOMKilled", severity="critical",
            namespace="production", resource="frontend",
            issue_type="oom",
            context_override={"pod": {"phase": "CrashLoopBackOff",
                                      "containers": [{"reason": "OOMKilled",
                                                      "restarts": 5,
                                                      "exit_code": 137}]}},
        )

        fake_ar = AnalysisResult(
            raw_text='{"root_cause":"x"}',
            parsed={"root_cause": "x", "severity": "critical",
                    "human_needed": True, "hypotheses": [], "impact": "",
                    "suggested_actions": [], "complete_elimination_plan": []},
            parse_error=False, model="m", tokens_in=1, tokens_out=1, cost_usd=0,
        )

        with patch.object(pipeline, "analyze_alert", return_value=fake_ar), \
             patch.object(pipeline, "post_alert"):
            pipeline.process_scan_results([result], self.store)

        # Cooldown branch must have attached raw_context — the new
        # occurrence row should be findable by get_latest_raw_context_by_state_key.
        latest = self.store.get_latest_raw_context_by_state_key(
            "Deployment:production/frontend:oom", max_age_hours=1)
        self.assertIsNotNone(latest, "cooldown path must persist raw_context")
        assert latest is not None
        raw = latest.get("raw_context")
        self.assertIsNotNone(raw, "raw_context must not be None on cooldown row")
        self.assertIsInstance(raw, dict)
        assert isinstance(raw, dict)
        self.assertIn("pod", raw)


if __name__ == "__main__":
    unittest.main()

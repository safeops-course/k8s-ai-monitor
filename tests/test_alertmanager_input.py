"""POST /alertmanager: Prometheus alerts become incidents in the shared pipeline."""
import json
import unittest
from unittest import mock

from aiohttp.test_utils import TestClient, TestServer

from src import config
from src.handlers import alertmanager, startup


def _alert(name="BackendErrorBudgetBurnFast", ns="production", status="firing",
           severity="critical", fp="abc123", **labels):
    return {
        "status": status,
        "labels": {"alertname": name, "namespace": ns, "severity": severity, **labels},
        "annotations": {"summary": f"{ns}: backend users are failing",
                        "runbook_url": "https://example.test/runbook"},
        "startsAt": "2026-10-05T10:00:00Z",
        "fingerprint": fp,
    }


class TestAlertToResult(unittest.TestCase):
    def setUp(self):
        p = mock.patch("src.handlers.events._in_watched_namespace", return_value=True)
        p.start()
        self.addCleanup(p.stop)

    def test_firing_alert_becomes_a_scan_result(self):
        r = alertmanager.alert_to_result(_alert(pod="backend-7c5bc9d4bd-x2kq8"))
        self.assertEqual(r.state_key, "Alert:production/BackendErrorBudgetBurnFast:abc123")
        self.assertEqual(r.severity, "critical")
        self.assertEqual(r.issue_type, "alert")
        self.assertEqual(r.pod_name, "backend-7c5bc9d4bd-x2kq8")
        self.assertFalse(r.auto_resolve)
        self.assertTrue(r.never_promote)  # the rule's severity is final
        self.assertEqual(r.context_override["runbook_url"], "https://example.test/runbook")

    def test_resolved_alert_closes_the_same_incident(self):
        firing = alertmanager.alert_to_result(_alert())
        resolved = alertmanager.alert_to_result(_alert(status="resolved"))
        self.assertEqual(firing.state_key, resolved.state_key)
        self.assertTrue(resolved.auto_resolve)

    def test_heartbeat_and_inhibitor_are_ignored(self):
        self.assertIsNone(alertmanager.alert_to_result(_alert(name="Watchdog", ns="")))
        self.assertIsNone(alertmanager.alert_to_result(_alert(name="InfoInhibitor")))

    def test_unknown_severity_becomes_warning(self):
        self.assertEqual(alertmanager.alert_to_result(_alert(severity="info")).severity, "warning")

    def test_cluster_scoped_alert_has_a_cluster_key(self):
        r = alertmanager.alert_to_result(_alert(name="KubeNodeNotReady", ns="", fp="n1"))
        self.assertEqual(r.state_key, "Alert:cluster/KubeNodeNotReady:n1")

    def test_payload_without_alerts_is_refused(self):
        with self.assertRaises(ValueError):
            alertmanager.payload_to_results({"status": "firing"})

    def test_payload_that_is_not_an_object_is_refused(self):
        with self.assertRaises(ValueError):
            alertmanager.payload_to_results(["not", "an", "object"])

    def test_malformed_labels_are_refused(self):
        with self.assertRaises(ValueError):
            alertmanager.alert_to_result({"labels": ["alertname"], "status": "firing"})

    def test_empty_array_labels_are_refused_but_null_is_empty(self):
        with self.assertRaises(ValueError):
            alertmanager.alert_to_result({"labels": [], "fingerprint": "f1"})
        # null labels = no alertname: not ours to track, not an error
        self.assertIsNone(alertmanager.alert_to_result({"labels": None, "annotations": None}))

    def test_alert_without_fingerprint_is_refused(self):
        for fp in (None, "", 42):
            alert = _alert()
            alert["fingerprint"] = fp
            with self.assertRaises(ValueError, msg=repr(fp)):
                alertmanager.alert_to_result(alert)

    def test_secret_in_summary_is_redacted_from_the_title(self):
        alert = _alert()
        alert["annotations"]["summary"] = "login failed, password=" + "hunter" + "2-demo"
        r = alertmanager.alert_to_result(alert)
        self.assertNotIn("hunter2-demo", r.title)


class TestNamespaceFilter(unittest.TestCase):
    def test_unwatched_namespace_is_dropped(self):
        with mock.patch("src.handlers.events._in_watched_namespace", return_value=False):
            self.assertIsNone(alertmanager.alert_to_result(_alert(ns="kube-system")))


class TestWebhookRoute(unittest.IsolatedAsyncioTestCase):
    async def _client(self):
        client = TestClient(TestServer(startup._build_app()))
        await client.start_server()
        self.addAsyncCleanup(client.close)
        return client

    async def test_bearer_token_is_accepted_and_alerts_reach_the_pipeline(self):
        payload = {"status": "firing", "alerts": [_alert(), _alert(name="Watchdog", ns="")]}
        with mock.patch.object(config, "INTERNAL_TOKEN", "s3cret"), \
             mock.patch("src.handlers.events._in_watched_namespace", return_value=True), \
             mock.patch("src.handlers.startup.get_store"), \
             mock.patch("src.engine.pipeline.process_scan_results", return_value=1) as pipe:
            client = await self._client()
            resp = await client.post("/alertmanager", data=json.dumps(payload),
                                     headers={"Authorization": "Bearer s3cret"})
            self.assertEqual(resp.status, 200)
            self.assertEqual(await resp.json(), {"received": 2, "processed": 1, "posted": 1})
            results = pipe.call_args[0][0]
            self.assertEqual([r.resource for r in results], ["Alert/BackendErrorBudgetBurnFast"])

    async def test_wrong_bearer_token_is_forbidden(self):
        with mock.patch.object(config, "INTERNAL_TOKEN", "s3cret"):
            client = await self._client()
            resp = await client.post("/alertmanager", data="{}",
                                     headers={"Authorization": "Bearer wrong"})
            self.assertEqual(resp.status, 403)

    async def test_bad_payload_is_a_400(self):
        with mock.patch.object(config, "INTERNAL_TOKEN", "s3cret"):
            client = await self._client()
            resp = await client.post("/alertmanager", data="not json",
                                     headers={"X-Internal-Token": "s3cret"})
            self.assertEqual(resp.status, 400)

    async def test_json_that_is_not_an_object_is_a_400(self):
        with mock.patch.object(config, "INTERNAL_TOKEN", "s3cret"):
            client = await self._client()
            for body in ("[]", '{"alerts": [{"labels": "x"}]}'):
                resp = await client.post("/alertmanager", data=body,
                                         headers={"X-Internal-Token": "s3cret"})
                self.assertEqual(resp.status, 400, body)


class TestWithoutAnLLMKey(unittest.TestCase):
    """kind without a key: a production incident is tracked and posted, not analysed."""

    def test_production_alert_is_posted_without_analysis(self):
        import tempfile

        from src.engine import pipeline
        from src.engine.store.sqlite import SqliteStore

        store = SqliteStore(tempfile.mkdtemp() + "/t.db")
        with mock.patch("src.handlers.events._in_watched_namespace", return_value=True), \
             mock.patch("src.engine.pipeline.llm_configured", return_value=False), \
             mock.patch("src.engine.pipeline.analyze_alert") as llm, \
             mock.patch("src.engine.pipeline.post_alert", return_value=True) as post:
            pipeline.process_scan_results(alertmanager.payload_to_results({"alerts": [_alert()]}), store)
            llm.assert_not_called()
            post.assert_called_once()
            self.assertEqual(store.get_incident(
                "Alert:production/BackendErrorBudgetBurnFast:abc123").status, "active")

    def test_llm_configured_follows_the_provider_key(self):
        from src.engine import llm
        cases = [("openai", {"OPENAI_API_KEY": "k"}, True), ("openai", {"GEMINI_API_KEY": "k"}, False),
                 ("gemini", {"GEMINI_API_KEY": "k"}, True), ("anthropic", {"ANTHROPIC_API_KEY": "k"}, True),
                 ("anthropic", {}, False)]
        for provider, keys, expected in cases:
            env = {"OPENAI_API_KEY": "", "GEMINI_API_KEY": "", "ANTHROPIC_API_KEY": "", **keys}
            with mock.patch.object(config, "LLM_PROVIDER", provider), \
                 mock.patch.multiple(config, **env):
                self.assertEqual(llm.llm_configured(), expected, (provider, keys))


if __name__ == "__main__":
    unittest.main()


class TestThroughThePipeline(unittest.TestCase):
    """The real pipeline and store: firing opens one incident, resolved closes it."""

    def test_firing_then_resolved(self):
        import tempfile

        from src.engine import pipeline
        from src.engine.llm import AnalysisResult
        from src.engine.store.sqlite import SqliteStore

        store = SqliteStore(tempfile.mkdtemp() + "/t.db")
        analysis = AnalysisResult(raw_text="{}", parsed={"root_cause": "x"}, parse_error=False,
                                  model="test", tokens_in=1, tokens_out=1, cost_usd=0.0)
        with mock.patch("src.handlers.events._in_watched_namespace", return_value=True), \
             mock.patch("src.engine.pipeline.llm_configured", return_value=True), \
             mock.patch("src.engine.pipeline.analyze_alert", return_value=analysis) as llm, \
             mock.patch("src.engine.pipeline.post_alert", return_value=True):
            pipeline.process_scan_results(alertmanager.payload_to_results({"alerts": [_alert()]}), store)
            inc = store.get_incident("Alert:production/BackendErrorBudgetBurnFast:abc123")
            self.assertIsNotNone(inc)
            self.assertEqual(inc.status, "active")
            self.assertEqual(inc.severity, "critical")
            llm.assert_called_once()  # production: analysed

            pipeline.process_scan_results(
                alertmanager.payload_to_results({"alerts": [_alert(status="resolved")]}), store)
            self.assertEqual(store.get_incident(inc.state_key).status, "resolved")

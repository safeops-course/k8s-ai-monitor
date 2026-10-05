"""Tests for LLM response parsing — new and old schema support."""
import json
import unittest

from src.engine.llm import parse_analysis, parse_daily_report
from src.engine.notifier import format_structured_analysis, format_daily_report


class TestParseAnalysisNewSchema(unittest.TestCase):
    """parse_analysis handles the new hypotheses/suggested_actions schema."""

    def test_valid_new_schema(self):
        raw = json.dumps({
            "root_cause": "OOM killed due to memory limit",
            "confidence": 0.85,
            "severity": "critical",
            "human_needed": True,
            "hypotheses": [
                {"cause": "Memory limit too low", "confidence": 0.85, "evidence": ["exit code 137", "mem_lim 256Mi"]},
                {"cause": "Memory leak", "confidence": 0.5, "evidence": ["heap growing"]},
            ],
            "impact": "Pod restarts every 5 minutes",
            "complete_elimination_plan": [
                {"step": "kubectl set resources deploy/app --limits=memory=512Mi", "priority": 1, "description": "Increase memory limit"},
                {"step": "Check for memory leaks in app code", "priority": 2, "description": "Investigate potential leak"},
            ],
        })
        parsed, error = parse_analysis(raw)
        self.assertFalse(error)
        self.assertEqual(parsed["root_cause"], "OOM killed due to memory limit")
        self.assertEqual(parsed["confidence"], 0.85)
        self.assertEqual(parsed["severity"], "critical")
        self.assertTrue(parsed["human_needed"])
        self.assertEqual(len(parsed["hypotheses"]), 2)
        self.assertEqual(parsed["hypotheses"][0]["cause"], "Memory limit too low")
        self.assertEqual(len(parsed["complete_elimination_plan"]), 2)
        self.assertEqual(parsed["complete_elimination_plan"][0]["priority"], 1)
        self.assertEqual(parsed["complete_elimination_plan"][0]["step"], "kubectl set resources deploy/app --limits=memory=512Mi")

    def test_human_needed_low_confidence(self):
        raw = json.dumps({
            "root_cause": "Unknown",
            "confidence": 0.4,
            "severity": "warning",
            "hypotheses": [],
            "impact": "Degraded",
            "suggested_actions": [],
        })
        parsed, _ = parse_analysis(raw)
        self.assertTrue(parsed["human_needed"])

    def test_priority_clamped(self):
        raw = json.dumps({
            "root_cause": "test",
            "confidence": 0.9,
            "suggested_actions": [
                {"action": "do something", "priority": 0},
                {"action": "do another", "priority": 5},
            ],
        })
        parsed, _ = parse_analysis(raw)
        self.assertEqual(parsed["suggested_actions"][0]["priority"], 1)
        self.assertEqual(parsed["suggested_actions"][1]["priority"], 3)

    def test_confidence_clamped(self):
        raw = json.dumps({"root_cause": "test", "confidence": 1.5})
        parsed, _ = parse_analysis(raw)
        self.assertEqual(parsed["confidence"], 1.0)

        raw2 = json.dumps({"root_cause": "test", "confidence": -0.5})
        parsed2, _ = parse_analysis(raw2)
        self.assertEqual(parsed2["confidence"], 0.0)


class TestParseAnalysisOldSchema(unittest.TestCase):
    """parse_analysis backward compat: old action_plan/evidence -> new schema."""

    def test_old_schema_converted(self):
        raw = json.dumps({
            "root_cause": "CrashLoopBackOff due to OOM",
            "confidence": 0.8,
            "impact": "Service degraded",
            "action_plan": ["Increase memory limit", "Check for leaks"],
            "human_needed": False,
            "evidence": ["exit code 137", "restarts=5"],
        })
        parsed, error = parse_analysis(raw)
        self.assertFalse(error)
        # Old evidence -> hypotheses
        self.assertEqual(len(parsed["hypotheses"]), 1)
        self.assertEqual(parsed["hypotheses"][0]["cause"], "CrashLoopBackOff due to OOM")
        self.assertEqual(parsed["hypotheses"][0]["evidence"], ["exit code 137", "restarts=5"])
        # Old action_plan -> suggested_actions
        self.assertEqual(len(parsed["suggested_actions"]), 2)
        self.assertEqual(parsed["suggested_actions"][0]["action"], "Increase memory limit")
        self.assertEqual(parsed["suggested_actions"][0]["priority"], 2)

    def test_old_schema_keeps_action_plan_field(self):
        """Old action_plan field preserved for backward compat in notifier."""
        raw = json.dumps({
            "root_cause": "test",
            "confidence": 0.7,
            "action_plan": ["step 1"],
            "evidence": ["e1"],
        })
        parsed, _ = parse_analysis(raw)
        # action_plan still exists from original JSON
        self.assertIn("action_plan", parsed)


class TestParseAnalysisErrors(unittest.TestCase):
    """Non-JSON and invalid input handling."""

    def test_non_json(self):
        parsed, error = parse_analysis("This is just a text response about the problem.")
        self.assertTrue(error)
        self.assertTrue(parsed["_parse_error"])
        self.assertIn("This is just a text", parsed["root_cause"])

    def test_markdown_fences_stripped(self):
        raw = '```json\n{"root_cause": "test", "confidence": 0.8}\n```'
        parsed, error = parse_analysis(raw)
        self.assertFalse(error)
        self.assertEqual(parsed["root_cause"], "test")

    def test_empty_string(self):
        parsed, error = parse_analysis("")
        self.assertTrue(error)

    def test_defaults_filled(self):
        raw = json.dumps({"root_cause": "minimal"})
        parsed, _ = parse_analysis(raw)
        self.assertEqual(parsed["confidence"], 0.3)
        self.assertEqual(parsed["severity"], "warning")
        self.assertEqual(parsed["impact"], "unknown")
        self.assertEqual(parsed["hypotheses"], [])
        self.assertEqual(parsed["suggested_actions"], [])


class TestFormatStructuredAnalysis(unittest.TestCase):
    """format_structured_analysis renders both schemas correctly."""

    def test_new_schema_format(self):
        analysis = {
            "root_cause": "OOM killed",
            "confidence": 0.85,
            "impact": "Service down",
            "hypotheses": [
                {"cause": "Memory limit too low", "confidence": 0.85, "evidence": ["exit code 137"]},
            ],
            "complete_elimination_plan": [
                {"step": "kubectl set resources ...", "priority": 1, "description": "Increase memory"},
                {"step": "Check logs", "priority": 3, "description": "Add monitoring"},
            ],
        }
        text = format_structured_analysis(analysis)
        self.assertIn("*Root Cause*", text)
        self.assertIn("OOM killed", text)
        self.assertIn("*Hypotheses*", text)
        self.assertIn("Memory limit too low", text)
        self.assertIn("*\u2705 Elimination Plan*", text)
        self.assertIn("kubectl set resources ...", text)

    def test_old_schema_format(self):
        analysis = {
            "root_cause": "CrashLoop",
            "confidence": 0.7,
            "impact": "Degraded",
            "action_plan": ["Fix config", "Restart pod"],
            "evidence": ["restarts=5", "exit code 1"],
        }
        text = format_structured_analysis(analysis)
        self.assertIn("*Action Plan*", text)
        self.assertIn("Fix config", text)
        self.assertIn("*Evidence*", text)
        self.assertIn("restarts=5", text)

    def test_parse_error_fallback(self):
        analysis = {
            "root_cause": "Raw LLM text here",
            "_parse_error": True,
        }
        text = format_structured_analysis(analysis)
        self.assertEqual(text, "Raw LLM text here")

    def test_human_needed_shown(self):
        analysis = {
            "root_cause": "test",
            "confidence": 0.4,
            "impact": "unknown",
            "human_needed": True,
        }
        text = format_structured_analysis(analysis)
        self.assertIn("Human review recommended", text)


class TestParseDailyReport(unittest.TestCase):
    """parse_daily_report handles valid, invalid, and non-JSON responses."""

    def test_valid_response(self):
        raw = json.dumps({
            "overall_status": "healthy",
            "confidence": 0.9,
            "summary": "All systems operational",
            "issues": [],
            "trends": [],
            "recommendations": [],
        })
        parsed, error = parse_daily_report(raw)
        self.assertFalse(error)
        self.assertEqual(parsed["overall_status"], "healthy")
        self.assertEqual(parsed["confidence"], 0.9)
        self.assertEqual(parsed["summary"], "All systems operational")

    def test_degraded_with_issues(self):
        raw = json.dumps({
            "overall_status": "degraded",
            "confidence": 0.8,
            "summary": "Some pods restarting",
            "issues": [
                {"description": "OOM kills", "severity": "warning", "affected": "app-abc"},
            ],
            "trends": [
                {"description": "Memory usage growing"},
            ],
            "recommendations": [
                {"action": "Increase memory limits", "priority": 1},
            ],
        })
        parsed, error = parse_daily_report(raw)
        self.assertFalse(error)
        self.assertEqual(parsed["overall_status"], "degraded")
        self.assertEqual(len(parsed["issues"]), 1)
        self.assertEqual(parsed["issues"][0]["severity"], "warning")
        self.assertEqual(len(parsed["trends"]), 1)
        self.assertEqual(len(parsed["recommendations"]), 1)
        self.assertEqual(parsed["recommendations"][0]["priority"], 1)

    def test_invalid_status_normalized(self):
        raw = json.dumps({
            "overall_status": "bad",
            "confidence": 0.7,
            "summary": "test",
        })
        parsed, error = parse_daily_report(raw)
        self.assertFalse(error)
        self.assertEqual(parsed["overall_status"], "degraded")

    def test_non_json_fallback(self):
        parsed, error = parse_daily_report("This is just plain text from the LLM.")
        self.assertTrue(error)
        self.assertTrue(parsed["_parse_error"])
        self.assertEqual(parsed["overall_status"], "degraded")
        self.assertIn("plain text", parsed["summary"])

    def test_defaults_filled(self):
        raw = json.dumps({"overall_status": "healthy"})
        parsed, _ = parse_daily_report(raw)
        self.assertEqual(parsed["confidence"], 0.5)
        self.assertEqual(parsed["summary"], "")
        self.assertEqual(parsed["issues"], [])
        self.assertEqual(parsed["trends"], [])
        self.assertEqual(parsed["recommendations"], [])

    def test_priority_clamped(self):
        raw = json.dumps({
            "overall_status": "degraded",
            "recommendations": [
                {"action": "do something", "priority": 0},
                {"action": "do another", "priority": 5},
            ],
        })
        parsed, _ = parse_daily_report(raw)
        self.assertEqual(parsed["recommendations"][0]["priority"], 1)
        self.assertEqual(parsed["recommendations"][1]["priority"], 3)

    def test_confidence_clamped(self):
        raw = json.dumps({"overall_status": "healthy", "confidence": 1.5})
        parsed, _ = parse_daily_report(raw)
        self.assertEqual(parsed["confidence"], 1.0)

        raw2 = json.dumps({"overall_status": "healthy", "confidence": -0.5})
        parsed2, _ = parse_daily_report(raw2)
        self.assertEqual(parsed2["confidence"], 0.0)

    def test_markdown_fences_stripped(self):
        raw = '```json\n{"overall_status": "healthy", "confidence": 0.9, "summary": "OK"}\n```'
        parsed, error = parse_daily_report(raw)
        self.assertFalse(error)
        self.assertEqual(parsed["overall_status"], "healthy")

    def test_empty_string(self):
        parsed, error = parse_daily_report("")
        self.assertTrue(error)
        self.assertTrue(parsed["_parse_error"])


class TestFormatDailyReport(unittest.TestCase):
    """format_daily_report renders Slack Block Kit blocks correctly."""

    def test_healthy_status(self):
        parsed = {
            "overall_status": "healthy",
            "confidence": 0.9,
            "summary": "All systems operational",
            "issues": [],
            "trends": [],
            "recommendations": [],
        }
        blocks = format_daily_report(parsed)
        self.assertGreater(len(blocks), 0)
        # First block should contain status + summary
        first_text = blocks[0]["text"]["text"]
        self.assertIn("HEALTHY", first_text)
        self.assertIn("All systems operational", first_text)

    def test_degraded_with_issues(self):
        parsed = {
            "overall_status": "degraded",
            "confidence": 0.8,
            "summary": "Some issues found",
            "issues": [
                {"description": "OOM kills", "severity": "critical", "affected": "app-abc"},
                {"description": "High memory", "severity": "warning", "affected": "worker-1"},
            ],
            "trends": [
                {"description": "Memory growing"},
            ],
            "recommendations": [
                {"action": "Increase limits", "priority": 1},
            ],
        }
        blocks = format_daily_report(parsed)
        all_text = " ".join(b["text"]["text"] for b in blocks if b["type"] == "section")
        self.assertIn("DEGRADED", all_text)
        self.assertIn("OOM kills", all_text)
        self.assertIn("Memory growing", all_text)
        self.assertIn("Increase limits", all_text)

    def test_parse_error_fallback(self):
        parsed = {
            "_parse_error": True,
            "summary": "Raw LLM text here",
        }
        blocks = format_daily_report(parsed)
        self.assertEqual(len(blocks), 1)
        self.assertIn("Raw LLM text here", blocks[0]["text"]["text"])

    def test_no_issues_no_issue_section(self):
        parsed = {
            "overall_status": "healthy",
            "confidence": 0.95,
            "summary": "All good",
            "issues": [],
            "trends": [],
            "recommendations": [],
        }
        blocks = format_daily_report(parsed)
        # Only status block, no issue/trend/recommendation blocks
        section_blocks = [b for b in blocks if b["type"] == "section"]
        self.assertEqual(len(section_blocks), 1)


class TestChainOfThoughtReasoning(unittest.TestCase):
    """Phase 1: `reasoning` is the first JSON field; parser preserves it
    from LLM output and defaults to empty string when missing or errored."""

    def test_parse_analysis_preserves_reasoning_field(self):
        """When the LLM returns a non-empty reasoning, it survives parsing
        verbatim and ends up in the parsed dict."""
        raw = json.dumps({
            "reasoning": "Pod phase is CrashLoopBackOff with 5 restarts in 3 min. "
                         "Last log shows connection refused to postgres. "
                         "SRE knowledge base indicates this is likely a dependency "
                         "issue, not an application bug.",
            "root_cause": "Postgres unreachable from backend",
            "confidence": 0.9,
            "severity": "critical",
            "human_needed": True,
            "hypotheses": [
                {"cause": "Postgres pod down", "confidence": 0.9,
                 "evidence": ["connection refused"]},
            ],
            "impact": "backend 5xx cascade",
            "complete_elimination_plan": [
                {"step": "kubectl -n production get pods -l app=postgres",
                 "priority": 1, "description": "Verify postgres pod state"},
            ],
        })
        parsed, error = parse_analysis(raw)
        self.assertFalse(error)
        self.assertIn("reasoning", parsed)
        self.assertIn("CrashLoopBackOff with 5 restarts", parsed["reasoning"])
        self.assertIn("connection refused to postgres", parsed["reasoning"])
        self.assertEqual(parsed["root_cause"], "Postgres unreachable from backend")

    def test_parse_analysis_defaults_reasoning_to_empty_string(self):
        """When the LLM omits reasoning entirely, parser fills the key with
        an empty string (defensive — the prompt marks reasoning as
        mandatory, but the parser shouldn't crash if it's missing)."""
        raw = json.dumps({
            "root_cause": "OOMKilled due to memory limit",
            "confidence": 0.85,
            "severity": "critical",
            "human_needed": True,
            "hypotheses": [],
            "impact": "",
            "complete_elimination_plan": [],
        })
        parsed, error = parse_analysis(raw)
        self.assertFalse(error)
        self.assertIn("reasoning", parsed)
        self.assertEqual(parsed["reasoning"], "")

    def test_parse_analysis_parse_error_includes_empty_reasoning(self):
        """When the LLM returns invalid JSON, the parse-error fallback
        dict must still include the reasoning key so downstream consumers
        (daily enrichment, notifier, etc.) can safely read it."""
        raw = "this is not JSON at all"
        parsed, error = parse_analysis(raw)
        self.assertTrue(error)
        self.assertIn("reasoning", parsed)
        self.assertEqual(parsed["reasoning"], "")
        self.assertTrue(parsed.get("_parse_error"))


if __name__ == "__main__":
    unittest.main()

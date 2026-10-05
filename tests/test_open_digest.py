"""Tests for the open-incidents digest (morning + end-of-day snapshots)."""
import time
import unittest
from unittest.mock import MagicMock, patch

from src.engine import open_digest
from src.engine.store import Incident


def _inc(state_key, severity="warning", status="active", *,
         occurrence_count=3, open_hours=5.0, seen_hours_ago=0.5):
    now = time.time()
    return Incident(
        id=1, state_key=state_key, fingerprint="f", issue_type="unhealthy",
        severity=severity, owner_ref="", first_seen_at=now - open_hours * 3600,
        last_seen_at=now - seen_hours_ago * 3600,
        active_since=now - open_hours * 3600,
        occurrence_count=occurrence_count, cooldown_until=None,
        last_slack_ts="", status=status, namespace="production",
    )


class TestBuildBlocks(unittest.TestCase):
    def test_empty_board_is_green_and_still_a_message(self):
        text, blocks, color = open_digest.build_blocks([], time.time())
        self.assertEqual(color, "#36A64F")
        self.assertIn("No open incidents", text)
        self.assertTrue(blocks)

    def test_critical_present_makes_it_red_and_sorts_first(self):
        incidents = [
            _inc("Deployment:production/a:unhealthy", "warning"),
            _inc("Pod:production/postgresql-1:unhealthy", "critical"),
        ]
        text, blocks, color = open_digest.build_blocks(incidents, time.time())
        self.assertEqual(color, "#D00000")
        self.assertIn("2 open incidents", text)
        self.assertIn("(1 critical)", text)
        rendered = "\n".join(str(b) for b in blocks)
        self.assertLess(
            rendered.index("postgresql-1"), rendered.index("production/a"),
            "critical must render before warning",
        )

    def test_acknowledged_is_labelled(self):
        incidents = [_inc("Deployment:production/a:unhealthy", status="acknowledged")]
        _, blocks, color = open_digest.build_blocks(incidents, time.time())
        self.assertEqual(color, "#FFA500")
        self.assertIn("acknowledged", "\n".join(str(b) for b in blocks))

    def test_overflow_collapses_with_criticals_kept(self):
        incidents = [
            _inc(f"Deployment:production/w{i}:unhealthy", "warning")
            for i in range(30)
        ] + [_inc("Pod:production/db-0:unhealthy", "critical")]
        _, blocks, _ = open_digest.build_blocks(incidents, time.time())
        rendered = "\n".join(str(b) for b in blocks)
        self.assertIn("+6 more open incidents", rendered)
        self.assertIn("db-0", rendered, "critical must survive the cut")


class TestRunOnce(unittest.TestCase):
    def _store(self, incidents):
        store = MagicMock()
        store.list_incidents.return_value = incidents
        return store

    @patch("src.engine.open_digest._post_notice", return_value=True)
    def test_posts_even_when_empty(self, mock_post):
        resolved = _inc("Deployment:production/x:crash", status="resolved")
        self.assertTrue(open_digest.run_once(self._store([resolved])))
        mock_post.assert_called_once()
        self.assertIn("No open incidents", mock_post.call_args[0][0])

    @patch("src.engine.open_digest._post_notice", return_value=True)
    def test_resolved_incidents_are_excluded(self, mock_post):
        incidents = [
            _inc("Pod:production/db-0:unhealthy", "critical"),
            _inc("Deployment:production/x:crash", status="resolved"),
        ]
        self.assertTrue(open_digest.run_once(self._store(incidents)))
        self.assertIn("1 open incident", mock_post.call_args[0][0])

    @patch("src.engine.open_digest._post_notice", return_value=False)
    def test_delivery_failure_returns_false(self, _mock_post):
        self.assertFalse(open_digest.run_once(self._store([])))

    @patch("src.engine.open_digest._post_notice")
    def test_store_failure_never_raises(self, mock_post):
        store = MagicMock()
        store.list_incidents.side_effect = RuntimeError("db locked")
        self.assertFalse(open_digest.run_once(store))
        mock_post.assert_not_called()

    @patch("src.engine.open_digest._post_notice", side_effect=RuntimeError("boom"))
    def test_delivery_raise_never_escapes(self, _mock_post):
        self.assertFalse(open_digest.run_once(self._store([])))






class TestHourListParsing(unittest.TestCase):
    def _parse(self, value):
        from src.config import _parse_hour_list
        with patch.dict("os.environ", {"OPEN_DIGEST_HOURS": value}):
            return _parse_hour_list("OPEN_DIGEST_HOURS")

    def test_morning_and_evening(self):
        self.assertEqual(self._parse("8,18"), [8, 18])

    def test_empty_disables(self):
        self.assertEqual(self._parse(""), [])

    def test_garbage_and_out_of_range_ignored(self):
        self.assertEqual(self._parse("8,noon,25,-1,18"), [8, 18])

    def test_duplicates_collapse(self):
        self.assertEqual(self._parse("18, 18 ,8"), [8, 18])

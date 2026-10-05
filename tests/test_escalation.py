"""check_escalation: the pipeline checks BEFORE it records the current occurrence."""
import time
import unittest

from src.engine.escalation import check_escalation
from src.engine.store import Incident


def _incident(recorded: int, first_seen_hours_ago: float = 2.0) -> Incident:
    now = time.time()
    return Incident(id=1, state_key="Pod:develop/backend-1", fingerprint="fp", issue_type="pod",
                    severity="warning", owner_ref="", first_seen_at=now - first_seen_hours_ago * 3600,
                    last_seen_at=now - 60, occurrence_count=recorded, cooldown_until=None,
                    last_slack_ts="", status="active")


class TestEscalationCount(unittest.TestCase):
    def test_second_occurrence_is_recurring(self):
        self.assertEqual(check_escalation(_incident(1), count_offset=1).level, "recurring")

    def test_third_occurrence_is_persistent(self):
        # 2 recorded + the current one = 3 = ESCALATION_PERSISTENT_MIN_OCCURRENCES (default)
        self.assertEqual(check_escalation(_incident(2), count_offset=1).level, "persistent")

    def test_without_offset_it_was_one_late(self):
        # the old call: the current occurrence not counted - no escalation on the 3rd
        self.assertIsNone(check_escalation(_incident(2)).level)

    def test_persistent_needs_age(self):
        self.assertIsNone(check_escalation(_incident(2, first_seen_hours_ago=0.1), count_offset=1).level)


if __name__ == "__main__":
    unittest.main()

"""The two halves of an occurrence must describe the same set of events.

`occurrence_count` is what the board shows as the lifetime total; the rows in
`incident_occurrence_hours` are what it shows as Today / 7d. If only some of the
recording paths push — the alerting ones but not the cooldown-suppressed or the
acknowledged ones — the windows undercount against the total sitting in the
tooltip right beside them, which is worse than having no windows at all.
"""
import ast
import pathlib
import unittest

from src.engine import central_push

_PIPELINE = pathlib.Path("src/engine/pipeline.py")


def _calls(name: str) -> list[int]:
    """Lines where `name(...)` is called in pipeline.py."""
    tree = ast.parse(_PIPELINE.read_text())
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        target = (f.attr if isinstance(f, ast.Attribute)
                  else f.id if isinstance(f, ast.Name) else None)
        if target == name:
            out.append(node.lineno)
    return out


class TestEveryRecordingPathPushes(unittest.TestCase):
    def test_the_store_is_reached_only_through_the_helper(self):
        """A bare store.record_occurrence bumps the count without a bucket, so
        the only one allowed is the helper's own."""
        tree = ast.parse(_PIPELINE.read_text())
        helper = next(n for n in ast.walk(tree)
                      if isinstance(n, ast.FunctionDef) and n.name == "_record_occurrence")
        span = range(helper.lineno, (helper.end_lineno or helper.lineno) + 1)
        outside = [ln for ln in _calls("record_occurrence") if ln not in span]
        self.assertEqual(
            outside, [],
            "pipeline must record through _record_occurrence, which pushes too")

    def test_the_helper_is_the_only_pusher(self):
        """One place to be wrong, instead of one per branch."""
        self.assertEqual(len(_calls("push_occurrence_hour")), 1)

    def test_every_recording_path_goes_through_it(self):
        """Four sites record: the immediate path, the two LLM paths, and the
        silent one for acknowledged incidents."""
        self.assertEqual(len(_calls("_record_occurrence")), 4)


class TestTimestampConversion(unittest.TestCase):
    def test_active_since_is_converted(self):
        """ClickHouse rejects the fractional part of a Unix float outright
        ("expected ',' before: '.770317'"), and _push swallows the error — so a
        missed field does not degrade the row, it kills the whole INSERT and the
        cluster silently stops reporting."""
        self.assertIn("active_since", central_push._TIMESTAMP_FIELDS)
        row = central_push._convert_timestamps({"active_since": 1789388046.770317})
        self.assertEqual(row["active_since"], "2026-09-14 12:14:06.770")

    def test_every_timestamp_the_pushers_send_is_declared(self):
        """The status row and the pipeline payloads must not grow a timestamp
        field that nobody converts."""
        for field in ("first_seen_at", "active_since", "last_seen_at", "resolved_at"):
            with self.subTest(field=field):
                self.assertIn(field, central_push._TIMESTAMP_FIELDS)


if __name__ == "__main__":
    unittest.main()

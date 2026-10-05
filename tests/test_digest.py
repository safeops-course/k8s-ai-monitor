"""The hourly digest: withheld alerts posted once, grouped - and nothing when quiet."""
from unittest.mock import MagicMock, patch

import pytest

from src.engine import digest
from src.engine.store.sqlite import SqliteStore


@pytest.fixture
def store(tmp_path):
    return SqliteStore(str(tmp_path / "t.db"))


# --- the digest -------------------------------------------------------------

def test_quiet_hour_posts_nothing(store):
    """Requirement, verbatim: a message only if the check finds a problem."""
    with patch("src.engine.digest._post_notice") as post:
        assert digest.run_once(store) is False
        post.assert_not_called()


def test_something_pending_posts_once(store):
    inc = store.create_incident(state_key="Deployment:production/api:crash",
                                fingerprint="f1", issue_type="crash",
                                severity="warning", owner_ref="", namespace="production")
    oid = store.record_occurrence(inc.id, context_hash="h")
    store.mark_occurrence_pending(oid)
    with patch("src.engine.digest._post_notice", return_value=True) as post:
        assert digest.run_once(store) is True
        assert post.call_count == 1
    # Drained: a second run has nothing left to say.
    with patch("src.engine.digest._post_notice") as post:
        assert digest.run_once(store) is False
        post.assert_not_called()


def test_failed_delivery_leaves_rows_pending(store):
    """A digest nobody received must not be marked as sent."""
    inc = store.create_incident(state_key="Deployment:production/api:crash",
                                fingerprint="f1", issue_type="crash",
                                severity="warning", owner_ref="", namespace="production")
    oid = store.record_occurrence(inc.id, context_hash="h")
    store.mark_occurrence_pending(oid)
    with patch("src.engine.digest._post_notice", return_value=False):
        assert digest.run_once(store) is False
    assert len(store.get_pending_batch_occurrences()) == 1


def test_blocks_group_by_namespace_and_count_repeats():
    pending = [
        {"id": 1, "state_key": "Deployment:production/api:crash",
         "namespace": "production", "original_severity": "warning"},
        {"id": 2, "state_key": "Deployment:production/api:crash",
         "namespace": "production", "original_severity": "warning"},
        {"id": 3, "state_key": "Deployment:staging/web:oom",
         "namespace": "staging", "original_severity": "critical"},
    ]
    text, blocks = digest.build_blocks(pending)
    body = "\n".join(b.get("text", {}).get("text", "") for b in blocks
                     if b["type"] == "section")
    assert "*production*" in body and "*staging*" in body
    assert "`api` crash ×2" in body
    assert "`web` oom" in body and "×" not in body.split("`web`")[1].split("\n")[0]
    assert "3 alerts withheld" in text


def test_blocks_survive_a_synthetic_state_key():
    """`Collective:production` has no alias segment and must not be mangled."""
    _, blocks = digest.build_blocks([
        {"id": 1, "state_key": "Collective:production",
         "namespace": "production", "original_severity": "warning"},
    ])
    body = "\n".join(b.get("text", {}).get("text", "") for b in blocks
                     if b["type"] == "section")
    assert "Collective:production" in body


def test_read_failure_is_survivable(store):
    broken = MagicMock()
    broken.get_pending_batch_occurrences.side_effect = RuntimeError("locked")
    assert digest.run_once(broken) is False


# --- announce once ----------------------------------------------------------

def test_resolved_by_defaults_to_empty_and_reads_as_operator(store):
    """Legacy and unmigrated rows must keep today's behaviour: a reopen
    announces itself."""
    store.create_incident(state_key="Deployment:production/api:crash",
                          fingerprint="f1", issue_type="crash",
                          severity="warning", owner_ref="", namespace="production")
    assert store.get_incident("Deployment:production/api:crash").resolved_by == ""


def test_resolved_by_round_trips(store):
    inc = store.create_incident(state_key="Deployment:production/api:crash",
                                fingerprint="f1", issue_type="crash",
                                severity="warning", owner_ref="", namespace="production")
    store.set_resolved_by(inc.id, "auto")
    assert store.get_incident("Deployment:production/api:crash").resolved_by == "auto"


def test_marking_addresses_the_exact_occurrence_not_the_newest(store):
    """A second occurrence landing between the write and the mark must not
    steal the flag. Scanners run in an executor pool and the event handler
    writes too, so this interleaving is reachable."""
    inc = store.create_incident(state_key="Deployment:production/api:crash",
                                fingerprint="f1", issue_type="crash",
                                severity="warning", owner_ref="", namespace="production")
    first = store.record_occurrence(inc.id, context_hash="h1")
    store.record_occurrence(inc.id, context_hash="h2")  # concurrent writer
    store.mark_occurrence_pending(first)
    pending = store.get_pending_batch_occurrences()
    assert len(pending) == 1
    assert pending[0]["context_hash"] == "h1"


def test_marking_a_missing_id_is_a_no_op(store):
    store.mark_occurrence_pending(None)
    assert store.get_pending_batch_occurrences() == []

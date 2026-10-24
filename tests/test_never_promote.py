"""A scanner may declare that its severity is final.

Two rules in the pipeline raise a warning to critical, and both are right for
the signals they were written for:

  net-new    a fingerprint nobody has seen before is worth waking someone for,
             because an unknown failure mode has no known blast radius
  persistent an incident that will not go away has outlasted the assumption
             that someone is already on it

Both assume a warning left alone might be an outage nobody noticed. For some
signals that assumption is simply false, and the HPA scanner is the case that
exposed it. On the day it shipped, its first wave arrived in Slack as:

    CRITICAL on golf/production - HPA at ceiling: backend (6/6)
    CRITICAL on bravo/production    - HPA at ceiling: frontend-bravo (6/6)
    CRITICAL on hotel/production    - HPA at ceiling: frontend-charlie (6/6)

all tagged @ai, all marked new, for three shops that were serving normally.
The scanner had set severity="warning" and documented that it must never be
critical; the pipeline overrode it on novelty alone — which every fingerprint
has on the day a scanner is introduced.

An autoscaler at its ceiling cannot become an outage by being novel or by
persisting. It means the workload is serving on fewer pods than it asked for.
`never_promote` lets a scanner say so.
"""
from unittest.mock import patch

import pytest

from src import config
from src.engine import pipeline
from src.engine.escalation import EscalationResult
from src.engine.store.sqlite import SqliteStore
from src.scanners._base import ScanResult


@pytest.fixture(autouse=True)
def _watch_everything(monkeypatch):
    monkeypatch.setattr(config, "WATCH_ALL_NAMESPACES", True)
    monkeypatch.setattr(config, "EXCLUDE_NAMESPACES", set())
    monkeypatch.setattr(config, "ALERT_EXCLUDE_WORKLOADS", ())


def _hpa_result(never_promote: bool, state_key="HPA:production/frontend-x:saturated"):
    return ScanResult(
        state_key=state_key,
        title="HPA at ceiling: frontend-x (6/6)",
        severity="warning",
        resource="HorizontalPodAutoscaler/frontend-x",
        namespace="production",
        issue_type="hpa",
        context_override="## Autoscaler at its ceiling\n",
        metadata={"max_replicas": 6},
        never_promote=never_promote,
        skip_llm=True,
    )


def _run(results, store):
    with patch("src.engine.pipeline.post_alert", return_value="1700000000.1"), \
         patch("src.engine.central_push.push_incident"), \
         patch("src.collectors.uptrace._resolve_token", return_value=""):
        pipeline.process_scan_results(results, store)


def _severity(store, state_key):
    return store.get_incident(state_key).severity


# --- net-new -----------------------------------------------------------------

def test_net_new_warning_is_promoted_without_the_flag(tmp_path):
    """The control. Without this the next test could pass on a broken guard."""
    store = SqliteStore(str(tmp_path / "a.db"))
    _run([_hpa_result(never_promote=False)], store)
    assert _severity(store, "HPA:production/frontend-x:saturated") == "critical"


def test_net_new_warning_stays_warning_with_the_flag(tmp_path):
    store = SqliteStore(str(tmp_path / "b.db"))
    _run([_hpa_result(never_promote=True)], store)
    assert _severity(store, "HPA:production/frontend-x:saturated") == "warning"


def test_the_new_marker_is_not_added_either(tmp_path):
    """The title carries a marker alongside the promotion. Both come from the
    same branch, so neither should fire."""
    store = SqliteStore(str(tmp_path / "c.db"))
    with patch("src.engine.pipeline.post_alert", return_value="1.1") as post, \
         patch("src.engine.central_push.push_incident"), \
         patch("src.collectors.uptrace._resolve_token", return_value=""):
        pipeline.process_scan_results([_hpa_result(never_promote=True)], store)
    posted = " ".join(str(a) for c in post.call_args_list for a in c.args)
    assert "\U0001f195" not in posted, "new-marker added to a result that opted out"


# --- persistent --------------------------------------------------------------

def _persistent(monkeypatch):
    """Force the persistent branch, patching where the name is actually bound.

    pipeline does `from src.engine.escalation import check_escalation`, so the
    name lives in pipeline's namespace. Patching src.engine.escalation.
    check_escalation leaves that binding untouched and the mock never applies —
    the test then silently exercises the net-new path instead and looks like it
    passes. Patch the pipeline attribute.

    The stand-in is a real EscalationResult rather than a hand-rolled stub, so
    it carries every field the alert path reads: level, should_alert, and
    prefix, which is used well after the promotion at `title = f"{esc.prefix}
    {r.title}"`.
    """
    monkeypatch.setattr(
        pipeline, "check_escalation",
        lambda incident, **kw: EscalationResult(
            level="persistent", should_alert=True, prefix="PERSISTENT: "),
    )


def test_persistent_warning_is_promoted_without_the_flag(tmp_path, monkeypatch):
    """The control for the test below, and it has to isolate the branch.

    A single result would be promoted by net-new on its first sighting, so a
    second run could not tell which rule acted. The first run therefore carries
    the flag: the incident is created as a warning and its fingerprint becomes
    known. The second run drops the flag, so net-new cannot fire — only the
    persistent rule can, and it does.

    Without this control, a mis-targeted patch would let the test below pass
    for the wrong reason. That is exactly what happened: the first version
    patched src.engine.escalation.check_escalation while pipeline binds the
    name directly, so the mock never applied and the "persistent" test was a
    second copy of the net-new one.
    """
    _persistent(monkeypatch)
    store = SqliteStore(str(tmp_path / "d0.db"))
    key = "HPA:production/frontend-y:saturated"
    _run([_hpa_result(never_promote=True, state_key=key)], store)
    assert _severity(store, key) == "warning", "net-new should not have fired"
    _run([_hpa_result(never_promote=False, state_key=key)], store)
    assert _severity(store, key) == "critical"


def test_persistent_warning_stays_warning_with_the_flag(tmp_path, monkeypatch):
    """An autoscaler capped for days is textbook 'persistent'. It is still not
    an outage."""
    _persistent(monkeypatch)
    store = SqliteStore(str(tmp_path / "d.db"))
    key = "HPA:production/frontend-x:saturated"
    r = _hpa_result(never_promote=True, state_key=key)
    _run([r], store)
    _run([r], store)
    assert _severity(store, key) == "warning"


# --- the flag must not leak --------------------------------------------------

def test_other_scanners_are_unaffected(tmp_path):
    """Everything that does not set the flag keeps today's behaviour, which is
    the property that matters when twenty clusters take the change."""
    store = SqliteStore(str(tmp_path / "e.db"))
    crash = ScanResult(
        state_key="Deployment:production/svc:crash",
        title="Pod Issue: CrashLoopBackOff",
        severity="warning",
        resource="Pod/svc-abc",
        namespace="production",
        issue_type="crash",
        pod_name="svc-abc",
        context_override={"event": {"pod": "svc-abc"}},
        skip_llm=True,
    )
    assert crash.never_promote is False, "the default must be today's behaviour"
    _run([crash], store)
    assert _severity(store, "Deployment:production/svc:crash") == "critical"


def test_a_critical_result_is_untouched_by_the_flag(tmp_path):
    """never_promote suppresses promotion, not severity. A scanner that says
    critical still means critical."""
    store = SqliteStore(str(tmp_path / "f.db"))
    r = _hpa_result(never_promote=True)
    r.severity = "critical"
    _run([r], store)
    assert _severity(store, "HPA:production/frontend-x:saturated") == "critical"


# --- the model's severity -----------------------------------------------------
# A Prometheus alert arrives with never_promote (handlers/alertmanager.py): its
# rule already decided the severity, and in production the LLM analyses it. The
# analysis may carry a severity of its own; the gate must not adopt it, and the
# forced-critical classes must not apply either.

def _analysis(parsed, parse_error=False):
    from src.engine.llm import AnalysisResult
    return AnalysisResult(raw_text="", parsed=parsed, parse_error=parse_error,
                          model="test", tokens_in=None, tokens_out=None, cost_usd=None)


def _alert(severity="warning", pod="postgres-0"):
    """A real Alertmanager result - the same conversion the webhook runs."""
    from src.handlers.alertmanager import alert_to_result
    r = alert_to_result({
        "status": "firing",
        "fingerprint": "a1b2c3",
        "labels": {"alertname": "KubePodNotReady", "namespace": "production",
                   "severity": severity, "pod": pod},
        "annotations": {"summary": "pod not ready"},
    })
    assert r is not None and r.never_promote
    return r


def test_the_model_cannot_raise_a_final_severity():
    _post, _reason, severity = pipeline._should_post_slack(
        _analysis({"severity": "critical"}), _alert(pod="web-0"), False)
    assert severity == "warning"


def test_the_model_cannot_lower_a_final_severity():
    _post, _reason, severity = pipeline._should_post_slack(
        _analysis({"severity": "warning"}), _alert(severity="critical", pod="web-0"), False)
    assert severity == "critical"


def test_an_infra_pod_does_not_raise_a_final_severity():
    """postgres is an infra-critical service: a scanner result for its pod is
    forced to critical, a Prometheus warning about it is not."""
    _post, _reason, severity = pipeline._should_post_slack(None, _alert(pod="postgres-0"), False)
    assert severity == "warning"


def _crash(severity="critical"):
    return ScanResult(
        state_key="Deployment:production/svc:crash",
        title="Pod Issue: CrashLoopBackOff",
        severity=severity,
        resource="Pod/svc-abc",
        namespace="production",
        issue_type="crash",
        pod_name="svc-abc",
    )


def test_without_the_flag_the_model_still_decides():
    """The control: without it the tests above could pass on a gate that never
    read the analysis at all."""
    _post, _reason, severity = pipeline._should_post_slack(
        _analysis({"severity": "warning"}), _crash("critical"), False)
    assert severity == "warning"


def test_a_reply_without_severity_keeps_the_scanners():
    import json
    from src.engine.llm import parse_analysis
    parsed, error = parse_analysis(json.dumps({"root_cause": "x", "confidence": 0.9}))
    assert not error
    _post, _reason, severity = pipeline._should_post_slack(
        _analysis(parsed), _crash("critical"), False)
    assert severity == "critical"


def test_a_reply_that_failed_to_parse_keeps_the_scanners():
    from src.engine.llm import parse_analysis
    parsed, error = parse_analysis("not json")
    assert error
    _post, _reason, severity = pipeline._should_post_slack(
        _analysis(parsed, parse_error=True), _crash("critical"), False)
    assert severity == "critical"


def test_a_batch_of_alerts_is_not_final(tmp_path, monkeypatch):
    """Five alerts in one namespace become one collective incident, copied from
    the first. The batch is not that alert: it must not inherit its final
    severity, or the net-new rule could not raise it like any other batch."""
    from src.handlers.alertmanager import alert_to_result
    monkeypatch.setattr(config, "MASS_EVENT_THRESHOLD", 5)
    store = SqliteStore(str(tmp_path / "batch.db"))
    alerts = [alert_to_result({
        "status": "firing", "fingerprint": f"f{i}",
        "labels": {"alertname": f"Alert{i}", "namespace": "production", "severity": "warning"},
        "annotations": {},
    }) for i in range(5)]
    assert all(a.never_promote for a in alerts)
    with patch("src.engine.pipeline.llm_configured", return_value=False):
        _run(alerts, store)
    assert _severity(store, "Collective:production") == "critical"

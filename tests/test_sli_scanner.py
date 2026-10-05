"""Tests for Sprint 12 — SLI scanner + dependency chain correlation."""
import time
from unittest.mock import patch

import pytest
import yaml

from src import config
from src.engine.store.sqlite import SqliteStore
from src.scanners import sli as sli_mod


def _write_config(tmp_path, slis: list[dict]) -> str:
    cfg = tmp_path / "sli.yaml"
    cfg.write_text(yaml.safe_dump({"slis": slis}))
    return str(cfg)


@pytest.fixture(autouse=True)
def _reset_config(monkeypatch):
    monkeypatch.setattr(config, "SCANNER_SLI_ENABLED", True)
    monkeypatch.setattr(config, "SCANNER_SLI_INTERVAL_SECONDS", 120)
    monkeypatch.setattr(config, "SLI_DEPENDENCY_MAX_DEPTH", 5)


def _basic_sli(**overrides) -> dict:
    base = {
        "name": "svc_latency",
        "query": "histogram_quantile(0.99, sum(rate(foo_bucket[5m])) by (le))",
        "threshold": 0.5,
        "comparison": ">",
        "duration_seconds": 300,
        "severity": "warning",
    }
    base.update(overrides)
    return base


# ── Config parsing ────────────────────────────────────────────────────

def test_config_valid_yaml_parses(tmp_path, monkeypatch):
    path = _write_config(tmp_path, [_basic_sli()])
    monkeypatch.setattr(config, "SLI_CONFIG_PATH", path)
    scanner = sli_mod.SliScanner()
    loaded = scanner._load_config()
    assert len(loaded) == 1
    assert loaded[0].name == "svc_latency"
    assert loaded[0].threshold == 0.5


def test_config_missing_required_field_rejected(tmp_path, monkeypatch):
    bad = _basic_sli()
    del bad["threshold"]
    path = _write_config(tmp_path, [bad])
    monkeypatch.setattr(config, "SLI_CONFIG_PATH", path)
    scanner = sli_mod.SliScanner()
    # Current behavior: bad config keeps previous defs (none) and logs error;
    # never raises out of the scan tick.
    loaded = scanner._load_config()
    assert loaded == []


def test_config_invalid_comparison_rejected(tmp_path, monkeypatch):
    bad = _basic_sli(comparison="~=")
    path = _write_config(tmp_path, [bad])
    monkeypatch.setattr(config, "SLI_CONFIG_PATH", path)
    scanner = sli_mod.SliScanner()
    loaded = scanner._load_config()
    assert loaded == []


def test_config_duplicate_names_rejected(tmp_path, monkeypatch):
    path = _write_config(tmp_path, [_basic_sli(), _basic_sli()])
    monkeypatch.setattr(config, "SLI_CONFIG_PATH", path)
    scanner = sli_mod.SliScanner()
    assert scanner._load_config() == []


# ── Breach detection + duration gating ────────────────────────────────

def test_first_breach_records_but_doesnt_emit(tmp_path, monkeypatch):
    path = _write_config(tmp_path, [_basic_sli(duration_seconds=300)])
    monkeypatch.setattr(config, "SLI_CONFIG_PATH", path)
    store = SqliteStore(":memory:")
    scanner = sli_mod.SliScanner()

    with patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.scanners.sli.prom_scalar", return_value=0.8):
        results = scanner.scan()

    assert results == []  # Duration hasn't elapsed yet
    breach = store.get_sli_breach("svc_latency", "")
    assert breach is not None
    assert breach["alerted"] == 0


def test_breach_emits_after_duration_gating(tmp_path, monkeypatch):
    path = _write_config(tmp_path, [_basic_sli(duration_seconds=300)])
    monkeypatch.setattr(config, "SLI_CONFIG_PATH", path)
    store = SqliteStore(":memory:")
    scanner = sli_mod.SliScanner()

    # Seed a breach row that's already old enough to meet the duration.
    old_ts = time.time() - 301
    conn = store._get_conn()
    conn.execute(
        """INSERT INTO sli_breach_state
           (sli_name, labels_hash, first_breach_at, last_seen_at,
            alerted, current_value, created_at)
           VALUES ('svc_latency', '', ?, ?, 0, 0.8, ?)""",
        (old_ts, old_ts, old_ts),
    )
    conn.commit()

    with patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.scanners.sli.prom_scalar", return_value=0.8):
        results = scanner.scan()

    assert len(results) == 1
    r = results[0]
    assert r.issue_type == "sli_breach"
    assert r.severity == "warning"
    # state_key follows pipeline convention: SLI:{name}:{ns}/{resource}
    # with "-" placeholder for cluster-scoped / no-label SLIs. This
    # makes rsplit(":", 1)[0] yield "SLI:svc_latency" as owner_key so
    # owner_cooldown scopes per-SLI instead of bleeding across all SLIs.
    assert r.state_key == "SLI:svc_latency:-/-"
    assert r.context_override["sli"]["current_value"] == 0.8
    assert r.context_override["root_cause"] == "svc_latency"  # leaf
    # Second scan must NOT re-emit — alerted=1 now.
    with patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.scanners.sli.prom_scalar", return_value=0.8):
        results2 = scanner.scan()
    assert results2 == []


def test_clear_on_recovery(tmp_path, monkeypatch):
    path = _write_config(tmp_path, [_basic_sli()])
    monkeypatch.setattr(config, "SLI_CONFIG_PATH", path)
    store = SqliteStore(":memory:")
    scanner = sli_mod.SliScanner()

    # Seed an existing breach row.
    now = time.time()
    conn = store._get_conn()
    conn.execute(
        """INSERT INTO sli_breach_state
           (sli_name, labels_hash, first_breach_at, last_seen_at,
            alerted, current_value, created_at)
           VALUES ('svc_latency', '', ?, ?, 1, 0.8, ?)""",
        (now - 400, now - 60, now - 400),
    )
    conn.commit()

    # Metric now under threshold — scanner emits auto_resolve (so
    # pipeline flips the incident to resolved) AND clears the row.
    with patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.scanners.sli.prom_scalar", return_value=0.2):
        results = scanner.scan()

    assert len(results) == 1
    r = results[0]
    assert r.auto_resolve is True
    assert r.severity == "info"
    assert r.state_key == "SLI:svc_latency:-/-"
    assert store.get_sli_breach("svc_latency", "") is None


# ── Severity per-SLI ──────────────────────────────────────────────────

def test_severity_critical_propagates_to_scanresult(tmp_path, monkeypatch):
    path = _write_config(tmp_path, [_basic_sli(severity="critical")])
    monkeypatch.setattr(config, "SLI_CONFIG_PATH", path)
    store = SqliteStore(":memory:")
    scanner = sli_mod.SliScanner()

    old_ts = time.time() - 301
    conn = store._get_conn()
    conn.execute(
        """INSERT INTO sli_breach_state
           (sli_name, labels_hash, first_breach_at, last_seen_at,
            alerted, current_value, created_at)
           VALUES ('svc_latency', '', ?, ?, 0, 0.8, ?)""",
        (old_ts, old_ts, old_ts),
    )
    conn.commit()

    with patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.scanners.sli.prom_scalar", return_value=0.8):
        results = scanner.scan()

    assert results[0].severity == "critical"


# ── Dependency chain walk ─────────────────────────────────────────────

def _seed_breach(store: SqliteStore, name: str, value: float):
    old_ts = time.time() - 301
    conn = store._get_conn()
    conn.execute(
        """INSERT INTO sli_breach_state
           (sli_name, labels_hash, first_breach_at, last_seen_at,
            alerted, current_value, created_at)
           VALUES (?, '', ?, ?, 0, ?, ?)""",
        (name, old_ts, old_ts, value, old_ts),
    )
    conn.commit()


def test_chain_walk_three_levels_all_breaching(tmp_path, monkeypatch):
    slis = [
        _basic_sli(name="frontend", threshold=0.5, upstream_slis=["api"]),
        _basic_sli(name="api", threshold=0.3, upstream_slis=["postgres"]),
        _basic_sli(name="postgres", threshold=0.85, upstream_slis=[]),
    ]
    path = _write_config(tmp_path, slis)
    monkeypatch.setattr(config, "SLI_CONFIG_PATH", path)
    store = SqliteStore(":memory:")
    scanner = sli_mod.SliScanner()
    _seed_breach(store, "frontend", 0.8)

    def fake_prom(query: str) -> float:
        # Return the breaching value per SLI based on which is queried.
        if "foo_bucket" not in query:
            return 999.0
        return 0.9  # All three share the same stub query text — all breach.

    with patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.scanners.sli.prom_scalar", side_effect=fake_prom):
        results = scanner.scan()

    assert len(results) == 1
    r = results[0]
    chain = r.context_override["chain"]
    assert len(chain) == 3
    assert [c["name"] for c in chain] == ["frontend", "api", "postgres"]
    assert r.context_override["root_cause"] == "postgres"


def test_chain_stops_at_non_breaching_upstream(tmp_path, monkeypatch):
    # Use distinct query strings so the mock can route per-SLI.
    slis = [
        _basic_sli(name="frontend", query="q_frontend",
                   threshold=0.5, upstream_slis=["api"]),
        _basic_sli(name="api", query="q_api",
                   threshold=0.3, upstream_slis=["postgres"]),
        _basic_sli(name="postgres", query="q_postgres",
                   threshold=0.85, upstream_slis=[]),
    ]
    path = _write_config(tmp_path, slis)
    monkeypatch.setattr(config, "SLI_CONFIG_PATH", path)
    store = SqliteStore(":memory:")
    scanner = sli_mod.SliScanner()
    _seed_breach(store, "frontend", 0.8)

    def fake_prom(query: str) -> float:
        # frontend breaching (>0.5), api NOT (<=0.3), postgres won't be reached
        return {
            "q_frontend": 0.8,
            "q_api": 0.1,
            "q_postgres": 0.0,
        }[query]

    with patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.scanners.sli.prom_scalar", side_effect=fake_prom):
        results = scanner.scan()

    assert len(results) == 1
    chain = results[0].context_override["chain"]
    assert [c["name"] for c in chain] == ["frontend"]
    assert results[0].context_override["root_cause"] == "frontend"


def test_chain_cycle_safety(tmp_path, monkeypatch):
    """A ↔ B circular config must not infinite-loop."""
    slis = [
        _basic_sli(name="a", upstream_slis=["b"]),
        _basic_sli(name="b", upstream_slis=["a"]),
    ]
    path = _write_config(tmp_path, slis)
    monkeypatch.setattr(config, "SLI_CONFIG_PATH", path)
    store = SqliteStore(":memory:")
    scanner = sli_mod.SliScanner()
    _seed_breach(store, "a", 0.8)

    with patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.scanners.sli.prom_scalar", return_value=0.8):
        results = scanner.scan()

    # Scanner completes without hanging; chain terminates at cycle.
    assert len(results) == 1
    chain = results[0].context_override["chain"]
    # a → b (breaching) → stops at cycle (a already visited)
    assert [c["name"] for c in chain] == ["a", "b"]


def test_chain_max_depth_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SLI_DEPENDENCY_MAX_DEPTH", 2)
    slis = [
        _basic_sli(name="s1", upstream_slis=["s2"]),
        _basic_sli(name="s2", upstream_slis=["s3"]),
        _basic_sli(name="s3", upstream_slis=["s4"]),
        _basic_sli(name="s4", upstream_slis=[]),
    ]
    path = _write_config(tmp_path, slis)
    monkeypatch.setattr(config, "SLI_CONFIG_PATH", path)
    store = SqliteStore(":memory:")
    scanner = sli_mod.SliScanner()
    _seed_breach(store, "s1", 0.8)

    with patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.scanners.sli.prom_scalar", return_value=0.8):
        results = scanner.scan()

    chain = results[0].context_override["chain"]
    assert len(chain) <= 2  # Capped


# ── Prometheus unreachable ────────────────────────────────────────────

def test_prometheus_none_does_not_clear_active_breach(tmp_path, monkeypatch):
    """Prometheus returning None (unreachable / no data) must NOT be
    confused with 'metric is healthy'. If there's an active breach
    row we must keep it intact — otherwise an outage in Prometheus
    itself would silently destroy breach-duration tracking for every
    active incident, making breaches re-fire as 'new' when Prometheus
    recovers."""
    path = _write_config(tmp_path, [_basic_sli()])
    monkeypatch.setattr(config, "SLI_CONFIG_PATH", path)
    store = SqliteStore(":memory:")
    scanner = sli_mod.SliScanner()
    _seed_breach(store, "svc_latency", 0.8)   # Active breach in progress.

    with patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.scanners.sli.prom_scalar", return_value=None):
        results = scanner.scan()

    assert results == []
    # Breach row MUST still be there — we didn't know enough to clear.
    assert store.get_sli_breach("svc_latency", "") is not None


def test_prometheus_none_skips_fresh_sli_without_recording(tmp_path, monkeypatch):
    """If there's no existing breach and Prometheus returns None,
    scanner should skip quietly without recording a phantom breach."""
    path = _write_config(tmp_path, [_basic_sli()])
    monkeypatch.setattr(config, "SLI_CONFIG_PATH", path)
    store = SqliteStore(":memory:")
    scanner = sli_mod.SliScanner()

    with patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.scanners.sli.prom_scalar", return_value=None):
        results = scanner.scan()

    assert results == []
    # No breach row written — None means "no data", not "breaching".
    assert store.get_sli_breach("svc_latency", "") is None


# ── Pipeline integration ──────────────────────────────────────────────

def test_pipeline_creates_incident_from_sli_breach(tmp_path, monkeypatch):
    """Emitted ScanResult flows through process_scan_results and creates
    an incidents row with fingerprint — proves end-to-end integration."""
    from src.engine import pipeline

    path = _write_config(tmp_path, [_basic_sli(namespaces=["production"])])
    monkeypatch.setattr(config, "SLI_CONFIG_PATH", path)
    store = SqliteStore(":memory:")
    scanner = sli_mod.SliScanner()
    _seed_breach(store, "svc_latency", 0.8)

    with patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.scanners.sli.prom_scalar", return_value=0.8), \
         patch("src.engine.pipeline.post_alert", return_value=""), \
         patch("src.engine.central_push.push_incident"), \
         patch("src.collectors.uptrace._resolve_token", return_value=""):
        results = scanner.scan()
        pipeline.process_scan_results(results, store)

    # state_key follows SLI:{name}:{ns}/{resource} convention.
    inc = store.get_incident("SLI:svc_latency:production/-")
    assert inc is not None
    assert inc.issue_type == "sli_breach"
    assert inc.fingerprint != ""
    assert inc.namespace == "production"


# --- the YAML severity is authoritative --------------------------------------
#
# This branch originally leaned on the pipeline's promoters as "the paging
# safety net". Four months later the HPA scanner shipped and showed what that
# means on day one: every fingerprint is new the first time it is seen, so its
# entire first wave arrived as CRITICAL with an @ai tag, for workloads that were
# serving normally.
#
# The starter bundle defines seven SLOs, all severity: warning. Without the
# guard the operator's choice would be overridden exactly once per SLO, on the
# first and most confusing occasion.

def _seed_breach(store, name="svc_latency", value=0.8, age=301):
    old = time.time() - age
    conn = store._get_conn()
    conn.execute(
        """INSERT INTO sli_breach_state
           (sli_name, labels_hash, first_breach_at, last_seen_at,
            alerted, current_value, created_at)
           VALUES (?, '', ?, ?, 0, ?, ?)""",
        (name, old, old, value, old),
    )
    conn.commit()


def test_breach_opts_out_of_promotion(tmp_path, monkeypatch):
    path = _write_config(tmp_path, [_basic_sli(duration_seconds=300)])
    monkeypatch.setattr(config, "SLI_CONFIG_PATH", path)
    store = SqliteStore(":memory:")
    _seed_breach(store)

    with patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.scanners.sli.prom_scalar", return_value=0.8):
        results = sli_mod.SliScanner().scan()

    assert results[0].never_promote is True


def test_a_warning_sli_survives_the_pipeline_as_a_warning(tmp_path, monkeypatch):
    """The end-to-end version: severity: warning in YAML must still be a
    warning after the pipeline has had it, on a fingerprint it has never seen.
    """
    from src.engine import pipeline

    path = _write_config(tmp_path, [_basic_sli(duration_seconds=300)])
    monkeypatch.setattr(config, "SLI_CONFIG_PATH", path)
    monkeypatch.setattr(config, "WATCH_ALL_NAMESPACES", True)
    monkeypatch.setattr(config, "EXCLUDE_NAMESPACES", set())
    monkeypatch.setattr(config, "ALERT_EXCLUDE_WORKLOADS", ())
    store = SqliteStore(str(tmp_path / "p.db"))
    _seed_breach(store)

    with patch("src.handlers.startup.get_store", return_value=store), \
         patch("src.scanners.sli.prom_scalar", return_value=0.8):
        results = sli_mod.SliScanner().scan()
    assert results and results[0].severity == "warning"

    with patch("src.engine.pipeline.post_alert", return_value="1.1"), \
         patch("src.engine.central_push.push_incident"), \
         patch("src.collectors.uptrace._resolve_token", return_value=""):
        pipeline.process_scan_results(results, store)

    assert store.get_incident(results[0].state_key).severity == "warning"


def test_moving_a_threshold_opens_a_new_incident(tmp_path, monkeypatch):
    """A threshold is a decision. The breach after it is a different fact from
    the one before, so it gets its own fingerprint rather than reopening the
    old incident."""
    from src.engine.fingerprint import compute_fingerprint

    a = compute_fingerprint("SLI:svc_latency:-/-", "sli_breach",
                            {"sli_name": "svc_latency", "threshold": 0.5})
    b = compute_fingerprint("SLI:svc_latency:-/-", "sli_breach",
                            {"sli_name": "svc_latency", "threshold": 0.9})
    assert a != b

    same = compute_fingerprint("SLI:svc_latency:-/-", "sli_breach",
                               {"sli_name": "svc_latency", "threshold": 0.5})
    assert a == same, "the same SLO at the same threshold must stay one incident"


# --- the daily report --------------------------------------------------------
#
# "Did the cluster hold its SLOs for the last 24 hours" is a different question
# from "what did we alert about". Alerts are damped: a breach shorter than
# duration_seconds never fires, an alerted breach stays silent until recovery,
# and the breach row is deleted on recovery so its length is gone. Attainment is
# therefore recomputed from Prometheus over the window rather than read from the
# incident table.

def _series(values, step_s=300):
    now = int(time.time())
    return [{"metric": {}, "values": [[now - (len(values) - i) * step_s, str(v)]
                                      for i, v in enumerate(values)]}]


def test_daily_reports_full_attainment_when_never_breaching(tmp_path, monkeypatch):
    path = _write_config(tmp_path, [_basic_sli()])
    monkeypatch.setattr(config, "SLI_CONFIG_PATH", path)
    with patch("src.scanners.sli.prom_range_query", return_value=_series([0.1] * 12)):
        out = sli_mod.SliScanner().collect_daily_data()
    assert "All 1 SLOs met" in out
    assert "met, 100% of 24h" in out


def test_daily_counts_breached_minutes_not_alerts(tmp_path, monkeypatch):
    """Three 5-minute samples over threshold is 15 minutes, whether or not any
    of it was ever alerted."""
    path = _write_config(tmp_path, [_basic_sli(duration_seconds=3600)])
    monkeypatch.setattr(config, "SLI_CONFIG_PATH", path)
    values = [0.1] * 9 + [0.8] * 3          # 12 samples, 3 breaching
    with patch("src.scanners.sli.prom_range_query", return_value=_series(values)):
        out = sli_mod.SliScanner().collect_daily_data()
    assert "MISSED" in out
    assert "75.0% of 24h" in out
    assert "15m" in out
    assert "worst 0.8" in out


def test_daily_does_not_count_missing_data_as_compliance(tmp_path, monkeypatch):
    """An SLO nobody can measure is the one most likely to be quietly broken."""
    path = _write_config(tmp_path, [_basic_sli()])
    monkeypatch.setattr(config, "SLI_CONFIG_PATH", path)
    with patch("src.scanners.sli.prom_range_query", return_value=None):
        out = sli_mod.SliScanner().collect_daily_data()
    assert "Not measurable" in out
    assert "All 1 SLOs met" not in out


def test_daily_is_silent_without_config(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SLI_CONFIG_PATH", str(tmp_path / "nope.yaml"))
    assert sli_mod.SliScanner().collect_daily_data() is None

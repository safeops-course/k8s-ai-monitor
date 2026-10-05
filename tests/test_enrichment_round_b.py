"""Tests for Round B enrichment blocks: resource trend + HPA state."""
from types import SimpleNamespace
from unittest.mock import patch

from src.engine import enrichment


def _series(values):
    """Wrap a list of values as a Prometheus range-query result."""
    return [{"metric": {}, "values": [[i * 60, str(v)] for i, v in enumerate(values)]}]


def test_summarize_range_basic():
    series = _series([10, 50, 30, 20])
    assert enrichment._summarize_range(series) == (10.0, 50.0, 20.0)


def test_summarize_range_empty():
    assert enrichment._summarize_range(None) is None
    assert enrichment._summarize_range([]) is None
    assert enrichment._summarize_range([{"metric": {}, "values": []}]) is None


def test_summarize_range_skips_unparseable():
    series = [{"metric": {}, "values": [[0, "NaN"], [60, "10"], [120, "20"]]}]
    assert enrichment._summarize_range(series) == (10.0, 20.0, 20.0)


def test_container_mem_limit_sums_across_containers():
    pod = {"containers": [
        {"resources": {"mem_lim": "1Gi"}},
        {"resources": {"mem_lim": "512Mi"}},
    ]}
    assert enrichment._container_mem_limit_bytes(pod) == 1536 * 1024 * 1024


def test_container_mem_limit_returns_none_when_any_missing():
    pod = {"containers": [
        {"resources": {"mem_lim": "1Gi"}},
        {"resources": {}},
    ]}
    assert enrichment._container_mem_limit_bytes(pod) is None


def test_fmt_cpu_cores():
    assert enrichment._fmt_cpu_cores(0.12) == "120m"
    assert enrichment._fmt_cpu_cores(1.5) == "1.50 cores"


def test_resource_trend_renders_memory_and_cpu():
    pod = {
        "name": "foo-pod",
        "namespace": "prod",
        "containers": [{"resources": {"mem_lim": "1Gi"}}],
    }
    context = {"pod": pod}

    # Memory: 512Mi → peak 1Gi → 900Mi. CPU: 0.1 → peak 0.5 → 0.2.
    mem_bytes = [512 * 1024**2, 1024 * 1024**2, 900 * 1024**2]
    cpu = [0.1, 0.5, 0.2]

    def fake_query(query, **_):
        if "memory" in query:
            return _series(mem_bytes)
        if "cpu" in query:
            return _series(cpu)
        return None

    with patch("src.engine.enrichment.prom_range_query", side_effect=fake_query):
        out = enrichment._resource_trend(context)

    assert "Trend (30m)" in out
    assert "Memory" in out
    assert "CPU" in out
    assert "peak" in out
    assert "limit 1.0Gi" in out
    # Peak 1024Mi >= 90% of 1024Mi limit and rising (512→900) → climbing marker.
    assert "100% of limit and climbing" in out


def test_resource_trend_high_but_flat_is_plateau_not_oom():
    """High-but-flat memory (JVM -Xmx plateau) → tagged flat/plateau, no ⚠️."""
    pod = {
        "name": "redis-combined-0",
        "namespace": "develop",
        "containers": [{"resources": {"mem_lim": "2Gi"}}],
    }
    # 1.70Gi → peak 1.72Gi → 1.71Gi: ~86% of 2Gi, essentially flat.
    mem_bytes = [1740 * 1024**2, 1760 * 1024**2, 1750 * 1024**2]

    def fake_query(query, **_):
        return _series(mem_bytes) if "memory" in query else None

    with patch("src.engine.enrichment.prom_range_query", side_effect=fake_query):
        out = enrichment._resource_trend(context={"pod": pod})

    assert "% of limit (flat/plateau)" in out
    assert "⚠" not in out          # no OOM-risk marker for a flat plateau
    assert "climbing" not in out


def test_resource_trend_high_and_rising_flags_oom():
    """Memory climbing toward the limit → ⚠️ climbing marker (a real OOM trend)."""
    pod = {
        "name": "leaky",
        "namespace": "prod",
        "containers": [{"resources": {"mem_lim": "1Gi"}}],
    }
    # 512Mi → peak 970Mi → 970Mi: 94% of limit and clearly rising.
    mem_bytes = [512 * 1024**2, 970 * 1024**2, 970 * 1024**2]

    def fake_query(query, **_):
        return _series(mem_bytes) if "memory" in query else None

    with patch("src.engine.enrichment.prom_range_query", side_effect=fake_query):
        out = enrichment._resource_trend(context={"pod": pod})

    assert "⚠" in out
    assert "climbing" in out


def test_resource_trend_skips_without_pod_name():
    assert enrichment._resource_trend({}) == ""
    assert enrichment._resource_trend({"pod": {"name": "x"}}) == ""
    assert enrichment._resource_trend({"pod": {"namespace": "x"}}) == ""


def test_resource_trend_empty_when_prom_returns_nothing():
    context = {"pod": {"name": "p", "namespace": "n"}}
    with patch("src.engine.enrichment.prom_range_query", return_value=None):
        assert enrichment._resource_trend(context) == ""


# ── HPA state ────────────────────────────────────────────────────────────

def _hpa(name, kind, target_name, current, desired, *,
         min_r=None, max_r=None, conditions=None):
    ref = SimpleNamespace(kind=kind, name=target_name)
    spec = SimpleNamespace(scale_target_ref=ref, min_replicas=min_r, max_replicas=max_r)
    status = SimpleNamespace(
        current_replicas=current,
        desired_replicas=desired,
        conditions=conditions or [],
    )
    metadata = SimpleNamespace(name=name)
    return SimpleNamespace(metadata=metadata, spec=spec, status=status)


def _cond(type_, status, reason=""):
    return SimpleNamespace(type=type_, status=status, reason=reason)


def _reset_hpa_cache():
    enrichment._hpa_cache.clear()


def test_hpa_state_renders_match():
    _reset_hpa_cache()
    hpa = _hpa("store-hpa", "Deployment", "frontend",
               current=3, desired=5, min_r=2, max_r=10)
    context = {
        "pod": {"name": "p", "namespace": "prod"},
        "owner": {"kind": "Deployment", "name": "frontend"},
    }
    with patch("src.engine.enrichment._get_namespace_hpas", return_value=[hpa]):
        out = enrichment._hpa_state(context)
    assert "HPA:" in out
    assert "store-hpa" in out
    assert "3/5 replicas" in out
    assert "min 2" in out
    assert "max 10" in out


def test_hpa_state_shows_scaling_limited():
    _reset_hpa_cache()
    hpa = _hpa("h", "Deployment", "app", 3, 5, conditions=[
        _cond("ScalingLimited", "True", "DesiredWithinRange"),
    ])
    context = {
        "pod": {"name": "p", "namespace": "n"},
        "owner": {"kind": "Deployment", "name": "app"},
    }
    with patch("src.engine.enrichment._get_namespace_hpas", return_value=[hpa]):
        out = enrichment._hpa_state(context)
    assert "ScalingLimited=DesiredWithinRange" in out


def test_hpa_state_empty_when_no_match():
    _reset_hpa_cache()
    hpa = _hpa("other-hpa", "Deployment", "other", 1, 1)
    context = {
        "pod": {"name": "p", "namespace": "n"},
        "owner": {"kind": "Deployment", "name": "app"},
    }
    with patch("src.engine.enrichment._get_namespace_hpas", return_value=[hpa]):
        assert enrichment._hpa_state(context) == ""


def test_hpa_state_empty_when_no_owner():
    context = {"pod": {"name": "p", "namespace": "n"}}
    assert enrichment._hpa_state(context) == ""


def test_get_namespace_hpas_uses_cache():
    _reset_hpa_cache()
    call_count = {"n": 0}

    def fake_list_hpa():
        call_count["n"] += 1
        return SimpleNamespace(items=[])

    class FakeApi:
        def list_namespaced_horizontal_pod_autoscaler(self, ns):
            return fake_list_hpa()

    with patch("kubernetes.client.AutoscalingV2Api", return_value=FakeApi()):
        enrichment._get_namespace_hpas("prod")
        enrichment._get_namespace_hpas("prod")
    assert call_count["n"] == 1  # second call served from cache

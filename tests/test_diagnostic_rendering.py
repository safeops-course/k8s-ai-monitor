"""Tests for type-aware diagnostic rendering in format_context_summary."""
from src.engine.notifier import _format_diagnostic, format_context_summary


def test_hpa_compact_line():
    out = _format_diagnostic("hpa", {
        "name": "store-hpa",
        "target": "Deployment/frontend",
        "current": 9,
        "desired": 9,
        "max": 9,
        "min": 3,
        "at_max": True,
    })
    assert out is not None
    assert "store-hpa" in out
    assert "Deployment/frontend" in out
    assert "9/9 replicas" in out
    assert "min 3" in out
    assert "max 9" in out
    assert "AT MAX" in out


def test_pdb_blocking():
    out = _format_diagnostic("pdb", {
        "name": "store-pdb",
        "min_available": 2,
        "current_healthy": 2,
        "desired_healthy": 2,
        "disruptions_allowed": 0,
        "blocking": True,
    })
    assert out is not None
    assert "store-pdb" in out
    assert "minAvailable=2" in out
    assert "healthy=2/2" in out
    assert "blocking" in out


def test_scheduling_constraints_renders_tolerations_and_selector():
    out = _format_diagnostic("scheduling_constraints", {
        "node_selector": {"role": "worker"},
        "tolerations": [
            {"key": "production", "value": "true", "effect": "NoSchedule"},
            {"key": "node.kubernetes.io/not-ready", "value": None, "effect": "NoExecute"},
        ],
        "affinity": True,
    })
    assert out is not None
    assert "Scheduling constraints" in out
    assert "nodeSelector=role=worker" in out
    assert "production=true:NoSchedule" in out
    assert "node.kubernetes.io/not-ready:NoExecute" in out
    assert "affinity=yes" in out


def test_scheduling_constraints_tolerations_overflow():
    tols = [{"key": f"k{i}", "value": "v", "effect": "NoSchedule"} for i in range(6)]
    out = _format_diagnostic("scheduling_constraints", {"tolerations": tols})
    assert out is not None
    assert "+2 more" in out


def test_node_capacity_summary():
    out = _format_diagnostic("node_capacity", [
        {"name": "a", "ready": "True", "schedulable": True, "selector_match": True},
        {"name": "b", "ready": "True", "schedulable": True, "selector_match": False},
        {"name": "c", "ready": "True", "schedulable": False, "selector_match": True},
        {"name": "d", "ready": "False", "schedulable": True, "selector_match": False},
    ])
    assert out is not None
    assert "4 total" in out
    assert "2 ready+schedulable" in out
    assert "1 cordoned" in out
    assert "2 match selector" in out


def test_cordoned_nodes_with_overflow():
    out = _format_diagnostic("cordoned_nodes",
                              [f"node-{i}" for i in range(8)])
    assert out is not None
    assert "node-0" in out
    assert "+3 more" in out


def test_cluster_autoscaler_groups_reasons():
    out = _format_diagnostic("cluster_autoscaler", {
        "recent_events": [
            {"reason": "NotTriggerScaleUp", "message": "Pod didn't trigger scale-up"},
            {"reason": "NotTriggerScaleUp", "message": "same"},
            {"reason": "ScaleDown", "message": "down"},
        ],
        "provisioning_nodes": [{"name": "n1"}],
    })
    assert out is not None
    assert "Autoscaler" in out
    assert "NotTriggerScaleUp(x2)" in out
    assert "provisioning=1" in out


def test_resource_limits_renders_requests_and_limits():
    out = _format_diagnostic("resource_limits", [
        {"container": "app", "cpu_req": "100m", "cpu_lim": "500m",
         "mem_req": "128Mi", "mem_lim": "512Mi"},
    ])
    assert out is not None
    assert "`app`" in out
    assert "cpu 100m/500m" in out
    assert "mem 128Mi/512Mi" in out


def test_current_usage_renders_pods():
    out = _format_diagnostic("current_usage", [
        {"container": "app", "cpu": "50m", "mem": "128Mi"},
    ])
    assert out is not None
    assert "`app`" in out
    assert "cpu=50m" in out


def test_oom_details_with_signal():
    out = _format_diagnostic("oom_details", [
        {"container": "app", "exit_code": 137, "signal": 9},
    ])
    assert out is not None
    assert "OOMKilled" in out
    assert "`app`" in out
    assert "exit=137" in out
    assert "signal=9" in out


def test_node_memory_shape():
    out = _format_diagnostic("node_memory", {
        "node": "node-a", "capacity": "16Gi", "allocatable": "15Gi",
    })
    assert out == "*Node memory (node-a):* capacity=16Gi, allocatable=15Gi"


def test_node_pressure_renders_conditions():
    out = _format_diagnostic("node_pressure", {
        "node": "node-a",
        "pressures": [
            {"type": "MemoryPressure", "status": "True", "message": "insufficient memory"},
        ],
    })
    assert out is not None
    assert "node-a" in out
    assert "MemoryPressure=True" in out
    assert "insufficient memory" in out


def test_node_pressure_empty_returns_none():
    assert _format_diagnostic("node_pressure", {"node": "x", "pressures": []}) is None


def test_restart_history_with_exit_code():
    out = _format_diagnostic("restart_history", [
        {"container": "app", "restarts": 5, "exit_code": 139, "reason": "Error", "signal": 11},
    ])
    assert out is not None
    assert "`app`" in out
    assert "restarts=5" in out
    assert "last exit=139" in out
    assert "Error" in out
    assert "signal=11" in out


def test_probe_config_renders_configured_probes():
    out = _format_diagnostic("probe_config", [
        {"container": "app", "probe": "liveness", "type": "httpGet",
         "path": "/healthz:8080", "period": 10, "timeout": 3, "failures": 3},
        {"container": "app", "probe": "startup", "configured": False},
    ])
    assert out is not None
    assert "liveness" in out
    assert "/healthz:8080" in out
    assert "period=10s" in out
    assert "startup: not set" in out


def test_probe_config_empty_returns_none():
    assert _format_diagnostic("probe_config", [
        {"container": "app", "probe": "liveness"},
    ]) is None


def test_pull_secrets_missing():
    out = _format_diagnostic("pull_secrets", [
        {"name": "gcr-token", "exists": True},
        {"name": "hub-token", "exists": False},
    ])
    assert out is not None
    assert "gcr-token" in out
    assert "ok" in out
    assert "hub-token" in out
    assert "MISSING" in out


def test_pull_secrets_not_configured():
    assert _format_diagnostic("pull_secrets_configured", False).startswith(
        "*Pull secrets:*"
    )
    assert "none configured" in _format_diagnostic("pull_secrets_configured", False)


def test_pvcs_with_events():
    out = _format_diagnostic("pvcs", [
        {"name": "data", "phase": "Pending", "events": [
            {"type": "Warning", "reason": "ProvisioningFailed",
             "message": "failed to provision volume with StorageClass"},
        ]},
    ])
    assert out is not None
    assert "data" in out
    assert "Pending" in out
    assert "ProvisioningFailed" in out
    assert "StorageClass" in out


def test_pvcs_bound_shows_without_warning():
    out = _format_diagnostic("pvcs", [
        {"name": "data", "phase": "Bound"},
    ])
    assert out is not None
    assert "Bound" in out
    assert "\u26a0\ufe0f" not in out


def test_images_renders_pull_policy():
    out = _format_diagnostic("images", [
        {"container": "app", "image": "gcr.io/x/foo:v1", "pull_policy": "IfNotPresent"},
    ])
    assert out is not None
    assert "gcr.io/x/foo:v1" in out
    assert "IfNotPresent" in out


def test_unknown_key_falls_back_to_json():
    out = _format_diagnostic("something_weird", {"a": 1, "b": 2})
    assert out is not None
    assert "something_weird" in out
    assert '"a"' in out


def test_empty_values_return_none():
    assert _format_diagnostic("hpa", None) is None
    assert _format_diagnostic("hpa", {}) is None
    assert _format_diagnostic("cordoned_nodes", []) is None


def test_format_context_summary_scheduling_shape():
    """End-to-end: the user's FailedScheduling example should render cleanly."""
    context = {
        "diagnostics": {
            "scheduling_constraints": {
                "tolerations": [
                    {"key": "production", "value": "true", "effect": "NoSchedule"},
                ],
            },
            "hpa": {
                "name": "store-hpa",
                "target": "Deployment/store",
                "current": 9, "desired": 9, "max": 9, "min": 3,
                "at_max": True,
            },
        },
        "events": [
            {"reason": "NotTriggerScaleUp", "count": 33,
             "message": "Pod didn't trigger scale-up: 1 max node group size reached"},
            {"reason": "FailedScheduling",
             "message": "0/4 nodes are available: 1 node(s) had untolerated taint {ops: true}, 3 Insufficient cpu."},
        ],
    }
    out = format_context_summary(context)
    assert "store-hpa" in out
    assert "AT MAX" in out
    assert "production=true:NoSchedule" in out
    assert "NotTriggerScaleUp" in out
    assert "(x33)" in out
    # Event message must not be cut off at 120 chars anymore.
    assert "Insufficient cpu" in out
    # And we shouldn't see the raw JSON curly-brace dump.
    assert '"at_max": true' not in out

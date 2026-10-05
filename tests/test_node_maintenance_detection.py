"""_check_node_maintenance must not read autoscaler scale-down as maintenance.

A node the cluster autoscaler is removing is cordoned (SchedulingDisabled) and
goes NotReady while it is deleted — the same two facts a maintenance drain
shows. This fired "Maintenance Mode Activated" for a single scale-down
node, which silences LLM analysis and prefixes every alert [Maintenance]
cluster-wide. The discriminator is the taint the autoscaler sets
before draining.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from src import config
from src.handlers import startup


def _node(name, *, taints=(), unschedulable=False, ready=True):
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name),
        spec=SimpleNamespace(
            taints=[SimpleNamespace(key=k) for k in taints],
            unschedulable=unschedulable,
        ),
        status=SimpleNamespace(
            conditions=[SimpleNamespace(type="Ready",
                                        status="True" if ready else "False")],
        ),
    )


def _run(nodes):
    store = MagicMock()
    store.get_maintenance_window.return_value = None
    api = MagicMock()
    api.list_node.return_value = SimpleNamespace(items=nodes)
    with patch("src.handlers.startup.k8s_client.CoreV1Api", return_value=api), \
         patch("src.handlers.startup.post_maintenance_notice"), \
         patch.object(config, "AUTO_MAINTENANCE_NODE_THRESHOLD", 1):
        startup._check_node_maintenance(store)
    return store


def test_scale_down_node_does_not_activate_maintenance():
    """Cordoned + NotReady + ToBeDeletedByClusterAutoscaler — routine, ignored."""
    store = _run([_node("scaledown",
                        taints=["ToBeDeletedByClusterAutoscaler"],
                        unschedulable=True, ready=False)])
    store.activate_auto_maintenance.assert_not_called()


def test_deletion_candidate_taint_also_ignored():
    store = _run([_node("candidate",
                        taints=["DeletionCandidateOfClusterAutoscaler"],
                        unschedulable=True, ready=False)])
    store.activate_auto_maintenance.assert_not_called()


def test_real_maintenance_taint_still_activates():
    """The explicit GKE termination taint is maintenance, scale-down or not."""
    store = _run([_node("draining",
                        taints=["cloud.google.com/impending-node-termination"])])
    store.activate_auto_maintenance.assert_called_once()


def test_manual_drain_without_autoscaler_taint_still_activates():
    """A cordoned + NotReady node with no autoscaler taint is a manual drain or
    a broken node — still worth suppressing on. The fix must not silence this."""
    store = _run([_node("manual", unschedulable=True, ready=False)])
    store.activate_auto_maintenance.assert_called_once()


def test_healthy_and_scaling_down_together_stay_quiet():
    """Ready nodes plus one scale-down node = zero affected, no maintenance."""
    store = _run([
        _node("healthy-1"),
        _node("healthy-2"),
        _node("scaledown", taints=["ToBeDeletedByClusterAutoscaler"],
              unschedulable=True, ready=False),
    ])
    store.activate_auto_maintenance.assert_not_called()

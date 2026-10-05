"""Tests for the node scanner."""
import time
import unittest
from unittest.mock import patch, MagicMock

from src.scanners.node import NodeScanner


def _make_node(
    name: str,
    *,
    unschedulable: bool = False,
    ready: str = "True",
    ready_reason: str = "KubeletReady",
    ready_message: str = "",
    memory_pressure: str = "False",
    disk_pressure: str = "False",
    pid_pressure: str = "False",
    labels: dict | None = None,
    taints: list | None = None,
) -> MagicMock:
    node = MagicMock()
    node.metadata.name = name
    node.metadata.labels = labels or {"kubernetes.io/hostname": name}
    node.spec.unschedulable = unschedulable
    node.spec.taints = taints or []

    def _cond(ctype: str, status: str, reason: str = "", message: str = "") -> MagicMock:
        c = MagicMock()
        c.type = ctype
        c.status = status
        c.reason = reason
        c.message = message
        return c

    node.status.conditions = [
        _cond("Ready", ready, ready_reason, ready_message),
        _cond("MemoryPressure", memory_pressure),
        _cond("DiskPressure", disk_pressure),
        _cond("PIDPressure", pid_pressure),
    ]
    node.status.node_info = MagicMock()
    node.status.node_info.kubelet_version = "v1.28.0"
    node.status.node_info.os_image = "Ubuntu 22.04"
    node.status.node_info.kernel_version = "5.15.0"
    node.status.node_info.container_runtime_version = "containerd://1.7.0"
    return node


@patch("src.scanners.node.k8s")
class TestNodeScanner(unittest.TestCase):
    def _scanner(self) -> NodeScanner:
        s = NodeScanner()
        s._first_seen.clear()
        return s

    def test_healthy_nodes_produce_auto_resolve(self, mock_k8s: MagicMock) -> None:
        mock_k8s.CoreV1Api.return_value.list_node.return_value.items = [
            _make_node("node-1"),
            _make_node("node-2"),
        ]
        scanner = self._scanner()
        results = scanner.scan()
        # All results should be auto_resolve
        assert all(r.auto_resolve for r in results)
        assert len(results) > 0

    def test_cordoned_node_within_grace_skipped(self, mock_k8s: MagicMock) -> None:
        mock_k8s.CoreV1Api.return_value.list_node.return_value.items = [
            _make_node("node-1", unschedulable=True),
        ]
        mock_k8s.V1NodeSpec = MagicMock
        scanner = self._scanner()
        results = scanner.scan()
        # Within grace period — no cordon alert
        issues = [r for r in results if not r.auto_resolve]
        assert len(issues) == 0

    @patch("src.scanners.node.config")
    def test_cordoned_node_after_grace(self, mock_config: MagicMock, mock_k8s: MagicMock) -> None:
        mock_config.SCANNER_NODE_ENABLED = True
        mock_config.NODE_SCAN_INTERVAL_SECONDS = 300
        mock_config.NODE_CORDON_GRACE_SECONDS = 0  # no grace
        mock_config.NODE_NOT_READY_GRACE_SECONDS = 120
        mock_k8s.CoreV1Api.return_value.list_node.return_value.items = [
            _make_node("node-1", unschedulable=True),
        ]
        mock_k8s.V1NodeSpec = MagicMock
        scanner = self._scanner()
        results = scanner.scan()
        issues = [r for r in results if not r.auto_resolve]
        assert len(issues) == 1
        assert issues[0].state_key == "Node:node-1:cordon"
        assert issues[0].severity == "warning"
        assert issues[0].skip_llm is True
        assert "SchedulingDisabled" in issues[0].title

    @patch("src.scanners.node.config")
    def test_notready_node_after_grace(self, mock_config: MagicMock, mock_k8s: MagicMock) -> None:
        mock_config.SCANNER_NODE_ENABLED = True
        mock_config.NODE_SCAN_INTERVAL_SECONDS = 300
        mock_config.NODE_CORDON_GRACE_SECONDS = 900
        mock_config.NODE_NOT_READY_GRACE_SECONDS = 0  # no grace
        mock_k8s.CoreV1Api.return_value.list_node.return_value.items = [
            _make_node("node-1", ready="False", ready_reason="KubeletNotReady", ready_message="container runtime down"),
        ]
        mock_k8s.V1NodeSpec = MagicMock
        scanner = self._scanner()
        results = scanner.scan()
        issues = [r for r in results if not r.auto_resolve]
        assert len(issues) == 1
        assert issues[0].state_key == "Node:node-1:notready"
        assert issues[0].severity == "critical"
        assert "NotReady" in issues[0].title

    @patch("src.scanners.node.config")
    def test_pressure_condition(self, mock_config: MagicMock, mock_k8s: MagicMock) -> None:
        mock_config.SCANNER_NODE_ENABLED = True
        mock_config.NODE_SCAN_INTERVAL_SECONDS = 300
        mock_config.NODE_CORDON_GRACE_SECONDS = 900
        mock_config.NODE_NOT_READY_GRACE_SECONDS = 0
        mock_k8s.CoreV1Api.return_value.list_node.return_value.items = [
            _make_node("node-1", disk_pressure="True"),
        ]
        mock_k8s.V1NodeSpec = MagicMock
        scanner = self._scanner()
        results = scanner.scan()
        issues = [r for r in results if not r.auto_resolve]
        assert len(issues) == 1
        assert "DiskPressure" in issues[0].title
        assert issues[0].severity == "warning"

    def test_auto_resolve_after_recovery(self, mock_k8s: MagicMock) -> None:
        mock_k8s.V1NodeSpec = MagicMock
        scanner = self._scanner()

        # First scan: cordoned (within grace, so no alert yet, but first_seen is set)
        mock_k8s.CoreV1Api.return_value.list_node.return_value.items = [
            _make_node("node-1", unschedulable=True),
        ]
        scanner.scan()

        # Second scan: node recovered
        mock_k8s.CoreV1Api.return_value.list_node.return_value.items = [
            _make_node("node-1"),
        ]
        results = scanner.scan()
        resolve_results = [r for r in results if r.auto_resolve and "cordon" in r.state_key]
        assert len(resolve_results) == 1

    def test_first_seen_cleanup(self, mock_k8s: MagicMock) -> None:
        mock_k8s.V1NodeSpec = MagicMock
        scanner = self._scanner()
        # Manually seed first_seen for a gone node
        scanner._first_seen["Node:old-node:cordon"] = time.monotonic() - 9999
        mock_k8s.CoreV1Api.return_value.list_node.return_value.items = [
            _make_node("node-1"),
        ]
        scanner.scan()
        assert "Node:old-node:cordon" not in scanner._first_seen

    def test_collect_daily_data(self, mock_k8s: MagicMock) -> None:
        mock_k8s.CoreV1Api.return_value.list_node.return_value.items = [
            _make_node("node-1"),
            _make_node("node-2", unschedulable=True),
        ]
        mock_k8s.V1NodeSpec = MagicMock
        scanner = self._scanner()
        data = scanner.collect_daily_data()
        assert data is not None
        assert "node-1" in data
        assert "node-2" in data
        assert "Cordoned" in data

    def test_context_includes_labels_and_conditions(self, mock_k8s: MagicMock) -> None:
        node = _make_node(
            "node-1",
            labels={"role": "worker", "zone": "us-east-1a"},
        )
        context = NodeScanner._build_context(node, "Test issue")
        assert "role: worker" in context
        assert "zone: us-east-1a" in context
        assert "Test issue" in context
        assert "Conditions" in context
        assert "Node Info" in context

    def test_api_failure_returns_empty(self, mock_k8s: MagicMock) -> None:
        mock_k8s.CoreV1Api.return_value.list_node.side_effect = Exception("API down")
        scanner = self._scanner()
        results = scanner.scan()
        assert results == []


if __name__ == "__main__":
    unittest.main()

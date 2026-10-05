"""Node scanner — detects cordoned, NotReady, and pressure-affected nodes."""
import logging
import time

from kubernetes import client as k8s

from src import config
from src.scanners._base import ScanResult

logger = logging.getLogger(__name__)


class NodeScanner:
    name = "node"
    startup_delay = 30

    def __init__(self) -> None:
        self._first_seen: dict[str, float] = {}

    @property
    def enabled(self) -> bool:
        return config.SCANNER_NODE_ENABLED

    @property
    def interval_seconds(self) -> int:
        return config.NODE_SCAN_INTERVAL_SECONDS

    def scan(self) -> list[ScanResult]:
        core = k8s.CoreV1Api()
        try:
            nodes = core.list_node()
        except Exception:
            logger.exception("Node scanner: failed to list nodes")
            return []

        now = time.monotonic()
        results: list[ScanResult] = []
        active_keys: set[str] = set()

        for node in nodes.items:
            name = node.metadata.name
            conditions = {c.type: c for c in (node.status.conditions or [])}
            spec = node.spec or k8s.V1NodeSpec()

            # --- Cordoned (SchedulingDisabled) ---
            if spec.unschedulable:
                key = f"Node:{name}:cordon"
                active_keys.add(key)
                if key not in self._first_seen:
                    self._first_seen[key] = now
                elapsed = now - self._first_seen[key]
                if elapsed < config.NODE_CORDON_GRACE_SECONDS:
                    logger.debug(
                        "Node %s cordoned for %.0fs (<%.0fs grace), skipping",
                        name, elapsed, config.NODE_CORDON_GRACE_SECONDS,
                    )
                    continue
                results.append(ScanResult(
                    state_key=key,
                    title=f"Node cordoned (SchedulingDisabled): {name}",
                    severity="warning",
                    resource=f"Node/{name}",
                    namespace="",
                    issue_type="node_cordon",
                    node_name=name,
                    skip_llm=True,
                    context_override=self._build_context(node, "Cordoned (SchedulingDisabled)"),
                ))
                continue

            # --- NotReady ---
            ready_cond = conditions.get("Ready")
            if ready_cond and ready_cond.status != "True":
                key = f"Node:{name}:notready"
                active_keys.add(key)
                if key not in self._first_seen:
                    self._first_seen[key] = now
                elapsed = now - self._first_seen[key]
                if elapsed < config.NODE_NOT_READY_GRACE_SECONDS:
                    logger.debug(
                        "Node %s NotReady for %.0fs (<%.0fs grace), skipping",
                        name, elapsed, config.NODE_NOT_READY_GRACE_SECONDS,
                    )
                    continue
                reason = ready_cond.reason or "Unknown"
                message = ready_cond.message or ""
                results.append(ScanResult(
                    state_key=key,
                    title=f"Node NotReady: {name} ({reason})",
                    severity="critical",
                    resource=f"Node/{name}",
                    namespace="",
                    issue_type="node_notready",
                    node_name=name,
                    skip_llm=True,
                    context_override=self._build_context(
                        node, f"NotReady: {reason} — {message}",
                    ),
                ))
                continue

            # --- Pressure conditions ---
            for pressure_type in ("MemoryPressure", "DiskPressure", "PIDPressure"):
                cond = conditions.get(pressure_type)
                if cond and cond.status == "True":
                    key = f"Node:{name}:pressure:{pressure_type}"
                    active_keys.add(key)
                    if key not in self._first_seen:
                        self._first_seen[key] = now
                    elapsed = now - self._first_seen[key]
                    if elapsed < config.NODE_NOT_READY_GRACE_SECONDS:
                        continue
                    results.append(ScanResult(
                        state_key=key,
                        title=f"Node {pressure_type}: {name}",
                        severity="warning",
                        resource=f"Node/{name}",
                        namespace="",
                        issue_type="node_pressure",
                        node_name=name,
                        skip_llm=True,
                        context_override=self._build_context(
                            node, f"{pressure_type}: {cond.reason or ''} — {cond.message or ''}",
                        ),
                    ))

            # --- Node is healthy → auto-resolve ---
            for suffix in ("cordon", "notready"):
                resolve_key = f"Node:{name}:{suffix}"
                if resolve_key not in active_keys:
                    results.append(ScanResult(
                        state_key=resolve_key,
                        title=f"Node OK: {name}",
                        severity="info",
                        resource=f"Node/{name}",
                        namespace="",
                        issue_type="node_ok",
                        node_name=name,
                        auto_resolve=True,
                    ))
            for pressure_type in ("MemoryPressure", "DiskPressure", "PIDPressure"):
                resolve_key = f"Node:{name}:pressure:{pressure_type}"
                if resolve_key not in active_keys:
                    results.append(ScanResult(
                        state_key=resolve_key,
                        title=f"Node OK: {name}",
                        severity="info",
                        resource=f"Node/{name}",
                        namespace="",
                        issue_type="node_ok",
                        node_name=name,
                        auto_resolve=True,
                    ))

        # Clean up first_seen for keys no longer active
        stale = [k for k in self._first_seen if k not in active_keys]
        for k in stale:
            del self._first_seen[k]

        issues = [r for r in results if not r.auto_resolve]
        if issues:
            details = "; ".join(f"{r.node_name}: {r.title}" for r in issues)
            logger.info("Node scanner: %d issues found: %s", len(issues), details)
        else:
            logger.info("Node scanner: all %d nodes OK", len(nodes.items))
        return results

    def collect_daily_data(self) -> str | None:
        core = k8s.CoreV1Api()
        try:
            nodes = core.list_node()
        except Exception:
            logger.warning("Node scanner: failed to list nodes for daily data")
            return None

        lines = [f"## Node Status ({len(nodes.items)} nodes)"]
        for node in nodes.items:
            name = node.metadata.name
            conditions = {c.type: c for c in (node.status.conditions or [])}
            ready = conditions.get("Ready")
            ready_str = ready.status if ready else "Unknown"
            spec = node.spec or k8s.V1NodeSpec()
            flags: list[str] = []
            if spec.unschedulable:
                flags.append("Cordoned")
            for pt in ("MemoryPressure", "DiskPressure", "PIDPressure"):
                cond = conditions.get(pt)
                if cond and cond.status == "True":
                    flags.append(pt)
            info = node.status.node_info
            version = info.kubelet_version if info else "?"
            status = f"Ready={ready_str}"
            if flags:
                status += f" [{', '.join(flags)}]"
            lines.append(f"- {name}: {status} (kubelet {version})")
        return "\n".join(lines)

    @staticmethod
    def _build_context(node: k8s.V1Node, issue: str) -> str:
        name = node.metadata.name
        labels = node.metadata.labels or {}
        info = node.status.node_info
        conditions = node.status.conditions or []
        spec = node.spec or k8s.V1NodeSpec()
        taints = spec.taints or []

        lines = [
            "## Node Alert",
            f"Node: {name}",
            f"Issue: {issue}",
            "",
            "### Labels",
        ]
        for k, v in sorted(labels.items()):
            lines.append(f"  {k}: {v}")

        if taints:
            lines.append("")
            lines.append("### Taints")
            for t in taints:
                lines.append(f"  {t.key}={t.value or ''}:{t.effect}")

        lines.append("")
        lines.append("### Conditions")
        for c in conditions:
            lines.append(
                f"  {c.type}: {c.status} — {c.reason or ''} — {c.message or ''}"
            )

        if info:
            lines.append("")
            lines.append("### Node Info")
            lines.append(f"  OS: {info.os_image}")
            lines.append(f"  Kernel: {info.kernel_version}")
            lines.append(f"  Kubelet: {info.kubelet_version}")
            lines.append(f"  Container Runtime: {info.container_runtime_version}")

        return "\n".join(lines)

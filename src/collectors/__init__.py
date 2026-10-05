"""Collector facade — maintains backward-compatible API while delegating to sub-modules."""
from kubernetes import client as k8s

from src.collectors.pod import collect_pod_context, query_app_metrics
from src.collectors.node import get_node_metrics_summary
from src.collectors.app_metrics import get_app_metrics_summary
from src.collectors.flux import collect_flux_context
from src.collectors.daily import collect_daily_data
from src.collectors.prometheus import prom_scalar, prom_query
from src.collectors._formatters import fmt_bytes


class Collector:
    """Facade that delegates to sub-modules. Keeps existing API surface."""

    def __init__(self):
        self.core = k8s.CoreV1Api()
        self.apps = k8s.AppsV1Api()
        self.custom = k8s.CustomObjectsApi()

    def collect_pod_context(self, pod_name: str, namespace: str) -> dict:
        return collect_pod_context(pod_name, namespace, self.core, self.apps)

    def collect_pod_context_with_diagnostics(self, pod_name: str, namespace: str, issue_type: str) -> dict:
        from src.diagnostics import collect_diagnostics
        import logging
        logger = logging.getLogger(__name__)
        # Single GET-pod here; both the context collector and the diagnostic
        # plugins consume the same V1Pod object (no second round-trip).
        try:
            pod = self.core.read_namespaced_pod(pod_name, namespace)
        except k8s.ApiException as e:
            if e.status == 404:
                logger.debug("Pod %s/%s no longer exists, skipping context+diag", namespace, pod_name)
                return {"error": f"Pod {namespace}/{pod_name} no longer exists (deleted or recreated)"}
            logger.exception("Failed to read pod %s/%s", namespace, pod_name)
            return {}
        except Exception:
            logger.exception("Failed to read pod %s/%s", namespace, pod_name)
            return {}
        data = collect_pod_context(pod_name, namespace, self.core, self.apps, pod=pod)
        try:
            diag = collect_diagnostics(pod, namespace, issue_type)
            if diag:
                data["diagnostics"] = diag
        except Exception:
            logger.debug("Failed to collect diagnostics for %s/%s", namespace, pod_name)
        return data

    def collect_flux_context(self, name: str, namespace: str, kind: str) -> dict:
        return collect_flux_context(name, namespace, kind)

    def collect_daily_data(self) -> dict:
        return collect_daily_data()

    def get_node_metrics_summary(self, node_name: str) -> str:
        return get_node_metrics_summary(node_name)

    def get_app_metrics_summary(self, pod_name: str, namespace: str) -> str:
        return get_app_metrics_summary(pod_name, namespace)

    def scan_pvc_usage(self) -> list[dict]:
        query = 'kubelet_volume_stats_used_bytes / kubelet_volume_stats_capacity_bytes'
        result = prom_query(query)
        if not result:
            return []

        from src import config
        alerts = []
        for r in result:
            pct = float(r["value"][1])
            if pct < config.PVC_WARNING_THRESHOLD:
                continue
            ns = r["metric"].get("namespace", "?")
            pvc = r["metric"].get("persistentvolumeclaim", "?")
            severity = "critical" if pct >= config.PVC_CRITICAL_THRESHOLD else "warning"

            used_q = f'kubelet_volume_stats_used_bytes{{namespace="{ns}",persistentvolumeclaim="{pvc}"}}'
            cap_q = f'kubelet_volume_stats_capacity_bytes{{namespace="{ns}",persistentvolumeclaim="{pvc}"}}'
            used_bytes = prom_scalar(used_q)
            cap_bytes = prom_scalar(cap_q)

            # 24h growth rate (bytes/sec → bytes/day) and days-to-full
            # projection. rate() can be negative if retention/GC ran, in
            # which case we skip the projection — no useful signal.
            growth_q = (
                f'rate(kubelet_volume_stats_used_bytes'
                f'{{namespace="{ns}",persistentvolumeclaim="{pvc}"}}[24h])'
            )
            growth_bps = prom_scalar(growth_q)
            growth_per_day = None
            days_to_full = None
            if (growth_bps is not None and growth_bps > 0
                    and used_bytes is not None and cap_bytes):
                growth_per_day = growth_bps * 86400
                remaining = cap_bytes - used_bytes
                if remaining > 0:
                    days_to_full = remaining / growth_per_day

            alerts.append({
                "namespace": ns,
                "pvc": pvc,
                "pct": pct,
                "used": fmt_bytes(used_bytes),
                "capacity": fmt_bytes(cap_bytes),
                "severity": severity,
                "growth_per_day": growth_per_day,
                "days_to_full": days_to_full,
            })

        alerts.sort(key=lambda x: x["pct"], reverse=True)
        return alerts

    # Kept for endpoint scanner context building
    def _query_app_metrics(self, pod_name: str, namespace: str) -> str | None:
        return query_app_metrics(pod_name, namespace)

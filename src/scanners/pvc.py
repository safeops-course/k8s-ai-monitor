"""PVC scanner — extracted from main._scan_pvcs."""
import logging

from src import config
from src.collectors import Collector
from src.collectors._formatters import fmt_bytes
from src.scanners._base import ScanResult

logger = logging.getLogger(__name__)


class PvcScanner:
    name = "pvc"
    startup_delay = 60

    @property
    def enabled(self):
        return config.SCANNER_PVC_ENABLED

    @property
    def interval_seconds(self):
        return config.PVC_SCAN_INTERVAL_SECONDS

    def scan(self) -> list[ScanResult]:
        if not config.PROMETHEUS_URL:
            logger.debug("PVC scanner: PROMETHEUS_URL not set, skipping")
            return []

        collector = Collector()
        alerts = collector.scan_pvc_usage()
        results = []
        problem_keys: set[str] = set()

        for a in alerts:
            if a["namespace"] in config.EXCLUDE_NAMESPACES:
                continue
            pct = a["pct"] * 100
            context_lines = [
                "## PVC Alert",
                f"PVC: {a['namespace']}/{a['pvc']}",
                f"Usage: {pct:.1f}% ({a['used']} / {a['capacity']})",
                f"Severity: {a['severity']}",
            ]
            growth_per_day = a.get("growth_per_day")
            days_to_full = a.get("days_to_full")
            if growth_per_day is not None:
                context_lines.append(
                    f"Growth (24h avg): {fmt_bytes(growth_per_day)}/day"
                )
                if days_to_full is not None:
                    if days_to_full < 1:
                        eta = f"{days_to_full * 24:.1f}h"
                    else:
                        eta = f"{days_to_full:.1f}d"
                    context_lines.append(f"Projected days-to-full: {eta}")
            context = "\n".join(context_lines) + "\n"
            state_key = f"PVC:{a['namespace']}/{a['pvc']}:{a['severity']}"
            problem_keys.add(state_key)
            results.append(ScanResult(
                state_key=state_key,
                title=f"PVC {pct:.0f}% Full: {a['pvc']}",
                severity=a["severity"],
                resource=f"PVC/{a['pvc']}",
                namespace=a["namespace"],
                issue_type="pvc",
                context_override=context,
            ))

        # Auto-resolve: check active PVC incidents against current state
        try:
            from src.handlers.startup import get_store
            store = get_store()
            active = store.get_active_incidents_by_prefix(["PVC:"])
            for incident in active:
                if incident.state_key in problem_keys:
                    continue
                # Parse namespace from state_key (format: "PVC:namespace/pvc:severity")
                parts = incident.state_key.split(":")
                ns_resource = parts[1] if len(parts) > 1 else ""
                ns_part = ns_resource.split("/")[0] if "/" in ns_resource else ""
                pvc_name = ns_resource.split("/")[1] if "/" in ns_resource else ns_resource
                results.append(ScanResult(
                    state_key=incident.state_key,
                    title=f"PVC Resolved: {pvc_name}",
                    severity="info",
                    resource=f"PVC/{pvc_name}",
                    namespace=ns_part,
                    issue_type="pvc",
                    auto_resolve=True,
                ))
            resolved_count = len(results) - len(problem_keys)
            if resolved_count > 0:
                logger.info("PVC scanner: %d incidents auto-resolved", resolved_count)
        except Exception:
            logger.warning("PVC scanner: failed to check for auto-resolve", exc_info=True)

        issues = [r for r in results if not r.auto_resolve]
        logger.info("PVC scanner completed: %d alerts from %d PVCs above threshold", len(issues), len(alerts))
        return results

    def collect_daily_data(self) -> str | None:
        return None  # daily PVC data handled by collectors/daily.py

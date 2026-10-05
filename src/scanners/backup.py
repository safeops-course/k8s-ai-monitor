"""Backup scanner - CloudNativePG backups: the latest Backup of each ScheduledBackup,
and recoverability from the Cluster status (lastSuccessfulBackup)."""
import logging
from datetime import datetime, timezone

from kubernetes import client as k8s

from src import config
from src.scanners._base import ScanResult

logger = logging.getLogger(__name__)

_TWO_HOURS = 2 * 3600


def _parse_time(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _age_hours(dt: datetime | None, now: datetime) -> float | None:
    if dt is None:
        return None
    return (now - dt).total_seconds() / 3600


class BackupScanner:
    name = "backup"
    startup_delay = 120

    @property
    def enabled(self):
        return config.SCANNER_BACKUP_ENABLED

    @property
    def interval_seconds(self):
        return config.BACKUP_SCAN_INTERVAL_SECONDS

    def scan(self) -> list[ScanResult]:
        results: list[ScanResult] = []
        results.extend(self._check_cnpg())

        if results:
            details = "; ".join(f"{r.namespace}/{r.resource}: {r.title}" for r in results)
            logger.info("Backup scanner: %d issues found: %s", len(results), details)
        else:
            logger.info("Backup scanner: no issues found")
        return results

    # ── CloudNativePG ScheduledBackups ──────────────────────────────

    def _check_cnpg(self) -> list[ScanResult]:
        custom = k8s.CustomObjectsApi()
        results: list[ScanResult] = []

        try:
            scheduled = custom.list_cluster_custom_object(
                "postgresql.cnpg.io", "v1", "scheduledbackups",
            )
        except k8s.ApiException as e:
            if e.status == 404:
                logger.debug("CNPG CRDs not available, skipping")
            else:
                logger.warning("Failed to list CNPG scheduledbackups: %s", e.reason)
            return []
        except Exception:
            logger.debug("CNPG not available, skipping")
            return []

        now = datetime.now(timezone.utc)
        max_age = config.BACKUP_MAX_AGE_HOURS
        # Recoverability is per cluster, not per ScheduledBackup — a cluster
        # with several schedules (daily + weekly) must be checked once, or each
        # tick makes duplicate GETs and duplicate same-state_key results.
        checked_clusters: set[tuple[str, str]] = set()

        for sb in scheduled.get("items", []):
            ns = sb["metadata"]["namespace"]
            if ns in config.EXCLUDE_NAMESPACES:
                continue
            cluster_name = sb["spec"].get("cluster", {}).get("name", "")
            sb_name = sb["metadata"]["name"]

            # Authoritative recoverability check. Runs per cluster regardless of
            # the per-Backup-CR verdict below (which a jammed backup queue slips
            # through entirely), so it sits before that logic and its `continue`s.
            if (ns, cluster_name) not in checked_clusters:
                checked_clusters.add((ns, cluster_name))
                rec = self._check_recoverability(custom, ns, cluster_name, now, max_age)
                if rec is not None:
                    results.append(rec)

            try:
                backups = custom.list_namespaced_custom_object(
                    "postgresql.cnpg.io", "v1", ns, "backups",
                )
            except Exception:
                logger.warning("Failed to list CNPG backups in %s", ns)
                continue

            # Filter backups for this cluster and sort by creation time
            cluster_backups = [
                b for b in backups.get("items", [])
                if b.get("spec", {}).get("cluster", {}).get("name") == cluster_name
            ]
            cluster_backups.sort(
                key=lambda b: b["metadata"].get("creationTimestamp", ""), reverse=True,
            )

            last_3 = cluster_backups[:3]
            latest = cluster_backups[0] if cluster_backups else None

            issue = None
            severity = "critical"
            auto_resolve = False

            if not latest:
                issue = f"No backups found for cluster {cluster_name}"
            else:
                status = latest.get("status", {})
                phase = status.get("phase", "unknown")
                started = _parse_time(status.get("startedAt") or latest["metadata"].get("creationTimestamp"))
                stopped = _parse_time(status.get("stoppedAt"))
                age = _age_hours(stopped or started, now)

                if phase == "failed":
                    issue = f"Latest backup failed for cluster {cluster_name}"
                elif phase == "completed":
                    if age is not None and age > max_age:
                        issue = f"Latest backup is {age:.1f}h old (>{max_age}h) for cluster {cluster_name}"
                    else:
                        auto_resolve = True
                elif phase == "running":
                    running_secs = (now - started).total_seconds() if started else 0
                    if running_secs > _TWO_HOURS:
                        issue = f"Backup running for {running_secs / 3600:.1f}h for cluster {cluster_name}"
                        severity = "warning"
                else:
                    if age is not None and age > max_age:
                        issue = f"Latest backup status '{phase}', {age:.1f}h old for cluster {cluster_name}"

            if auto_resolve:
                results.append(ScanResult(
                    state_key=f"Backup:cnpg:{ns}/{cluster_name}",
                    title=f"Backup OK: cluster {cluster_name}",
                    severity="info",
                    resource=f"ScheduledBackup/{sb_name}",
                    namespace=ns,
                    issue_type="backup",
                    auto_resolve=True,
                ))
                continue

            if not issue:
                continue

            context = self._cnpg_context(sb, last_3)
            results.append(ScanResult(
                state_key=f"Backup:cnpg:{ns}/{cluster_name}",
                title=f"Backup: {issue}",
                severity=severity,
                resource=f"ScheduledBackup/{sb_name}",
                namespace=ns,
                issue_type="backup",
                context_override=context,
            ))

        return results

    def _check_recoverability(self, custom, ns: str, cluster_name: str, now, max_age):
        """Alert on cluster.status.lastSuccessfulBackup age — the only signal
        that reflects real recoverability.

        The per-Backup-CR logic in `_check_cnpg` keys on the *latest* Backup
        object's phase and age. A cluster that mints a fresh Backup daily but
        never completes one — a zombie stuck in `started` holding the
        per-cluster backup lock, a jammed queue — always presents a young latest
        object with an empty phase. It matches no branch (`failed`/`completed`/
        `running`), the `else` fires only past max_age which a daily-recreated
        object never reaches, and the scanner emits nothing at all: not an alert,
        not even an OK. A cluster can run for weeks this way - hundreds of pending
        Backups behind one `started` zombie, WAL growing unpruned, zero alerts.

        `lastSuccessfulBackup` is set by the operator only when a base backup
        actually completes, so it cannot be faked by the daily churn. Read it
        directly and independently.

        Returns a ScanResult (critical when stale/never, auto-resolving info when
        fresh) or None when the cluster cannot be read.
        """
        try:
            cluster = custom.get_namespaced_custom_object(
                "postgresql.cnpg.io", "v1", ns, "clusters", cluster_name,
            )
        except Exception:
            logger.debug(
                "Recoverability: failed to get cluster %s/%s", ns, cluster_name,
                exc_info=True,
            )
            return None
        # The real client returns a dict; an unconfigured test mock returns a
        # MagicMock. Never fabricate a verdict from a non-dict.
        if not isinstance(cluster, dict):
            return None

        status = cluster.get("status") or {}
        state_key = f"Backup:cnpg-recoverability:{ns}/{cluster_name}"
        last_success = _parse_time(status.get("lastSuccessfulBackup"))

        if last_success is None:
            # Never a successful backup. Grace for a freshly-created cluster
            # whose first backup simply has not run yet — mirrors the CronJob
            # new-deployment grace. Past that, silence itself is the failure.
            created = _parse_time((cluster.get("metadata") or {}).get("creationTimestamp"))
            age_h = _age_hours(created, now)
            if age_h is not None and age_h < max_age:
                return None
            return ScanResult(
                state_key=state_key,
                title=f"Backup: cluster {cluster_name} has no successful backup on record",
                severity="critical",
                resource=f"Cluster/{cluster_name}",
                namespace=ns,
                issue_type="backup",
                context_override=self._recoverability_context(ns, cluster_name, status, "never"),
            )

        age = _age_hours(last_success, now)
        if age is not None and age > max_age:
            return ScanResult(
                state_key=state_key,
                title=(
                    f"Backup: cluster {cluster_name} last SUCCESSFUL backup "
                    f"{age:.0f}h ago (>{max_age}h) — recoverability at risk"
                ),
                severity="critical",
                resource=f"Cluster/{cluster_name}",
                namespace=ns,
                issue_type="backup",
                context_override=self._recoverability_context(ns, cluster_name, status, "stale"),
            )

        # Fresh — emit an OK so a prior recoverability alert auto-resolves.
        return ScanResult(
            state_key=state_key,
            title=f"Backup OK: cluster {cluster_name} recoverable ({age:.0f}h since last success)",
            severity="info",
            resource=f"Cluster/{cluster_name}",
            namespace=ns,
            issue_type="backup",
            auto_resolve=True,
        )

    @staticmethod
    def _recoverability_context(ns: str, cluster_name: str, status: dict, kind: str) -> str:
        lines = [
            "## CNPG Recoverability Alert",
            f"Cluster: {ns}/{cluster_name}",
            f"Last successful backup: {status.get('lastSuccessfulBackup', 'never')}",
            f"First recoverability point: {status.get('firstRecoverabilityPoint', '?')}",
            "",
        ]
        if kind == "stale":
            lines.append(
                "Scheduled Backup objects are still being created but none has "
                "completed since the timestamp above. A base backup stuck in "
                "phase=started holds the per-cluster backup lock and jams the "
                "queue behind it; WAL is then retained back to the recoverability "
                "point and grows unbounded. Check for a Backup in phase=started "
                "and a backlog of empty-phase Backups, delete the zombie, and let "
                "a fresh backup complete."
            )
        else:
            lines.append(
                "No base backup has ever completed for this cluster. Continuous "
                "WAL archiving alone cannot restore without a base backup."
            )
        return "\n".join(lines)

    @staticmethod
    def _cnpg_context(sb: dict, last_backups: list[dict]) -> str:
        spec = sb.get("spec", {})
        lines = [
            "## CNPG Backup Alert",
            f"ScheduledBackup: {sb['metadata']['namespace']}/{sb['metadata']['name']}",
            f"Cluster: {spec.get('cluster', {}).get('name', '?')}",
            f"Schedule: {spec.get('schedule', '?')}",
            f"Method: {spec.get('method', 'barmanObjectStore')}",
            "",
        ]
        for b in last_backups:
            status = b.get("status", {})
            lines.append(
                f"Backup {b['metadata']['name']}: phase={status.get('phase', '?')} "
                f"started={status.get('startedAt', '?')} stopped={status.get('stoppedAt', '?')}"
            )
        return "\n".join(lines)

    # ── CronJob-based Backups ──────────────────────────────────────


    # ── Storage Verification ───────────────────────────────────────


    # ── Cross-check CronJob ↔ S3 ─────────────────────────────────


    # ── Daily data ─────────────────────────────────────────────────

    def collect_daily_data(self) -> str | None:
        lines = ["## Backup Status Summary", ""]
        has_data = False
        has_issues = False

        # CNPG
        cnpg_data = self._daily_cnpg()
        if cnpg_data:
            lines.extend(cnpg_data)
            has_data = True
            if any(":warning:" in l or ":x:" in l for l in cnpg_data):
                has_issues = True

        if not has_data:
            return None

        if not has_issues:
            lines.append("All backups are healthy — no issues detected.")

        return "\n".join(lines)

    def _daily_cnpg(self) -> list[str] | None:
        custom = k8s.CustomObjectsApi()
        try:
            scheduled = custom.list_cluster_custom_object(
                "postgresql.cnpg.io", "v1", "scheduledbackups",
            )
        except Exception:
            logger.debug("CNPG not available for daily report")
            return None

        now = datetime.now(timezone.utc)
        lines = ["### CloudNativePG Backups", "| Namespace | Cluster | Last Backup | Age (h) | Status |", "|---|---|---|---|---|"]
        found = False

        for sb in scheduled.get("items", []):
            ns = sb["metadata"]["namespace"]
            if ns in config.EXCLUDE_NAMESPACES:
                continue
            cluster_name = sb["spec"].get("cluster", {}).get("name", "?")

            try:
                backups = custom.list_namespaced_custom_object(
                    "postgresql.cnpg.io", "v1", ns, "backups",
                )
                cluster_backups = [
                    b for b in backups.get("items", [])
                    if b.get("spec", {}).get("cluster", {}).get("name") == cluster_name
                ]
                cluster_backups.sort(
                    key=lambda b: b["metadata"].get("creationTimestamp", ""), reverse=True,
                )
                if cluster_backups:
                    latest = cluster_backups[0]
                    status = latest.get("status", {})
                    phase = status.get("phase", "?")
                    stopped = _parse_time(status.get("stoppedAt"))
                    started = _parse_time(status.get("startedAt") or latest["metadata"].get("creationTimestamp"))
                    ts = stopped or started
                    age = _age_hours(ts, now)
                    flag = " :warning:" if (age and age > config.BACKUP_MAX_AGE_HOURS) or phase == "failed" else ""
                    age_str = f"{age:.1f}" if age else "?"
                    lines.append(f"| {ns} | {cluster_name} | {ts or '?'} | {age_str} | {phase}{flag} |")
                else:
                    lines.append(f"| {ns} | {cluster_name} | NONE | - | :x: no backups |")
                found = True
            except Exception:
                logger.debug("Failed to list backups for CNPG cluster %s/%s", ns, cluster_name, exc_info=True)
                continue

        return lines + [""] if found else None


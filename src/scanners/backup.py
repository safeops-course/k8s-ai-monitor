"""Backup scanner — checks CloudNativePG, CronJob-based, and Percona MongoDB backups."""
import gzip
import logging
import struct
from datetime import date, datetime, timedelta, timezone

from kubernetes import client as k8s

from src import config
from src.scanners._base import ScanResult

logger = logging.getLogger(__name__)

_TWO_HOURS = 2 * 3600

_BACKUP_CRONJOB_NAMES = ("postgres-backup", "pg-backup", "mongo-backup", "mongodb-backup")


def _is_backup_cronjob(name: str) -> bool:
    return any(pat in name for pat in _BACKUP_CRONJOB_NAMES)


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


def _fmt_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f}KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f}MB"
    return f"{size_bytes / (1024 * 1024 * 1024):.2f}GB"


class BackupScanner:
    name = "backup"
    startup_delay = 120

    def __init__(self) -> None:
        self._last_storage_check_date: date | None = None

    @property
    def enabled(self):
        return config.SCANNER_BACKUP_ENABLED

    @property
    def interval_seconds(self):
        return config.BACKUP_SCAN_INTERVAL_SECONDS

    def scan(self) -> list[ScanResult]:
        results: list[ScanResult] = []
        results.extend(self._check_cnpg())
        results.extend(self._check_cronjob())
        results.extend(self._check_percona())

        # Storage verification — once per day at the configured hour
        results.extend(self._check_storage())

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

        for sb in scheduled.get("items", []):
            ns = sb["metadata"]["namespace"]
            if ns in config.EXCLUDE_NAMESPACES:
                continue
            cluster_name = sb["spec"].get("cluster", {}).get("name", "")
            sb_name = sb["metadata"]["name"]

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

    def _check_cronjob(self) -> list[ScanResult]:
        batch = k8s.BatchV1Api()
        results: list[ScanResult] = []
        now = datetime.now(timezone.utc)
        max_age = config.BACKUP_MAX_AGE_HOURS

        for ns in config.get_namespaces():
            try:
                crons = batch.list_namespaced_cron_job(ns)
            except k8s.ApiException as e:
                if e.status == 404:
                    logger.debug("CronJob API not available in %s", ns)
                else:
                    logger.warning("Failed to list cronjobs in %s: %s", ns, e.reason)
                continue
            except Exception:
                logger.warning("Failed to list cronjobs in %s", ns, exc_info=True)
                continue

            for cj in crons.items:
                name = cj.metadata.name
                if not _is_backup_cronjob(name):
                    continue

                issue = None
                severity = "critical"
                auto_resolve = False

                # Check suspended
                if cj.spec.suspend:
                    issue = f"CronJob {name} is suspended"
                    severity = "warning"

                # Check last successful time
                last_success = cj.status.last_successful_time
                if not issue:
                    if last_success is None:
                        issue = f"CronJob {name} has never succeeded"
                    else:
                        if last_success.tzinfo is None:
                            last_success = last_success.replace(tzinfo=timezone.utc)
                        age = _age_hours(last_success, now)
                        if age is not None and age > max_age:
                            issue = f"CronJob {name} last success {age:.1f}h ago (>{max_age}h)"
                        else:
                            auto_resolve = True

                # Check for failed jobs
                if not issue and not auto_resolve:
                    try:
                        jobs = batch.list_namespaced_job(ns)
                        # Filter jobs owned by this cronjob
                        cj_jobs = []
                        for job in jobs.items:
                            owners = job.metadata.owner_references or []
                            if any(o.name == name for o in owners):
                                cj_jobs.append(job)
                        cj_jobs.sort(
                            key=lambda j: j.metadata.creation_timestamp or datetime.min.replace(tzinfo=timezone.utc),
                            reverse=True,
                        )
                        if cj_jobs:
                            latest_job = cj_jobs[0]
                            if latest_job.status.conditions:
                                for cond in latest_job.status.conditions:
                                    if cond.type == "Failed" and cond.status == "True":
                                        issue = f"CronJob {name} latest job failed"
                                        break
                    except Exception:
                        logger.debug("Failed to list jobs for cronjob %s/%s", ns, name)

                if auto_resolve:
                    results.append(ScanResult(
                        state_key=f"Backup:cronjob:{ns}/{name}",
                        title=f"Backup OK: CronJob {name}",
                        severity="info",
                        resource=f"CronJob/{name}",
                        namespace=ns,
                        issue_type="backup",
                        auto_resolve=True,
                    ))
                    continue

                if not issue:
                    continue

                context = self._cronjob_context(cj, ns, name)
                results.append(ScanResult(
                    state_key=f"Backup:cronjob:{ns}/{name}",
                    title=f"Backup: {issue}",
                    severity=severity,
                    resource=f"CronJob/{name}",
                    namespace=ns,
                    issue_type="backup",
                    context_override=context,
                ))

        return results

    def _cronjob_context(self, cj, ns: str, name: str) -> str:
        spec = cj.spec
        container = None
        if spec.job_template and spec.job_template.spec and spec.job_template.spec.template:
            containers = spec.job_template.spec.template.spec.containers or []
            if containers:
                container = containers[0]

        lines = [
            "## CronJob Backup Alert",
            f"CronJob: {ns}/{name}",
            f"Schedule: {spec.schedule}",
            f"Suspended: {spec.suspend}",
            f"Last successful: {cj.status.last_successful_time or '?'}",
            f"Last scheduled: {cj.status.last_schedule_time or '?'}",
        ]
        if container:
            lines.append(f"Image: {container.image}")
            if container.command:
                lines.append(f"Command: {' '.join(container.command[:3])}")

        # Recent jobs
        try:
            batch = k8s.BatchV1Api()
            jobs = batch.list_namespaced_job(ns)
            cj_jobs = []
            for job in jobs.items:
                owners = job.metadata.owner_references or []
                if any(o.name == name for o in owners):
                    cj_jobs.append(job)
            cj_jobs.sort(
                key=lambda j: j.metadata.creation_timestamp or datetime.min.replace(tzinfo=timezone.utc),
                reverse=True,
            )
            for job in cj_jobs[:3]:
                status_str = "active" if job.status.active else "succeeded" if job.status.succeeded else "failed"
                lines.append(
                    f"Job {job.metadata.name}: {status_str} "
                    f"started={job.status.start_time} completed={job.status.completion_time}"
                )

            # Pod logs for latest failed job
            if cj_jobs and not cj_jobs[0].status.succeeded:
                try:
                    core = k8s.CoreV1Api()
                    pods = core.list_namespaced_pod(
                        ns, label_selector=f"job-name={cj_jobs[0].metadata.name}",
                    )
                    if pods.items:
                        logs = core.read_namespaced_pod_log(
                            pods.items[0].metadata.name, ns, tail_lines=30,
                        )
                        lines.append(f"\nLatest pod logs:\n{logs}")
                except Exception:
                    logger.debug("Failed to get pod logs for job %s/%s", ns, cj_jobs[0].metadata.name, exc_info=True)
        except Exception:
            logger.debug("Failed to list recent jobs for cronjob %s/%s", ns, name, exc_info=True)

        return "\n".join(lines)

    # ── Percona MongoDB Backups ────────────────────────────────────

    def _check_percona(self) -> list[ScanResult]:
        custom = k8s.CustomObjectsApi()
        results: list[ScanResult] = []

        try:
            backups = custom.list_cluster_custom_object(
                "psmdb.percona.com", "v1", "perconaservermongodbbackups",
            )
        except k8s.ApiException as e:
            if e.status == 404:
                logger.debug("Percona PSMDB CRDs not available, skipping")
            else:
                logger.warning("Failed to list Percona backups: %s", e.reason)
            return []
        except Exception:
            logger.debug("Percona PSMDB not available, skipping")
            return []

        now = datetime.now(timezone.utc)
        max_age = config.BACKUP_MAX_AGE_HOURS

        # Group by namespace/cluster
        clusters: dict[str, list[dict]] = {}
        for b in backups.get("items", []):
            ns = b["metadata"]["namespace"]
            if ns in config.EXCLUDE_NAMESPACES:
                continue
            cluster = b.get("spec", {}).get("clusterName", b.get("spec", {}).get("psmdbCluster", "unknown"))
            key = f"{ns}/{cluster}"
            clusters.setdefault(key, []).append(b)

        for key, items in clusters.items():
            ns, cluster_name = key.split("/", 1)
            items.sort(
                key=lambda b: b["metadata"].get("creationTimestamp", ""), reverse=True,
            )
            last_3 = items[:3]
            latest = items[0]

            status = latest.get("status", {})
            state = status.get("state", "unknown")
            created = _parse_time(latest["metadata"].get("creationTimestamp"))
            completed = _parse_time(status.get("completedAt") or status.get("lastTransitionTime"))
            age = _age_hours(completed or created, now)

            issue = None
            severity = "critical"
            auto_resolve = False

            if state == "error":
                issue = f"Latest Percona backup failed for cluster {cluster_name}"
            elif state == "ready":
                if age is not None and age > max_age:
                    issue = f"Latest Percona backup is {age:.1f}h old (>{max_age}h) for cluster {cluster_name}"
                else:
                    auto_resolve = True
            elif state == "running":
                running_secs = (now - created).total_seconds() if created else 0
                if running_secs > _TWO_HOURS:
                    issue = f"Percona backup running for {running_secs / 3600:.1f}h for cluster {cluster_name}"
                    severity = "warning"
            else:
                if age is not None and age > max_age:
                    issue = f"Latest Percona backup state '{state}', {age:.1f}h old for cluster {cluster_name}"

            if auto_resolve:
                results.append(ScanResult(
                    state_key=f"Backup:psmdb:{ns}/{cluster_name}",
                    title=f"Backup OK: Percona cluster {cluster_name}",
                    severity="info",
                    resource=f"PerconaBackup/{latest['metadata']['name']}",
                    namespace=ns,
                    issue_type="backup",
                    auto_resolve=True,
                ))
                continue

            if not issue:
                continue

            context = self._percona_context(cluster_name, ns, last_3)
            results.append(ScanResult(
                state_key=f"Backup:psmdb:{ns}/{cluster_name}",
                title=f"Backup: {issue}",
                severity=severity,
                resource=f"PerconaBackup/{latest['metadata']['name']}",
                namespace=ns,
                issue_type="backup",
                context_override=context,
            ))

        return results

    @staticmethod
    def _percona_context(cluster_name: str, ns: str, last_backups: list[dict]) -> str:
        lines = [
            "## Percona MongoDB Backup Alert",
            f"Cluster: {ns}/{cluster_name}",
            "",
        ]
        for b in last_backups:
            spec = b.get("spec", {})
            status = b.get("status", {})
            lines.append(
                f"Backup {b['metadata']['name']}: state={status.get('state', '?')} "
                f"storage={spec.get('storageName', '?')} "
                f"created={b['metadata'].get('creationTimestamp', '?')} "
                f"completed={status.get('completedAt', '?')}"
            )
        return "\n".join(lines)

    # ── Storage Verification ───────────────────────────────────────

    def _check_storage(self) -> list[ScanResult]:
        """Verify backup files exist on storage. Runs once per day at BACKUP_STORAGE_VERIFY_HOUR_UTC."""
        if not config.BACKUP_STORAGE_PROVIDER:
            return []

        now = datetime.now(timezone.utc)
        today = now.date()

        # Only run once per day, at or after the configured hour
        if now.hour < config.BACKUP_STORAGE_VERIFY_HOUR_UTC:
            return []
        if self._last_storage_check_date == today:
            return []

        logger.info("Running daily storage verification (provider=%s)", config.BACKUP_STORAGE_PROVIDER)

        from src.scanners.storage_verify import get_storage_client, S3Client
        client = get_storage_client()
        if client is None:
            logger.warning("Could not create storage client, skipping storage verification")
            return []

        results: list[ScanResult] = []
        if isinstance(client, S3Client):
            results = self._verify_s3_backups(client)
            results.extend(self._cross_check_cronjob_s3(client))
            self._last_storage_check_date = today
        else:
            logger.warning("Unsupported storage client type: %s", type(client).__name__)

        return results

    def _verify_s3_backups(self, client) -> list[ScanResult]:
        """Discover services from K8s and verify each has today's backup in S3.

        Discovery:
        - Postgres: backup CronJobs postgres-backup-<service> / pg-backup-<service> → service
        - MongoDB: pods with MONGO_URI env → service = owner deployment name

        S3 structure: {bucket}/{dump_type}/{namespace}/{service}/{YYYY}/{MM}/{DD}/{file}
        """
        bucket = client.bucket
        if not bucket:
            logger.warning("No bucket name in S3 secret, skipping storage verification")
            return []

        results: list[ScanResult] = []
        today = datetime.now(timezone.utc).date()
        yesterday = today - timedelta(days=1)

        # Find namespaces that have backup CronJobs
        backup_namespaces = self._find_backup_namespaces()
        if not backup_namespaces:
            logger.info("No backup CronJobs found, skipping storage verification")
            return []

        for ns in backup_namespaces:
            # Postgres services from the backup CronJobs
            pg_services = self._discover_postgres_services(ns)
            for service in pg_services:
                label = f"postgres-dump/{ns}/{service}"
                try:
                    result = self._verify_s3_service(client, bucket, "postgres-dump", ns, service, today, yesterday)
                    results.extend(result)
                except Exception:
                    logger.warning("Storage check failed for %s", label, exc_info=True)

            # MongoDB services from pods with MONGO_URI
            mongo_services = self._discover_mongo_services(ns)
            for service in mongo_services:
                label = f"mongodb-dump/{ns}/{service}"
                try:
                    result = self._verify_s3_service(client, bucket, "mongodb-dump", ns, service, today, yesterday)
                    results.extend(result)
                except Exception:
                    logger.warning("Storage check failed for %s", label, exc_info=True)

        return results

    def _find_backup_namespaces(self) -> list[str]:
        """Find namespaces that have backup CronJobs."""
        batch = k8s.BatchV1Api()
        namespaces = []
        for ns in config.get_namespaces():
            try:
                crons = batch.list_namespaced_cron_job(ns)
                if any(_is_backup_cronjob(cj.metadata.name) for cj in crons.items):
                    namespaces.append(ns)
            except k8s.ApiException as e:
                if e.status == 404:
                    logger.debug("CronJob API not available in %s", ns)
                else:
                    logger.warning("Failed to list cronjobs in %s: %s", ns, e.reason)
            except Exception:
                logger.warning("Failed to list cronjobs in %s", ns, exc_info=True)
        return namespaces

    @staticmethod
    def _discover_postgres_services(ns: str) -> list[str]:
        """Discover postgres services from the backup CronJobs in a namespace.

        postgres-backup-<service> / pg-backup-<service> -> <service>. Deliberately not from Secrets:
        listing Secrets returns their contents, and the monitor has no access to Secrets by design.
        """
        batch = k8s.BatchV1Api()
        services = set()
        try:
            for cj in batch.list_namespaced_cron_job(ns).items:
                parsed = BackupScanner._parse_service_from_cronjob(cj.metadata.name)
                if parsed and parsed[1] == "postgres-dump":
                    services.add(parsed[0])
        except k8s.ApiException as e:
            if e.status == 404:
                logger.debug("CronJob API not available in %s", ns)
            else:
                logger.warning("Failed to list cronjobs in %s for postgres discovery: %s", ns, e.reason)
        except Exception:
            logger.warning("Failed to list cronjobs in %s for postgres discovery", ns, exc_info=True)
        return sorted(services)

    @staticmethod
    def _discover_mongo_services(ns: str) -> list[str]:
        """Discover mongo services from pods with MONGO_URI env var."""
        core = k8s.CoreV1Api()
        services = set()
        try:
            pods = core.list_namespaced_pod(ns)
            for pod in pods.items:
                if not pod.spec or not pod.spec.containers:
                    continue
                has_mongo = any(
                    env.name == "MONGO_URI"
                    for c in pod.spec.containers
                    for env in (c.env or [])
                )
                if not has_mongo:
                    continue
                # Get owner deployment name
                for owner in (pod.metadata.owner_references or []):
                    if owner.kind == "ReplicaSet":
                        # Strip ReplicaSet hash suffix to get Deployment name
                        parts = owner.name.rsplit("-", 1)
                        if len(parts) == 2:
                            services.add(parts[0])
                        else:
                            services.add(owner.name)
        except k8s.ApiException as e:
            if e.status == 404:
                logger.debug("Pods API not available in %s", ns)
            else:
                logger.warning("Failed to list pods in %s for mongo discovery: %s", ns, e.reason)
        except Exception:
            logger.warning("Failed to list pods in %s for mongo discovery", ns, exc_info=True)
        return sorted(services)

    def _verify_s3_service(
        self, client, bucket: str, dump_type: str, ns: str, service: str,
        today: date, yesterday: date,
    ) -> list[ScanResult]:
        """Check a single service has backup files for today (or yesterday), with integrity and trending."""
        label = f"{dump_type}/{ns}/{service}"
        state_key = f"Backup:storage:{label}"
        min_size = config.BACKUP_STORAGE_MIN_SIZE_BYTES
        now = datetime.now(timezone.utc)

        # List objects for both today and yesterday
        today_objects: list = []
        yesterday_objects: list = []

        today_prefix = f"{dump_type}/{ns}/{service}/{today:%Y}/{today:%m}/{today:%d}/"
        yesterday_prefix = f"{dump_type}/{ns}/{service}/{yesterday:%Y}/{yesterday:%m}/{yesterday:%d}/"

        try:
            today_objects = client.list_objects(bucket, today_prefix, max_keys=5)
        except Exception as e:
            logger.debug("Failed to list %s/%s: %s", bucket, today_prefix, e)

        try:
            yesterday_objects = client.list_objects(bucket, yesterday_prefix, max_keys=5)
        except Exception as e:
            logger.debug("Failed to list %s/%s: %s", bucket, yesterday_prefix, e)

        # Use today's files if available, otherwise fall back to yesterday
        if today_objects:
            objects = today_objects
            checked_date = today
        elif yesterday_objects:
            objects = yesterday_objects
            checked_date = yesterday
        else:
            return [ScanResult(
                state_key=state_key,
                title=f"Backup: No files found for {label}",
                severity="critical",
                resource=f"S3/{bucket}/{dump_type}",
                namespace=ns,
                issue_type="backup",
                skip_llm=True,
                context_override=(
                    f"## Storage Verification\n"
                    f"Bucket: {bucket}\n"
                    f"Service: {label}\n"
                    f"Checked: {today} and {yesterday}\n"
                    f"No backup files found!"
                ),
            )]

        latest = objects[0]
        age = _age_hours(latest.last_modified, now)
        issue = None
        severity = "critical"
        integrity_info = ""

        # Skip min_size check for mongodb — empty databases produce valid small dumps
        if latest.size < min_size and not dump_type.startswith("mongodb"):
            issue = f"Backup file suspiciously small ({_fmt_size(latest.size)}) for {label}"
            severity = "warning"
        elif config.BACKUP_STORAGE_DOWNLOAD_VERIFY:
            try:
                ok, reason = self._verify_file_integrity(client, bucket, latest.key, dump_type)
                integrity_info = reason
                if not ok:
                    issue = f"Backup file integrity check failed for {label}: {reason}"
                    severity = "warning"
            except Exception:
                logger.debug("Integrity check failed for %s/%s", bucket, latest.key, exc_info=True)

        # ── Size trending: compare today vs yesterday ──
        trending_info = ""
        if today_objects and yesterday_objects:
            today_size = today_objects[0].size
            yesterday_size = yesterday_objects[0].size
            if yesterday_size > 0:
                ratio = today_size / yesterday_size
                threshold = config.BACKUP_SIZE_DROP_THRESHOLD
                if ratio < threshold:
                    pct = (1 - ratio) * 100
                    trending_info = (
                        f"Size dropped by {pct:.0f}% "
                        f"(today: {_fmt_size(today_size)}, yesterday: {_fmt_size(yesterday_size)})"
                    )
                    if not issue:
                        issue = f"Backup size dropped significantly for {label}: {trending_info}"
                        severity = "warning"
                elif ratio > 3.0:
                    pct = (ratio - 1) * 100
                    trending_info = (
                        f"Size increased by {pct:.0f}% "
                        f"(today: {_fmt_size(today_size)}, yesterday: {_fmt_size(yesterday_size)})"
                    )
                    logger.info("Backup %s: unusual size increase — %s", label, trending_info)
                else:
                    trending_info = f"today: {_fmt_size(today_size)}, yesterday: {_fmt_size(yesterday_size)}"

        # Build context
        context_lines = [
            "## Storage Verification",
            f"Bucket: {bucket}",
            f"Service: {label}",
            f"Date checked: {checked_date}",
        ]
        if integrity_info:
            context_lines.append(f"Integrity: {integrity_info}")
        if trending_info:
            context_lines.append(f"Trending: {trending_info}")
        context_lines.append("")
        context_lines.append("Files found:")
        for obj in objects[:3]:
            context_lines.append(f"  {obj.key} — {_fmt_size(obj.size)} — {obj.last_modified.isoformat()}")
        context = "\n".join(context_lines)

        if issue:
            return [ScanResult(
                state_key=state_key,
                title=f"Backup: {issue}",
                severity=severity,
                resource=f"S3/{bucket}/{dump_type}",
                namespace=ns,
                issue_type="backup",
                skip_llm=True,
                context_override=context,
            )]

        return [ScanResult(
            state_key=state_key,
            title=f"Backup OK: {label} ({_fmt_size(latest.size)}, {age:.0f}h ago)",
            severity="info",
            resource=f"S3/{bucket}/{dump_type}",
            namespace=ns,
            issue_type="backup",
            auto_resolve=True,
            context_override=context,
        )]

    @staticmethod
    def _verify_file_integrity(client, bucket: str, key: str, dump_type: str) -> tuple[bool, str]:
        """Download first chunk and validate backup file integrity.

        Returns (ok, reason).  Fail-open: download errors → (True, "...assuming OK").
        """
        verify_bytes = config.BACKUP_STORAGE_VERIFY_BYTES
        try:
            data = client.download_bytes(bucket, key, (0, verify_bytes - 1))
        except Exception:
            logger.debug("Download verify failed for %s/%s", bucket, key, exc_info=True)
            return True, "download failed, assuming OK"

        if not data:
            return False, "empty file"

        # ── pg_dump custom format (PGDMP magic) ──
        if data[:5] == b"PGDMP":
            if len(data) >= 8:
                # bytes 5-7 are version major/minor/revision
                return True, f"pg_dump custom format v{data[5]}.{data[6]}.{data[7]}"
            return True, "pg_dump custom format"

        # ── gzip-compressed file ──
        if data[:2] == b"\x1f\x8b":
            try:
                decompressed = gzip.decompress(data)
            except EOFError:
                # Partial gzip chunk — expected since we only downloaded a prefix
                # Use raw deflate fallback
                import zlib
                try:
                    dec = zlib.decompressobj(wbits=zlib.MAX_WBITS | 16)
                    decompressed = dec.decompress(data)
                except Exception:
                    # Can't decompress even partially — still might be valid
                    return True, "gzip header valid, partial decompression failed"
            except Exception as e:
                return False, f"gzip decompression failed: {e}"

            # Check decompressed content for known markers
            if dump_type == "postgres-dump":
                sample = decompressed[:8192]
                pg_markers = [b"SET ", b"CREATE ", b"COPY ", b"pg_dump", b"PostgreSQL"]
                if any(marker in sample for marker in pg_markers):
                    return True, "gzip valid, contains SQL markers"
                return True, "gzip valid, no SQL markers found (may be binary format)"

            if dump_type == "mongodb-dump":
                # MongoDB archive is gzip of BSON records
                # First 4 bytes of BSON document are little-endian int32 length
                if len(decompressed) >= 4:
                    bson_len = struct.unpack("<i", decompressed[:4])[0]
                    if 4 < bson_len < 16 * 1024 * 1024:
                        return True, f"gzip valid, BSON document length={bson_len}"
                    return True, "gzip valid, unexpected BSON length"
                return True, "gzip valid, decompressed data too short for BSON check"

            return True, "gzip valid"

        # ── Unknown format — basic non-null check ──
        if any(b != 0 for b in data[:8]):
            return True, "non-null binary data"

        return False, "file appears to be all null bytes"

    # ── Cross-check CronJob ↔ S3 ─────────────────────────────────

    @staticmethod
    def _parse_service_from_cronjob(name: str) -> tuple[str, str] | None:
        """Extract (service_name, dump_type) from a backup CronJob name.

        Returns None if the CronJob name doesn't match known patterns.
        """
        for prefix, dtype in [
            ("postgres-backup-", "postgres-dump"),
            ("pg-backup-", "postgres-dump"),
            ("mongo-backup-", "mongodb-dump"),
            ("mongodb-backup-", "mongodb-dump"),
        ]:
            if name.startswith(prefix):
                return name[len(prefix):], dtype
        return None

    def _cross_check_cronjob_s3(self, client) -> list[ScanResult]:
        """Check that CronJobs reporting success have matching files in S3."""
        bucket = client.bucket
        if not bucket:
            return []

        batch = k8s.BatchV1Api()
        results: list[ScanResult] = []
        now = datetime.now(timezone.utc)

        for ns in config.get_namespaces():
            try:
                crons = batch.list_namespaced_cron_job(ns)
            except k8s.ApiException as e:
                if e.status == 404:
                    logger.debug("Cross-check: CronJob API not available in %s", ns)
                else:
                    logger.warning("Cross-check: failed to list cronjobs in %s: %s", ns, e.reason)
                continue
            except Exception:
                logger.warning("Cross-check: failed to list cronjobs in %s", ns, exc_info=True)
                continue

            for cj in crons.items:
                name = cj.metadata.name
                if not _is_backup_cronjob(name):
                    continue

                parsed = self._parse_service_from_cronjob(name)
                if not parsed:
                    continue

                service, dump_type = parsed
                last_success = cj.status.last_successful_time
                if last_success is None:
                    continue

                if last_success.tzinfo is None:
                    last_success = last_success.replace(tzinfo=timezone.utc)

                # Only cross-check if success was today
                if last_success.date() != now.date():
                    continue

                # Check S3 for today's file
                success_date = last_success.date()
                prefix = f"{dump_type}/{ns}/{service}/{success_date:%Y}/{success_date:%m}/{success_date:%d}/"
                try:
                    objects = client.list_objects(bucket, prefix, max_keys=1)
                except Exception:
                    logger.debug("Cross-check: failed to list S3 for %s/%s", ns, name, exc_info=True)
                    continue

                if not objects:
                    state_key = f"Backup:crosscheck:{ns}/{name}"
                    results.append(ScanResult(
                        state_key=state_key,
                        title=f"Backup: CronJob {name} reports success but no file in S3 for {dump_type}/{ns}/{service}",
                        severity="critical",
                        resource=f"CronJob/{name}",
                        namespace=ns,
                        issue_type="backup",
                        skip_llm=True,
                        context_override=(
                            f"## CronJob ↔ S3 Cross-Check\n"
                            f"CronJob: {ns}/{name}\n"
                            f"Last success: {last_success.isoformat()}\n"
                            f"Expected S3 prefix: {prefix}\n"
                            f"Bucket: {bucket}\n"
                            f"No matching file found!"
                        ),
                    ))

        return results

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

        # CronJob
        cj_data = self._daily_cronjob()
        if cj_data:
            lines.extend(cj_data)
            has_data = True
            if any(":warning:" in l for l in cj_data):
                has_issues = True

        # Percona
        psmdb_data = self._daily_percona()
        if psmdb_data:
            lines.extend(psmdb_data)
            has_data = True
            if any(":warning:" in l or ":x:" in l for l in psmdb_data):
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

    def _daily_cronjob(self) -> list[str] | None:
        batch = k8s.BatchV1Api()
        now = datetime.now(timezone.utc)
        lines = ["### CronJob Backups", "| Namespace | CronJob | Last Success | Age (h) | Status |", "|---|---|---|---|---|"]
        found = False

        for ns in config.get_namespaces():
            try:
                crons = batch.list_namespaced_cron_job(ns)
            except Exception:
                logger.debug("Failed to list cronjobs in %s", ns, exc_info=True)
                continue
            for cj in crons.items:
                name = cj.metadata.name
                if not _is_backup_cronjob(name):
                    continue
                last = cj.status.last_successful_time
                if last and last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                age = _age_hours(last, now)
                status = "suspended" if cj.spec.suspend else ("ok" if age and age <= config.BACKUP_MAX_AGE_HOURS else "overdue")
                flag = " :warning:" if status != "ok" else ""
                age_str = f"{age:.1f}" if age else "?"
                lines.append(f"| {ns} | {name} | {last or 'NEVER'} | {age_str} | {status}{flag} |")
                found = True

        return lines + [""] if found else None

    def _daily_percona(self) -> list[str] | None:
        custom = k8s.CustomObjectsApi()
        try:
            backups = custom.list_cluster_custom_object(
                "psmdb.percona.com", "v1", "perconaservermongodbbackups",
            )
        except Exception:
            logger.debug("Percona not available for daily report")
            return None

        now = datetime.now(timezone.utc)
        lines = ["### Percona MongoDB Backups", "| Namespace | Cluster | Last Backup | Age (h) | Status |", "|---|---|---|---|---|"]
        found = False

        clusters: dict[str, list[dict]] = {}
        for b in backups.get("items", []):
            ns = b["metadata"]["namespace"]
            if ns in config.EXCLUDE_NAMESPACES:
                continue
            cluster = b.get("spec", {}).get("clusterName", b.get("spec", {}).get("psmdbCluster", "unknown"))
            key = f"{ns}/{cluster}"
            clusters.setdefault(key, []).append(b)

        for key, items in clusters.items():
            ns, cluster_name = key.split("/", 1)
            items.sort(key=lambda b: b["metadata"].get("creationTimestamp", ""), reverse=True)
            latest = items[0]
            status = latest.get("status", {})
            state = status.get("state", "?")
            created = _parse_time(latest["metadata"].get("creationTimestamp"))
            completed = _parse_time(status.get("completedAt") or status.get("lastTransitionTime"))
            ts = completed or created
            age = _age_hours(ts, now)
            flag = " :warning:" if (age and age > config.BACKUP_MAX_AGE_HOURS) or state == "error" else ""
            age_str = f"{age:.1f}" if age else "?"
            lines.append(f"| {ns} | {cluster_name} | {ts or '?'} | {age_str} | {state}{flag} |")
            found = True

        return lines + [""] if found else None

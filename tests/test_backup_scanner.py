"""Tests for backup scanner — K8s checks and storage verification."""
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from src.scanners.backup import BackupScanner, _is_backup_cronjob
from src.scanners.storage_verify import ObjectInfo, S3Client, GCSClient


# ── Helpers ──────────────────────────────────────────────────────────


def _utc_now():
    return datetime.now(timezone.utc)


def _hours_ago(h: float) -> datetime:
    return _utc_now() - timedelta(hours=h)


def _make_cronjob(name, last_success=None, suspend=False):
    """Build a mock CronJob object matching kubernetes client shape."""
    cj = MagicMock()
    cj.metadata.name = name
    cj.spec.suspend = suspend
    cj.spec.schedule = "0 1 * * *"
    cj.spec.job_template.spec.template.spec.containers = []
    cj.status.last_successful_time = last_success
    cj.status.last_schedule_time = last_success
    return cj


def _make_cnpg_backup(name, ns, cluster, phase="completed", age_hours=2):
    ts = (_utc_now() - timedelta(hours=age_hours)).isoformat()
    return {
        "metadata": {"name": name, "namespace": ns, "creationTimestamp": ts},
        "spec": {"cluster": {"name": cluster}},
        "status": {
            "phase": phase,
            "startedAt": ts,
            "stoppedAt": ts if phase == "completed" else None,
        },
    }


def _make_scheduled_backup(name, ns, cluster, schedule="0 0 * * *"):
    return {
        "metadata": {"name": name, "namespace": ns},
        "spec": {
            "cluster": {"name": cluster},
            "schedule": schedule,
            "method": "barmanObjectStore",
        },
    }


def _make_object(key="backup.gz", size=10000, age_hours=2):
    return ObjectInfo(
        key=key, size=size,
        last_modified=_hours_ago(age_hours),
    )


# ── CronJob Name Filter ─────────────────────────────────────────────


class TestCronJobNameFilter(unittest.TestCase):
    def test_postgres_backup(self):
        self.assertTrue(_is_backup_cronjob("postgres-backup"))
        self.assertTrue(_is_backup_cronjob("my-postgres-backup-daily"))

    def test_pg_backup(self):
        self.assertTrue(_is_backup_cronjob("pg-backup"))


    def test_unrelated_cronjob(self):
        self.assertFalse(_is_backup_cronjob("cleanup-job"))
        self.assertFalse(_is_backup_cronjob("report-generator"))


# ── CNPG Checks ─────────────────────────────────────────────────────


class TestCNPGCheck(unittest.TestCase):
    def setUp(self):
        self.scanner = BackupScanner()

    @patch("src.scanners.backup.k8s.CustomObjectsApi")
    def test_completed_backup_ok(self, mock_api_class):
        api = mock_api_class.return_value
        api.list_cluster_custom_object.return_value = {
            "items": [_make_scheduled_backup("sb1", "production", "pg-cluster")],
        }
        api.list_namespaced_custom_object.return_value = {
            "items": [_make_cnpg_backup("bk1", "production", "pg-cluster", "completed", 2)],
        }

        results = self.scanner._check_cnpg()
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].auto_resolve)

    @patch("src.scanners.backup.k8s.CustomObjectsApi")
    def test_failed_backup(self, mock_api_class):
        api = mock_api_class.return_value
        api.list_cluster_custom_object.return_value = {
            "items": [_make_scheduled_backup("sb1", "production", "pg-cluster")],
        }
        api.list_namespaced_custom_object.return_value = {
            "items": [_make_cnpg_backup("bk1", "production", "pg-cluster", "failed", 1)],
        }

        results = self.scanner._check_cnpg()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].severity, "critical")
        self.assertIn("failed", results[0].title)

    @patch("src.scanners.backup.k8s.CustomObjectsApi")
    def test_no_backups(self, mock_api_class):
        api = mock_api_class.return_value
        api.list_cluster_custom_object.return_value = {
            "items": [_make_scheduled_backup("sb1", "production", "pg-cluster")],
        }
        api.list_namespaced_custom_object.return_value = {"items": []}

        results = self.scanner._check_cnpg()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].severity, "critical")
        self.assertIn("No backups found", results[0].title)

    @patch("src.scanners.backup.k8s.CustomObjectsApi")
    def test_stale_backup(self, mock_api_class):
        api = mock_api_class.return_value
        api.list_cluster_custom_object.return_value = {
            "items": [_make_scheduled_backup("sb1", "production", "pg-cluster")],
        }
        api.list_namespaced_custom_object.return_value = {
            "items": [_make_cnpg_backup("bk1", "production", "pg-cluster", "completed", 30)],
        }

        results = self.scanner._check_cnpg()
        self.assertEqual(len(results), 1)
        self.assertIn("old", results[0].title)

    @patch("src.scanners.backup.k8s.CustomObjectsApi")
    def test_crd_not_installed(self, mock_api_class):
        from kubernetes.client import ApiException
        api = mock_api_class.return_value
        api.list_cluster_custom_object.side_effect = ApiException(status=404)

        results = self.scanner._check_cnpg()
        self.assertEqual(results, [])


# ── CronJob Checks ──────────────────────────────────────────────────


class TestCronJobCheck(unittest.TestCase):
    def setUp(self):
        self.scanner = BackupScanner()

    @patch("src.scanners.backup.config")
    @patch("src.scanners.backup.k8s.BatchV1Api")
    def test_recent_success(self, mock_api_class, mock_config):
        mock_config.get_namespaces.return_value = ["production"]
        mock_config.BACKUP_MAX_AGE_HOURS = 26
        mock_config.EXCLUDE_NAMESPACES = set()

        api = mock_api_class.return_value
        cj = _make_cronjob("postgres-backup", last_success=_hours_ago(5))
        api.list_namespaced_cron_job.return_value = MagicMock(items=[cj])

        results = self.scanner._check_cronjob()
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].auto_resolve)

    @patch("src.scanners.backup.config")
    @patch("src.scanners.backup.k8s.BatchV1Api")
    def test_stale_cronjob(self, mock_api_class, mock_config):
        mock_config.get_namespaces.return_value = ["production"]
        mock_config.BACKUP_MAX_AGE_HOURS = 26
        mock_config.EXCLUDE_NAMESPACES = set()

        api = mock_api_class.return_value
        cj = _make_cronjob("postgres-backup", last_success=_hours_ago(30))
        api.list_namespaced_cron_job.return_value = MagicMock(items=[cj])

        results = self.scanner._check_cronjob()
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].auto_resolve)
        self.assertIn("last success", results[0].title)

    @patch("src.scanners.backup.config")
    @patch("src.scanners.backup.k8s.BatchV1Api")
    def test_suspended_cronjob(self, mock_api_class, mock_config):
        mock_config.get_namespaces.return_value = ["production"]
        mock_config.BACKUP_MAX_AGE_HOURS = 26
        mock_config.EXCLUDE_NAMESPACES = set()

        api = mock_api_class.return_value
        cj = _make_cronjob("postgres-backup", suspend=True)
        api.list_namespaced_cron_job.return_value = MagicMock(items=[cj])

        results = self.scanner._check_cronjob()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].severity, "warning")
        self.assertIn("suspended", results[0].title)


    @patch("src.scanners.backup.config")
    @patch("src.scanners.backup.k8s.BatchV1Api")
    def test_never_succeeded(self, mock_api_class, mock_config):
        mock_config.get_namespaces.return_value = ["production"]
        mock_config.BACKUP_MAX_AGE_HOURS = 26
        mock_config.EXCLUDE_NAMESPACES = set()

        api = mock_api_class.return_value
        cj = _make_cronjob("pg-backup", last_success=None)
        api.list_namespaced_cron_job.return_value = MagicMock(items=[cj])

        results = self.scanner._check_cronjob()
        self.assertEqual(len(results), 1)
        self.assertIn("never succeeded", results[0].title)


# ── S3 Storage Verification ─────────────────────────────────────────


class TestS3ServiceVerification(unittest.TestCase):
    """Test _verify_s3_service — per-service date-based check."""

    def setUp(self):
        self.scanner = BackupScanner()
        self.today = _utc_now().date()
        self.yesterday = self.today - timedelta(days=1)

    def test_todays_file_ok(self):
        client = MagicMock()
        today_obj = _make_object(
            key=f"postgres-dump/production/core-service/{self.today:%Y}/{self.today:%m}/{self.today:%d}/core-service.tar",
            size=50000, age_hours=3,
        )

        def mock_list_objects(bucket, prefix, max_keys=10):
            if f"/{self.today:%Y}/{self.today:%m}/{self.today:%d}/" in prefix:
                return [today_obj]
            return []

        client.list_objects.side_effect = mock_list_objects

        with patch("src.scanners.backup.config") as cfg:
            cfg.BACKUP_STORAGE_MIN_SIZE_BYTES = 1024
            cfg.BACKUP_STORAGE_DOWNLOAD_VERIFY = False
            cfg.BACKUP_SIZE_DROP_THRESHOLD = 0.5
            results = self.scanner._verify_s3_service(
                client, "test-backups", "postgres-dump", "production", "core-service",
                self.today, self.yesterday,
            )

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].auto_resolve)
        self.assertIn("core-service", results[0].title)

    def test_no_files_today_fallback_yesterday_ok(self):
        client = MagicMock()

        def mock_list_objects(bucket, prefix, max_keys=10):
            if f"/{self.yesterday:%Y}/{self.yesterday:%m}/{self.yesterday:%d}/" in prefix:
                return [_make_object(size=50000, age_hours=26)]
            return []

        client.list_objects.side_effect = mock_list_objects

        with patch("src.scanners.backup.config") as cfg:
            cfg.BACKUP_STORAGE_MIN_SIZE_BYTES = 1024
            cfg.BACKUP_STORAGE_DOWNLOAD_VERIFY = False
            cfg.BACKUP_SIZE_DROP_THRESHOLD = 0.5
            results = self.scanner._verify_s3_service(
                client, "test-backups", "postgres-dump", "production", "core-service",
                self.today, self.yesterday,
            )

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].auto_resolve)

    def test_no_files_at_all_critical(self):
        client = MagicMock()
        client.list_objects.return_value = []

        with patch("src.scanners.backup.config") as cfg:
            cfg.BACKUP_STORAGE_MIN_SIZE_BYTES = 1024
            cfg.BACKUP_STORAGE_DOWNLOAD_VERIFY = False
            cfg.BACKUP_SIZE_DROP_THRESHOLD = 0.5
            results = self.scanner._verify_s3_service(
                client, "test-backups", "postgres-dump", "production", "core-service",
                self.today, self.yesterday,
            )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].severity, "critical")
        self.assertIn("No files found", results[0].title)

    def test_small_file_warning(self):
        client = MagicMock()

        def mock_list_objects(bucket, prefix, max_keys=10):
            if f"/{self.today:%Y}/{self.today:%m}/{self.today:%d}/" in prefix:
                return [_make_object(size=100, age_hours=2)]
            return []

        client.list_objects.side_effect = mock_list_objects

        with patch("src.scanners.backup.config") as cfg:
            cfg.BACKUP_STORAGE_MIN_SIZE_BYTES = 1024
            cfg.BACKUP_STORAGE_DOWNLOAD_VERIFY = False
            cfg.BACKUP_SIZE_DROP_THRESHOLD = 0.5
            results = self.scanner._verify_s3_service(
                client, "test-backups", "postgres-dump", "production", "core-service",
                self.today, self.yesterday,
            )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].severity, "warning")
        self.assertIn("small", results[0].title)


    def test_download_verify_gzip_ok(self):
        import gzip as _gzip
        client = MagicMock()
        today_obj = _make_object(size=50000)

        def mock_list_objects(bucket, prefix, max_keys=10):
            if f"/{self.today:%Y}/{self.today:%m}/{self.today:%d}/" in prefix:
                return [today_obj]
            return []

        client.list_objects.side_effect = mock_list_objects
        # Create valid gzip with BSON-like content
        import struct
        raw = struct.pack("<i", 256) + b"\x00" * 252
        client.download_bytes.return_value = _gzip.compress(raw)

        with patch("src.scanners.backup.config") as cfg:
            cfg.BACKUP_STORAGE_MIN_SIZE_BYTES = 1024
            cfg.BACKUP_STORAGE_DOWNLOAD_VERIFY = True
            cfg.BACKUP_STORAGE_VERIFY_BYTES = 1048576
            cfg.BACKUP_SIZE_DROP_THRESHOLD = 0.5
            results = self.scanner._verify_s3_service(
                client, "test-backups", "postgres-dump", "production", "cms-service",
                self.today, self.yesterday,
            )

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].auto_resolve)

    def test_download_verify_invalid_format(self):
        client = MagicMock()
        today_obj = _make_object(size=50000)

        def mock_list_objects(bucket, prefix, max_keys=10):
            if f"/{self.today:%Y}/{self.today:%m}/{self.today:%d}/" in prefix:
                return [today_obj]
            return []

        client.list_objects.side_effect = mock_list_objects
        client.download_bytes.return_value = b"\x00" * 16

        with patch("src.scanners.backup.config") as cfg:
            cfg.BACKUP_STORAGE_MIN_SIZE_BYTES = 1024
            cfg.BACKUP_STORAGE_DOWNLOAD_VERIFY = True
            cfg.BACKUP_STORAGE_VERIFY_BYTES = 1048576
            cfg.BACKUP_SIZE_DROP_THRESHOLD = 0.5
            results = self.scanner._verify_s3_service(
                client, "test-backups", "postgres-dump", "production", "cms-service",
                self.today, self.yesterday,
            )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].severity, "warning")
        self.assertIn("integrity check failed", results[0].title)


class TestS3BackupDiscovery(unittest.TestCase):
    """Test _verify_s3_backups — discovers services from K8s secrets/pods."""

    def setUp(self):
        self.scanner = BackupScanner()

    @patch.object(BackupScanner, "_discover_postgres_services")
    @patch.object(BackupScanner, "_find_backup_namespaces")
    @patch("src.scanners.backup.config")
    def test_discovers_services_per_namespace(self, mock_config, mock_find_ns, mock_pg):
        mock_config.BACKUP_STORAGE_MIN_SIZE_BYTES = 1024
        mock_config.BACKUP_STORAGE_DOWNLOAD_VERIFY = False
        mock_config.BACKUP_SIZE_DROP_THRESHOLD = 0.5

        mock_find_ns.return_value = ["production"]
        mock_pg.return_value = ["core-service", "user-service"]

        client = MagicMock()
        client.bucket = "test-backups"
        client.list_objects.return_value = [_make_object(size=50000, age_hours=3)]

        results = self.scanner._verify_s3_backups(client)
        # one result per postgres service
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.auto_resolve for r in results))

    @patch("src.scanners.backup.config")
    def test_empty_bucket_returns_empty(self, mock_config):
        client = MagicMock()
        client.bucket = ""

        results = self.scanner._verify_s3_backups(client)
        self.assertEqual(results, [])

    @patch.object(BackupScanner, "_discover_postgres_services")
    @patch.object(BackupScanner, "_find_backup_namespaces")
    @patch("src.scanners.backup.config")
    def test_no_services_found(self, mock_config, mock_find_ns, mock_pg):
        mock_find_ns.return_value = ["production"]
        mock_pg.return_value = []

        client = MagicMock()
        client.bucket = "test-backups"

        results = self.scanner._verify_s3_backups(client)
        self.assertEqual(results, [])

    @patch.object(BackupScanner, "_discover_postgres_services")
    @patch.object(BackupScanner, "_find_backup_namespaces")
    @patch("src.scanners.backup.config")
    def test_no_backup_namespaces(self, _mock_config, mock_find_ns, mock_pg):
        mock_find_ns.return_value = []

        client = MagicMock()
        client.bucket = "test-backups"

        results = self.scanner._verify_s3_backups(client)
        self.assertEqual(results, [])
        mock_pg.assert_not_called()

    @patch.object(BackupScanner, "_discover_postgres_services")
    @patch.object(BackupScanner, "_find_backup_namespaces")
    @patch("src.scanners.backup.config")
    def test_mixed_success_and_failure(self, mock_config, mock_find_ns, mock_pg):
        mock_config.BACKUP_STORAGE_MIN_SIZE_BYTES = 1024
        mock_config.BACKUP_STORAGE_DOWNLOAD_VERIFY = False
        mock_config.BACKUP_SIZE_DROP_THRESHOLD = 0.5

        mock_find_ns.return_value = ["production"]
        mock_pg.return_value = ["core-service", "dead-service"]

        client = MagicMock()
        client.bucket = "test-backups"

        # core-service has file, dead-service has nothing
        def mock_list_objects(bucket, prefix, max_keys=10):
            if "core-service" in prefix:
                return [_make_object(size=50000)]
            return []

        client.list_objects.side_effect = mock_list_objects

        results = self.scanner._verify_s3_backups(client)
        self.assertEqual(len(results), 2)
        ok = [r for r in results if r.auto_resolve]
        critical = [r for r in results if r.severity == "critical"]
        self.assertEqual(len(ok), 1)
        self.assertEqual(len(critical), 1)
        self.assertIn("dead-service", critical[0].title)


# ── _check_storage scheduling ───────────────────────────────────────


class TestStorageScheduling(unittest.TestCase):
    def setUp(self):
        self.scanner = BackupScanner()

    @patch("src.scanners.backup.config")
    def test_disabled_when_no_provider(self, mock_config):
        mock_config.BACKUP_STORAGE_PROVIDER = ""
        results = self.scanner._check_storage()
        self.assertEqual(results, [])

    @patch("src.scanners.backup.datetime")
    @patch("src.scanners.backup.config")
    def test_skipped_outside_verify_hour(self, mock_config, mock_dt):
        mock_config.BACKUP_STORAGE_PROVIDER = "s3"
        mock_config.BACKUP_STORAGE_VERIFY_HOUR_UTC = 7
        now = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)  # hour=10, not 7
        mock_dt.now.return_value = now
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)

        results = self.scanner._check_storage()
        self.assertEqual(results, [])

    @patch("src.scanners.backup.config")
    def test_skipped_when_already_ran_today(self, mock_config):
        mock_config.BACKUP_STORAGE_PROVIDER = "s3"
        mock_config.BACKUP_STORAGE_VERIFY_HOUR_UTC = _utc_now().hour

        self.scanner._last_storage_check_date = _utc_now().date()

        results = self.scanner._check_storage()
        self.assertEqual(results, [])


# ── Storage client factory ──────────────────────────────────────────


class TestStorageClientFactory(unittest.TestCase):
    @patch("src.scanners.storage_verify.config")
    def test_s3_provider(self, mock_config):
        mock_config.BACKUP_STORAGE_PROVIDER = "s3"
        from src.scanners.storage_verify import get_storage_client
        client = get_storage_client()
        self.assertIsInstance(client, S3Client)

    @patch("src.scanners.storage_verify.config")
    def test_gcs_provider(self, mock_config):
        mock_config.BACKUP_STORAGE_PROVIDER = "gcs"
        from src.scanners.storage_verify import get_storage_client
        client = get_storage_client()
        self.assertIsInstance(client, GCSClient)

    @patch("src.scanners.storage_verify.config")
    def test_empty_provider(self, mock_config):
        mock_config.BACKUP_STORAGE_PROVIDER = ""
        from src.scanners.storage_verify import get_storage_client
        client = get_storage_client()
        self.assertIsNone(client)

    @patch("src.scanners.storage_verify.config")
    def test_unknown_provider(self, mock_config):
        mock_config.BACKUP_STORAGE_PROVIDER = "azure"
        from src.scanners.storage_verify import get_storage_client
        client = get_storage_client()
        self.assertIsNone(client)


# ── File integrity verification ────────────────────────────────────


class TestFileIntegrityVerification(unittest.TestCase):
    def setUp(self):
        self.scanner = BackupScanner()

    @patch("src.scanners.backup.config")
    def test_pgdump_custom_format(self, mock_config):
        mock_config.BACKUP_STORAGE_VERIFY_BYTES = 1048576
        client = MagicMock()
        client.download_bytes.return_value = b"PGDMP\x01\x0e\x00" + b"\x00" * 8
        ok, reason = self.scanner._verify_file_integrity(client, "bucket", "key", "postgres-dump")
        self.assertTrue(ok)
        self.assertIn("pg_dump custom format", reason)

    @patch("src.scanners.backup.config")
    def test_gzip_with_sql_markers(self, mock_config):
        import gzip as _gzip
        mock_config.BACKUP_STORAGE_VERIFY_BYTES = 1048576
        client = MagicMock()
        # Create a real gzip payload with SQL content
        raw = b"SET statement_timeout = 0;\nCREATE TABLE test (\n  id int\n);\n"
        compressed = _gzip.compress(raw)
        client.download_bytes.return_value = compressed
        ok, reason = self.scanner._verify_file_integrity(client, "bucket", "key", "postgres-dump")
        self.assertTrue(ok)
        self.assertIn("SQL markers", reason)


    @patch("src.scanners.backup.config")
    def test_bad_gzip(self, mock_config):
        mock_config.BACKUP_STORAGE_VERIFY_BYTES = 1048576
        client = MagicMock()
        # gzip magic header but corrupt data
        client.download_bytes.return_value = b"\x1f\x8b\x08\x00" + b"\xff" * 100
        ok, reason = self.scanner._verify_file_integrity(client, "bucket", "key", "postgres-dump")
        # Should either fail or succeed with a partial decompression note
        # The important thing is it doesn't crash
        self.assertIsInstance(ok, bool)
        self.assertIsInstance(reason, str)

    @patch("src.scanners.backup.config")
    def test_all_null_invalid(self, mock_config):
        mock_config.BACKUP_STORAGE_VERIFY_BYTES = 1048576
        client = MagicMock()
        client.download_bytes.return_value = b"\x00" * 16
        ok, reason = self.scanner._verify_file_integrity(client, "bucket", "key", "postgres-dump")
        self.assertFalse(ok)
        self.assertIn("null", reason)

    @patch("src.scanners.backup.config")
    def test_empty_file_invalid(self, mock_config):
        mock_config.BACKUP_STORAGE_VERIFY_BYTES = 1048576
        client = MagicMock()
        client.download_bytes.return_value = b""
        ok, reason = self.scanner._verify_file_integrity(client, "bucket", "key", "postgres-dump")
        self.assertFalse(ok)
        self.assertIn("empty", reason)

    @patch("src.scanners.backup.config")
    def test_download_error_assumes_ok(self, mock_config):
        mock_config.BACKUP_STORAGE_VERIFY_BYTES = 1048576
        client = MagicMock()
        client.download_bytes.side_effect = Exception("timeout")
        ok, reason = self.scanner._verify_file_integrity(client, "bucket", "key", "postgres-dump")
        self.assertTrue(ok)
        self.assertIn("assuming OK", reason)

    @patch("src.scanners.backup.config")
    def test_non_null_binary_valid(self, mock_config):
        mock_config.BACKUP_STORAGE_VERIFY_BYTES = 1048576
        client = MagicMock()
        client.download_bytes.return_value = b"\x42\x53\x4f\x4e" + b"\x00" * 12
        ok, reason = self.scanner._verify_file_integrity(client, "bucket", "key", "postgres-dump")
        self.assertTrue(ok)
        self.assertIn("non-null", reason)


# ── Size trending ──────────────────────────────────────────────────


class TestSizeTrending(unittest.TestCase):
    def setUp(self):
        self.scanner = BackupScanner()
        self.today = _utc_now().date()
        self.yesterday = self.today - timedelta(days=1)

    def test_size_drop_warning(self):
        """Backup size dropped >50% → warning."""
        client = MagicMock()
        # Today: 10KB, Yesterday: 50KB → 80% drop
        today_obj = _make_object(size=10000, age_hours=2)
        yesterday_obj = _make_object(size=50000, age_hours=26)

        def mock_list_objects(bucket, prefix, max_keys=10):
            if f"/{self.today:%Y}/{self.today:%m}/{self.today:%d}/" in prefix:
                return [today_obj]
            if f"/{self.yesterday:%Y}/{self.yesterday:%m}/{self.yesterday:%d}/" in prefix:
                return [yesterday_obj]
            return []

        client.list_objects.side_effect = mock_list_objects

        with patch("src.scanners.backup.config") as cfg:
            cfg.BACKUP_STORAGE_MIN_SIZE_BYTES = 1024
            cfg.BACKUP_STORAGE_DOWNLOAD_VERIFY = False
            cfg.BACKUP_SIZE_DROP_THRESHOLD = 0.5
            results = self.scanner._verify_s3_service(
                client, "bucket", "postgres-dump", "production", "core-service",
                self.today, self.yesterday,
            )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].severity, "warning")
        self.assertIn("dropped", results[0].title)

    def test_normal_size_no_warning(self):
        """Backup size similar to yesterday → OK."""
        client = MagicMock()
        today_obj = _make_object(size=50000, age_hours=2)
        yesterday_obj = _make_object(size=48000, age_hours=26)

        def mock_list_objects(bucket, prefix, max_keys=10):
            if f"/{self.today:%Y}/{self.today:%m}/{self.today:%d}/" in prefix:
                return [today_obj]
            if f"/{self.yesterday:%Y}/{self.yesterday:%m}/{self.yesterday:%d}/" in prefix:
                return [yesterday_obj]
            return []

        client.list_objects.side_effect = mock_list_objects

        with patch("src.scanners.backup.config") as cfg:
            cfg.BACKUP_STORAGE_MIN_SIZE_BYTES = 1024
            cfg.BACKUP_STORAGE_DOWNLOAD_VERIFY = False
            cfg.BACKUP_SIZE_DROP_THRESHOLD = 0.5
            results = self.scanner._verify_s3_service(
                client, "bucket", "postgres-dump", "production", "core-service",
                self.today, self.yesterday,
            )

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].auto_resolve)

    def test_no_yesterday_skips_trending(self):
        """No yesterday files → skip trending, still OK if today is fine."""
        client = MagicMock()
        today_obj = _make_object(size=50000, age_hours=2)

        def mock_list_objects(bucket, prefix, max_keys=10):
            if f"/{self.today:%Y}/{self.today:%m}/{self.today:%d}/" in prefix:
                return [today_obj]
            return []

        client.list_objects.side_effect = mock_list_objects

        with patch("src.scanners.backup.config") as cfg:
            cfg.BACKUP_STORAGE_MIN_SIZE_BYTES = 1024
            cfg.BACKUP_STORAGE_DOWNLOAD_VERIFY = False
            cfg.BACKUP_SIZE_DROP_THRESHOLD = 0.5
            results = self.scanner._verify_s3_service(
                client, "bucket", "postgres-dump", "production", "core-service",
                self.today, self.yesterday,
            )

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].auto_resolve)


# ── CronJob ↔ S3 Cross-check ──────────────────────────────────────


class TestCrossCheckCronJobS3(unittest.TestCase):
    def setUp(self):
        self.scanner = BackupScanner()

    def test_parse_service_from_cronjob(self):
        self.assertEqual(
            BackupScanner._parse_service_from_cronjob("postgres-backup-core-service"),
            ("core-service", "postgres-dump"),
        )
        self.assertEqual(
            BackupScanner._parse_service_from_cronjob("pg-backup-user-service"),
            ("user-service", "postgres-dump"),
        )
        self.assertIsNone(BackupScanner._parse_service_from_cronjob("cleanup-daily"))

    @patch("src.scanners.backup.config")
    @patch("src.scanners.backup.k8s.BatchV1Api")
    def test_success_but_no_s3_file(self, mock_api_class, mock_config):
        mock_config.get_namespaces.return_value = ["production"]
        mock_config.EXCLUDE_NAMESPACES = set()

        api = mock_api_class.return_value
        cj = _make_cronjob("postgres-backup-core-service", last_success=_hours_ago(1))
        api.list_namespaced_cron_job.return_value = MagicMock(items=[cj])

        client = MagicMock()
        client.bucket = "test-backups"
        client.list_objects.return_value = []  # No S3 file

        results = self.scanner._cross_check_cronjob_s3(client)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].severity, "critical")
        self.assertIn("reports success but no file", results[0].title)

    @patch("src.scanners.backup.config")
    @patch("src.scanners.backup.k8s.BatchV1Api")
    def test_success_with_s3_file_ok(self, mock_api_class, mock_config):
        mock_config.get_namespaces.return_value = ["production"]
        mock_config.EXCLUDE_NAMESPACES = set()

        api = mock_api_class.return_value
        cj = _make_cronjob("postgres-backup-core-service", last_success=_hours_ago(1))
        api.list_namespaced_cron_job.return_value = MagicMock(items=[cj])

        client = MagicMock()
        client.bucket = "test-backups"
        client.list_objects.return_value = [_make_object(size=50000)]

        results = self.scanner._cross_check_cronjob_s3(client)
        self.assertEqual(len(results), 0)

    @patch("src.scanners.backup.config")
    @patch("src.scanners.backup.k8s.BatchV1Api")
    def test_no_success_skipped(self, mock_api_class, mock_config):
        """CronJob with no last_successful_time → skip cross-check."""
        mock_config.get_namespaces.return_value = ["production"]
        mock_config.EXCLUDE_NAMESPACES = set()

        api = mock_api_class.return_value
        cj = _make_cronjob("postgres-backup-core-service", last_success=None)
        api.list_namespaced_cron_job.return_value = MagicMock(items=[cj])

        client = MagicMock()
        client.bucket = "test-backups"

        results = self.scanner._cross_check_cronjob_s3(client)
        self.assertEqual(len(results), 0)

    @patch("src.scanners.backup.config")
    @patch("src.scanners.backup.k8s.BatchV1Api")
    def test_yesterday_success_skipped(self, mock_api_class, mock_config):
        """CronJob with success yesterday → skip (only check today)."""
        mock_config.get_namespaces.return_value = ["production"]
        mock_config.EXCLUDE_NAMESPACES = set()

        api = mock_api_class.return_value
        cj = _make_cronjob("postgres-backup-core-service", last_success=_hours_ago(25))
        api.list_namespaced_cron_job.return_value = MagicMock(items=[cj])

        client = MagicMock()
        client.bucket = "test-backups"

        results = self.scanner._cross_check_cronjob_s3(client)
        self.assertEqual(len(results), 0)

    @patch("src.scanners.backup.config")
    @patch("src.scanners.backup.k8s.BatchV1Api")
    def test_unparseable_cronjob_name_skipped(self, mock_api_class, mock_config):
        """CronJob name that doesn't match known patterns → skip."""
        mock_config.get_namespaces.return_value = ["production"]
        mock_config.EXCLUDE_NAMESPACES = set()

        api = mock_api_class.return_value
        # "postgres-backup" without service suffix won't parse
        cj = _make_cronjob("postgres-backup", last_success=_hours_ago(1))
        api.list_namespaced_cron_job.return_value = MagicMock(items=[cj])

        client = MagicMock()
        client.bucket = "test-backups"

        results = self.scanner._cross_check_cronjob_s3(client)
        self.assertEqual(len(results), 0)


# ── Auto-resolve ────────────────────────────────────────────────────


class TestAutoResolve(unittest.TestCase):
    def setUp(self):
        self.scanner = BackupScanner()

    @patch("src.scanners.backup.k8s.CustomObjectsApi")
    def test_cnpg_auto_resolve_after_recovery(self, mock_api_class):
        api = mock_api_class.return_value
        api.list_cluster_custom_object.return_value = {
            "items": [_make_scheduled_backup("sb1", "production", "pg-cluster")],
        }
        # First: failed
        api.list_namespaced_custom_object.return_value = {
            "items": [_make_cnpg_backup("bk1", "production", "pg-cluster", "failed", 1)],
        }
        results1 = self.scanner._check_cnpg()
        self.assertEqual(len(results1), 1)
        self.assertFalse(results1[0].auto_resolve)

        # Then: recovered
        api.list_namespaced_custom_object.return_value = {
            "items": [
                _make_cnpg_backup("bk2", "production", "pg-cluster", "completed", 0.5),
                _make_cnpg_backup("bk1", "production", "pg-cluster", "failed", 1),
            ],
        }
        results2 = self.scanner._check_cnpg()
        self.assertEqual(len(results2), 1)
        self.assertTrue(results2[0].auto_resolve)


if __name__ == "__main__":
    unittest.main()


class TestNoSecretAccess(unittest.TestCase):
    """The monitor has no access to Secrets by design (least privilege)."""

    @patch("src.scanners.backup.k8s.CoreV1Api")
    @patch("src.scanners.backup.k8s.BatchV1Api")
    def test_postgres_services_come_from_backup_cronjobs(self, mock_batch, mock_core):
        mock_batch.return_value.list_namespaced_cron_job.return_value.items = [
            _make_cronjob("postgres-backup-app"),
            _make_cronjob("pg-backup-billing"),
            _make_cronjob("mongo-backup-orders"),
            _make_cronjob("cleanup-logs"),
        ]
        self.assertEqual(BackupScanner._discover_postgres_services("prod"), ["app", "billing"])
        mock_core.return_value.list_namespaced_secret.assert_not_called()

    def test_image_pull_diagnostic_does_not_read_secrets(self):
        from src.diagnostics.image_pull import ImagePullDiagnostic

        core = MagicMock()
        pod = MagicMock()
        pod.metadata.namespace = "develop"
        pod.spec.containers = []
        secret_ref = MagicMock()
        secret_ref.name = "ghcr-credentials"
        pod.spec.image_pull_secrets = [secret_ref]
        data = ImagePullDiagnostic().diagnose(core, pod)
        core.read_namespaced_secret.assert_not_called()
        self.assertEqual(data["pull_secrets"][0]["name"], "ghcr-credentials")


class TestCertificateStatusWithoutSecrets(unittest.TestCase):
    def _certs(self, *items):
        return {"items": list(items)}

    def _cert(self, name, secret, status):
        return {"metadata": {"name": name}, "spec": {"secretName": secret},
                "status": {"conditions": [{"type": "Ready", "status": status, "message": "m"}]}}

    @patch("src.scanners.critical_endpoint.k8s.CustomObjectsApi")
    def test_ready_certificate(self, mock_api):
        from src.scanners.critical_endpoint import _certificate_status
        mock_api.return_value.list_namespaced_custom_object.return_value = self._certs(
            self._cert("frontend", "frontend-tls", "True"))
        self.assertTrue(_certificate_status("develop", "frontend-tls").startswith("ready"))

    @patch("src.scanners.critical_endpoint.k8s.CustomObjectsApi")
    def test_not_ready_and_unknown_secret(self, mock_api):
        from src.scanners.critical_endpoint import _certificate_status
        mock_api.return_value.list_namespaced_custom_object.return_value = self._certs(
            self._cert("frontend", "frontend-tls", "False"))
        self.assertTrue(_certificate_status("develop", "frontend-tls").startswith("NOT READY"))
        self.assertIn("no cert-manager Certificate", _certificate_status("develop", "other-tls"))

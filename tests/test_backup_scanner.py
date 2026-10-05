"""Tests for the backup scanner - CloudNativePG Backups and recoverability."""
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from src.scanners.backup import BackupScanner


# ── Helpers ──────────────────────────────────────────────────────────


def _utc_now():
    return datetime.now(timezone.utc)


def _hours_ago(h: float) -> datetime:
    return _utc_now() - timedelta(hours=h)


_UNSET = object()


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


def _make_cnpg_cluster(
    name, ns, last_success_hours=None, created_hours=1000, first_rp_hours=None,
):
    """Build a CNPG Cluster object dict as the k8s client returns it.

    `last_success_hours=None` models a cluster whose status has no
    lastSuccessfulBackup at all (never completed one). `created_hours` defaults
    well past BACKUP_MAX_AGE_HOURS so the never-backed-up grace does not silently
    change what a test asserts.
    """
    status = {}
    if last_success_hours is not None:
        status["lastSuccessfulBackup"] = (
            _utc_now() - timedelta(hours=last_success_hours)
        ).isoformat()
    if first_rp_hours is not None:
        status["firstRecoverabilityPoint"] = (
            _utc_now() - timedelta(hours=first_rp_hours)
        ).isoformat()
    return {
        "metadata": {
            "name": name,
            "namespace": ns,
            "creationTimestamp": (_utc_now() - timedelta(hours=created_hours)).isoformat(),
        },
        "spec": {},
        "status": status,
    }


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


# ── CNPG Recoverability (lastSuccessfulBackup) ──────────────────────


class TestCNPGRecoverability(unittest.TestCase):
    """The authoritative check on cluster.status.lastSuccessfulBackup.

    Guards a blind spot: a cluster minting a fresh, empty-phase Backup
    every day looks perpetually young to the per-Backup logic and slips through,
    while its last completed backup is months stale.
    """

    def setUp(self):
        self.scanner = BackupScanner()

    @staticmethod
    def _rec(results):
        return [r for r in results if r.state_key.startswith("Backup:cnpg-recoverability:")]

    @patch("src.scanners.backup.k8s.CustomObjectsApi")
    def test_stale_last_success_alerts_despite_young_pending_backup(self, mock_api_class):
        """The blind-spot case - fails against pre-fix code.

        Latest Backup CR is young (9h) with an empty phase (queued behind a
        zombie), so the per-Backup logic emits nothing. But lastSuccessfulBackup
        is 82 days old. Pre-fix: zero results. Post-fix: one critical.
        """
        api = mock_api_class.return_value
        api.list_cluster_custom_object.return_value = {
            "items": [_make_scheduled_backup("postgresql-daily-backup", "production", "postgresql")],
        }
        # The daily-recreated pending CR: young, empty phase → slips every branch.
        api.list_namespaced_custom_object.return_value = {
            "items": [_make_cnpg_backup("postgresql-daily-backup-today", "production", "postgresql", phase="", age_hours=9)],
        }
        # But the cluster has not had a successful backup for 82 days.
        api.get_namespaced_custom_object.return_value = _make_cnpg_cluster(
            "postgresql", "production", last_success_hours=82 * 24, first_rp_hours=85 * 24,
        )

        results = self.scanner._check_cnpg()
        rec = self._rec(results)
        self.assertEqual(len(rec), 1, "recoverability must alert on 82-day-stale last success")
        self.assertEqual(rec[0].severity, "critical")
        self.assertIn("SUCCESSFUL backup", rec[0].title)

    @patch("src.scanners.backup.k8s.CustomObjectsApi")
    def test_fresh_last_success_is_ok(self, mock_api_class):
        api = mock_api_class.return_value
        api.list_cluster_custom_object.return_value = {
            "items": [_make_scheduled_backup("sb1", "production", "pg-cluster")],
        }
        api.list_namespaced_custom_object.return_value = {
            "items": [_make_cnpg_backup("bk1", "production", "pg-cluster", "completed", 2)],
        }
        api.get_namespaced_custom_object.return_value = _make_cnpg_cluster(
            "pg-cluster", "production", last_success_hours=6,
        )

        rec = self._rec(self.scanner._check_cnpg())
        self.assertEqual(len(rec), 1)
        self.assertTrue(rec[0].auto_resolve, "fresh recoverability must auto-resolve")

    @patch("src.scanners.backup.k8s.CustomObjectsApi")
    def test_never_backed_up_old_cluster_alerts(self, mock_api_class):
        api = mock_api_class.return_value
        api.list_cluster_custom_object.return_value = {
            "items": [_make_scheduled_backup("sb1", "production", "pg-cluster")],
        }
        api.list_namespaced_custom_object.return_value = {"items": []}
        api.get_namespaced_custom_object.return_value = _make_cnpg_cluster(
            "pg-cluster", "production", last_success_hours=None, created_hours=1000,
        )

        rec = self._rec(self.scanner._check_cnpg())
        self.assertEqual(len(rec), 1)
        self.assertEqual(rec[0].severity, "critical")
        self.assertIn("no successful backup", rec[0].title)

    @patch("src.scanners.backup.k8s.CustomObjectsApi")
    def test_never_backed_up_young_cluster_is_grace(self, mock_api_class):
        """A just-created cluster whose first backup has not run yet must not
        alert - a new cluster gets a grace period."""
        api = mock_api_class.return_value
        api.list_cluster_custom_object.return_value = {
            "items": [_make_scheduled_backup("sb1", "production", "pg-cluster")],
        }
        api.list_namespaced_custom_object.return_value = {"items": []}
        api.get_namespaced_custom_object.return_value = _make_cnpg_cluster(
            "pg-cluster", "production", last_success_hours=None, created_hours=3,
        )

        rec = self._rec(self.scanner._check_cnpg())
        self.assertEqual(rec, [], "young cluster with no backup yet is grace, not an alert")

    @patch("src.scanners.backup.k8s.CustomObjectsApi")
    def test_multiple_scheduled_backups_same_cluster_checked_once(self, mock_api_class):
        """Two ScheduledBackups (daily + weekly) targeting one cluster must
        yield exactly ONE recoverability result — the state_key is per cluster,
        so per-ScheduledBackup checks would duplicate GETs and results."""
        api = mock_api_class.return_value
        api.list_cluster_custom_object.return_value = {
            "items": [
                _make_scheduled_backup("sb-daily", "production", "pg-cluster"),
                _make_scheduled_backup("sb-weekly", "production", "pg-cluster", schedule="0 0 * * 0"),
            ],
        }
        api.list_namespaced_custom_object.return_value = {
            "items": [_make_cnpg_backup("bk1", "production", "pg-cluster", "completed", 2)],
        }
        api.get_namespaced_custom_object.return_value = _make_cnpg_cluster(
            "pg-cluster", "production", last_success_hours=6,
        )

        rec = self._rec(self.scanner._check_cnpg())
        self.assertEqual(len(rec), 1, "one recoverability result per cluster, not per ScheduledBackup")
        self.assertEqual(rec[0].state_key, "Backup:cnpg-recoverability:production/pg-cluster")
        self.assertEqual(api.get_namespaced_custom_object.call_count, 1)

    @patch("src.scanners.backup.k8s.CustomObjectsApi")
    def test_cluster_fetch_failure_is_silent(self, mock_api_class):
        """If the cluster object cannot be read, emit no recoverability verdict
        rather than a fabricated one."""
        from kubernetes.client import ApiException
        api = mock_api_class.return_value
        api.list_cluster_custom_object.return_value = {
            "items": [_make_scheduled_backup("sb1", "production", "pg-cluster")],
        }
        api.list_namespaced_custom_object.return_value = {
            "items": [_make_cnpg_backup("bk1", "production", "pg-cluster", "completed", 2)],
        }
        api.get_namespaced_custom_object.side_effect = ApiException(status=500)

        rec = self._rec(self.scanner._check_cnpg())
        self.assertEqual(rec, [])






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

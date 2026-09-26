import os
import logging
from kubernetes import client as k8s

class _ColorFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[90m",       # gray
        "INFO": "\033[36m",        # cyan
        "WARNING": "\033[33m",     # yellow
        "ERROR": "\033[31m",       # red
        "CRITICAL": "\033[1;31m",  # bold red
    }
    RESET = "\033[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelname, "")
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


_handler = logging.StreamHandler()
_handler.setFormatter(_ColorFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    handlers=[_handler],
)

CLUSTER_NAME = os.environ.get("CLUSTER_NAME", "unknown")
_raw_namespaces = os.environ.get("WATCH_NAMESPACES", "production")
WATCH_ALL_NAMESPACES = _raw_namespaces.strip() in ("*", "")
NAMESPACES = [] if WATCH_ALL_NAMESPACES else [ns.strip() for ns in _raw_namespaces.split(",")]
_raw_exclude = os.environ.get("EXCLUDE_NAMESPACES", os.environ.get("ENDPOINT_SCAN_EXCLUDE_NAMESPACES", ""))
EXCLUDE_NAMESPACES = {ns.strip() for ns in _raw_exclude.split(",") if ns.strip()}

# Non-prod: monitored but LLM only for critical_endpoint scanner
_raw_nonprod = os.environ.get("NON_PROD_NAMESPACES", "")
NON_PROD_NAMESPACES: set[str] = {ns.strip() for ns in _raw_nonprod.split(",") if ns.strip()}
NON_PROD_DEBOUNCE_MULTIPLIER = int(os.environ.get("NON_PROD_DEBOUNCE_MULTIPLIER", "2"))
SLACK_WEBHOOK_URL_NONPROD = os.environ.get("SLACK_WEBHOOK_URL_NONPROD", "")

# LLM
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "anthropic")  # anthropic | openai
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
LLM_MODEL = os.environ.get("LLM_MODEL", "")  # auto-selected per provider if empty
LLM_MODEL_REPORT = os.environ.get("LLM_MODEL_REPORT", "")  # model for daily reports (expensive tier)
LLM_DEBUG = os.environ.get("LLM_DEBUG", "false").lower() == "true"

# Slack
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")

# Prometheus
PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://prometheus-operated:9090")

# Elasticsearch
ELASTICSEARCH_URL = os.environ.get("ELASTICSEARCH_URL", "")
ELASTICSEARCH_USER = os.environ.get("ELASTICSEARCH_USER", "elastic")
ELASTICSEARCH_PASSWORD = os.environ.get("ELASTICSEARCH_PASSWORD", "")
ELASTICSEARCH_INDEX_PREFIX = os.environ.get("ELASTICSEARCH_INDEX_PREFIX", "")  # default: CLUSTER_NAME

# Uptrace
UPTRACE_API_URL = os.environ.get("UPTRACE_API_URL", "")
UPTRACE_API_TOKEN = os.environ.get("UPTRACE_API_TOKEN", "")
UPTRACE_PROJECT_ID = os.environ.get("UPTRACE_PROJECT_ID", "1")

# Watcher
DEBOUNCE_SECONDS = int(os.environ.get("DEBOUNCE_SECONDS", "1800"))  # 30 min
NODE_READY_GRACE_SECONDS = int(os.environ.get("NODE_READY_GRACE_SECONDS", "300"))  # 5 min
NODE_NOT_READY_GRACE_SECONDS = int(os.environ.get("NODE_NOT_READY_GRACE_SECONDS", "120"))  # 2 min
POD_LOG_LINES = int(os.environ.get("POD_LOG_LINES", "50"))

# Rate limiting
MAX_LLM_CALLS_PER_HOUR = int(os.environ.get("MAX_LLM_CALLS_PER_HOUR", "20"))

# Context size caps (bytes) — hard limit before LLM call
MAX_CONTEXT_BYTES_ALERT = int(os.environ.get("MAX_CONTEXT_BYTES_ALERT", "16000"))
MAX_CONTEXT_BYTES_REPORT = int(os.environ.get("MAX_CONTEXT_BYTES_REPORT", "80000"))

# Pod scanner
SCANNER_INTERVAL_SECONDS = int(os.environ.get("SCANNER_INTERVAL_SECONDS", "1800"))  # 30 min

# PVC scanner
PVC_SCAN_INTERVAL_SECONDS = int(os.environ.get("PVC_SCAN_INTERVAL_SECONDS", "3600"))  # 1 hour
PVC_WARNING_THRESHOLD = float(os.environ.get("PVC_WARNING_THRESHOLD", "0.8"))  # 80%
PVC_CRITICAL_THRESHOLD = float(os.environ.get("PVC_CRITICAL_THRESHOLD", "0.9"))  # 90%

# cert-manager scanner
CERT_SCAN_INTERVAL_SECONDS = int(os.environ.get("CERT_SCAN_INTERVAL_SECONDS", "3600"))  # 1 hour
CERT_EXPIRY_WARNING_DAYS = int(os.environ.get("CERT_EXPIRY_WARNING_DAYS", "14"))

# HTTP auth for write endpoints
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "")

# Endpoint scanner
ENDPOINT_SCAN_ENABLED = os.environ.get("ENDPOINT_SCAN_ENABLED", "false").lower() == "true"
ENDPOINT_SCAN_INTERVAL_SECONDS = int(os.environ.get("ENDPOINT_SCAN_INTERVAL_SECONDS", "300"))  # 5 min
ENDPOINT_SCAN_TIMEOUT = int(os.environ.get("ENDPOINT_SCAN_TIMEOUT", "10"))  # seconds
ENDPOINT_INGRESS_SERVICE = os.environ.get("ENDPOINT_INGRESS_SERVICE", "")  # e.g. "traefik.traefik.svc.cluster.local"
ENDPOINT_BATCH_THRESHOLD = int(os.environ.get("ENDPOINT_BATCH_THRESHOLD", "3"))  # min endpoints to trigger batch mode
ENDPOINT_REDIS_SERVICE = os.environ.get("ENDPOINT_REDIS_SERVICE", "")  # fallback Redis address; e.g. "redis-master.production.svc.cluster.local:6379"

# Backup scanner
SCANNER_BACKUP_ENABLED = os.environ.get("SCANNER_BACKUP_ENABLED", "true").lower() == "true"
BACKUP_SCAN_INTERVAL_SECONDS = int(os.environ.get("BACKUP_SCAN_INTERVAL_SECONDS", "3600"))  # 1 hour
BACKUP_MAX_AGE_HOURS = int(os.environ.get("BACKUP_MAX_AGE_HOURS", "26"))  # slightly over 24h

# Storage verification
BACKUP_STORAGE_PROVIDER = os.environ.get("BACKUP_STORAGE_PROVIDER", "")  # "s3", "gcs", or "" (disabled)
BACKUP_STORAGE_VERIFY_HOUR_UTC = int(os.environ.get("BACKUP_STORAGE_VERIFY_HOUR_UTC", "7"))
BACKUP_STORAGE_DOWNLOAD_VERIFY = os.environ.get("BACKUP_STORAGE_DOWNLOAD_VERIFY", "false").lower() == "true"
BACKUP_STORAGE_VERIFY_BYTES = int(os.environ.get("BACKUP_STORAGE_VERIFY_BYTES", "1048576"))  # 1MB
BACKUP_STORAGE_MIN_SIZE_BYTES = int(os.environ.get("BACKUP_STORAGE_MIN_SIZE_BYTES", "1024"))
BACKUP_SIZE_DROP_THRESHOLD = float(os.environ.get("BACKUP_SIZE_DROP_THRESHOLD", "0.5"))
BACKUP_S3_SECRET_NAME = os.environ.get("BACKUP_S3_SECRET_NAME", "s3-backup-credentials")
BACKUP_S3_SECRET_NAMESPACE = os.environ.get("BACKUP_S3_SECRET_NAMESPACE", "")

# S3: dump type prefixes to scan (comma-separated top-level dirs in bucket)
BACKUP_STORAGE_S3_DUMP_PREFIXES = [
    p.strip() for p in os.environ.get("BACKUP_STORAGE_S3_DUMP_PREFIXES", "postgres-dump").split(",") if p.strip()
]

# Scanner feature flags
SCANNER_POD_ENABLED = os.environ.get("SCANNER_POD_ENABLED", "true").lower() == "true"
SCANNER_PVC_ENABLED = os.environ.get("SCANNER_PVC_ENABLED", "true").lower() == "true"
SCANNER_CERT_ENABLED = os.environ.get("SCANNER_CERT_ENABLED", "true").lower() == "true"
# ENDPOINT_SCAN_ENABLED is already defined above

# Critical endpoint scanner
SCANNER_CRITICAL_ENDPOINT_ENABLED = os.environ.get("SCANNER_CRITICAL_ENDPOINT_ENABLED", "false").lower() == "true"
CRITICAL_ENDPOINT_INTERVAL_SECONDS = int(os.environ.get("CRITICAL_ENDPOINT_INTERVAL_SECONDS", "60"))
CRITICAL_ENDPOINT_CHAIN_DEPTH = int(os.environ.get("CRITICAL_ENDPOINT_CHAIN_DEPTH", "3"))
_raw_ce_exclude = os.environ.get("CRITICAL_ENDPOINT_EXCLUDE_NAMES", "")
CRITICAL_ENDPOINT_EXCLUDE_NAMES: set[str] = {n.strip() for n in _raw_ce_exclude.split(",") if n.strip()}
CRITICAL_ENDPOINT_INGRESS_NAMESPACES = os.environ.get("CRITICAL_ENDPOINT_INGRESS_NAMESPACES", "traefik,kube-system")

# Auto-maintenance detection (GKE node upgrades, etc.)
AUTO_MAINTENANCE_ENABLED = os.environ.get("AUTO_MAINTENANCE_ENABLED", "false").lower() == "true"
AUTO_MAINTENANCE_NODE_THRESHOLD = int(os.environ.get("AUTO_MAINTENANCE_NODE_THRESHOLD", "2"))
AUTO_MAINTENANCE_CHECK_INTERVAL = int(os.environ.get("AUTO_MAINTENANCE_CHECK_INTERVAL", "30"))
AUTO_MAINTENANCE_DURATION_HOURS = float(os.environ.get("AUTO_MAINTENANCE_DURATION_HOURS", "2"))

# State persistence
SQLITE_PATH = os.environ.get("SQLITE_PATH", "/data/k8s-ai-monitor.db")

# Escalation
ESCALATION_RECURRING_WINDOW_H = float(os.environ.get("ESCALATION_RECURRING_WINDOW_HOURS", "6"))
ESCALATION_PERSISTENT_MIN_COUNT = int(os.environ.get("ESCALATION_PERSISTENT_MIN_OCCURRENCES", "3"))
ESCALATION_PERSISTENT_MIN_AGE_H = float(os.environ.get("ESCALATION_PERSISTENT_MIN_AGE_HOURS", "1"))

# Daily report — timezone-aware scheduling
REPORT_TIMEZONE = os.environ.get("REPORT_TIMEZONE", "Europe/Sofia")
# If DAILY_REPORT_HOUR is explicitly set, use it; otherwise fall back to DAILY_REPORT_HOUR_UTC
_daily_hour_explicit = os.environ.get("DAILY_REPORT_HOUR")
if _daily_hour_explicit is not None:
    DAILY_REPORT_HOUR = int(_daily_hour_explicit)
else:
    DAILY_REPORT_HOUR = int(os.environ.get("DAILY_REPORT_HOUR_UTC", "9"))
# Keep for backward compat — unused internally but referenced in tests/docs
DAILY_REPORT_HOUR_UTC = DAILY_REPORT_HOUR  # deprecated alias

# Weekly report
WEEKLY_REPORT_ENABLED = os.environ.get("WEEKLY_REPORT_ENABLED", "true").lower() == "true"
WEEKLY_REPORT_DAY = int(os.environ.get("WEEKLY_REPORT_DAY", "0"))  # 0=Monday (ISO weekday)
WEEKLY_REPORT_HOUR = int(os.environ.get("WEEKLY_REPORT_HOUR", "9"))  # local time

# Central ClickHouse push
CENTRAL_AGGREGATE = os.environ.get("CENTRAL_AGGREGATE", "false").lower() == "true"
CENTRAL_CH_URL = os.environ.get("CENTRAL_CH_URL", "")
CENTRAL_CH_USER = os.environ.get("CENTRAL_CH_USER", "monitor")
CENTRAL_CH_PASSWORD = os.environ.get("CENTRAL_CH_PASSWORD", "")
CENTRAL_CH_DATABASE = os.environ.get("CENTRAL_CH_DATABASE", "monitor")

_SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease", "flux-system"}

_NONPROD_PREFIX = {"develop": "[DEV]", "staging": "[STG]"}


def is_nonprod_namespace(ns: str) -> bool:
    return ns in NON_PROD_NAMESPACES


def nonprod_title_prefix(ns: str) -> str:
    return _NONPROD_PREFIX.get(ns, f"[{ns.upper()[:4]}]")


def get_namespaces() -> list[str]:
    """Return the list of namespaces to watch, including non-prod.

    If WATCH_ALL_NAMESPACES, fetches live from API.
    NON_PROD_NAMESPACES are always appended (deduplicated).
    """
    if not WATCH_ALL_NAMESPACES:
        base = [ns for ns in NAMESPACES if ns not in EXCLUDE_NAMESPACES]
    else:
        try:
            core = k8s.CoreV1Api()
            base = [
                ns.metadata.name
                for ns in core.list_namespace().items
                if ns.metadata.name not in _SYSTEM_NAMESPACES
                and ns.metadata.name not in EXCLUDE_NAMESPACES
            ]
        except Exception:
            logging.getLogger(__name__).warning("Failed to list namespaces, falling back to NAMESPACES")
            base = [ns for ns in NAMESPACES if ns not in EXCLUDE_NAMESPACES]
    # Append non-prod namespaces (not excluded, not already present)
    seen = set(base)
    for ns in sorted(NON_PROD_NAMESPACES):
        if ns not in seen and ns not in EXCLUDE_NAMESPACES:
            base.append(ns)
    return base

import math
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


def parse_env_int(name: str, default: int,
                  min_value: int | None = None,
                  max_value: int | None = None) -> int:
    """Parse an integer env var with graceful fallback on non-numeric or out-of-range values."""
    val = os.environ.get(name)
    if val is None:
        return default
    try:
        parsed = int(val)
    except ValueError:
        logging.getLogger(__name__).warning(
            "Invalid value for %s: %s (expected integer). Using default: %d",
            name, val, default)
        return default
    if min_value is not None and parsed < min_value:
        logging.getLogger(__name__).warning(
            "Value for %s too low: %d (min %d). Using default: %d",
            name, parsed, min_value, default)
        return default
    if max_value is not None and parsed > max_value:
        logging.getLogger(__name__).warning(
            "Value for %s too high: %d (max %d). Using default: %d",
            name, parsed, max_value, default)
        return default
    return parsed


def parse_env_float(name: str, default: float,
                    min_value: float | None = None,
                    max_value: float | None = None) -> float:
    """Parse a float env var with graceful fallback.

    A typo like LLM_TEMPERATURE=zero would otherwise crash the process at
    import time. This mirrors parse_env_int but for floats.

    Python's float() happily parses "nan" and "inf" — neither is a useful
    tuning value for any of our knobs (timeouts, thresholds, ratios), so
    we reject non-finite values and fall back to the default.
    """
    val = os.environ.get(name)
    if val is None:
        return default
    try:
        parsed = float(val)
    except ValueError:
        logging.getLogger(__name__).warning(
            "Invalid value for %s: %s (expected float). Using default: %s",
            name, val, default)
        return default
    if not math.isfinite(parsed):
        logging.getLogger(__name__).warning(
            "Non-finite value for %s: %s (nan/inf rejected). Using default: %s",
            name, val, default)
        return default
    if min_value is not None and parsed < min_value:
        logging.getLogger(__name__).warning(
            "Value for %s too low: %s (min %s). Using default: %s",
            name, parsed, min_value, default)
        return default
    if max_value is not None and parsed > max_value:
        logging.getLogger(__name__).warning(
            "Value for %s too high: %s (max %s). Using default: %s",
            name, parsed, max_value, default)
        return default
    return parsed


def parse_env_bool(name: str, default: bool) -> bool:
    """Parse a boolean env var with graceful fallback on invalid values.

    Mirrors parse_env_int/float: a typo like FLAG=ture warns and falls back to
    the default instead of being silently swallowed as false.
    """
    val = os.environ.get(name)
    if val is None:
        return default
    lowered = val.strip().lower()
    if lowered in ("true", "1", "yes", "on"):
        return True
    if lowered in ("false", "0", "no", "off"):
        return False
    logging.getLogger(__name__).warning(
        "Invalid value for %s: %s (expected boolean). Using default: %s",
        name, val, default)
    return default


CLUSTER_NAME = os.environ.get("CLUSTER_NAME", "unknown")
_raw_namespaces = os.environ.get("WATCH_NAMESPACES", "production")
WATCH_ALL_NAMESPACES = _raw_namespaces.strip() in ("*", "")
NAMESPACES = [] if WATCH_ALL_NAMESPACES else [ns.strip() for ns in _raw_namespaces.split(",")]
_raw_exclude = os.environ.get("EXCLUDE_NAMESPACES", os.environ.get("ENDPOINT_SCAN_EXCLUDE_NAMESPACES", ""))
EXCLUDE_NAMESPACES = {ns.strip() for ns in _raw_exclude.split(",") if ns.strip()}

# Non-prod: monitored without LLM. The LLM is never called for non-prod
# incidents — incidents are still tracked, fingerprinted and posted to the
# non-prod Slack webhook, but we never burn tokens on develop/staging noise.
_raw_nonprod = os.environ.get("NON_PROD_NAMESPACES", "")
NON_PROD_NAMESPACES: set[str] = {ns.strip() for ns in _raw_nonprod.split(",") if ns.strip()}
NON_PROD_DEBOUNCE_MULTIPLIER = parse_env_int("NON_PROD_DEBOUNCE_MULTIPLIER", 2, min_value=1)
# NON_PROD_CRITICAL_ENDPOINT_LLM_ENABLED was removed after the
# deprecation period. If a stale deployment manifest still sets it, the
# env var is silently ignored — Python doesn't crash on unknown env vars.
NON_PROD_SCANNER_ENABLED = os.environ.get("NON_PROD_SCANNER_ENABLED", "false").lower() == "true"
SLACK_WEBHOOK_URL_NONPROD = os.environ.get("SLACK_WEBHOOK_URL_NONPROD", "")
# Optional mention prepended on critical alerts - a person, a group or a
# follow-up bot, in Slack's <@USERID> / <!subteam^ID> syntax (plain "@name" does
# not notify). Empty by default: no mention. "off"/"none"/"disabled" also silence it.
_raw_critical_mention = os.environ.get("SLACK_CRITICAL_MENTION", "").strip()
# Investigation directives appended to the top-level Slack text on critical
# alerts (only when SLACK_CRITICAL_MENTION is set). Goal: keep the follow-up
# reader focused on root cause + cheapest
# permanent fix instead of "scale up" reflex. Override per cluster with
# SLACK_CRITICAL_INVESTIGATION_DIRECTIVES (use empty string to silence).
_DEFAULT_DIRECTIVES = (
    "Focus: root cause over symptoms. Permanent fix first — scaling is "
    "only a temporary workaround. Check the LIVE cluster "
    "(kubectl/Uptrace/Prometheus), not just git — git is desired state, "
    "reality may differ. Cite real queries and numbers, not paraphrases."
)
SLACK_CRITICAL_INVESTIGATION_DIRECTIVES = os.environ.get(
    "SLACK_CRITICAL_INVESTIGATION_DIRECTIVES", _DEFAULT_DIRECTIVES
).strip()
SLACK_CRITICAL_MENTION = (
    "" if _raw_critical_mention.lower() in ("", "off", "none", "disabled")
    else _raw_critical_mention
)

# @ai mention cooldown: once tagged for an incident, skip the mention on
# subsequent re-fires for this many hours. The alert still posts to
# Slack with severity=critical; only the @ai mention is suppressed so
# the bot doesn't burn context re-analyzing the same chronic issue
# every cooldown cycle. First alert, first-seen resurrection, and
# alerts after the window elapses all re-include the mention.
# Set to 0 to disable cooldown (mention on every critical re-fire).
AI_MENTION_REMINDER_HOURS = parse_env_int("AI_MENTION_REMINDER_HOURS", 6, min_value=0)

# LLM
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "anthropic")  # anthropic | openai | gemini
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "") or os.environ.get("GOOGLE_API_KEY", "")
LLM_MODEL = os.environ.get("LLM_MODEL", "")  # auto-selected per provider if empty
LLM_MODEL_REPORT = os.environ.get("LLM_MODEL_REPORT", "")  # model for daily reports (expensive tier)
LLM_DEBUG = os.environ.get("LLM_DEBUG", "false").lower() == "true"
# Flex routing: lower-priority scheduling for ~50% token discount, used by
# daily / weekly reports where latency tolerance is high (runs async on a
# schedule, not in the alert hot path). Off by default: the flex/batch tier is
# deprioritised under load and was the source of the 503 UNAVAILABLE / 504
# DEADLINE_EXCEEDED spikes that dropped daily reports. Opt in per cluster.
GEMINI_FLEX_ENABLED = os.environ.get("GEMINI_FLEX_ENABLED", "false").lower() == "true"

# Critical services — split into two tiers:
#
#   INFRA_CRITICAL_SERVICES: stateful infrastructure. If one of these is
#     down the whole business is affected. Forced to severity=critical,
#     @ai-paged, and treated as potential root cause for dependency
#     correlation. Shortest debounce cap (CRITICAL_ALERT_COOLDOWN_SECONDS).
#
#   IMPORTANT_SERVICES: business-facing application services. Customer
#     impact IF unhealthy, but not paging-worthy for every restart during
#     a deploy. Their scanner-assigned severity is RESPECTED (not forced
#     critical), and they get a middle debounce tier — faster than the
#     default but slower than infra reminders.
#
#   Legacy CRITICAL_SERVICES env var: if set, seeds INFRA_CRITICAL_SERVICES
#     (for back-compat with existing deployments). A one-shot startup
#     warning nudges operators to migrate.
_INFRA_CRITICAL_DEFAULT = (
    # Common token-compatible forms so default pod names like "postgres-0" /
    # "redis-master" match by the tokenized subset rule without overrides.
    "postgres,postgresql,redis"
)
_infra_critical_env = os.environ.get("INFRA_CRITICAL_SERVICES")
_legacy_critical_env = os.environ.get("CRITICAL_SERVICES")
if _infra_critical_env is None and _legacy_critical_env is not None:
    # Legacy env is being used as the fallback seed. Warn once at import
    # time so operators see it in the startup log and migrate to the new
    # variable name.
    logging.getLogger(__name__).warning(
        "CRITICAL_SERVICES env var is deprecated — set "
        "INFRA_CRITICAL_SERVICES instead (this cluster is currently "
        "seeding INFRA_CRITICAL_SERVICES from the legacy value). "
        "Rename the env var in your deployment manifest."
    )
INFRA_CRITICAL_SERVICES: set[str] = {
    s.strip() for s in (
        _infra_critical_env
        if _infra_critical_env is not None
        else (_legacy_critical_env if _legacy_critical_env is not None
              else _INFRA_CRITICAL_DEFAULT)
    ).split(",") if s.strip()
}
IMPORTANT_SERVICES: set[str] = {
    s.strip() for s in os.environ.get(
        "IMPORTANT_SERVICES",
        "backend,frontend",
    ).split(",") if s.strip()
}
# Union — used for callsites that just ask "is this an important workload?"
# (Flux stall handling, event handler severity, LLM watchlist). See matches_critical_service() in engine/critical.py.
CRITICAL_SERVICES: set[str] = INFRA_CRITICAL_SERVICES | IMPORTANT_SERVICES
CRITICAL_ALERT_COOLDOWN_SECONDS = parse_env_int("CRITICAL_ALERT_COOLDOWN_SECONDS", 300, min_value=60)  # 5 min base for infra critical
# Debounce base for IMPORTANT services — between infra (300s) and
# default (1800s). Business apps deserve faster reminders than generic
# workloads but shouldn't pager like infra does.
IMPORTANT_ALERT_COOLDOWN_SECONDS = parse_env_int("IMPORTANT_ALERT_COOLDOWN_SECONDS", 600, min_value=60)
# Root-cause correlation: when a critical-service incident (postgres
# OOM, redis down, a database crash, etc.) fires, we remember it for
# this many seconds so subsequent alerts in the SAME namespace can show
# a "⚠️ Correlates with active root: <root_state_key>" hint. We
# deliberately do NOT suppress the dependent alerts — a cascade of
# 4 alerts for 1 outage is useful signal that those services have
# fragile dependency handling (missing retries / circuit breakers /
# graceful degradation) and they should be fixed, not hidden.
ROOT_CAUSE_CORRELATION_ENABLED = os.environ.get(
    "ROOT_CAUSE_CORRELATION_ENABLED", "true",
).lower() in ("true", "1", "yes")
ROOT_CAUSE_CORRELATION_SECONDS = parse_env_int(
    "ROOT_CAUSE_CORRELATION_SECONDS", 600, min_value=0,  # 10 min default
)
# How often the SQLite store maintenance pass runs. Previously triggered after
# every scan tick, which produced concurrent cleanup work and the occasional
# "database is locked" warning. A single periodic task is enough.
STORE_CLEANUP_INTERVAL_SECONDS = parse_env_int("STORE_CLEANUP_INTERVAL_SECONDS", 1800, min_value=60)
# Threshold at which a burst of same-namespace scan results is folded into
# a single Collective Incident Slack message instead of being sent as N
# individual alerts. Default 5: enough to suppress a rolling restart or
# node replacement cascade, low enough that a genuine partial outage
# (affecting half a namespace) still trips batching. Tune per-cluster —
# dense namespaces benefit from higher values, sparse ones from lower.
MASS_EVENT_THRESHOLD = parse_env_int("MASS_EVENT_THRESHOLD", 5, min_value=2)
# Days to keep resolved incidents + their occurrences + orphan context blobs.
# Long-term incident history is pushed to the central ClickHouse aggregator,
# so the SQLite store only needs to be a short-horizon working set. 30 days
# was chosen to comfortably cover weekly-report windows and one-off
# investigation of recent flaps without letting the DB grow unbounded.
DB_RETENTION_DAYS = parse_env_int("DB_RETENTION_DAYS", 30, min_value=1)
# How often a full SQLite VACUUM runs (hours). cleanup() already triggers
# PRAGMA wal_checkpoint + incremental_vacuum every cycle; the full VACUUM is
# the heavier fragmentation-cleanup pass that reclaims pages which auto_vacuum
# can't reach, or that accumulated on legacy DBs created before auto_vacuum was
# enabled. Once a week during quiet hours is sufficient.
DB_VACUUM_INTERVAL_HOURS = parse_env_int("DB_VACUUM_INTERVAL_HOURS", 168, min_value=1)
# Hard ceiling on the exponential backoff for critical services. Without this,
# an active critical incident decays to 5h+ between reminders very quickly,
# which defeats the point of "critical" — operators want frequent nudges.
CRITICAL_ALERT_MAX_COOLDOWN_SECONDS = parse_env_int(
    "CRITICAL_ALERT_MAX_COOLDOWN_SECONDS", 1800, min_value=60  # 30 min cap
)

# Sampling temperature for RCA / report calls. SDK defaults are 0.7-1.0 which
# is fine for creative writing but pushes the model to invent service names,
# trace IDs and "transient latency" guesses on production-incident analysis.
# A near-zero value keeps it close to the data we actually feed it.
LLM_TEMPERATURE = parse_env_float("LLM_TEMPERATURE", 0.0, min_value=0.0, max_value=2.0)

# Slack — two delivery paths:
#
#   1) Incoming Webhook (legacy): SLACK_WEBHOOK_URL — posts new top-level
#      messages only; can't thread; doesn't return a ts. Kept as fallback
#      for clusters that haven't rolled out the bot Secret yet.
#
#   2) Bot API (primary when configured): chat.postMessage returns the
#      message ts, enabling thread_ts replies for recurring / resolved
#      alerts. Token from the SLACK_BOT_TOKEN env var only - the monitor
#      reads no Kubernetes Secrets.
#
# Bot API wins when configured; webhook is the fallback on any failure.
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")
# Channel IDs (e.g. C0123456789). Required when using bot API — webhooks
# have a channel baked in but chat.postMessage needs an explicit channel.
SLACK_CHANNEL_ID = os.environ.get("SLACK_CHANNEL_ID", "")
SLACK_CHANNEL_ID_NONPROD = os.environ.get("SLACK_CHANNEL_ID_NONPROD", "")
SLACK_BOT_API_URL = os.environ.get("SLACK_BOT_API_URL", "https://slack.com/api")

# Prometheus
PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://prometheus-operated:9090")

# Elasticsearch
ELASTICSEARCH_URL = os.environ.get("ELASTICSEARCH_URL", "")
ELASTICSEARCH_USER = os.environ.get("ELASTICSEARCH_USER", "elastic")
ELASTICSEARCH_PASSWORD = os.environ.get("ELASTICSEARCH_PASSWORD", "")
ELASTICSEARCH_INDEX_PREFIX = os.environ.get("ELASTICSEARCH_INDEX_PREFIX", "")  # default: CLUSTER_NAME

# Uptrace - optional trace lookups (span search, a trace by id, service stats).
# Off unless both UPTRACE_API_URL and UPTRACE_API_TOKEN are set; the token comes
# from an env var (the Deployment's Secret), never from a Secret read at runtime.
# The Uptrace REST API resolves the project from the token, so UPTRACE_PROJECT_ID
# is only the path segment it expects.
UPTRACE_API_URL = os.environ.get("UPTRACE_API_URL", "")
UPTRACE_API_TOKEN = os.environ.get("UPTRACE_API_TOKEN", "")
UPTRACE_PROJECT_ID = os.environ.get("UPTRACE_PROJECT_ID", "1")

# Watcher
DEBOUNCE_SECONDS = parse_env_int("DEBOUNCE_SECONDS", 1800, min_value=60)  # 30 min
NODE_READY_GRACE_SECONDS = parse_env_int("NODE_READY_GRACE_SECONDS", 300, min_value=0)  # 5 min
NODE_NOT_READY_GRACE_SECONDS = parse_env_int("NODE_NOT_READY_GRACE_SECONDS", 120, min_value=0)  # 2 min
IMAGE_PULL_GRACE_SECONDS = parse_env_int("IMAGE_PULL_GRACE_SECONDS", 90, min_value=0)  # 90s for transient DNS/registry
# ECK emits Unhealthy "cluster health degraded" on any non-green blip. On a
# single-node cluster the daily index rollover briefly initializes new primary
# shards (transient yellow), which recovers in seconds. Wait this long, then
# re-read the Elasticsearch status.health: still non-green => real, green =>
# benign transient (auto-resolved, no alert).
ELASTICSEARCH_HEALTH_GRACE_SECONDS = parse_env_int("ELASTICSEARCH_HEALTH_GRACE_SECONDS", 120, min_value=0)
# Kill switch for the Elasticsearch Unhealthy grace/re-check behaviour above.
# Default on; set false to fall back to forwarding every ECK Unhealthy event as
# a normal warning (lets operators roll the feature out / back independently
# while keeping ELASTICSEARCH_HEALTH_GRACE_SECONDS configured).
ELASTICSEARCH_HEALTH_CHECK_ENABLED = parse_env_bool("ELASTICSEARCH_HEALTH_CHECK_ENABLED", True)
EVENT_AUTO_RESOLVE_DELAY_SECONDS = parse_env_int("EVENT_AUTO_RESOLVE_DELAY_SECONDS", 300, min_value=0)  # 5 min

# How long an event-born incident must go without a fresh event before the
# reconcile scanner is allowed to close it. The deferred check above is the
# fast path; this is the durable one, and it must never race it — keep this
# comfortably above EVENT_AUTO_RESOLVE_DELAY_SECONDS so a deferred task that
# is still sleeping always wins.
EVENT_ONLY_RESOLVE_GRACE_SECONDS = parse_env_int(
    "EVENT_ONLY_RESOLVE_GRACE_SECONDS", 900, min_value=0,
)  # 15 min

# The ordering above is an invariant, not a suggestion: if the grace window is
# not longer than the deferred delay, the reconcile scanner becomes eligible to
# close an incident while the deferred task is still sleeping on it, and the
# two race. Enforced here rather than left to `min_value` because either side
# can break it — a low EVENT_ONLY_RESOLVE_GRACE_SECONDS override, or a high
# EVENT_AUTO_RESOLVE_DELAY_SECONDS one, which `min_value` cannot see (and
# parse_env_int never range-checks a default in the first place).
if EVENT_ONLY_RESOLVE_GRACE_SECONDS <= EVENT_AUTO_RESOLVE_DELAY_SECONDS:
    _grace_floor = EVENT_AUTO_RESOLVE_DELAY_SECONDS + 60
    logging.getLogger(__name__).warning(
        "EVENT_ONLY_RESOLVE_GRACE_SECONDS (%d) must exceed "
        "EVENT_AUTO_RESOLVE_DELAY_SECONDS (%d); raising it to %d",
        EVENT_ONLY_RESOLVE_GRACE_SECONDS,
        EVENT_AUTO_RESOLVE_DELAY_SECONDS,
        _grace_floor,
    )
    EVENT_ONLY_RESOLVE_GRACE_SECONDS = _grace_floor

# How often a suppressed-but-still-firing incident re-pushes itself to the
# central store. While an incident is inside its cooldown the pipeline records
# the occurrence locally and stays silent everywhere else — which left the
# central row frozen at whatever was last pushed, so a live incident read as a
# days-old one on the central dashboard. This is a heartbeat, not an alert: it
# carries no Slack post, no LLM call and no escalation, and exists only so
# last_seen_at and occurrence_count in ClickHouse keep telling the truth.
# 0 disables it.
CENTRAL_HEARTBEAT_INTERVAL_SECONDS = parse_env_int(
    "CENTRAL_HEARTBEAT_INTERVAL_SECONDS", 900, min_value=0,
)  # 15 min

# How long the CURRENT container must have been running before an OOM incident
# counts as recovered. Kubernetes caps CrashLoopBackOff at 5 minutes, so a
# container up for longer than that cap is provably not in a restart-backoff
# loop; the default is 2x the cap for margin. Raise it for a workload that OOMs
# on a slow cycle (memory filling over tens of minutes) if you see its incident
# flap between resolved and active.
POD_OOM_RECOVERY_STABLE_SECONDS = parse_env_int("POD_OOM_RECOVERY_STABLE_SECONDS", 600, min_value=60)
# Probe-failure (Unhealthy) events on a pod younger than this are startup churn
# until proven otherwise: the handler waits out the remainder of this window and
# alerts only if the pod is STILL not ready. Covers slow warmups the probe-config
# budget cannot see (Prometheus WAL replay burned 3.7 cores and flapped probes
# minutes after the ~40s probe budget expired, alerting at random after a
# StatefulSet recreate). 0 restores the probe-budget-only behavior.
UNHEALTHY_STARTUP_SETTLE_SECONDS = parse_env_int("UNHEALTHY_STARTUP_SETTLE_SECONDS", 300, min_value=0)
POD_LOG_LINES = parse_env_int("POD_LOG_LINES", 50, min_value=1)

# Rate limiting — safety valve on the critical_endpoint + reports path,
# which are the only LLM callers left. A storm of critical_endpoint alerts
# from one prod outage could otherwise hammer the provider.
MAX_LLM_CALLS_PER_HOUR = parse_env_int("MAX_LLM_CALLS_PER_HOUR", 60, min_value=1)

# Retry on transient LLM errors (5xx / 429 / timeouts / connection
# errors). Without this, a brief provider outage (e.g. a provider 503)
# causes the daily report to silently drop when it ran during the outage.
# `LLM_RETRY_COUNT` is additional attempts beyond the first call, so
# default 2 → 3 total attempts. `LLM_RETRY_BACKOFF_SECONDS` is base
# for exponential backoff (5s, 10s, 20s by default). Set retry count
# to 0 to disable retry entirely (pre-fix behaviour).
LLM_RETRY_COUNT = parse_env_int("LLM_RETRY_COUNT", 2, min_value=0, max_value=10)
LLM_RETRY_BACKOFF_SECONDS = parse_env_float("LLM_RETRY_BACKOFF_SECONDS", 5.0, min_value=0.0)

# Context size caps (bytes) — hard limit before LLM call
MAX_CONTEXT_BYTES_ALERT = parse_env_int("MAX_CONTEXT_BYTES_ALERT", 16000, min_value=1024)
MAX_CONTEXT_BYTES_REPORT = parse_env_int("MAX_CONTEXT_BYTES_REPORT", 80000, min_value=1024)
# Max output tokens for daily/weekly reports = a CEILING, not a target. Billing
# is per token GENERATED, so raising it costs nothing unless the model actually
# writes more; the report is JSON-schema-bounded (~2-4k tokens typical), so it
# never approaches this.
#
# Critically, on Gemini "thinking" models this ceiling covers THINKING tokens
# too, and thinking is spent FIRST. Measured by replaying
# the real failing payload: thoughts=2164-2391, answer=536-603. At the old 4096
# ceiling a busy cluster's thinking left ~150 tokens for the answer, so the JSON
# was cut mid-`reasoning` string → parse fail → raw dump to Slack (8% of the
# reports over two weeks). GEMINI_THINKING_LEVEL below removes the
# cause; this ceiling is the backstop.
REPORT_MAX_OUTPUT_TOKENS = parse_env_int("REPORT_MAX_OUTPUT_TOKENS", 16384, min_value=1024)

# Gemini 3 thinking level. Mirrors google.genai.types.ThinkingLevel, minus the
# UNSPECIFIED sentinel; "" means "send no thinking_config at all" and lets the
# model pick. Kept as a literal rather than imported from the SDK so config
# stays importable when LLM_PROVIDER is not gemini.
GEMINI_THINKING_LEVELS = ("", "minimal", "low", "medium", "high")


def parse_env_thinking_level(name: str, default: str) -> str:
    """Parse the Gemini thinking level, warning and falling back on a typo.

    This has to be validated HERE because the SDK will not do it for us: as of
    google-genai 2.15.0, `ThinkingConfig(thinking_level="bogus")` does not
    raise — it emits a `UserWarning` (which goes to the `warnings` module, not
    our logger, so it never reaches pod logs) and happily builds a
    `ThinkingLevel.bogus` that is then sent to the API. A typo would otherwise
    degrade every LLM call with no usable signal anywhere.
    """
    val = os.environ.get(name)
    if val is None:
        return default
    lowered = val.strip().lower()
    if lowered in GEMINI_THINKING_LEVELS:
        return lowered
    logging.getLogger(__name__).warning(
        "Invalid value for %s: %s (expected one of %s). Using default: %s",
        name, val, ", ".join(repr(v) for v in GEMINI_THINKING_LEVELS), default)
    return default


# Our prompts already mandate an explicit `reasoning` field as the FIRST JSON
# key, so the model reasons in the OUTPUT — where we can read, log and audit it.
# Paying for a second, invisible thinking pass on top is redundant, and it is
# what silently consumed the output budget. Measured:
# "low" drops thinking ~2391 → 0 tokens with no loss of answer quality (536 vs
# 557 answer tokens, valid JSON either way). Set to "" to restore the default.
GEMINI_THINKING_LEVEL = parse_env_thinking_level("GEMINI_THINKING_LEVEL", "low")

# Pod scanner
SCANNER_INTERVAL_SECONDS = parse_env_int("SCANNER_INTERVAL_SECONDS", 300, min_value=60)  # 5 min

# PVC scanner
PVC_SCAN_INTERVAL_SECONDS = parse_env_int("PVC_SCAN_INTERVAL_SECONDS", 3600, min_value=60)  # 1 hour
# 0.85 (was 0.8): volumes with a built-in size governor sit at ~80-85% forever
# by design — e.g. Prometheus with retentionSize=10GB on an 11Gi PVC holds
# ~84.7% permanently and paged as "82% full" for 32h straight. 85% still fires
# well before real exhaustion for organically filling volumes. If a
# retention-capped volume flaps across 85% during compaction, bump to 0.87 or
# expand its PVC instead of lowering this back.
PVC_WARNING_THRESHOLD = parse_env_float("PVC_WARNING_THRESHOLD", 0.85, min_value=0.0, max_value=1.0)  # 85%
PVC_CRITICAL_THRESHOLD = parse_env_float("PVC_CRITICAL_THRESHOLD", 0.9, min_value=0.0, max_value=1.0)  # 90%

# cert-manager scanner
CERT_SCAN_INTERVAL_SECONDS = parse_env_int("CERT_SCAN_INTERVAL_SECONDS", 3600, min_value=60)  # 1 hour
CERT_EXPIRY_WARNING_DAYS = parse_env_int("CERT_EXPIRY_WARNING_DAYS", 14, min_value=1)

# HPA scanner
HPA_SCAN_INTERVAL_SECONDS = parse_env_int("HPA_SCAN_INTERVAL_SECONDS", 300, min_value=60)  # 5 min
# How long an autoscaler must sit against its ceiling before it is worth saying
# so. Being briefly clamped is ordinary: a deploy alone moved one service
# 3 -> 6 -> 3 inside ten minutes while its CPU never left 0.2 cores. Fifteen
# minutes is three scans, and it is measured from the condition's own
# lastTransitionTime rather than counted here, so it survives a restart.
HPA_SATURATED_MIN_MINUTES = parse_env_int("HPA_SATURATED_MIN_MINUTES", 15, min_value=1)

# Node scanner
SCANNER_NODE_ENABLED = os.environ.get("SCANNER_NODE_ENABLED", "true").lower() == "true"
NODE_SCAN_INTERVAL_SECONDS = parse_env_int("NODE_SCAN_INTERVAL_SECONDS", 300, min_value=60)  # 5 min
NODE_CORDON_GRACE_SECONDS = parse_env_int("NODE_CORDON_GRACE_SECONDS", 900, min_value=0)  # 15 min

# HTTP auth for write endpoints
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "")

# Endpoint scanner
ENDPOINT_SCAN_ENABLED = os.environ.get("ENDPOINT_SCAN_ENABLED", "false").lower() == "true"
ENDPOINT_SCAN_INTERVAL_SECONDS = parse_env_int("ENDPOINT_SCAN_INTERVAL_SECONDS", 300, min_value=30)  # 5 min
ENDPOINT_SCAN_TIMEOUT = parse_env_int("ENDPOINT_SCAN_TIMEOUT", 10, min_value=1)  # seconds
ENDPOINT_INGRESS_SERVICE = os.environ.get("ENDPOINT_INGRESS_SERVICE", "")  # e.g. "traefik.traefik.svc.cluster.local"
ENDPOINT_BATCH_THRESHOLD = parse_env_int("ENDPOINT_BATCH_THRESHOLD", 3, min_value=1)  # min endpoints to trigger batch mode
ENDPOINT_REDIS_SERVICE = os.environ.get("ENDPOINT_REDIS_SERVICE", "")  # fallback if auto-discovery fails; e.g. "redis-master.production.svc.cluster.local:6379"

# SLI scanner — SLO-based symptom detection with dependency
# chain correlation. Reads SLI definitions from a ConfigMap-mounted YAML
# file, polls Prometheus on each scan tick, tracks breach state with
# duration gating in `sli_breach_state` table, emits ScanResult through
# the shared pipeline. On breach, walks `upstream_slis` to find the
# root-cause link in the dependency chain (e.g. frontend slow →
# backend slow → postgres_query_latency high).
SCANNER_SLI_ENABLED = os.environ.get("SCANNER_SLI_ENABLED", "false").lower() == "true"
SCANNER_SLI_INTERVAL_SECONDS = parse_env_int("SCANNER_SLI_INTERVAL_SECONDS", 120, min_value=30)
SLI_CONFIG_PATH = os.environ.get("SLI_CONFIG_PATH", "/etc/sli-config/sli.yaml")
# Safety cap on recursive chain walks — prevents stack blow-up on
# accidentally-cyclic configs (cycle detection guards against revisit,
# this caps total depth).
SLI_DEPENDENCY_MAX_DEPTH = parse_env_int("SLI_DEPENDENCY_MAX_DEPTH", 5, min_value=1, max_value=20)

# Backup scanner
SCANNER_BACKUP_ENABLED = os.environ.get("SCANNER_BACKUP_ENABLED", "true").lower() == "true"
BACKUP_SCAN_INTERVAL_SECONDS = parse_env_int("BACKUP_SCAN_INTERVAL_SECONDS", 3600, min_value=60)  # 1 hour
BACKUP_MAX_AGE_HOURS = parse_env_int("BACKUP_MAX_AGE_HOURS", 26, min_value=1)  # slightly over 24h

# Storage verification

# Scanner feature flags
SCANNER_POD_ENABLED = os.environ.get("SCANNER_POD_ENABLED", "true").lower() == "true"
SCANNER_PVC_ENABLED = os.environ.get("SCANNER_PVC_ENABLED", "true").lower() == "true"
SCANNER_CERT_ENABLED = os.environ.get("SCANNER_CERT_ENABLED", "true").lower() == "true"
# On by default. Unlike the feature gates, this scanner cannot silence
# anything - it only raises a warning nobody was getting before. The three
# conditions it requires (see src/scanners/hpa.py) are what keep it quiet.
SCANNER_HPA_ENABLED = os.environ.get("SCANNER_HPA_ENABLED", "true").lower() == "true"
# ENDPOINT_SCAN_ENABLED is already defined above

# Critical endpoint scanner
SCANNER_CRITICAL_ENDPOINT_ENABLED = os.environ.get("SCANNER_CRITICAL_ENDPOINT_ENABLED", "false").lower() == "true"
CRITICAL_ENDPOINT_INTERVAL_SECONDS = parse_env_int("CRITICAL_ENDPOINT_INTERVAL_SECONDS", 60, min_value=15)
# Transient errors (single dropped TCP connection, TLS handshake flake, one slow
# backend response) otherwise fire a critical alert on the first failed probe
# and auto-resolve 60s later — a false positive flap. Retry a few times with a
# short backoff before declaring the endpoint down. Only 5xx / timeout /
# connection errors retry; 4xx is the client's problem, not ours.
CRITICAL_ENDPOINT_RETRY_COUNT = parse_env_int("CRITICAL_ENDPOINT_RETRY_COUNT", 3, min_value=0)
CRITICAL_ENDPOINT_RETRY_BACKOFF_SECONDS = parse_env_float(
    "CRITICAL_ENDPOINT_RETRY_BACKOFF_SECONDS", 3.0, min_value=0.0, max_value=30.0,
)
CRITICAL_ENDPOINT_CHAIN_DEPTH = parse_env_int("CRITICAL_ENDPOINT_CHAIN_DEPTH", 3, min_value=0)
# Cross-cycle hysteresis (flap damping). The per-cycle retries above absorb a
# single flaky probe, but a backend that alternates healthy/unhealthy across
# scan cycles (e.g. pods rescheduled during GKE node upgrades) produced a NEW
# critical incident every minute: one healthy probe emitted Recovered (closing
# the incident), the next failure opened a fresh one — observed as 952 Down +
# 952 Recovered pairs on one service in a single maintenance window.
# DOWN_CYCLES=2: at the 60s scan interval a real outage must persist across two
# consecutive probes (~60-120s down) before it pages, so a sub-minute blip that
# self-heals within one cycle raises no alert — a genuine downtime is >60s.
# RECOVER_CYCLES=3 requires three consecutive healthy cycles before Recovered,
# so a flapping endpoint keeps ONE incident open (occurrences accumulate)
# instead of paging on every cycle.
CRITICAL_ENDPOINT_DOWN_CYCLES = parse_env_int("CRITICAL_ENDPOINT_DOWN_CYCLES", 2, min_value=1)
CRITICAL_ENDPOINT_RECOVER_CYCLES = parse_env_int("CRITICAL_ENDPOINT_RECOVER_CYCLES", 3, min_value=1)
_raw_ce_exclude = os.environ.get("CRITICAL_ENDPOINT_EXCLUDE_NAMES", "")
CRITICAL_ENDPOINT_EXCLUDE_NAMES: set[str] = {n.strip() for n in _raw_ce_exclude.split(",") if n.strip()}
_raw_ce_exclude_domains = os.environ.get("CRITICAL_ENDPOINT_EXCLUDE_DOMAINS", "")
CRITICAL_ENDPOINT_EXCLUDE_DOMAINS: set[str] = {d.strip() for d in _raw_ce_exclude_domains.split(",") if d.strip()}

# Auto-maintenance detection (GKE node upgrades, etc.)
AUTO_MAINTENANCE_ENABLED = os.environ.get("AUTO_MAINTENANCE_ENABLED", "true").lower() == "true"
AUTO_MAINTENANCE_NODE_THRESHOLD = parse_env_int("AUTO_MAINTENANCE_NODE_THRESHOLD", 1, min_value=1)
AUTO_MAINTENANCE_CHECK_INTERVAL = parse_env_int("AUTO_MAINTENANCE_CHECK_INTERVAL", 30, min_value=5)
AUTO_MAINTENANCE_DURATION_HOURS = parse_env_float("AUTO_MAINTENANCE_DURATION_HOURS", 2.0, min_value=0.1, max_value=24.0)

# State persistence
SQLITE_PATH = os.environ.get("SQLITE_PATH", "/data/k8s-ai-monitor.db")

# Retention for LLM usage tables — unbounded growth was crowding the DB on
# heavy clusters. Both caps are applied from SqliteStore.cleanup().
LLM_CALLS_RETENTION_DAYS = parse_env_int("LLM_CALLS_RETENTION_DAYS", 30, min_value=1)
LLM_DEBUG_RETENTION_DAYS = parse_env_int("LLM_DEBUG_RETENTION_DAYS", 7, min_value=1)
# Per-incident occurrence history cap. Flappy incidents (e.g. a flapping endpoint
# critical_endpoint) reached 892+ occurrence rows with nothing pruning
# them. Keep the newest N and drop the rest on cleanup(); context body
# lives in context_store (deduplicated by hash) so we don't lose the
# actual diagnostic payload — just the per-occurrence pointer.
OCCURRENCE_HISTORY_CAP = parse_env_int("OCCURRENCE_HISTORY_CAP", 50, min_value=0)

# Escalation
ESCALATION_RECURRING_WINDOW_H = parse_env_float("ESCALATION_RECURRING_WINDOW_HOURS", 6.0, min_value=0.1, max_value=168.0)
ESCALATION_PERSISTENT_MIN_COUNT = parse_env_int("ESCALATION_PERSISTENT_MIN_OCCURRENCES", 3, min_value=1)
ESCALATION_PERSISTENT_MIN_AGE_H = parse_env_float("ESCALATION_PERSISTENT_MIN_AGE_HOURS", 1.0, min_value=0.0, max_value=168.0)

# Daily report — timezone-aware scheduling
REPORT_TIMEZONE = os.environ.get("REPORT_TIMEZONE", "Europe/Sofia")
# If DAILY_REPORT_HOUR is explicitly set, use it; otherwise fall back to DAILY_REPORT_HOUR_UTC
if os.environ.get("DAILY_REPORT_HOUR") is not None:
    DAILY_REPORT_HOUR = parse_env_int("DAILY_REPORT_HOUR", 9, min_value=0, max_value=23)
else:
    DAILY_REPORT_HOUR = parse_env_int("DAILY_REPORT_HOUR_UTC", 9, min_value=0, max_value=23)
# Keep for backward compat — unused internally but referenced in tests/docs
DAILY_REPORT_HOUR_UTC = DAILY_REPORT_HOUR  # deprecated alias

# Report-level retry: the per-call `LLM_RETRY_COUNT` backoff only spans ~tens
# of seconds, so a provider demand spike that outlasts it (observed: Gemini
# 503 UNAVAILABLE / 504 DEADLINE_EXCEEDED for several minutes) leaves the
# daily report failed until the NEXT day's scheduled run. These knobs let the
# scheduler keep re-attempting the whole report — every
# DAILY_REPORT_RETRY_INTERVAL_MINUTES, for up to DAILY_REPORT_RETRY_MAX_HOURS —
# until a real report is produced. The window is bounded so a multi-hour outage
# can't have a retry loop bleed into the next day's scheduled run. Set the
# window to 0 to restore the old single-shot behaviour.
DAILY_REPORT_RETRY_MAX_HOURS = parse_env_float("DAILY_REPORT_RETRY_MAX_HOURS", 12.0, min_value=0.0, max_value=23.0)
DAILY_REPORT_RETRY_INTERVAL_MINUTES = parse_env_int(
    "DAILY_REPORT_RETRY_INTERVAL_MINUTES", 30, min_value=1, max_value=240)

# Weekly report
WEEKLY_REPORT_ENABLED = os.environ.get("WEEKLY_REPORT_ENABLED", "true").lower() == "true"
WEEKLY_REPORT_DAY = parse_env_int("WEEKLY_REPORT_DAY", 0, min_value=0, max_value=6)  # 0=Monday (ISO weekday)
WEEKLY_REPORT_HOUR = parse_env_int("WEEKLY_REPORT_HOUR", 9, min_value=0, max_value=23)  # local time

# Central ClickHouse push
CENTRAL_AGGREGATE = os.environ.get("CENTRAL_AGGREGATE", "false").lower() == "true"
CENTRAL_CH_URL = os.environ.get("CENTRAL_CH_URL", "")
CENTRAL_CH_USER = os.environ.get("CENTRAL_CH_USER", "monitor")
CENTRAL_CH_PASSWORD = os.environ.get("CENTRAL_CH_PASSWORD", "")
CENTRAL_CH_DATABASE = os.environ.get("CENTRAL_CH_DATABASE", "monitor")


_SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease", "flux-system", "gmp-system", "gmp-public"}

# Workload exclusion — skip alerts for specific workloads (substring match on state_key/owner_key)
_raw_exclude_workloads = os.environ.get("ALERT_EXCLUDE_WORKLOADS", "")
ALERT_EXCLUDE_WORKLOADS: set[str] = {w.strip() for w in _raw_exclude_workloads.split(",") if w.strip()}

_NONPROD_PREFIX = {"develop": "[DEV]", "staging": "[STG]"}


def is_nonprod_namespace(ns: str) -> bool:
    return ns in NON_PROD_NAMESPACES


# --- Behaviour switches (feature gates) - off unless set to "true" ---

# A scanner-resolved incident that reopens does not force a Slack post on its own.
REOPEN_PROVENANCE_ENABLED = os.environ.get("REOPEN_PROVENANCE_ENABLED", "false").lower() == "true"

# Post withheld alerts as one grouped message on an interval - and nothing at
# all when there is nothing to say.
HOURLY_DIGEST_ENABLED = os.environ.get("HOURLY_DIGEST_ENABLED", "false").lower() == "true"

DIGEST_INTERVAL_SECONDS = parse_env_int("DIGEST_INTERVAL_SECONDS", 3600, min_value=300)
DIGEST_CHECK_INTERVAL_SECONDS = parse_env_int("DIGEST_CHECK_INTERVAL_SECONDS", 300, min_value=30)
# A burst inside one namespace is itself signal and should not wait out the hour.
DIGEST_BURST_THRESHOLD = parse_env_int("DIGEST_BURST_THRESHOLD", 25, min_value=2)

# Snapshot of every still-open (active/acknowledged) incident, posted at each
# listed hour in REPORT_TIMEZONE — e.g. "8,18" for a morning and an end-of-day
# view. Unlike the hourly digest it ALWAYS posts — an empty board is worth
# hearing and doubles as a liveness signal. Empty (the default) disables it.
def _parse_hour_list(name: str) -> list[int]:
    hours: set[int] = set()
    for part in os.environ.get(name, "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            hour = int(part)
        except ValueError:
            logging.getLogger(__name__).warning(
                "Invalid hour %r in %s — ignored", part, name)
            continue
        if 0 <= hour <= 23:
            hours.add(hour)
        else:
            logging.getLogger(__name__).warning(
                "Hour %d out of range in %s — ignored", hour, name)
    return sorted(hours)


OPEN_DIGEST_HOURS: list[int] = _parse_hour_list("OPEN_DIGEST_HOURS")


def reopen_provenance_enabled() -> bool:
    return REOPEN_PROVENANCE_ENABLED


def hourly_digest_enabled() -> bool:
    return HOURLY_DIGEST_ENABLED


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
    # When non-prod scanning is disabled (default), strip non-prod namespaces
    # from the list — even if they were discovered via WATCH_ALL_NAMESPACES=*.
    # When enabled, append any non-prod ns that wasn't already discovered.
    if not NON_PROD_SCANNER_ENABLED:
        base = [ns for ns in base if ns not in NON_PROD_NAMESPACES]
    else:
        seen = set(base)
        for ns in sorted(NON_PROD_NAMESPACES):
            if ns not in seen and ns not in EXCLUDE_NAMESPACES:
                base.append(ns)
    return base


def get_prod_namespaces() -> list[str]:
    """Return only production namespaces (excludes NON_PROD_NAMESPACES).

    Used by daily/weekly reports to avoid noise from develop/staging.
    """
    return [ns for ns in get_namespaces() if ns not in NON_PROD_NAMESPACES]

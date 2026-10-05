# Configuration reference

Generated from `src/config.py` by `scripts/gen-config-doc.py` - do not edit by hand.
Every variable, its default and the comment that explains it, in the order of config.py.
Features marked off by default (feature gates) are not used on the SafeOps course platform
unless the course says so.

| Variable | Default | Notes |
|---|---|---|
| `LOG_LEVEL` | `"INFO"` |  |
| `CLUSTER_NAME` | `"unknown"` |  |
| `WATCH_NAMESPACES` | `"production"` |  |
| `EXCLUDE_NAMESPACES` | falls back to `ENDPOINT_SCAN_EXCLUDE_NAMESPACES` |  |
| `ENDPOINT_SCAN_EXCLUDE_NAMESPACES` | `""` |  |
| `NON_PROD_NAMESPACES` | `""` | Non-prod: monitored without LLM. The LLM is never called for non-prod incidents — incidents are still tracked, fingerprinted and posted to the non-prod Slack webhook, but we never burn tokens on develop/staging noise. |
| `NON_PROD_DEBOUNCE_MULTIPLIER` | `2` |  |
| `NON_PROD_SCANNER_ENABLED` | `"false"` | NON_PROD_CRITICAL_ENDPOINT_LLM_ENABLED was removed 2026-04-20 after the deprecation period. If a stale deployment manifest still sets it, the env var is silently ignored — Python doesn't crash on unknown env vars. |
| `SLACK_WEBHOOK_URL_NONPROD` | `""` |  |
| `SLACK_CRITICAL_MENTION` | `""` | Optional mention prepended on critical alerts - a person, a group or a follow-up bot, in Slack's <@USERID> / <!subteam^ID> syntax (plain "@name" does not notify). Empty by default: no mention. "off"/"none"/"disabled" also silence it. |
| `SLACK_CRITICAL_INVESTIGATION_DIRECTIVES` | `_DEFAULT_DIRECTIVES` |  |
| `AI_MENTION_REMINDER_HOURS` | `6` | @ai mention cooldown: once tagged for an incident, skip the mention on subsequent re-fires for this many hours. The alert still posts to Slack with severity=critical; only the @ai mention is suppressed so the bot doesn't burn context re-analyzing the same chronic issue every cooldown cycle. First alert, first-seen resurrection, and alerts after the window elapses all re-include the mention. Set to 0 to disable cooldown (mention on every critical re-fire). |
| `LLM_PROVIDER` | `"anthropic"` | LLM |
| `ANTHROPIC_API_KEY` | `""` |  |
| `OPENAI_API_KEY` | `""` |  |
| `GEMINI_API_KEY` | `""` |  |
| `GOOGLE_API_KEY` | `""` |  |
| `LLM_MODEL` | `""` |  |
| `LLM_MODEL_REPORT` | `""` |  |
| `LLM_DEBUG` | `"false"` |  |
| `GEMINI_FLEX_ENABLED` | `"false"` | Flex routing: lower-priority scheduling for ~50% token discount, used by daily / weekly reports where latency tolerance is high (runs async on a schedule, not in the alert hot path). Off by default: the flex/batch tier is deprioritised under load and was the source of the 503 UNAVAILABLE / 504 DEADLINE_EXCEEDED spikes that dropped daily reports. Opt in per cluster. |
| `INFRA_CRITICAL_SERVICES` | _(empty)_ | Common token-compatible forms so default pod names like "postgres-0" / "redis-master" match by the tokenized subset rule without overrides. |
| `CRITICAL_SERVICES` | _(empty)_ |  |
| `IMPORTANT_SERVICES` | _(empty)_ |  |
| `CRITICAL_ALERT_COOLDOWN_SECONDS` | `300` |  |
| `IMPORTANT_ALERT_COOLDOWN_SECONDS` | `600` | Debounce base for IMPORTANT services — between infra (300s) and default (1800s). Business apps deserve faster reminders than generic workloads but shouldn't pager like infra does. |
| `ROOT_CAUSE_CORRELATION_ENABLED` | `"true"` | Root-cause correlation: when a critical-service incident (postgres OOM, redis down, a database crash, etc.) fires, we remember it for this many seconds so subsequent alerts in the SAME namespace can show a "⚠️ Correlates with active root: <root_state_key>" hint. We deliberately do NOT suppress the dependent alerts — a cascade of 4 alerts for 1 outage is useful signal that those services have fragile dependency handling (missing retries / circuit breakers / graceful degradation) and they should be fixed, not hidden. |
| `ROOT_CAUSE_CORRELATION_SECONDS` | `600` |  |
| `STORE_CLEANUP_INTERVAL_SECONDS` | `1800` | How often the SQLite store maintenance pass runs. Previously triggered after every scan tick, which produced concurrent cleanup work and the occasional "database is locked" warning. A single periodic task is enough. |
| `MASS_EVENT_THRESHOLD` | `5` | Threshold at which a burst of same-namespace scan results is folded into a single Collective Incident Slack message instead of being sent as N individual alerts. Default 5: enough to suppress a rolling restart or node replacement cascade, low enough that a genuine partial outage (affecting half a namespace) still trips batching. Tune per-cluster — dense namespaces benefit from higher values, sparse ones from lower. |
| `DB_RETENTION_DAYS` | `30` | Days to keep resolved incidents + their occurrences + orphan context blobs. Long-term incident history is pushed to the central ClickHouse aggregator, so the SQLite store only needs to be a short-horizon working set. 30 days was chosen to comfortably cover weekly-report windows and one-off investigation of recent flaps without letting the DB grow unbounded. |
| `DB_VACUUM_INTERVAL_HOURS` | `168` | How often a full SQLite VACUUM runs (hours). cleanup() already triggers PRAGMA wal_checkpoint + incremental_vacuum every cycle; the full VACUUM is the heavier fragmentation-cleanup pass that reclaims pages which auto_vacuum can't reach, or that accumulated on legacy DBs created before auto_vacuum was enabled. Once a week during quiet hours is sufficient. |
| `CRITICAL_ALERT_MAX_COOLDOWN_SECONDS` | `1800` | Hard ceiling on the exponential backoff for critical services. Without this, an active critical incident decays to 5h+ between reminders very quickly, which defeats the point of "critical" — operators want frequent nudges. |
| `LLM_TEMPERATURE` | `0.0` | Sampling temperature for RCA / report calls. SDK defaults are 0.7-1.0 which is fine for creative writing but pushes the model to invent service names, trace IDs and "transient latency" guesses on production-incident analysis. A near-zero value keeps it close to the data we actually feed it. |
| `SLACK_WEBHOOK_URL` | `""` | Slack — two delivery paths (Sprint 10a, 2026-04-19):  1) Incoming Webhook (legacy): SLACK_WEBHOOK_URL — posts new top-level messages only; can't thread; doesn't return a ts. Kept as fallback for clusters that haven't rolled out the bot Secret yet.  2) Bot API (primary when configured): chat.postMessage returns the message ts, enabling thread_ts replies for recurring / resolved alerts. Token from the SLACK_BOT_TOKEN env var only - the monitor reads no Kubernetes Secrets.  Bot API wins when configured; webhook is the fallback on any failure. |
| `SLACK_BOT_TOKEN` | `""` |  |
| `SLACK_CHANNEL_ID` | `""` | Channel IDs (e.g. C0123456789). Required when using bot API — webhooks have a channel baked in but chat.postMessage needs an explicit channel. |
| `SLACK_CHANNEL_ID_NONPROD` | `""` |  |
| `SLACK_BOT_API_URL` | `"https://slack.com/api"` |  |
| `PROMETHEUS_URL` | `"http://prometheus-operated:9090"` | Prometheus |
| `ELASTICSEARCH_URL` | `""` | Elasticsearch |
| `ELASTICSEARCH_USER` | `"elastic"` |  |
| `ELASTICSEARCH_PASSWORD` | `""` |  |
| `ELASTICSEARCH_INDEX_PREFIX` | `""` |  |
| `UPTRACE_API_URL` | `""` | Uptrace - optional trace lookups (span search, a trace by id, service stats). Off unless both UPTRACE_API_URL and UPTRACE_API_TOKEN are set; the token comes from an env var (the Deployment's Secret), never from a Secret read at runtime. The Uptrace REST API resolves the project from the token, so UPTRACE_PROJECT_ID is only the path segment it expects. |
| `UPTRACE_API_TOKEN` | `""` |  |
| `UPTRACE_PROJECT_ID` | `"1"` |  |
| `DEBOUNCE_SECONDS` | `1800` | Watcher |
| `NODE_READY_GRACE_SECONDS` | `300` |  |
| `NODE_NOT_READY_GRACE_SECONDS` | `120` |  |
| `IMAGE_PULL_GRACE_SECONDS` | `90` |  |
| `ELASTICSEARCH_HEALTH_GRACE_SECONDS` | `120` | ECK emits Unhealthy "cluster health degraded" on any non-green blip. On a single-node cluster the daily index rollover briefly initializes new primary shards (transient yellow), which recovers in seconds. Wait this long, then re-read the Elasticsearch status.health: still non-green => real, green => benign transient (auto-resolved, no alert). |
| `ELASTICSEARCH_HEALTH_CHECK_ENABLED` | `True` | Kill switch for the Elasticsearch Unhealthy grace/re-check behaviour above. Default on; set false to fall back to forwarding every ECK Unhealthy event as a normal warning (lets operators roll the feature out / back independently while keeping ELASTICSEARCH_HEALTH_GRACE_SECONDS configured). |
| `EVENT_AUTO_RESOLVE_DELAY_SECONDS` | `300` |  |
| `EVENT_ONLY_RESOLVE_GRACE_SECONDS` | `900` | How long an event-born incident must go without a fresh event before the reconcile scanner is allowed to close it. The deferred check above is the fast path; this is the durable one, and it must never race it — keep this comfortably above EVENT_AUTO_RESOLVE_DELAY_SECONDS so a deferred task that is still sleeping always wins. |
| `CENTRAL_HEARTBEAT_INTERVAL_SECONDS` | `900` | How often a suppressed-but-still-firing incident re-pushes itself to the central store. While an incident is inside its cooldown the pipeline records the occurrence locally and stays silent everywhere else — which left the central row frozen at whatever was last pushed, so a live incident read as a days-old one on the fleet dashboard. This is a heartbeat, not an alert: it carries no Slack post, no LLM call and no escalation, and exists only so last_seen_at and occurrence_count in ClickHouse keep telling the truth. 0 disables it. |
| `POD_OOM_RECOVERY_STABLE_SECONDS` | `600` | How long the CURRENT container must have been running before an OOM incident counts as recovered. Kubernetes caps CrashLoopBackOff at 5 minutes, so a container up for longer than that cap is provably not in a restart-backoff loop; the default is 2x the cap for margin. Raise it for a workload that OOMs on a slow cycle (memory filling over tens of minutes) if you see its incident flap between resolved and active. |
| `UNHEALTHY_STARTUP_SETTLE_SECONDS` | `300` | Probe-failure (Unhealthy) events on a pod younger than this are startup churn until proven otherwise: the handler waits out the remainder of this window and alerts only if the pod is STILL not ready. Covers slow warmups the probe-config budget cannot see (Prometheus WAL replay burned 3.7 cores and flapped probes minutes after the ~40s probe budget expired — 2026-09-01, alert lottery across 15 clusters after an STS recreate). 0 restores the probe-budget-only behavior. |
| `POD_LOG_LINES` | `50` |  |
| `MAX_LLM_CALLS_PER_HOUR` | `60` | Rate limiting — safety valve on the critical_endpoint + reports path, which are the only LLM callers left. A storm of critical_endpoint alerts from one prod outage could otherwise hammer the provider. |
| `LLM_RETRY_COUNT` | `2` | Retry on transient LLM errors (5xx / 429 / timeouts / connection errors). Without this, a brief provider outage (e.g. Gemini 503 at 06:00 UTC on 2026-04-24) causes the daily report to silently drop for clusters that ran their report during the outage window. `LLM_RETRY_COUNT` is additional attempts beyond the first call, so default 2 → 3 total attempts. `LLM_RETRY_BACKOFF_SECONDS` is base for exponential backoff (5s, 10s, 20s by default). Set retry count to 0 to disable retry entirely (pre-fix behaviour). |
| `LLM_RETRY_BACKOFF_SECONDS` | `5.0` |  |
| `MAX_CONTEXT_BYTES_ALERT` | `16000` | Context size caps (bytes) — hard limit before LLM call |
| `MAX_CONTEXT_BYTES_REPORT` | `80000` |  |
| `REPORT_MAX_OUTPUT_TOKENS` | `16384` | Max output tokens for daily/weekly reports = a CEILING, not a target. Billing is per token GENERATED, so raising it costs nothing unless the model actually writes more; the report is JSON-schema-bounded (~2-4k tokens typical), so it never approaches this.  Critically, on Gemini "thinking" models this ceiling covers THINKING tokens too, and thinking is spent FIRST. Measured by replaying the real failing payload: thoughts=2164-2391, answer=536-603. At the old 4096 ceiling a busy cluster's thinking left ~150 tokens for the answer, so the JSON was cut mid-`reasoning` string → parse fail → raw dump to Slack (21 of 262 fleet reports, 8%, over 14 days). GEMINI_THINKING_LEVEL below removes the cause; this ceiling is the backstop. |
| `GEMINI_THINKING_LEVEL` | `"low"` | Our prompts already mandate an explicit `reasoning` field as the FIRST JSON key, so the model reasons in the OUTPUT — where we can read, log and audit it. Paying for a second, invisible thinking pass on top is redundant, and it is what silently consumed the output budget. Measured: "low" drops thinking ~2391 → 0 tokens with no loss of answer quality (536 vs 557 answer tokens, valid JSON either way). Set to "" to restore the default. |
| `SCANNER_INTERVAL_SECONDS` | `300` | Pod scanner |
| `PVC_SCAN_INTERVAL_SECONDS` | `3600` | PVC scanner |
| `PVC_WARNING_THRESHOLD` | `0.85` | 0.85 (was 0.8): volumes with a built-in size governor sit at ~80-85% forever by design — e.g. Prometheus with retentionSize=10GB on an 11Gi PVC holds ~84.7% permanently and paged as "82% full" for 32h straight. 85% still fires well before real exhaustion for organically filling volumes. If a retention-capped volume flaps across 85% during compaction, bump to 0.87 or expand its PVC instead of lowering this back. |
| `PVC_CRITICAL_THRESHOLD` | `0.9` |  |
| `CERT_SCAN_INTERVAL_SECONDS` | `3600` | cert-manager scanner |
| `CERT_EXPIRY_WARNING_DAYS` | `14` |  |
| `HPA_SCAN_INTERVAL_SECONDS` | `300` | HPA scanner |
| `HPA_SATURATED_MIN_MINUTES` | `15` | How long an autoscaler must sit against its ceiling before it is worth saying so. Being briefly clamped is ordinary: a deploy alone moved one service 3 -> 6 -> 3 inside ten minutes while its CPU never left 0.2 cores. Fifteen minutes is three scans, and it is measured from the condition's own lastTransitionTime rather than counted here, so it survives a restart. |
| `SCANNER_NODE_ENABLED` | `"true"` | Node scanner |
| `NODE_SCAN_INTERVAL_SECONDS` | `300` |  |
| `NODE_CORDON_GRACE_SECONDS` | `900` |  |
| `INTERNAL_TOKEN` | `""` | HTTP auth for write endpoints |
| `ENDPOINT_SCAN_ENABLED` | `"false"` | Endpoint scanner |
| `ENDPOINT_SCAN_INTERVAL_SECONDS` | `300` |  |
| `ENDPOINT_SCAN_TIMEOUT` | `10` |  |
| `ENDPOINT_INGRESS_SERVICE` | `""` |  |
| `ENDPOINT_BATCH_THRESHOLD` | `3` |  |
| `ENDPOINT_REDIS_SERVICE` | `""` |  |
| `SCANNER_SLI_ENABLED` | `"false"` | SLI scanner (Sprint 12) — SLO-based symptom detection with dependency chain correlation. Reads SLI definitions from a ConfigMap-mounted YAML file, polls Prometheus on each scan tick, tracks breach state with duration gating in `sli_breach_state` table, emits ScanResult through the shared pipeline. On breach, walks `upstream_slis` to find the root-cause link in the dependency chain (e.g. frontend slow → backend slow → postgres_query_latency high). |
| `SCANNER_SLI_INTERVAL_SECONDS` | `120` |  |
| `SLI_CONFIG_PATH` | `"/etc/sli-config/sli.yaml"` |  |
| `SLI_DEPENDENCY_MAX_DEPTH` | `5` | Safety cap on recursive chain walks — prevents stack blow-up on accidentally-cyclic configs (cycle detection guards against revisit, this caps total depth). |
| `SCANNER_BACKUP_ENABLED` | `"true"` | Backup scanner |
| `BACKUP_SCAN_INTERVAL_SECONDS` | `3600` |  |
| `BACKUP_MAX_AGE_HOURS` | `26` |  |
| `SCANNER_POD_ENABLED` | `"true"` | Scanner feature flags |
| `SCANNER_PVC_ENABLED` | `"true"` |  |
| `SCANNER_CERT_ENABLED` | `"true"` |  |
| `SCANNER_HPA_ENABLED` | `"true"` | On by default. Unlike the gates added in #77-#81, this scanner cannot silence anything — it only raises a warning nobody was getting before, and the shape of the fleet is exactly what we want to see everywhere at once. The three conditions it requires (see src/scanners/hpa.py) are what keep it quiet. |
| `SCANNER_CRITICAL_ENDPOINT_ENABLED` | `"false"` | Critical endpoint scanner |
| `CRITICAL_ENDPOINT_INTERVAL_SECONDS` | `60` |  |
| `CRITICAL_ENDPOINT_RETRY_COUNT` | `3` | Transient errors (single dropped TCP connection, TLS handshake flake, one slow backend response) otherwise fire a critical alert on the first failed probe and auto-resolve 60s later — a false positive flap. Retry a few times with a short backoff before declaring the endpoint down. Only 5xx / timeout / connection errors retry; 4xx is the client's problem, not ours. |
| `CRITICAL_ENDPOINT_RETRY_BACKOFF_SECONDS` | `3.0` |  |
| `CRITICAL_ENDPOINT_CHAIN_DEPTH` | `3` |  |
| `CRITICAL_ENDPOINT_DOWN_CYCLES` | `2` | Cross-cycle hysteresis (flap damping). The per-cycle retries above absorb a single flaky probe, but a backend that alternates healthy/unhealthy across scan cycles (e.g. pods rescheduled during GKE node upgrades) produced a NEW critical incident every minute: one healthy probe emitted Recovered (closing the incident), the next failure opened a fresh one — observed as 952 Down + 952 Recovered pairs on one service in a single maintenance window. DOWN_CYCLES=2: at the 60s scan interval a real outage must persist across two consecutive probes (~60-120s down) before it pages, so a sub-minute blip that self-heals within one cycle raises no alert — a genuine downtime is >60s. RECOVER_CYCLES=3 requires three consecutive healthy cycles before Recovered, so a flapping endpoint keeps ONE incident open (occurrences accumulate) instead of paging on every cycle. |
| `CRITICAL_ENDPOINT_RECOVER_CYCLES` | `3` |  |
| `CRITICAL_ENDPOINT_EXCLUDE_NAMES` | `""` |  |
| `CRITICAL_ENDPOINT_EXCLUDE_DOMAINS` | `""` |  |
| `AUTO_MAINTENANCE_ENABLED` | `"true"` | Auto-maintenance detection (GKE node upgrades, etc.) |
| `AUTO_MAINTENANCE_NODE_THRESHOLD` | `1` |  |
| `AUTO_MAINTENANCE_CHECK_INTERVAL` | `30` |  |
| `AUTO_MAINTENANCE_DURATION_HOURS` | `2.0` |  |
| `SQLITE_PATH` | `"/data/k8s-ai-monitor.db"` | State persistence |
| `LLM_CALLS_RETENTION_DAYS` | `30` | Retention for LLM usage tables — unbounded growth was crowding the DB on heavy clusters. Both caps are applied from SqliteStore.cleanup(). |
| `LLM_DEBUG_RETENTION_DAYS` | `7` |  |
| `OCCURRENCE_HISTORY_CAP` | `50` | Per-incident occurrence history cap. Flappy incidents (e.g. a flapping endpoint critical_endpoint) reached 892+ occurrence rows with nothing pruning them. Keep the newest N and drop the rest on cleanup(); context body lives in context_store (deduplicated by hash) so we don't lose the actual diagnostic payload — just the per-occurrence pointer. |
| `ESCALATION_RECURRING_WINDOW_HOURS` | `6.0` | Escalation |
| `ESCALATION_PERSISTENT_MIN_OCCURRENCES` | `3` |  |
| `ESCALATION_PERSISTENT_MIN_AGE_HOURS` | `1.0` |  |
| `REPORT_TIMEZONE` | `"Europe/Sofia"` | Daily report — timezone-aware scheduling |
| `DAILY_REPORT_HOUR` | _(empty)_ | If DAILY_REPORT_HOUR is explicitly set, use it; otherwise fall back to DAILY_REPORT_HOUR_UTC |
| `DAILY_REPORT_HOUR_UTC` | `9` |  |
| `DAILY_REPORT_RETRY_MAX_HOURS` | `12.0` | Report-level retry: the per-call `LLM_RETRY_COUNT` backoff only spans ~tens of seconds, so a provider demand spike that outlasts it (observed: Gemini 503 UNAVAILABLE / 504 DEADLINE_EXCEEDED for several minutes) leaves the daily report failed until the NEXT day's scheduled run. These knobs let the scheduler keep re-attempting the whole report — every DAILY_REPORT_RETRY_INTERVAL_MINUTES, for up to DAILY_REPORT_RETRY_MAX_HOURS — until a real report is produced. The window is bounded so a multi-hour outage can't have a retry loop bleed into the next day's scheduled run. Set the window to 0 to restore the old single-shot behaviour. |
| `DAILY_REPORT_RETRY_INTERVAL_MINUTES` | `30` |  |
| `WEEKLY_REPORT_ENABLED` | `"true"` | Weekly report |
| `WEEKLY_REPORT_DAY` | `0` |  |
| `WEEKLY_REPORT_HOUR` | `9` |  |
| `CENTRAL_AGGREGATE` | `"false"` | Central ClickHouse push |
| `CENTRAL_CH_URL` | `""` |  |
| `CENTRAL_CH_USER` | `"monitor"` |  |
| `CENTRAL_CH_PASSWORD` | `""` |  |
| `CENTRAL_CH_DATABASE` | `"monitor"` |  |
| `DASHBOARD_PORT` | `8080` | Fleet dashboard (reads the central ClickHouse) |
| `ALERT_EXCLUDE_WORKLOADS` | `""` | Workload exclusion — skip alerts for specific workloads (substring match on state_key/owner_key) |
| `REOPEN_PROVENANCE_ENABLED` | `"false"` | A scanner-resolved incident that reopens does not force a Slack post on its own. |
| `HOURLY_DIGEST_ENABLED` | `"false"` | Post withheld alerts as one grouped message on an interval - and nothing at all when there is nothing to say. |
| `DIGEST_INTERVAL_SECONDS` | `3600` |  |
| `DIGEST_CHECK_INTERVAL_SECONDS` | `300` |  |
| `DIGEST_BURST_THRESHOLD` | `25` | A burst inside one namespace is itself signal and should not wait out the hour. |
| `OPEN_DIGEST_HOURS` | `""` |  |

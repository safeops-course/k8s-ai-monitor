# CLAUDE.md — k8s-ai-monitor

## What is this

Kubernetes monitoring operator (Kopf-based) that detects cluster issues and uses LLMs (Claude/GPT) to analyze root causes. Posts structured alerts and daily reports to Slack.

## Quick Reference

```bash
# Run tests
python -m pytest tests/

# Lint & type check
ruff check src/
mypy src/

# Build
docker build -t k8s-ai-monitor:latest .

# Entry point (what the Dockerfile runs)
kopf run --standalone --all-namespaces src/handlers/__init__.py

# CLI (inside container via kubectl exec)
python -m src.cli incidents
python -m src.cli incident 1
python -m src.cli llm-usage --hours 24

# MCP server (stdio transport, used by Claude Code via .mcp.json)
python3 -m src.mcp_server
```

## Project Structure

```text
src/
├── config.py                  # All env vars, get_namespaces()
├── cli.py                     # CLI tool (python -m src.cli)
├── mcp_server.py              # MCP server for Claude Code (python -m src.mcp_server)
├── reporter.py                # Daily report orchestration
├── handlers/                  # Kopf event handlers
│   ├── __init__.py           #   imports all handlers for Kopf discovery
│   ├── startup.py            #   startup, HTTP server, scanner loops, daily scheduler
│   ├── events.py             #   Warning K8s event handler (pods)
│   └── flux.py               #   Flux Kustomization/HelmRelease stall handler
├── engine/                    # Core processing logic
│   ├── constants.py          #   IMPORTANT_EVENT_REASONS, PROBLEM_ALIASES, etc.
│   ├── llm.py                #   LLM calls, parsing, rate limiting, cost tracking
│   ├── pipeline.py           #   Shared detect→dedup→analyze→alert pipeline
│   ├── notifier.py           #   Slack posting & Block Kit formatting
│   ├── central_push.py       #   Push incidents/reports/LLM usage to central ClickHouse
│   ├── escalation.py         #   Recurring/persistent incident escalation
│   ├── fingerprint.py        #   Incident fingerprinting (SHA256)
│   ├── owner.py              #   Pod → ReplicaSet → Deployment owner resolution
│   ├── context_budget.py     #   Context size measurement & truncation
│   ├── sanitizer.py          #   Password/token redaction
│   └── store/
│       ├── __init__.py       #   Incident dataclass
│       └── sqlite.py         #   Full incident DB (incidents, occurrences, llm_calls, reports)
├── scanners/                  # Periodic scanners
│   ├── __init__.py           #   ALL_SCANNERS registry, get_enabled_scanners()
│   ├── _base.py              #   ScanResult dataclass, Scanner protocol
│   ├── pod.py                #   Pod status & container states
│   ├── pvc.py                #   PVC disk usage via Prometheus
│   ├── certificate.py        #   cert-manager certificate expiry
│   ├── endpoint.py           #   HTTP endpoint health checks
│   ├── backup.py             #   CNPG and CronJob (pg_dump) backup checks
│   ├── critical_endpoint.py  #   Traefik IngressRoute chain probing
│   ├── storage_verify.py     #   S3/GCS backup storage verification
│   └── _probe.py             #   HTTP probe helpers
├── collectors/                # Context collection for LLM
│   ├── __init__.py           #   Collector facade (pod context, PVC scan, daily data)
│   ├── pod.py                #   Pod status, logs, events, owner
│   ├── node.py               #   Node CPU/memory (Prometheus or Metrics API)
│   ├── app_metrics.py        #   Pod CPU/memory from Prometheus
│   ├── daily.py              #   24-hour cluster health summary
│   ├── flux.py               #   Flux Kustomization/HelmRelease context
│   ├── prometheus.py         #   prom_scalar(), prom_query()
│   ├── elasticsearch.py      #   ES log search (search_logs, search_error_logs)
│   ├── uptrace.py            #   Uptrace span search & service stats
│   ├── metrics_range.py      #   prom_range_query() for time-series
│   └── _formatters.py        #   fmt_bytes(), fmt_mem(), parse_cpu()
└── diagnostics/               # Issue-specific diagnostic plugins
    ├── __init__.py           #   Registry & collect_diagnostics() dispatcher
    ├── _base.py              #   DiagnosticPlugin protocol
    ├── _helpers.py           #   Common helpers (usage, prev logs, limits)
    ├── oom.py                #   OOMKilled diagnostics
    ├── crash.py              #   CrashLoopBackOff diagnostics
    ├── image_pull.py         #   ImagePullBackOff diagnostics
    ├── scheduling.py         #   FailedScheduling diagnostics
    ├── mount.py              #   FailedMount diagnostics
    ├── error.py              #   Container error diagnostics
    ├── unhealthy.py          #   Probe failure diagnostics
    └── evicted.py            #   Eviction diagnostics

tests/
├── test_llm_schema.py        # LLM response parsing & formatting
├── test_sanitizer.py          # Sensitive data redaction
├── test_context_budget.py     # Context truncation logic
└── test_daily_report_store.py # Daily report persistence
```

## Architecture

### Detection → Pipeline → Alert flow

Four detection sources feed into a shared pipeline:

1. **Real-time events** (`handlers/events.py`) — Kopf watches Warning K8s events, filters by `IMPORTANT_EVENT_REASONS`
2. **Periodic scanners** (`scanners/`) — Pod, PVC, Certificate, Endpoint run on independent async loops
3. **Flux events** (`handlers/flux.py`) — Kopf watches Kustomization/HelmRelease for `Stalled` condition
4. **Daily report** (`reporter.py`) — Scheduled at `DAILY_REPORT_HOUR_UTC`

All scanner results go through `engine/pipeline.py: process_scan_results()`:
```text
ScanResult → dedup check (store) → collect context (collectors) →
sanitize → budget/truncate → LLM analyze → format → Slack post
```

### Key Protocols

- **Scanner** (`scanners/_base.py`) — `scan() -> list[ScanResult]`, `collect_daily_data() -> str | None`
- **DiagnosticPlugin** (`diagnostics/_base.py`) — `diagnose(core, pod) -> dict`
- **SqliteStore** (`engine/store/sqlite.py`) — Full incident lifecycle: incidents, occurrences, escalation, suppressions, LLM call tracking, daily reports

### State Backend

SQLite database at `SQLITE_PATH` with tables: `incidents`, `incident_occurrences`, `context_store`, `llm_calls`, `daily_reports`, `suppressions`.

### Namespace Filtering

`EXCLUDE_NAMESPACES` is the global exclude list, applied in:
- `config.get_namespaces()` — used by pod scanner, endpoint scanner, daily report
- `handlers/events.py: _in_watched_namespace()` — real-time event handler
- `scanners/certificate.py` — cluster-wide cert scan
- `scanners/pvc.py` — Prometheus PVC results

`NON_PROD_NAMESPACES` — monitored but LLM is only called for `critical_endpoint` scanner. All other alerts go to Slack with raw context, no LLM. Uses separate webhook (`SLACK_WEBHOOK_URL_NONPROD`) and 2x debounce.

System namespaces (`kube-system`, `kube-public`, `kube-node-lease`, `flux-system`) are always excluded when `WATCH_ALL_NAMESPACES=true`.

### Deduplication Layers

1. **In-flight set** — prevents concurrent duplicate alerts for same state_key
2. **SqliteStore** — prevents repeated alerts within cooldown window
3. **Context hash** — prevents re-analyzing identical context
4. **Escalation** — manages recurring/persistent incident lifecycle

### Escalation

Cooldown: `DEBOUNCE_SECONDS * 2^(count, max 10)`, capped at 12 hours.
Levels: fresh → recurring (2nd within window) → persistent (3+ occurrences, age > threshold).

## HTTP API

Port `HTTP_PORT` (default 8080):

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/healthz` | GET | No | Health check |
| `/report` | GET/POST | Token | Trigger daily report |
| `/state` | GET | Token | View dedup state |
| `/certs` | GET | Token | Trigger cert scan |
| `/llm-usage?hours=N` | GET | Token | LLM cost/usage |
| `/incidents` | GET | Token | List incidents |
| `/incidents/{id}` | GET | Token | Incident detail |
| `/incidents/{id}/ack` | POST | Token | Acknowledge incident |
| `/incidents/{id}/resolve` | POST | Token | Resolve incident |
| `/reports` | GET | Token | Daily report history |
| `/reports/{id}` | GET | Token | Report detail |
| `/suppressions` | GET | Token | List suppressions |
| `/suppressions` | POST | Token | Create suppression |
| `/suppressions/{id}` | DELETE | Token | Delete suppression |

Auth: every route except `/healthz` needs the `X-Internal-Token` header matching `INTERNAL_TOKEN` (`_auth_middleware` in `src/handlers/startup.py`). Without `INTERNAL_TOKEN` the API is locked (401). `/healthz` pings the store and returns 503 when it cannot be reached.

## Environment Variables

### Core
| Variable | Default | Description |
|---|---|---|
| `CLUSTER_NAME` | `unknown` | Cluster identifier for alerts |
| `WATCH_NAMESPACES` | `production` | Comma-separated, or `*` for all |
| `EXCLUDE_NAMESPACES` | _(empty)_ | Global namespace exclude list (comma-separated) |
| `LOG_LEVEL` | `INFO` | Python log level |

### Non-prod

| Variable | Default | Description |
|---|---|---|
| `NON_PROD_NAMESPACES` | _(empty)_ | Comma-separated namespaces monitored without LLM (except critical_endpoint) |
| `NON_PROD_DEBOUNCE_MULTIPLIER` | `2` | Debounce multiplier for non-prod namespaces |
| `SLACK_WEBHOOK_URL_NONPROD` | _(empty)_ | Separate Slack webhook for non-prod alerts |

### LLM
| Variable | Default | Description |
|---|---|---|
| `LLM_PROVIDER` | `anthropic` | `anthropic` or `openai` |
| `ANTHROPIC_API_KEY` | | Required if provider=anthropic |
| `OPENAI_API_KEY` | | Required if provider=openai |
| `LLM_MODEL` | _(auto)_ | Alert model override |
| `LLM_MODEL_REPORT` | _(auto)_ | Report model override (expensive tier) |
| `LLM_DEBUG` | `false` | Enable LLM debug logging |
| `MAX_LLM_CALLS_PER_HOUR` | `20` | Rate limit |
| `MAX_CONTEXT_BYTES_ALERT` | `16000` | Max context before truncation |
| `MAX_CONTEXT_BYTES_REPORT` | `80000` | Max context for daily reports |

### Notification
| Variable | Default | Description |
|---|---|---|
| `SLACK_WEBHOOK_URL` | _(empty)_ | Slack webhook (console fallback if empty) |

### Scanners
| Variable | Default | Description |
|---|---|---|
| `SCANNER_POD_ENABLED` | `true` | Enable pod scanner |
| `SCANNER_PVC_ENABLED` | `true` | Enable PVC scanner |
| `SCANNER_CERT_ENABLED` | `true` | Enable certificate scanner |
| `ENDPOINT_SCAN_ENABLED` | `false` | Enable endpoint scanner |
| `SCANNER_INTERVAL_SECONDS` | `1800` | Pod scanner interval |
| `PVC_SCAN_INTERVAL_SECONDS` | `3600` | PVC scanner interval |
| `CERT_SCAN_INTERVAL_SECONDS` | `3600` | Certificate scanner interval |
| `ENDPOINT_SCAN_INTERVAL_SECONDS` | `300` | Endpoint scanner interval |
| `ENDPOINT_SCAN_TIMEOUT` | `10` | HTTP probe timeout |
| `ENDPOINT_INGRESS_SERVICE` | _(empty)_ | Traefik LB service for external probes (e.g. `traefik.traefik.svc.cluster.local`) |
| `ENDPOINT_REDIS_SERVICE` | _(empty)_ | Fallback Redis address (e.g. `redis-master.production.svc.cluster.local:6379`) |
| `SCANNER_BACKUP_ENABLED` | `true` | Enable backup scanner |
| `SCANNER_CRITICAL_ENDPOINT_ENABLED` | `false` | Enable critical endpoint scanner |
| `BACKUP_SCAN_INTERVAL_SECONDS` | `3600` | Backup scanner interval |
| `CRITICAL_ENDPOINT_INTERVAL_SECONDS` | `60` | Critical endpoint scanner interval |
| `CRITICAL_ENDPOINT_EXCLUDE_NAMES` | _(empty)_ | Comma-separated IngressRoute names to skip |
| `CRITICAL_ENDPOINT_INGRESS_NAMESPACES` | `traefik,kube-system` | Namespaces to search for Traefik pods |

### Backup & Storage
| Variable | Default | Description |
|---|---|---|
| `BACKUP_MAX_AGE_HOURS` | `26` | Max backup age before alerting |
| `BACKUP_STORAGE_PROVIDER` | _(empty)_ | `s3`, `gcs`, or empty (disabled) |
| `BACKUP_STORAGE_VERIFY_HOUR_UTC` | `7` | Hour (UTC) for daily storage check |
| `BACKUP_STORAGE_DOWNLOAD_VERIFY` | `false` | Deep integrity validation (gzip, pg_dump) |
| `BACKUP_STORAGE_VERIFY_BYTES` | `1048576` | Bytes to download for integrity check (1MB) |
| `BACKUP_STORAGE_MIN_SIZE_BYTES` | `1024` | Minimum backup file size |
| `BACKUP_SIZE_DROP_THRESHOLD` | `0.5` | Size drop ratio vs yesterday triggering warning |
| `BACKUP_S3_SECRET_NAME` | `s3-backup-credentials` | K8s secret with S3 creds |
| `BACKUP_S3_SECRET_NAMESPACE` | _(auto)_ | Namespace of S3 secret |
| `BACKUP_STORAGE_S3_DUMP_PREFIXES` | `postgres-dump` | S3 prefix paths to scan |

### Thresholds
| Variable | Default | Description |
|---|---|---|
| `PVC_WARNING_THRESHOLD` | `0.8` | PVC usage warning (80%) |
| `PVC_CRITICAL_THRESHOLD` | `0.9` | PVC usage critical (90%) |
| `CERT_EXPIRY_WARNING_DAYS` | `14` | Cert expiry warning threshold |
| `DEBOUNCE_SECONDS` | `1800` | Base dedup/cooldown window |
| `NODE_READY_GRACE_SECONDS` | `300` | Grace period for new nodes |
| `NODE_NOT_READY_GRACE_SECONDS` | `120` | Wait before alerting on established NotReady nodes |
| `POD_LOG_LINES` | `50` | Log lines to collect |

### Escalation
| Variable | Default | Description |
|---|---|---|
| `ESCALATION_RECURRING_WINDOW_HOURS` | `6` | Window for "recurring" |
| `ESCALATION_PERSISTENT_MIN_OCCURRENCES` | `3` | Min count for "persistent" |
| `ESCALATION_PERSISTENT_MIN_AGE_HOURS` | `1` | Min age for "persistent" |

### Central ClickHouse Push

| Variable | Default | Description |
|---|---|---|
| `CENTRAL_AGGREGATE` | `false` | Enable push to central ClickHouse |
| `CENTRAL_CH_URL` | _(empty)_ | ClickHouse HTTP URL |
| `CENTRAL_CH_USER` | `monitor` | ClickHouse user |
| `CENTRAL_CH_PASSWORD` | _(empty)_ | ClickHouse password (from a Secret) |
| `CENTRAL_CH_DATABASE` | `monitor` | ClickHouse database name |

### State & Infra
| Variable | Default | Description |
|---|---|---|
| `SQLITE_PATH` | `/data/k8s-ai-monitor.db` | SQLite DB path |
| `PROMETHEUS_URL` | `http://prometheus-operated:9090` | Prometheus endpoint |
| `INTERNAL_TOKEN` | _(empty)_ | Auth token for every HTTP endpoint except `/healthz`; empty = API locked |
| `HTTP_PORT` | `8080` | HTTP server port |
| `DAILY_REPORT_HOUR_UTC` | `8` | Daily report hour (UTC) |

### Elasticsearch

| Variable | Default | Description |
|---|---|---|
| `ELASTICSEARCH_URL` | _(empty)_ | ES base URL (e.g. `https://es.example.com:9200`) |
| `ELASTICSEARCH_USER` | `elastic` | ES username |
| `ELASTICSEARCH_PASSWORD` | _(empty)_ | ES password |
| `ELASTICSEARCH_INDEX_PREFIX` | _(auto)_ | Log index prefix (default: `CLUSTER_NAME`) |

### Uptrace

| Variable | Default | Description |
|---|---|---|
| `UPTRACE_API_URL` | _(empty)_ | Uptrace API URL (e.g. `https://uptrace.example.com`) |
| `UPTRACE_API_TOKEN` | _(empty)_ | Uptrace API token |
| `UPTRACE_PROJECT_ID` | `1` | Uptrace project ID |

## Adding a New Scanner

1. Create `src/scanners/myscanner.py` implementing the `Scanner` protocol
2. Return `list[ScanResult]` from `scan()`
3. Register in `src/scanners/__init__.py` → `ALL_SCANNERS`
4. Add feature flag env var in `config.py`

## Adding a New Diagnostic Plugin

1. Create `src/diagnostics/myissue.py` implementing `DiagnosticPlugin`
2. Set `issue_type` matching a `PROBLEM_ALIASES` value
3. Register in `src/diagnostics/__init__.py` → `_PLUGIN_MAP`

## CLI Tool

Management CLI for use inside the container (`kubectl exec`). No auth needed.

```bash
# Incidents
python -m src.cli incidents [--status active|resolved|acknowledged|all] [--limit N]
python -m src.cli incident <id>              # Detail view
python -m src.cli incident <id> ack          # Acknowledge
python -m src.cli incident <id> resolve      # Resolve

# Suppressions
python -m src.cli suppressions               # List active
python -m src.cli suppress --type certificate --ns production --pattern '*storefront*' --reason 'known issue' [--hours 24]
python -m src.cli unsuppress <id>

# Reports
python -m src.cli reports [--limit N]
python -m src.cli report <id>

# LLM usage
python -m src.cli llm-usage [--hours 24]

# State
python -m src.cli state

# Elasticsearch log search
python -m src.cli logs --ns production --pod '*storefront*' --since 30 --query 'timeout OR 503'
python -m src.cli logs --ns production --errors --since 60

# Uptrace span search
python -m src.cli traces --service storefront --since 30 --errors
python -m src.cli traces --service storefront --slow --min-duration 1000
python -m src.cli traces --service storefront --stats

# Prometheus metrics
python -m src.cli metrics --ns production --pod storefront --since 30
python -m src.cli metrics --query 'rate(http_requests_total[5m])' --since 30

# Multi-source investigation
python -m src.cli investigate --ns production --since 30
python -m src.cli investigate --ns production --pod storefront --since 60 --llm

# Observability audit
python -m src.cli audit --ns production
python -m src.cli audit --ns production --pod storefront
```

## Deployment

Deployed via FluxCD from the platform repository (`safeops-course/sre`, `flux/infrastructure/observability/k8s-ai-monitor/`). Image: `ghcr.io/safeops-course/k8s-ai-monitor`.

## MCP Server

`src/mcp_server.py` — exposes cluster data as MCP tools for Claude Code. Registered via `.mcp.json` (stdio transport).

### Tools

| Tool | Description |
|------|-------------|
| `cluster_health` | Cluster overview: nodes, pod issues, incidents, events, backups, latest report |
| `investigate` | Deep investigation of a namespace/pod: pods, events, metrics, logs, traces |
| `audit` | Observability audit: probe/logging/tracing/metrics coverage per deployment |
| `search_logs` | Elasticsearch log search by namespace/pod/query |
| `search_traces` | Uptrace span search: errors, slow spans |
| `get_service_stats` | Uptrace service stats: error rate, latency percentiles |
| `query_metrics` | Prometheus queries: custom PromQL or preset battery |
| `list_incidents` | List incidents from SQLite store |
| `get_incident` | Incident detail with occurrences and analysis |
| `list_reports` | List daily reports |

### Skills

- `/cluster-status` — health check playbook (`.claude/skills/cluster-status/SKILL.md`)
- `/investigate [namespace] [pod]` — deep investigation playbook (`.claude/skills/investigate/SKILL.md`)

### Graceful Degradation

All tools handle missing data sources gracefully. If ES/Uptrace/Prometheus is not configured, tools return `{"status": "not_configured"}` instead of crashing.

---

## AI Agent Guidelines

### Operating Principles

1. **Read before writing** — Always read existing code before modifying. Understand the pattern before changing it.
2. **Verify findings against actual code** — Don't assume a bug exists from description alone. Read the lines, confirm the issue, then fix.
3. **Parallel execution** — When multiple independent operations are needed, invoke tools simultaneously.
4. **Clean up after yourself** — If you create temporary files or scripts for iteration, remove them when done.
5. **Feasibility first** — If a task is unreasonable or a test is incorrect, say so. Don't force a bad solution.

### Code Principles

- **KISS** — Keep it simple. Don't over-engineer. The simplest correct solution is the best one.
- **Errors should never pass silently** — No bare `except: pass`. Always log or surface errors. This is the #1 bug pattern in this codebase.
- **Explicit is better than implicit** — Clear variable names, documented intentions, obvious control flow.
- **Readability counts** — Code is read more often than written. If it needs a decoder ring, rewrite it simpler.
- **Do what was asked, nothing more** — Don't add features, refactor surroundings, or "improve" code beyond the task scope.

### Security Rules

- Never hardcode API keys, tokens, or credentials — all secrets come from env vars or K8s secrets
- No access to Kubernetes Secrets: the ClusterRole grants none - listing or reading a Secret returns its contents. Take what you need from other objects (CronJob names, cert-manager Certificate status, events). The only exception is the opt-in S3 storage check (one Secret, namespaced Role with resourceNames)
- Use `sanitizer.py` patterns for any new context that might contain sensitive data
- SQL queries in `store/sqlite.py` must use parameterized queries only — never string interpolation
- All datetimes must be timezone-aware (UTC) — never use naive datetimes

### Patterns to Follow

- **New scanner** → implement `Scanner` protocol, return `list[ScanResult]`, register in `__init__.py`, add env var in `config.py`
- **New diagnostic** → implement `DiagnosticPlugin`, match `issue_type` to `PROBLEM_ALIASES`, register in `_PLUGIN_MAP`
- **K8s API errors** → 404 means CRD not installed (debug log, not warning). Other errors get `logger.warning`.
- **Exception handling** → Catch specific exceptions. If catching broad `Exception`, always log with `exc_info=True` or at minimum the error message.
- **ScanResult.state_key** → Must be unique and deterministic for dedup. Format: `{Type}:{source}:{namespace}/{resource}`
- **Auto-resolve** → When a previously-alerting condition is healthy, emit `ScanResult(auto_resolve=True)` to clear it.

### No Half-Measures

When fixing an issue in one place, check if the same pattern exists elsewhere:
- Use grep/search to find ALL instances of what you're changing
- Don't leave some files using old patterns while others use new ones
- A fix in one scanner should be verified against all scanners

### Definition of Done

Before marking a task as completed:
1. Code changes implemented correctly
2. `python -m pytest tests/` passes
3. `ruff check src/` passes (zero errors)
4. `mypy src/` passes clean (zero errors)
5. No regressions introduced in existing functionality
6. Error handling follows the "never silent" principle
7. Any new env vars added to both `config.py` and `CLAUDE.md`

# k8s-ai-monitor

Kubernetes monitoring operator that detects cluster issues and uses LLMs (Claude/GPT) to analyze root causes, posting structured alerts and daily reports to Slack.

## Features

- **8 scanners** — Pods, PVCs, certificates, HTTP endpoints, critical endpoint chains, backups (CNPG, CronJob), and S3/GCS storage verification
- **LLM-powered analysis** — Claude or GPT analyzes root causes with full pod context (logs, events, metrics, owner chain)
- **Slack alerts** — Structured Block Kit messages with severity, namespace, and actionable recommendations
- **Daily reports** — Scheduled cluster health summaries covering all monitored resources
- **CLI** — Manage incidents, suppressions, reports, and LLM usage from inside the container
- **Escalation** — Exponential backoff deduplication with recurring/persistent incident lifecycle

## Architecture

```
Detection                    Pipeline                         Output
─────────                    ────────                         ──────
K8s Warning Events ──┐
Periodic Scanners ───┤       ScanResult                      Slack Alert
Flux Stall Events ───┼──→  → dedup check ──→ collect context  (Block Kit)
Daily Scheduler ─────┘       → sanitize ──→ LLM analyze ──→  Daily Report
                             → format ──→ post
```

Four detection sources feed a shared pipeline (`engine/pipeline.py`):

1. **Real-time events** — Kopf watches Warning K8s events, filters by important reasons
2. **Periodic scanners** — Pod, PVC, Certificate, Endpoint, Critical Endpoint, Backup run on independent async loops
3. **Flux events** — Kopf watches Kustomization/HelmRelease for `Stalled` condition
4. **Daily report** — Scheduled at configurable hour (UTC)

## Scanners

| Scanner | What it checks | Default interval |
|---|---|---|
| Pod | Container states (CrashLoop, OOM, ImagePull, etc.) | 30 min |
| PVC | Disk usage via Prometheus | 1 hour |
| Certificate | cert-manager certificate expiry | 1 hour |
| Endpoint | HTTP health checks on ingress endpoints | 5 min |
| Critical Endpoint | Deep chain probing: Storefront → API Gateway → subgraphs | 1 min |
| Backup | CNPG and CronJob-based (pg_dump) backup status | 1 hour |

### Backup Scanner

Checks three backup systems with auto-discovery:

- **CloudNativePG** — Queries `ScheduledBackup` and `Backup` CRs, checks phase and age
- **CronJob** — Matches CronJobs named `*postgres-backup*` or `*pg-backup*`

**S3/GCS storage verification** runs once daily at a configurable hour. It dynamically discovers services from the bucket structure:

```
{bucket}/{dump_type}/{namespace}/{service}/{YYYY}/{MM}/{DD}/{file}
```

Checks: file existence, minimum size, and optionally validates file format (gzip, PGDMP magic bytes).

## Quick Start

```bash
# Build
docker build -t k8s-ai-monitor:latest .

# Run (requires in-cluster K8s access)
docker run -e CLUSTER_NAME=my-cluster \
           -e ANTHROPIC_API_KEY=sk-ant-... \
           -e SLACK_WEBHOOK_URL=https://hooks.slack.com/... \
           k8s-ai-monitor:latest
```

The entry point runs: `kopf run --standalone --all-namespaces src/handlers/__init__.py`

## Configuration

### Core

| Variable | Default | Description |
|---|---|---|
| `CLUSTER_NAME` | `unknown` | Cluster identifier for alerts |
| `WATCH_NAMESPACES` | `production` | Comma-separated, or `*` for all |
| `EXCLUDE_NAMESPACES` | _(empty)_ | Namespace exclude list (comma-separated) |
| `LOG_LEVEL` | `INFO` | Python log level |

### LLM

| Variable | Default | Description |
|---|---|---|
| `LLM_PROVIDER` | `anthropic` | `anthropic` or `openai` |
| `ANTHROPIC_API_KEY` | | Required if provider=anthropic |
| `OPENAI_API_KEY` | | Required if provider=openai |
| `LLM_MODEL` | _(auto)_ | Alert model override |
| `LLM_MODEL_REPORT` | _(auto)_ | Report model override |
| `MAX_LLM_CALLS_PER_HOUR` | `20` | Rate limit |
| `MAX_CONTEXT_BYTES_ALERT` | `24000` | Max context before truncation |
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
| `SCANNER_CRITICAL_ENDPOINT_ENABLED` | `false` | Enable critical endpoint scanner |
| `SCANNER_BACKUP_ENABLED` | `true` | Enable backup scanner |
| `SCANNER_INTERVAL_SECONDS` | `1800` | Pod scanner interval |
| `PVC_SCAN_INTERVAL_SECONDS` | `3600` | PVC scanner interval |
| `CERT_SCAN_INTERVAL_SECONDS` | `3600` | Certificate scanner interval |
| `ENDPOINT_SCAN_INTERVAL_SECONDS` | `300` | Endpoint scanner interval |
| `CRITICAL_ENDPOINT_INTERVAL_SECONDS` | `60` | Critical endpoint scanner interval |
| `BACKUP_SCAN_INTERVAL_SECONDS` | `3600` | Backup scanner interval |
| `ENDPOINT_SCAN_TIMEOUT` | `10` | HTTP probe timeout (seconds) |
| `ENDPOINT_INGRESS_SERVICE` | _(empty)_ | Ingress service for external probes |

### Backup & Storage

| Variable | Default | Description |
|---|---|---|
| `BACKUP_MAX_AGE_HOURS` | `26` | Max age before alerting (slightly over 24h) |
| `BACKUP_STORAGE_PROVIDER` | _(empty)_ | `s3`, `gcs`, or empty (disabled) |
| `BACKUP_STORAGE_VERIFY_HOUR_UTC` | `7` | Hour (UTC) to run daily storage check |
| `BACKUP_STORAGE_DOWNLOAD_VERIFY` | `false` | Download and validate file format |
| `BACKUP_STORAGE_MIN_SIZE_BYTES` | `1024` | Minimum backup file size |
| `BACKUP_S3_SECRET_NAME` | `s3-backup-credentials` | K8s secret with S3 credentials |
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
| `NODE_NOT_READY_GRACE_SECONDS` | `120` | Wait before alerting on NotReady nodes |
| `POD_LOG_LINES` | `50` | Log lines to collect |

### Escalation

| Variable | Default | Description |
|---|---|---|
| `ESCALATION_RECURRING_WINDOW_HOURS` | `6` | Window for "recurring" |
| `ESCALATION_PERSISTENT_MIN_OCCURRENCES` | `3` | Min count for "persistent" |
| `ESCALATION_PERSISTENT_MIN_AGE_HOURS` | `1` | Min age for "persistent" |

### State & Infrastructure

| Variable | Default | Description |
|---|---|---|
| `SQLITE_PATH` | `/data/k8s-ai-monitor.db` | SQLite DB path |
| `PROMETHEUS_URL` | `http://prometheus-operated:9090` | Prometheus endpoint |
| `INTERNAL_TOKEN` | _(empty)_ | Auth token for write HTTP endpoints |
| `HTTP_PORT` | `8080` | HTTP server port |
| `DAILY_REPORT_HOUR_UTC` | `8` | Daily report hour (UTC) |

## CLI Reference

Management CLI for use inside the container via `kubectl exec`.

```bash
# List incidents
python -m src.cli incidents [--status active|resolved|acknowledged|all] [--limit N]

# View/manage incident
python -m src.cli incident <id>
python -m src.cli incident <id> ack
python -m src.cli incident <id> resolve

# Suppressions
python -m src.cli suppressions
python -m src.cli suppress --type certificate --ns production --pattern '*storefront*' --reason 'known issue' [--hours 24]
python -m src.cli unsuppress <id>

# Reports
python -m src.cli reports [--limit N]
python -m src.cli report <id>

# LLM usage
python -m src.cli llm-usage [--hours 24]

# Dedup state
python -m src.cli state

# Manual backup storage check
python -m src.cli check-backups
```

## HTTP API

Port `HTTP_PORT` (default 8080):

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/healthz` | GET | No | Health check |
| `/report` | GET/POST | No | Trigger daily report |
| `/state` | GET | No | View dedup state |
| `/certs` | GET | No | Trigger cert scan |
| `/llm-usage?hours=N` | GET | No | LLM cost/usage |
| `/incidents` | GET | No | List incidents |
| `/incidents/{id}` | GET | No | Incident detail |
| `/incidents/{id}/ack` | POST | Token | Acknowledge incident |
| `/incidents/{id}/resolve` | POST | Token | Resolve incident |
| `/reports` | GET | No | Daily report history |
| `/reports/{id}` | GET | No | Report detail |
| `/suppressions` | GET | No | List suppressions |
| `/suppressions` | POST | Token | Create suppression |
| `/suppressions/{id}` | DELETE | Token | Delete suppression |

Auth endpoints require `X-Internal-Token` header matching `INTERNAL_TOKEN` env var.

## Deployment

Deployed via FluxCD. Image: `gcr.io/team-operations/k8s-ai-monitor:latest`.

Flux manifest: `flux_capacitor/modules/k8s-ai-monitor/deployment.yaml`

## Development

```bash
# Run tests
python -m pytest tests/

# Project structure
src/
├── config.py           # All env vars
├── cli.py              # CLI tool
├── reporter.py         # Daily report orchestration
├── handlers/           # Kopf event handlers (startup, events, flux)
├── engine/             # Core logic (LLM, pipeline, notifier, escalation, dedup, store)
├── scanners/           # Periodic scanners (pod, pvc, cert, endpoint, critical_endpoint, backup)
├── collectors/         # Context collection for LLM (pod, node, metrics, daily, flux, prometheus)
└── diagnostics/        # Issue-specific diagnostic plugins (OOM, crash, image pull, scheduling, etc.)
```


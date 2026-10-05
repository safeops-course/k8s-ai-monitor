# k8s-ai-monitor

The Guardian of the SafeOps course platform: a Kubernetes operator (Kopf) that detects cluster
issues, deduplicates them into incidents, enriches them with context (pod status, logs, events,
metrics, traces) and asks an LLM for a root-cause analysis - then posts one structured alert per
incident to Slack, and daily / weekly reports. **AI proposes, people decide:** the monitor only
reads the cluster (no Secrets, no writes), and its analysis is advice.

## Features

- **Scanners** - pods, nodes, HPAs at their ceiling, PVCs (usage and growth), certificates, HTTP
  endpoints, critical endpoint chains (Traefik IngressRoutes), CloudNativePG backups and
  recoverability, plus a reconcile pass that closes incidents whose cause is gone.
- **One pipeline for every source** - Kubernetes Warning events, Flux stalls and scanner results all
  go through the same dedup, escalation, enrichment and resolve logic (`engine/pipeline.py`).
- **LLM analysis for production incidents** - Anthropic, OpenAI or Gemini (the cheapest). Non-prod
  incidents are tracked and posted without an LLM call, to keep the cost for production.
- **Enrichment without an LLM** - flap history, resource trend, HPA state, last deploy, and (when
  Uptrace is configured) the trace of a failing request.
- **Noise control** - fingerprints, exponential cooldowns, recurring / persistent escalation,
  flap damping on critical endpoints, root-cause correlation, an optional hourly digest.
- **Slack** - incoming webhooks, or the Bot API (`chat.postMessage`) with threaded follow-ups.
- **CLI and MCP server** - incidents, suppressions, reports, LLM usage, investigations.

## Architecture

```
Detection                    Pipeline                              Output
─────────                    ────────                              ──────
K8s Warning Events ──┐
Periodic Scanners ───┤       ScanResult
Flux Stall Events ───┼──→  → dedup / escalation ──→ enrichment   Slack alert
                     │     → sanitize ──→ LLM (production only)   (one per incident)
Daily / weekly ──────┘     → format ──→ post                      Daily / weekly report
```

## Scanners

| Scanner | What it checks | Default | Flag |
|---|---|---|---|
| Pod | container states (CrashLoop, OOM, ImagePull, ...); a finished pod with a healthy owner is not an incident | on | `SCANNER_POD_ENABLED` |
| Node | cordoned, NotReady, memory / disk / PID pressure | on | `SCANNER_NODE_ENABLED` |
| HPA | an autoscaler pinned at its maximum (the `TooManyReplicas` reason, not just `ScalingLimited`) | on | `SCANNER_HPA_ENABLED` |
| PVC | disk usage and growth (days to full) via Prometheus | on | `SCANNER_PVC_ENABLED` |
| Certificate | cert-manager certificate expiry | on | `SCANNER_CERT_ENABLED` |
| Backup | CloudNativePG: the latest Backup of each ScheduledBackup, and recoverability from the Cluster's `lastSuccessfulBackup` | on | `SCANNER_BACKUP_ENABLED` |
| Reconcile | closes incidents whose cause is gone (nodes, Flux, cert-manager, Jobs, event-only workloads) | always | - |
| Endpoint | HTTP health checks on ingress endpoints | off | `ENDPOINT_SCAN_ENABLED` |
| Critical endpoint | Traefik IngressRoute chain probing, with flap damping | off | `SCANNER_CRITICAL_ENDPOINT_ENABLED` |
| SLI | SLIs declared in a YAML file, checked against Prometheus | off | `SCANNER_SLI_ENABLED` |

## Quick Start

```bash
pip install -r requirements.txt
export LLM_PROVIDER=anthropic ANTHROPIC_API_KEY=...   # or openai / gemini
export SLACK_WEBHOOK_URL=...                          # empty: alerts go to the console
export INTERNAL_TOKEN=...                             # empty: the HTTP API is locked
kopf run --standalone --all-namespaces src/handlers/__init__.py
```

## Configuration

Everything is configured through environment variables. The complete, generated reference - every
variable, its default and what it does - is **[docs/configuration.md](docs/configuration.md)**.

The settings that matter first:

| Variable | Default | |
|---|---|---|
| `CLUSTER_NAME` | `unknown` | shown in every alert |
| `WATCH_NAMESPACES` / `NON_PROD_NAMESPACES` | `production` / empty | production gets the LLM; non-prod is tracked without it |
| `LLM_PROVIDER` | `anthropic` | `anthropic`, `openai` or `gemini`, with its API key |
| `SLACK_WEBHOOK_URL` / `SLACK_WEBHOOK_URL_NONPROD` | empty | where alerts go; empty = console |
| `INTERNAL_TOKEN` | empty | required for every HTTP route except `/healthz`; empty = API locked |
| `PROMETHEUS_URL` | see reference | metrics for context, PVC growth, SLIs |
| `UPTRACE_API_URL` / `UPTRACE_API_TOKEN` | empty | optional trace lookups |

### Available, off by default, not used on the course platform

These are general features, kept for other setups. They stay off unless their variables are set:
- **Elasticsearch** log search and error patterns (`ELASTICSEARCH_URL`) - the course reads pod logs
  from the Kubernetes API.
- **Central aggregation** - pushing incidents and reports to a central ClickHouse for many clusters
  (`CENTRAL_AGGREGATE=true`). The course has one cluster and publishes nothing centrally.
- **SLI scanner** (`SCANNER_SLI_ENABLED=true`) - the course alerts through PrometheusRules and
  Alertmanager instead.
- **Hourly digest** (`HOURLY_DIGEST_ENABLED`), **open-incident digest** (`OPEN_DIGEST_HOURS`),
  **a Slack mention on critical alerts** (`SLACK_CRITICAL_MENTION`).

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
python -m src.cli suppress --type certificate --ns production --pattern '*backend*' --reason 'known issue' [--hours 24]
python -m src.cli unsuppress <id>

# Reports
python -m src.cli reports [--limit N]
python -m src.cli report <id>

# LLM usage
python -m src.cli llm-usage [--hours 24]

# Dedup state
python -m src.cli state
```

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

Every endpoint except `/healthz` requires the `X-Internal-Token` header matching `INTERNAL_TOKEN`. Without `INTERNAL_TOKEN` the API is locked (401), not open; `/healthz` returns 503 when the SQLite store cannot be reached, so the kubelet restarts the pod.

## Deployment

Deployed via FluxCD from the platform repository (`safeops-course/sre`):
`flux/infrastructure/observability/k8s-ai-monitor/`. Image: `ghcr.io/safeops-course/k8s-ai-monitor`,
built by `.github/workflows/build.yml` on every push to `main`.

## Development

```bash
# Run tests
python -m pytest tests/

# Project structure
src/
├── config.py           # All env vars (reference: docs/configuration.md, generated)
├── cli.py              # CLI tool
├── mcp_server.py       # MCP server (stdio) for AI agents
├── reporter.py         # Daily / weekly report orchestration
├── handlers/           # Kopf handlers: startup + HTTP API, Warning events, Flux stalls
├── engine/             # pipeline, LLM, notifier, escalation, enrichment, digests, sanitizer, store
├── scanners/           # pod, node, hpa, pvc, certificate, endpoint, critical_endpoint, backup, reconcile, sli
├── collectors/         # Context for the LLM: pod, node, metrics, daily, flux, prometheus, uptrace
└── diagnostics/        # Issue-specific diagnostic plugins (OOM, crash, image pull, scheduling, ...)

# Hooks: branch guard, gitleaks, ruff, config-doc check; pytest before push
pip install pre-commit && pre-commit install

# After changing src/config.py
python3 scripts/gen-config-doc.py
```


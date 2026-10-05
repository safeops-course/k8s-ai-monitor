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
├── config.py                  # All env vars - reference: docs/configuration.md (generated)
├── cli.py                     # CLI tool (python -m src.cli)
├── mcp_server.py              # MCP server for AI agents (python -m src.mcp_server)
├── reporter.py                # Daily / weekly report orchestration
├── handlers/                  # Kopf handlers
│   ├── startup.py            #   startup, HTTP API (auth middleware), scanner loops, schedulers
│   ├── events.py             #   Warning K8s events -> ScanResults through the pipeline
│   ├── alertmanager.py       #   POST /alertmanager: Prometheus alerts -> ScanResults (never_promote)
│   └── flux.py               #   Flux Kustomization/HelmRelease stalls -> the pipeline
├── engine/
│   ├── pipeline.py           #   Shared detect -> dedup -> enrich -> analyze -> alert pipeline
│   ├── llm.py                #   LLM calls (anthropic / openai / gemini), parsing, retry, cost
│   ├── notifier.py           #   Slack: webhooks, or Bot API with threading; Block Kit formatting
│   ├── enrichment.py         #   Context without an LLM: flap history, trend, HPA, deploy, trace
│   ├── digest.py             #   Hourly digest of withheld alerts (HOURLY_DIGEST_ENABLED)
│   ├── open_digest.py        #   Still-open incidents at fixed hours (OPEN_DIGEST_HOURS)
│   ├── critical.py           #   Infra / important service tiers (forced severity, debounce)
│   ├── escalation.py         #   Recurring / persistent escalation
│   ├── fingerprint.py        #   Incident fingerprints
│   ├── owner.py              #   Pod -> ReplicaSet -> Deployment owner resolution
│   ├── context_budget.py     #   Context size measurement & truncation
│   ├── sanitizer.py          #   Secret / token redaction
│   ├── central_push.py       #   Optional central ClickHouse aggregation (off; unused in the course)
│   └── store/sqlite.py       #   Incidents, occurrences, LLM calls, reports, suppressions, migrations
├── scanners/                  # Periodic scanners, auto-discovered (Scanner protocol)
│   ├── pod.py, node.py, hpa.py, pvc.py, certificate.py, endpoint.py
│   ├── critical_endpoint.py  #   Traefik IngressRoute chain probing + flap damping
│   ├── backup.py             #   CloudNativePG Backups + recoverability (lastSuccessfulBackup)
│   ├── reconcile.py          #   Closes incidents whose cause is gone
│   └── sli.py                #   YAML-declared SLIs (off by default)
├── collectors/                # Context: pod, node, metrics, daily, flux, prometheus, uptrace, elasticsearch (optional)
└── diagnostics/               # Issue-specific diagnostic plugins (OOM, crash, image pull, ...)

scripts/gen-config-doc.py      # Generates docs/configuration.md from src/config.py
tests/                         # pytest suite - runs in pre-push and in CI (test.yml)
```

## Architecture

### Detection → Pipeline → Alert flow

Four detection sources feed into a shared pipeline:

1. **Real-time events** (`handlers/events.py`) — Kopf watches Warning K8s events, filters by `IMPORTANT_EVENT_REASONS`
2. **Periodic scanners** (`scanners/`) — pod, node, HPA, PVC, certificate, endpoint, critical endpoint, backup, reconcile on independent async loops
3. **Flux events** (`handlers/flux.py`) — Kopf watches Kustomization/HelmRelease for `Stalled` condition
4. **Daily report** (`reporter.py`) — Scheduled at `DAILY_REPORT_HOUR_UTC`

All scanner results go through `engine/pipeline.py: process_scan_results()`:
```text
ScanResult → dedup / escalation (store) → collect context + enrichment →
sanitize → budget/truncate → LLM analyze (production only) → format → Slack post
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

`NON_PROD_NAMESPACES` — monitored, never sent to the LLM: incidents are tracked, fingerprinted and posted with their collected context to `SLACK_WEBHOOK_URL_NONPROD`, with 2x debounce. The LLM cost is kept for production.

Without an API key for `LLM_PROVIDER` (`llm.llm_configured()`), every incident takes the non-prod
path: tracked, fingerprinted and posted with its collected context, never analysed; the daily and
weekly reports (LLM summaries) are skipped with a warning. The course runs it that way on kind.

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
| `/alertmanager` | POST | Token | Alertmanager webhook receiver: each alert becomes an incident (`resolved` closes it) |
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

Auth: every route except `/healthz` needs `X-Internal-Token` or `Authorization: Bearer` matching `INTERNAL_TOKEN` (`_auth_middleware` in `src/handlers/startup.py`). Without `INTERNAL_TOKEN` the API is locked (401). `/healthz` pings the store and returns 503 when it cannot be reached.

## Environment Variables

The complete reference is generated from `src/config.py`: **docs/configuration.md** (`python3
scripts/gen-config-doc.py`; pre-commit checks it is current). Do not keep env tables by hand -
they drift. Rules:

- A new env var goes into `config.py` with a comment above it; regenerate the doc.
- New behaviour that changes who gets paged ships **off** behind a boolean feature gate.
- Features the course platform does not run stay available but off: Elasticsearch, central
  ClickHouse aggregation (`CENTRAL_AGGREGATE`), the SLI scanner.

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
python -m src.cli suppress --type certificate --ns production --pattern '*backend*' --reason 'known issue' [--hours 24]
python -m src.cli unsuppress <id>

# Reports
python -m src.cli reports [--limit N]
python -m src.cli report <id>

# LLM usage
python -m src.cli llm-usage [--hours 24]

# State
python -m src.cli state

# Elasticsearch log search (optional - only when ELASTICSEARCH_URL is set; unused in the course)
python -m src.cli logs --ns production --pod '*backend*' --since 30 --query 'timeout OR 503'
python -m src.cli logs --ns production --errors --since 60

# Uptrace span search
python -m src.cli traces --service backend --since 30 --errors
python -m src.cli traces --service backend --slow --min-duration 1000
python -m src.cli traces --service backend --stats

# Prometheus metrics
python -m src.cli metrics --ns production --pod backend --since 30
python -m src.cli metrics --query 'rate(http_requests_total[5m])' --since 30

# Multi-source investigation
python -m src.cli investigate --ns production --since 30
python -m src.cli investigate --ns production --pod backend --since 60 --llm

# Observability audit
python -m src.cli audit --ns production
python -m src.cli audit --ns production --pod backend
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
| `search_logs` | Elasticsearch log search (optional; returns not_configured without ES) |
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
- No access to Kubernetes Secrets: the ClusterRole grants none - listing or reading a Secret returns its contents. Take what you need from other objects (CNPG Cluster status, cert-manager Certificate status, events). Tokens (Slack bot, Uptrace, LLM) come from env vars that the Deployment fills from its own Secret - never from a Secret read at runtime. No exceptions
- Use `sanitizer.py` for any new context that might contain sensitive data (`sanitize_dict` also redacts any string under a secret-named key). Logs and alert text are untrusted input to the LLM - redaction is not a defence against prompt injection, and the LLM's commands are proposals a person checks
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

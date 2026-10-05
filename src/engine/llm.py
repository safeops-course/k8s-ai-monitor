"""LLM abstraction — extracted from analyzer.py."""
import functools
import json
import logging
import re
import sqlite3
import threading
import time
from collections import deque
from dataclasses import dataclass

from src import config
from src.engine import central_push

logger = logging.getLogger(__name__)

ALERT_SYSTEM_PROMPT = """You are a Kubernetes SRE assistant. Analyze the JSON diagnostic data.
Return STRICT JSON only. No text outside JSON.

{{
  "reasoning": "string - FIRST, write 2-5 sentences of step-by-step analysis. Work through the data: pod phase, container state, restart count, exit code, recent log lines, events, node metrics. Cross-reference the SRE knowledge base for noise patterns, blast-radius rules, recovery-timing grace windows, and service baselines. Cite SPECIFIC evidence (log substring, event reason, metric value). DO NOT jump to conclusions here — this is your scratch space before committing to root_cause.",
  "root_cause": "string - derived from your reasoning above, with specific evidence",
  "confidence": 0.0-1.0,
  "severity": "warning|critical",
  "human_needed": boolean - true if manual intervention is required, false for self-healing/trivial issues,
  "hypotheses": [
    {{"cause": "string", "confidence": 0.0-1.0, "evidence": ["string"]}}
  ],
  "impact": "string - what is affected and blast radius",
  "complete_elimination_plan": [
    {{"step": "string - concrete kubectl/config command", "priority": 1-3, "description": "why this helps"}}
  ]
}}

Rules:
- reasoning: write this FIRST as the opening JSON field. It is mandatory, not optional. Reference specific log lines, event reasons, or metric values from the observed data. Reference the SRE knowledge base where relevant (noise patterns, blast-radius, recovery timing). This is mandatory thinking before you derive root_cause — not commentary about the alert.
- severity: SMART RE-EVALUATION. If the data suggests a non-critical resource (e.g. low-impact worker, ephemeral job) is failing, set to "warning" even if the raw error is OOM/Crash. Only "critical" if it affects users, data integrity, or core infrastructure.
- memory: a container sitting at a STABLE percentage of its limit (a flat first→last memory trend) is NORMAL for heap-bounded workloads (JVM -Xmx, Go GOMEMLIMIT, etc.) — RSS plateaus at a fixed level and does NOT grow into an OOM. Do NOT report high-but-flat memory (e.g. 80-90% of limit, marked "flat/plateau") as an OOM risk. Only treat memory as a concern when the trend is RISING toward the limit over the window, or there are actual OOMKilled events (exit code 137) in the container state/history.
- human_needed: false if the issue is self-healing, expected, or can be ignored. true if an SRE MUST act to resolve it.
- complete_elimination_plan: provide specific, copy-pasteable commands where possible. Priority 1=immediate fix, 2=short-term, 3=preventive.
- JSON only, no fences.

Cluster: {cluster_name}"""

DAILY_REPORT_SYSTEM_PROMPT = """You are a Kubernetes operations expert. You receive cluster health data as JSON containing: current state snapshot and last 24-hour history (incidents, restarts, OOM kills).
Return STRICT JSON only. No text outside JSON.

{{
  "reasoning": "string - FIRST, write 3-6 sentences walking through the input. Inventory what you see: which services had incidents, which were recurring, which current_snapshot values diverge from initial_analysis, what patterns suggest a common underlying cause. Cross-reference each incident's `initial_analysis.reasoning` — do not duplicate it, but USE it to decide whether the situation is stable, evolving, or escalating. This is your scratch space before writing overall_status, summary, issues, trends, and recommendations.",
  "overall_status": "healthy|degraded|critical",
  "confidence": 0.0-1.0,
  "summary": "1-2 sentence overview",
  "issues": [
    {{"description": "string", "severity": "critical|warning", "affected": "what's affected"}}
  ],
  "trends": [
    {{"description": "pattern observed OR a benign info-level observation"}}
  ],
  "recommendations": [
    {{"action": "concrete step", "priority": 1-3}}
  ]
}}

Rules:
- reasoning: mandatory first field. Write it BEFORE you commit to overall_status or a summary. Reference specific incident state_keys, evidence from `initial_analysis`, and SRE-knowledge-base patterns where relevant.

## Severity Matrix — determines overall_status:

CRITICAL (real outage — immediate action required):
- Node(s) NotReady
- Production pods in CrashLoopBackOff RIGHT NOW (phase != "Running" or ready == false)
- Active OOMKilled events in the last 2 hours
- PVC usage > 95%
- Multiple HelmRelease/Kustomization failures (deployments blocked)

WARNING (needs attention, but workloads ARE running):
- Pods restarted recently AND still not stable (hours_since_last_restart < 2 AND restarts > 3)
- Single HelmRelease or Kustomization failure
- Certificates expiring in < 7 days
- Node memory > 90% together with OOM kills

INFORMATIONAL (mention in "trends" ONLY — never in "issues" — and do NOT raise overall_status):
- Pod restarted but currently Running stable (hours_since_last_restart > 2, phase="Running", ready=true) — RECOVERED, not degraded
- HelmRepository / HelmChart / GitRepository / OCIRepository errors — source-level Flux, does NOT impact running workloads unless a downstream HelmRelease is also failing
- System/infra pod restarts (external-dns, cert-manager, kube-proxy, coredns) with low count and currently stable
- Node memory 70-90% — normal Linux page cache, reclaimable on demand
- CONTAINER memory sitting at a stable 70-95% of its limit is NORMAL for heap-bounded workloads and is NOT an OOM risk. A JVM service (-Xmx) RSS = fixed heap + off-heap that is mostly reclaimable page cache and direct buffers; a Node.js service (--max-old-space-size) grows its heap into whatever it is given and plateaus. Do NOT recommend raising memory limits for high-but-flat container memory — the heap cannot exceed -Xmx and the cache shrinks under pressure. Only a memory trend RISING toward the limit over the window, or actual OOMKilled events (exit 137), is a real concern.
- Resolved or acknowledged incidents from last_24h
- Transient probe failures ("Unhealthy" readiness/liveness Warning events) where the affected pods have NO restarts and are currently Running+ready — typically HPA scale-up / pod startup blips (app not yet bound to its port, "connection refused"). Informational, not warning. Only escalate if the probe failures caused restarts or a pod is currently stuck not-ready.
- FailedScheduling for ephemeral/runner pods (actions-runner, github-runner) — normal queue behavior
- hcloud-csi-node image pull errors on new/autoscaled nodes — transient and expected

## Key Rule:
overall_status reflects ACTIVE impact on production workloads ONLY.
- If all pods are Running+ready, all nodes Ready, deployments succeeding → "healthy" even with info-level observations.
- "degraded" requires: production pods not Running/not ready, active crash loops, or failed deployments blocking releases.
- "critical" requires: actual outage, data loss risk, or nodes down.
- Put ONLY warning/critical (actionable) items in "issues". Info-level / benign observations go in "trends", never "issues". Do NOT escalate overall_status unless the criteria above are met.

## Pod restart triage:
- Each entry has "hours_since_last_restart", "phase", and "ready" fields.
- hours_since_last_restart > 2 AND phase="Running" AND ready=true → RECOVERED, informational only.
- hours_since_last_restart < 2 AND restarts > 3 → active crash loop, warning or critical.
- Multiple pods restarting on the SAME node → likely node-level issue (memory pressure, OOM), report as node problem.
- The daily report covers the LAST 24h ONLY. Do NOT surface restarts, incidents, or events older than 24h — those belong to the weekly report. If an incident's last activity is >24h ago, treat it as out of scope for the daily report.

## Flux resource triage:
- HelmRelease / Kustomization failure = deployment pipeline blocked → warning.
- HelmRepository / GitRepository / OCIRepository / HelmChart error = source-level only, existing releases keep running → informational.
- Only escalate source errors if a downstream HelmRelease is ALSO failing.

## Incident status triage (last_24h):
- "active": assess current impact using the rules above.
- "resolved": occurred and recovered — mention in trends, never raise severity.
- "acknowledged": someone is aware — mention, don't escalate.

## Per-incident enrichment (last_24h.incidents):

Each incident entry may carry three optional fields that represent the
incident's own history within the reporting window:

- `initial_analysis`: the full LLM diagnosis performed when the incident was
  first seen in this window — `root_cause`, `confidence`, `severity`,
  `hypotheses`, `impact`, `suggested_actions`, `analyzed_at`, `analyzed_by`.
  Reuse these fields instead of re-deriving them. Do NOT duplicate
  `hypotheses` in your own output; reference the initial diagnosis briefly
  ("Initial analysis: memory limit too low").
- `repetition`: `{{count_since_initial, duration_minutes, note}}`. A high
  `count_since_initial` with unchanged analysis means the incident has been
  stable but unresolved — surface the highest-priority item from
  `initial_analysis.suggested_actions` in your `recommendations`.
- `current_snapshot`: the most recent observed state (e.g. `restart_count`,
  `last_reason`, `phase`, `ready` for pods; `status_code`, `url` for
  endpoints). Compare against `initial_analysis`:
  - snapshot matches initial (same reason/phase): repeat the initial
    diagnosis briefly and flag that the suggested actions haven't been
    applied.
  - snapshot differs (new reason, worse counts): flag as "evolving —
    recommend re-investigation" in `trends`.

## General:
- If all data sections are empty → overall_status="healthy", summary="All systems operational".
- issues: warning/critical ONLY; group by severity, reference specific pods/nodes. When there are no warning/critical problems, "issues" MUST be an empty array [] — a healthy cluster lists observations under "trends", not "issues".
- recommendations: priority 1=immediate, 2=short-term, 3=preventive.
- confidence: 0.0-1.0 based on data completeness.
- JSON only, no fences.

Cluster: {cluster_name}"""

WEEKLY_REPORT_SYSTEM_PROMPT = """You are a Kubernetes operations expert. You receive a weekly summary as JSON containing: daily report statuses, incident aggregation by type/severity, incident details, and LLM cost data for the past 7 days.
Return STRICT JSON only. No text outside JSON.

{{
  "overall_trend": "improving|stable|degrading",
  "summary": "1-2 sentence week overview",
  "recurring_issues": [
    {{"description": "string", "frequency": 0, "services_affected": ["string"], "impact_level": "production|operational|noise"}}
  ],
  "trends": [
    {{"description": "pattern observed", "direction": "improving|worsening|stable"}}
  ],
  "recommendations": [
    {{"action": "concrete step", "priority": 1-3, "impact": "expected outcome"}}
  ],
  "cost_summary": {{
    "total_llm_cost_usd": 0.0,
    "total_alerts": 0,
    "total_reports": 0
  }}
}}

## Impact Classification (CRITICAL — apply before analyzing):

PRODUCTION impact (affects users/workloads — report as recurring_issues):
- Pods in CrashLoopBackOff that did NOT recover (status remains "active")
- OOMKilled events on production workload pods
- HelmRelease / Kustomization failures (deployment pipeline blocked)
- Node NotReady events
- PVC near-full on production volumes
- Backup job failures for production databases

OPERATIONAL impact (infrastructure concern, no user impact — mention briefly):
- System/infra pod restarts that self-healed (external-dns, cert-manager, coredns, node-exporter, kube-proxy, k8s-ai-monitor) — these are self-healing infrastructure components, NOT application instability
- Single HelmRelease failure that resolved quickly
- Certificate warnings (expiring > 7 days)

NOISE (do NOT include in recurring_issues or trends):
- HelmRepository / GitRepository / OCIRepository / HelmChart errors — source-level Flux, does NOT block running workloads. Only mention if a downstream HelmRelease is ALSO failing.
- FailedScheduling for ephemeral/runner pods (actions-runner, github-runner) — normal queue behavior, runners scale up and down constantly
- hcloud-csi-node / csi-driver image pull errors on new/autoscaled nodes — transient and expected
- Resolved incidents that did not recur — happened once, self-healed, done
- Pod restarts where status="resolved" and occurrences=1 — one-off restart, not a pattern
- Container memory sitting at a stable 70-95% of its limit for a heap-bounded workload — NOT a capacity problem and NOT a recommendation to raise limits. A JVM service (-Xmx) RSS = a fixed heap plus mostly-reclaimable off-heap (page cache, direct buffers); a Node.js service plateaus at its --max-old-space-size. An IDLE cluster shows the same high percentage as a busy one, because it is heap reservation, not load. "Increase the memory limits" for such a workload is a recurring WRONG recommendation from this exact misread — the heap cannot exceed -Xmx and the cache shrinks under pressure. Only flag memory when RSS is RISING toward the limit across the week, or there are actual OOMKilled events (exit 137). A rising weekly RSS trend IS actionable, but do NOT classify it as an off-heap leak on the trend alone — name a leak only with corroborating evidence (OOMKilled events, growth that keeps climbing toward the limit while the workload stays flat, or another concrete leak indicator); absent that, report it as a rising-memory trend to watch, still not grounds to raise the limit.

## Rules for recurring_issues:
- ONLY include issues with PRODUCTION or OPERATIONAL impact_level
- Do NOT group unrelated services into one "recurring issue" — external-dns restarts and backend restarts are different issues with different root causes
- Each recurring_issue must describe ONE specific problem, not a category
- frequency = actual count of occurrences, not number of affected services
- Occurrence count vs duration: for CONTINUOUS issues (FailedScheduling deadlock, a persistently-unhealthy pod, a backup failing every run) the `occurrences` field is just the number of scan re-detections (~one every 30-60s), NOT distinct failures. Describe these by DURATION first, using `duration_hours` — e.g. "persisted ~4h (534 detections)" — not "534x". Keep a leading raw "Nx" only for DISCRETE events where each occurrence is a separate real failure (an endpoint flapping down/up N times, a backup job failing on N distinct scheduled runs).
- Set impact_level: "production" for user-facing, "operational" for infra-only, "noise" (but these should not appear)

## Rules for overall_trend:
- "degrading" ONLY if production-impacting incidents are INCREASING in frequency or severity across the week
- "improving" if production incidents decreased or resolved
- "stable" if the pattern is consistent — even if there are operational/noise items
- Infrastructure noise (source-level Flux, runner scheduling, self-healing restarts) does NOT affect trend direction

## Rules for recommendations:
- Be SPECIFIC: name the exact service, namespace, and action. "Investigate restarts" is not actionable.
- Do NOT recommend generic best practices ("add probes", "validate RBAC", "add monitoring") unless there is specific evidence they are missing
- Focus on ROOT CAUSE: if external-dns restarts weekly, recommend checking the specific provider config or memory limits — not "inspect logs"
- priority 1 = fix this week (production impact), 2 = fix soon (operational), 3 = track/improve (pattern)
- Maximum 3 recommendations. Quality over quantity.

## Rules for trends:
- Compare daily report statuses across the week — are there more "degraded" days at the end vs the start?
- Look at incident severity distribution changes, not just counts
- Self-healing restarts are a PATTERN to note ("X restarts weekly but self-heals"), not "instability"

- cost_summary: use the provided LLM usage data
- JSON only, no fences

Cluster: {cluster_name}"""

# Thread-safe sliding window rate limiter
_call_timestamps: deque[float] = deque()
_rate_lock = threading.Lock()

# Pricing per million tokens: {model_prefix: (input_$/MTok, output_$/MTok)}
# Gemini 3.1 prices are for ≤200k token contexts (standard tier). Above 200k,
# input doubles and output rises ~50% — not modeled here, we stay within 200k.
_MODEL_PRICING = {
    "claude-opus-4":              (5.0, 25.0),
    "claude-sonnet-4":            (3.0, 15.0),
    "claude-haiku-4":             (1.0, 5.0),
    "gpt-4o-mini":                (0.15, 0.6),
    "gpt-4o":                     (2.5, 10.0),
    "gpt-4.1-mini":               (0.4, 1.6),
    "gpt-4.1-nano":               (0.1, 0.4),
    "gpt-5-mini":                 (0.25, 2.0),
    "gpt-5.2":                    (1.75, 14.0),
    "gemini-3.1-pro":             (2.0, 12.0),
    "gemini-3.1-flash-lite":      (0.25, 1.5),
    "gemini-3.1-flash":           (0.30, 2.5),  # placeholder until official pricing confirmed
}

# Structured JSON parsing defaults.
# NOTE: `human_needed` is deliberately NOT in this dict. It is auto-derived
# from `confidence` further down in `parse_analysis` (missing → confidence
# >= 0.7 means False, else True). Putting a default of True here would
# shadow that branch and force every high-confidence response that omits
# the field into `human_needed=True`, which destroys the noise-reduction
# gate in `pipeline._should_post_slack`.
_ANALYSIS_DEFAULTS = {
    "reasoning": "",
    "confidence": 0.3,
    "severity": "warning",
    "impact": "unknown",
    "hypotheses": [],
    "suggested_actions": [],
    "complete_elimination_plan": [],
}


@dataclass
class AnalysisResult:
    raw_text: str
    parsed: dict | None        # structured JSON if parse succeeded
    parse_error: bool
    model: str
    tokens_in: int | None      # None when the provider returns no usage metadata
    tokens_out: int | None     # None when the provider returns no usage metadata
    cost_usd: float | None
    latency_ms: float = 0.0
    # True when the LLM call itself failed (provider error / timeout), as
    # opposed to a successful call whose output merely failed to parse as JSON
    # (parse_error). Callers that want to retry on transient provider outages
    # — e.g. the daily report scheduler — key off this, not parse_error.
    llm_error: bool = False


def parse_analysis(raw: str) -> tuple[dict, bool]:
    """Parse structured JSON from LLM response. Returns (parsed_dict, had_error)."""
    text = raw.strip()
    # Strip markdown fences if LLM added them
    if text.startswith("```"):
        lines = text.split("\n")
        end_idx = len(lines)
        for i in range(len(lines) - 1, 0, -1):
            if lines[i].startswith("```"):
                end_idx = i
                break
        text = "\n".join(lines[1:end_idx])

    try:
        data = json.loads(text)
        if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict):
            data = data[0]
        if not isinstance(data, dict):
            raise ValueError("Expected JSON object")
        # Fill missing keys with defaults
        for key, default in _ANALYSIS_DEFAULTS.items():
            data.setdefault(key, default)
        # Ensure root_cause exists
        data.setdefault("root_cause", "Unknown")
        # Clamp confidence
        try:
            data["confidence"] = max(0.0, min(1.0, float(data.get("confidence", 0.3))))
        except (ValueError, TypeError):
            data["confidence"] = 0.3

        # Validate hypotheses
        if not isinstance(data.get("hypotheses"), list):
            data["hypotheses"] = []
        for h in data["hypotheses"]:
            if isinstance(h, dict):
                h.setdefault("cause", "")
                h.setdefault("confidence", data["confidence"])
                if not isinstance(h.get("evidence"), list):
                    h["evidence"] = []

        # Validate suggested_actions
        if not isinstance(data.get("suggested_actions"), list):
            data["suggested_actions"] = []
        for sa in data["suggested_actions"]:
            if isinstance(sa, dict):
                sa.setdefault("action", "")
                try:
                    sa["priority"] = max(1, min(3, int(sa.get("priority", 2))))
                except (ValueError, TypeError):
                    sa["priority"] = 2

        # Validate complete_elimination_plan
        if not isinstance(data.get("complete_elimination_plan"), list):
            data["complete_elimination_plan"] = []
        for ep in data["complete_elimination_plan"]:
            if isinstance(ep, dict):
                ep.setdefault("step", "")
                ep.setdefault("description", "")
                try:
                    ep["priority"] = max(1, min(3, int(ep.get("priority", 2))))
                except (ValueError, TypeError):
                    ep["priority"] = 2

        # Backward compat: old schema → new schema
        if not data["hypotheses"] and data.get("evidence"):
            data["hypotheses"] = [{
                "cause": data["root_cause"],
                "confidence": data["confidence"],
                "evidence": data["evidence"],
            }]
        if not data["suggested_actions"] and data.get("action_plan"):
            data["suggested_actions"] = [
                {"action": step, "priority": 2}
                for step in data["action_plan"]
            ]
        if not data["complete_elimination_plan"] and data.get("suggested_actions"):
            data["complete_elimination_plan"] = [
                {"step": sa["action"], "priority": sa["priority"], "description": ""}
                for sa in data["suggested_actions"]
            ]
        # Reverse fallback: old enrichment (daily.py) expects suggested_actions
        if not data.get("suggested_actions") and data["complete_elimination_plan"]:
            data["suggested_actions"] = [
                {"action": ep["step"], "priority": ep["priority"]}
                for ep in data["complete_elimination_plan"]
            ]

        # Auto-derive human_needed if missing or low confidence
        if "human_needed" not in data:
            data["human_needed"] = data["confidence"] < 0.7
        if data["confidence"] < 0.7:
            data["human_needed"] = True

        return data, False
    except (json.JSONDecodeError, ValueError, TypeError):
        return {
            "reasoning": "",
            "root_cause": raw,
            "confidence": 0.3,
            "severity": "warning",
            "impact": "unknown",
            "hypotheses": [],
            "suggested_actions": [],
            "complete_elimination_plan": [],
            "human_needed": True,
            "_parse_error": True,
        }, True


_DAILY_REPORT_DEFAULTS = {
    "overall_status": "healthy",
    "confidence": 0.5,
    "summary": "",
    "issues": [],
    "trends": [],
    "recommendations": [],
}


def parse_daily_report(raw: str) -> tuple[dict, bool]:
    """Parse structured JSON from daily report LLM response. Returns (parsed_dict, had_error)."""
    text = raw.strip()
    # Strip markdown fences if LLM added them
    if text.startswith("```"):
        lines = text.split("\n")
        end_idx = len(lines)
        for i in range(len(lines) - 1, 0, -1):
            if lines[i].startswith("```"):
                end_idx = i
                break
        text = "\n".join(lines[1:end_idx])

    try:
        data = json.loads(text)
        # LLM sometimes wraps the response in an array — unwrap single-element lists.
        if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict):
            data = data[0]
        if not isinstance(data, dict):
            raise ValueError("Expected JSON object")
        # Fill missing keys with defaults
        for key, default in _DAILY_REPORT_DEFAULTS.items():
            data.setdefault(key, default)
        # Validate overall_status
        if data["overall_status"] not in ("healthy", "degraded", "critical"):
            data["overall_status"] = "degraded"
        # Clamp confidence
        try:
            data["confidence"] = max(0.0, min(1.0, float(data.get("confidence", 0.5))))
        except (ValueError, TypeError):
            data["confidence"] = 0.5
        # Validate issues
        if not isinstance(data.get("issues"), list):
            data["issues"] = []
        for issue in data["issues"]:
            if isinstance(issue, dict):
                issue.setdefault("description", "")
                issue.setdefault("severity", "info")
                issue.setdefault("affected", "")
        # Validate trends
        if not isinstance(data.get("trends"), list):
            data["trends"] = []
        # Validate recommendations
        if not isinstance(data.get("recommendations"), list):
            data["recommendations"] = []
        for rec in data["recommendations"]:
            if isinstance(rec, dict):
                rec.setdefault("action", "")
                try:
                    rec["priority"] = max(1, min(3, int(rec.get("priority", 2))))
                except (ValueError, TypeError):
                    rec["priority"] = 2

        return data, False
    except (json.JSONDecodeError, ValueError, TypeError):
        return {
            "overall_status": "degraded",
            "confidence": 0.3,
            "summary": raw,
            "issues": [],
            "trends": [],
            "recommendations": [],
            "_parse_error": True,
        }, True


def _check_rate_limit() -> bool:
    with _rate_lock:
        now = time.time()
        cutoff = now - 3600
        while _call_timestamps and _call_timestamps[0] < cutoff:
            _call_timestamps.popleft()
        if len(_call_timestamps) >= config.MAX_LLM_CALLS_PER_HOUR:
            logger.warning(
                "Rate limit reached: %d/%d calls in the last hour",
                len(_call_timestamps), config.MAX_LLM_CALLS_PER_HOUR,
            )
            return False
        _call_timestamps.append(now)
        return True


@functools.lru_cache(maxsize=4)
def _get_client_cached(provider: str):
    """Build a provider client once and reuse it across all LLM calls.

    Re-instantiating the SDK on every analyze_alert call (there are five
    call sites) was discarding the HTTP connection pool / keep-alive, so
    under a burst of alerts each request paid a full TCP + TLS handshake.
    With lru_cache the pool survives and we avoid the ephemeral-port
    exhaustion the reviewers flagged.
    """
    if provider == "openai":
        if not config.OPENAI_API_KEY:
            raise RuntimeError(
                "LLM_PROVIDER=openai but OPENAI_API_KEY is not set")
        import openai
        return "openai", openai.OpenAI(api_key=config.OPENAI_API_KEY, timeout=60.0)
    elif provider == "gemini":
        if not config.GEMINI_API_KEY:
            raise RuntimeError(
                "LLM_PROVIDER=gemini but neither GEMINI_API_KEY nor GOOGLE_API_KEY is set")
        from google import genai
        from google.genai import types as _genai_types_mod
        # Explicit 60s timeout — genai.Client's default has hung indefinitely
        # during network partitions in the past; a bounded value lets the
        # per-call asyncio.wait_for / executor timeout eventually kill the
        # task and release the worker.
        http_opts = _genai_types_mod.HttpOptions(timeout=60_000)  # ms
        return "gemini", genai.Client(
            api_key=config.GEMINI_API_KEY, http_options=http_opts,
        )
    else:
        if not config.ANTHROPIC_API_KEY:
            raise RuntimeError(
                "LLM_PROVIDER=anthropic but ANTHROPIC_API_KEY is not set")
        import anthropic
        return "anthropic", anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY, timeout=60.0)


def _get_client():
    """Legacy wrapper so all existing call sites keep their zero-arg signature.
    The cached version keyed by provider is the actual worker."""
    return _get_client_cached(config.LLM_PROVIDER)


def _get_model(provider: str, tier: str = "alert") -> str:
    if tier == "report" and config.LLM_MODEL_REPORT:
        return config.LLM_MODEL_REPORT
    if tier == "alert" and config.LLM_MODEL:
        return config.LLM_MODEL
    if provider == "gemini":
        # Flash for reports (good reasoning with CoT, much cheaper than Pro).
        # Flash-Lite for alerts (cheapest, fastest).
        return "gemini-3-flash-preview" if tier == "report" else "gemini-3.1-flash-lite-preview"
    if tier == "report":
        return "gpt-5.2" if provider == "openai" else "claude-sonnet-4-5-20250929"
    return "gpt-5-mini" if provider == "openai" else "claude-haiku-4-5-20251001"


def _estimate_cost(model: str, input_tokens: int | None, output_tokens: int | None,
                    flex: bool = False) -> float | None:
    if input_tokens is None or output_tokens is None:
        return 0.0 if model in ("sonnet", "opus", "haiku") else None
    for prefix, (inp_price, out_price) in _MODEL_PRICING.items():
        if model.startswith(prefix):
            cost = (input_tokens * inp_price + output_tokens * out_price) / 1_000_000
            if flex:
                cost *= 0.5
            return cost
    return 0.0 if model in ("sonnet", "opus", "haiku") else None


def _format_cost(cost: float | None) -> str:
    return f"${cost:.4f}" if cost is not None else "?"


def _is_gemini_config_rejection(exc: BaseException) -> bool:
    """True if Gemini rejected an OPTIONAL generation kwarg (flex routing or
    thinking level) rather than failing the request for a real reason.

    The SDK raises TypeError/ValueError when it does not know a parameter, but
    when the SDK accepts it and the *backend* rejects it (a model that has no
    thinking support, a tier not enabled for the project) it surfaces as an
    HTTP 400 / INVALID_ARGUMENT instead. Both mean the same thing to us: retry
    once without the optional knobs. Everything else must propagate — an auth
    failure or an oversized context is not something a retry can fix.
    """
    if isinstance(exc, (TypeError, ValueError)):
        return True
    msg = str(exc)
    if "400" not in msg and "INVALID_ARGUMENT" not in msg:
        return False
    return any(tok in msg.lower() for tok in
               ("thinking", "thinking_level", "thinking_config", "service_tier", "flex"))


def _log_gemini_finish(resp, usage, model: str, max_tokens: int, text_len: int) -> None:
    """Surface a non-STOP Gemini finish reason.

    `resp.text` returns whatever the model managed to emit before it stopped,
    with no indication that it stopped early — so a budget exhaustion looks
    exactly like a formatting mistake by the time it reaches the parser. This
    names it in the logs, with the thinking/answer token split that explains it.
    """
    try:
        candidates = getattr(resp, "candidates", None) or []
        if not candidates:
            return
        finish = getattr(candidates[0], "finish_reason", None)
        name = getattr(finish, "name", None) or str(finish or "")
        if not name or name == "STOP":
            return
        thoughts = getattr(usage, "thoughts_token_count", None)
        answer = getattr(usage, "candidates_token_count", None)
        if name == "MAX_TOKENS":
            logger.error(
                "Gemini hit MAX_TOKENS for %s — output truncated at %d chars. "
                "Budget max_output_tokens=%d was consumed by thinking=%s + "
                "answer=%s tokens; the JSON is incomplete and will fail to parse. "
                "Lower GEMINI_THINKING_LEVEL or raise REPORT_MAX_OUTPUT_TOKENS.",
                model, text_len, max_tokens, thoughts, answer)
        else:
            logger.error(
                "Gemini stopped early for %s: finish_reason=%s (thinking=%s, "
                "answer=%s tokens, %d chars emitted). Output is likely incomplete.",
                model, name, thoughts, answer, text_len)
    except Exception:  # never let diagnostics break the call path
        logger.debug("Could not inspect Gemini finish_reason", exc_info=True)


def _call_llm(provider: str, client, model: str, system: str, user_content: str,
              max_tokens: int, flex: bool = False) -> tuple[str, int | None, int | None, float, int]:
    """Call LLM and return (text, tokens_in, tokens_out, latency_ms, cached_tokens).

    cached_tokens is the count of input tokens served from a context cache
    (Gemini only — 0 for other providers).

    flex: when True AND provider is Gemini, requests "flex" (lower-priority)
    routing for ~50% token cost savings. Used by the cold-path batcher where
    latency tolerance is high. The exact API parameter may vary between SDK
    versions — if the SDK raises TypeError, the call falls back to standard
    routing and logs a warning.
    """
    t0 = time.monotonic()
    cached_tokens = 0
    if provider == "openai":
        # GPT-5+ models require max_completion_tokens instead of max_tokens
        token_param = ("max_completion_tokens" if model.startswith("gpt-5")
                       else "max_tokens")
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user_content},
            ],
            temperature=config.LLM_TEMPERATURE,
            **{token_param: max_tokens},
        )
        tokens_in = resp.usage.prompt_tokens if resp.usage else 0
        tokens_out = resp.usage.completion_tokens if resp.usage else 0
        if not resp.choices:
            logger.warning("OpenAI returned empty choices for %s (usage=%s)", model, resp.usage)
            text = ""
        else:
            text = resp.choices[0].message.content or ""
            finish = resp.choices[0].finish_reason
            if not text:
                logger.warning("OpenAI returned empty content (finish_reason=%s) for %s", finish, model)
    elif provider == "gemini":
        from google.genai import types as _genai_types

        # The critical-services watchlist goes into the system instruction, so
        # the model knows which workloads matter most on this cluster.
        watchlist = ", ".join(sorted(config.CRITICAL_SERVICES))
        contents = user_content
        full_system = (
            f"{system}\n\n"
            f"## Critical Services Watchlist\n{watchlist}\n"
        )

        # Flex routing: 50% token discount using off-peak compute capacity.
        # Latency: 1-15 min (acceptable for batch/reports, not for hot alerts).
        flex_kwargs: dict = {}
        use_flex = flex and config.GEMINI_FLEX_ENABLED
        if use_flex:
            flex_kwargs["service_tier"] = "flex"
            logger.debug("Gemini flex routing enabled for this call")

        # Thinking tokens are billed against `max_output_tokens` and are spent
        # BEFORE the answer, so an expensive thinking pass silently steals the
        # budget the JSON answer needs — the model then stops mid-string and we
        # get an unparseable report. Our prompts already require an explicit
        # `reasoning` field as the first JSON key, so a second invisible
        # reasoning pass buys nothing. See GEMINI_THINKING_LEVEL in config.
        thinking_kwargs: dict = {}
        if config.GEMINI_THINKING_LEVEL:
            thinking_kwargs["thinking_config"] = _genai_types.ThinkingConfig(
                thinking_level=config.GEMINI_THINKING_LEVEL,
            )

        def _build_gen_config(**extra):
            # temperature=0 (configurable via LLM_TEMPERATURE) keeps the model
            # deterministic for RCA — no inventing service names, no creative
            # "transient latency" filler. The JSON schema already constrains
            # output, but matching temperature=0 stops free-text fields
            # (root_cause, hypotheses) from drifting away from the input data.
            return _genai_types.GenerateContentConfig(
                system_instruction=full_system,
                max_output_tokens=max_tokens,
                response_mime_type="application/json",
                temperature=config.LLM_TEMPERATURE,
                **thinking_kwargs,
                **extra,
            )

        try:
            gen_config = _build_gen_config(**flex_kwargs)
            resp = client.models.generate_content(
                model=model, contents=contents, config=gen_config,
            )
        except Exception as exc:
            # Either kwarg can be rejected by an older SDK or a model that does
            # not support it. Drop both optional knobs and retry once — losing
            # flex pricing or thinking control beats losing the whole report.
            if (use_flex or thinking_kwargs) and _is_gemini_config_rejection(exc):
                # Log the rejection itself: the retry usually succeeds, so
                # without the cause here the only trace of a permanently
                # ignored knob is a warning that never says why.
                logger.warning(
                    "Gemini rejected optional kwargs (flex=%s, thinking=%s) — "
                    "retrying without them. Update GEMINI_FLEX_ENABLED / "
                    "GEMINI_THINKING_LEVEL once the correct parameters are "
                    "confirmed. Rejection was: %s",
                    flex_kwargs or None, thinking_kwargs or None, exc,
                    exc_info=True)
                thinking_kwargs = {}
                gen_config = _build_gen_config()
                resp = client.models.generate_content(
                    model=model, contents=contents, config=gen_config,
                )
            else:
                raise
        usage = getattr(resp, "usage_metadata", None)
        tokens_in = getattr(usage, "prompt_token_count", 0) or 0
        tokens_out = getattr(usage, "candidates_token_count", 0) or 0
        text = resp.text or ""
        # Fail loudly on a non-STOP finish. Until this check existed, a
        # MAX_TOKENS cut was indistinguishable from a model that just wrote bad
        # JSON: the caller saw only `parse_error` and Slack got a fallback
        # notice, with nothing in the logs naming the real cause. Log the
        # thinking/answer token split so the budget arithmetic is visible.
        _log_gemini_finish(resp, usage, model, max_tokens, len(text))
        if not text:
            logger.warning("Gemini returned empty text for %s (usage=%s)", model, usage)
    else:
        # Anthropic's API rejects temperature > 1.0; our config allows up to
        # 2.0 (the OpenAI/Gemini ceiling). Clamp here and log once when we
        # actually had to truncate so operators see the override.
        anthropic_temp = min(config.LLM_TEMPERATURE, 1.0)
        if anthropic_temp != config.LLM_TEMPERATURE and not getattr(
            _call_llm, "_anthropic_temp_clamped", False,
        ):
            logger.warning(
                "LLM_TEMPERATURE=%s clamped to %s for Anthropic API (max 1.0)",
                config.LLM_TEMPERATURE, anthropic_temp,
            )
            _call_llm._anthropic_temp_clamped = True  # type: ignore[attr-defined]
        resp = client.messages.create(
            model=model,
            system=system,
            messages=[
                {"role": "user", "content": user_content},
                {"role": "assistant", "content": "{"},
            ],
            max_tokens=max_tokens,
            temperature=anthropic_temp,
        )
        tokens_in = resp.usage.input_tokens if resp.usage else 0
        tokens_out = resp.usage.output_tokens if resp.usage else 0
        text = "{" + resp.content[0].text
    latency_ms = (time.monotonic() - t0) * 1000
    cost = _estimate_cost(model, tokens_in, tokens_out)
    cache_str = f", cached={cached_tokens}" if cached_tokens else ""
    logger.info("LLM usage [%s]: input=%d, output=%d tokens%s, cost=%s, latency=%.0fms",
                 model, tokens_in, tokens_out, cache_str, _format_cost(cost), latency_ms)
    return text, tokens_in, tokens_out, latency_ms, cached_tokens


# --- LLM call logging to SQLite ---

_log_local = threading.local()
_schema_ready = False
_schema_lock = threading.Lock()


# Exception substrings / types that indicate a transient provider issue —
# retryable without operator intervention. Provider-specific SDKs raise
# their own classes (openai.RateLimitError, anthropic.APIStatusError,
# google.genai exceptions), but all of them typically embed the HTTP
# status code in str(exc). Matching on substring is a provider-agnostic
# classifier that works across SDK upgrades.
_RETRYABLE_STATUS_TOKENS = (
    "429",  # rate limit (short backoff usually resolves)
    "500",  # generic server error
    "502",  # bad gateway
    "503",  # service unavailable
    "504",  # gateway timeout
    "UNAVAILABLE", "SERVICE_UNAVAILABLE", "INTERNAL",  # Google canonical names
    "overloaded",  # Anthropic 529 text variant
)


def _is_retryable_llm_error(exc: BaseException) -> bool:
    """True if the exception looks like a transient provider issue
    worth retrying with backoff (5xx / 429 / timeouts / connection
    errors). False for auth failures, malformed requests, context-size
    errors — those won't succeed on retry."""
    # Networking / timeout classes are always retryable.
    if isinstance(exc, (TimeoutError, ConnectionError, ConnectionResetError)):
        return True
    msg = str(exc)
    return any(tok in msg for tok in _RETRYABLE_STATUS_TOKENS)


def _call_llm_with_retry(provider: str, client, model: str, system: str,
                          user_content: str, max_tokens: int, flex: bool = False,
                          *, max_retries: int | None = None,
                          backoff_seconds: float | None = None):
    """Wrap `_call_llm` with exponential-backoff retry on transient
    provider errors. Non-retryable errors (auth, bad request, context
    too large) propagate immediately so we fail fast.

    `max_retries` default from `LLM_RETRY_COUNT` (default 2 → 3 total
    attempts). `backoff_seconds` default from `LLM_RETRY_BACKOFF_SECONDS`
    (default 5s → 5, 10, 20...). 0 disables retry for callers that
    want the old single-attempt behaviour.

    Returns `_call_llm`'s tuple with the actually-used flex flag appended:
    `(text, tokens_in, tokens_out, latency_ms, cached_tokens, effective_flex)`.
    Callers MUST use the returned `effective_flex` for cost estimation — a
    flex request that fell back to the standard tier (below) was billed at the
    standard rate, not the discounted flex rate.
    """
    retries = max_retries if max_retries is not None else config.LLM_RETRY_COUNT
    base = backoff_seconds if backoff_seconds is not None else config.LLM_RETRY_BACKOFF_SECONDS
    last_exc: BaseException | None = None
    # The flex/batch tier is best-effort and deprioritised under load — exactly
    # the condition that yields 503 UNAVAILABLE / 504 DEADLINE_EXCEEDED. Start
    # on the requested tier (cheap), but after the first transient failure drop
    # to the standard tier for the remaining attempts so a spike on the flex
    # queue doesn't sink the whole call.
    effective_flex = flex
    for attempt in range(retries + 1):
        try:
            result = _call_llm(provider, client, model, system, user_content, max_tokens, flex=effective_flex)
            return (*result, effective_flex)
        except Exception as exc:  # noqa: BLE001 — classifier handles selection
            last_exc = exc
            if attempt >= retries or not _is_retryable_llm_error(exc):
                raise
            if effective_flex:
                logger.info("Dropping Gemini flex tier for remaining retry attempts after transient error")
                effective_flex = False
            delay = base * (2 ** attempt)
            # SDK exception messages sometimes echo the API key back
            # (OpenAI's "Incorrect API key provided: sk-..." is the
            # canonical example). sanitize_value runs the provider-
            # token patterns from src/engine/sanitizer.py (_PATTERNS)
            # so these don't land unredacted in the monitor's log
            # stream / central log aggregation.
            from src.engine.sanitizer import sanitize_value
            snippet = sanitize_value(str(exc).split("\n")[0])[:200]
            logger.warning(
                "LLM call failed with transient error (attempt %d/%d, retrying in %.1fs): %s",
                attempt + 1, retries + 1, delay, snippet,
            )
            time.sleep(delay)
    # Unreachable — loop either returns or raises — but keep type-checkers happy.
    assert last_exc is not None
    raise last_exc


def _ensure_schema_migrated() -> None:
    """Make sure SqliteStore has run its CREATE TABLE / migrations before we
    open a raw write connection. _log_llm_call and _log_llm_debug bypass
    SqliteStore (they keep a thread-local raw connection in the hot path),
    so without this guard a fresh container could try to INSERT into a
    column that hasn't been added yet.
    """
    global _schema_ready
    if _schema_ready:
        return
    with _schema_lock:
        if _schema_ready:
            return
        try:
            from src.engine.store.sqlite import SqliteStore
            SqliteStore()  # __init__ runs CREATE TABLEs + migrations
            _schema_ready = True
        except Exception:
            # Don't block the LLM call on a one-off migration failure;
            # we'll retry on the next log attempt.
            logger.debug("Failed to ensure LLM call schema is migrated",
                         exc_info=True)


def _log_llm_debug(*, call_type, resource, system_prompt, user_content, response_text):
    """Log full LLM payloads to SQLite when LLM_DEBUG is enabled. Never raises."""
    if not config.LLM_DEBUG:
        return
    _ensure_schema_migrated()
    try:
        if not hasattr(_log_local, "conn") or _log_local.conn is None:
            _log_local.conn = sqlite3.connect(config.SQLITE_PATH)
            _log_local.conn.execute("PRAGMA journal_mode=WAL")
            # Match the incident-store busy_timeout (30s): these LLM-log
            # writers hit the SAME SQLite file and otherwise lose rows when
            # the maintenance loop's VACUUM / big cleanup DELETEs hold the
            # write lock longer than 5s. See store/sqlite.py _get_conn.
            _log_local.conn.execute("PRAGMA busy_timeout=30000")
        now = time.time()
        _log_local.conn.execute(
            """INSERT INTO llm_debug_payloads
               (called_at, call_type, resource, system_prompt, user_content,
                response_text, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (now, call_type, resource, system_prompt, user_content,
             response_text, now),
        )
        _log_local.conn.commit()
    except Exception:
        logger.debug("Failed to log LLM debug payload to SQLite", exc_info=True)


def _log_llm_call(*, call_type, provider, model, resource,
                  context_bytes, section_bytes, sections,
                  tokens_in, tokens_out, cost_usd, latency_ms,
                  truncated, truncation_notes, error=False, cached_tokens=0):
    """Log LLM call to SQLite. Never raises — wrapped in try/except."""
    _ensure_schema_migrated()
    try:
        if not hasattr(_log_local, "conn") or _log_local.conn is None:
            _log_local.conn = sqlite3.connect(config.SQLITE_PATH)
            _log_local.conn.execute("PRAGMA journal_mode=WAL")
            # Match the incident-store busy_timeout (30s): these LLM-log
            # writers hit the SAME SQLite file and otherwise lose rows when
            # the maintenance loop's VACUUM / big cleanup DELETEs hold the
            # write lock longer than 5s. See store/sqlite.py _get_conn.
            _log_local.conn.execute("PRAGMA busy_timeout=30000")
        now = time.time()
        _log_local.conn.execute(
            """INSERT INTO llm_calls
               (called_at, call_type, provider, model, resource,
                context_bytes, section_bytes_json, sections_json,
                tokens_in, tokens_out, cached_tokens, cost_usd, latency_ms,
                truncated, truncation_notes, error, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (now, call_type, provider, model, resource,
             context_bytes,
             json.dumps(section_bytes) if section_bytes else "{}",
             json.dumps(sections) if sections else "[]",
             tokens_in, tokens_out, cached_tokens or 0, cost_usd, latency_ms,
             truncated, "; ".join(truncation_notes) if truncation_notes else None,
             error, now),
        )
        _log_local.conn.commit()
    except Exception:
        logger.debug("Failed to log LLM call to SQLite", exc_info=True)


# HTTP status codes that sometimes leak into exception messages — mapped
# to plain-language hints so the operator doesn't have to memorise them.
_HTTP_STATUS_HINTS: dict[int, str] = {
    401: "credentials invalid or missing (check API key Secret)",
    403: "permission / scope rejected (check API key scopes)",
    408: "request timed out (model overloaded or egress slow)",
    413: "context too large (lower MAX_CONTEXT_BYTES_*)",
    429: "rate-limited or quota exhausted (billing / tier cap)",
    500: "provider internal error — retryable",
    502: "provider upstream bad gateway — retryable",
    503: "provider unavailable — retryable",
    504: "provider gateway timeout — retryable",
}


def _format_llm_error(exc: BaseException, kind: str) -> str:
    """Build an actionable fallback message for Slack when an LLM call
    fails.

    Instead of the previous generic `"⚠️ AI analysis unavailable — LLM
    API error."` — which left operators to dig through pod logs just to
    see the exception class — this includes the exception type name,
    a short sanitized message snippet, an HTTP-status hint if the
    message looks like it carries one, and a pointer to the canonical
    debug location. Sanitisation strips API-key-looking patterns from
    the excerpt so we don't leak credentials into Slack.

    `kind` is the short noun used in the Slack line, e.g. "analysis",
    "daily report", "weekly report", "investigation".
    """
    from src.engine.sanitizer import sanitize_value

    exc_type = type(exc).__name__
    raw = str(exc) or "(no message)"
    # Keep the excerpt short — Slack blocks render whole message
    # inline and long traces bloat the alert body.
    snippet = sanitize_value(raw.split("\n")[0])[:240]

    # Pull an HTTP status out of the message if present (most SDKs
    # format "401 Unauthorized" / "Error code: 429 ..."). Match an
    # isolated 3-digit integer with digit-boundary regex so substrings
    # in unrelated numbers ("4136 seconds", "latency:5000ms") don't
    # register as 413 / 500.
    hint = ""
    for match in re.finditer(r"(?<!\d)(\d{3})(?!\d)", raw):
        code = int(match.group(1))
        if code in _HTTP_STATUS_HINTS:
            hint = f"\n→ {_HTTP_STATUS_HINTS[code]}"
            break

    return (
        f"\u26a0\ufe0f AI {kind} unavailable — {exc_type}: {snippet}"
        f"{hint}\n"
        f"(see `kubectl logs deploy/k8s-ai-monitor` / llm_calls table for details)"
    )


def analyze_alert(context: dict, resource: str = "", system_prompt_override: str | None = None, flex: bool = False) -> AnalysisResult:
    """Analyze alert context via LLM. Accepts structured dict, returns AnalysisResult."""
    from src.engine.sanitizer import sanitize_dict
    from src.engine.context_budget import build_alert_payload

    context = sanitize_dict(context)
    json_payload, truncated, trunc_notes = build_alert_payload(
        context, resource, config.CLUSTER_NAME, config.MAX_CONTEXT_BYTES_ALERT)

    context_bytes = len(json_payload.encode("utf-8"))

    if not _check_rate_limit():
        logger.warning("Skipped analysis for %s — rate limit exhausted", resource or "alert")
        return AnalysisResult(
            raw_text=f"Rate limit reached ({config.MAX_LLM_CALLS_PER_HOUR}/hr). "
                     f"Raw context:\n\n{json_payload[:2000]}",
            parsed=None, parse_error=True, model="", tokens_in=0, tokens_out=0, cost_usd=None,
        )

    provider, client = _get_client()
    model = _get_model(provider, tier="alert")
    system = system_prompt_override or ALERT_SYSTEM_PROMPT.format(cluster_name=config.CLUSTER_NAME)

    flex_label = " [FLEX]" if flex else ""
    logger.info("Analyzing %s via %s (%s), context=%dB%s%s",
                resource or "alert", provider, model,
                context_bytes, " [TRUNCATED]" if truncated else "", flex_label)
    try:
        raw_text, tokens_in, tokens_out, latency_ms, cached_tokens, effective_flex = _call_llm_with_retry(
            provider, client, model, system, json_payload, 4096, flex=flex)
        cost = _estimate_cost(model, tokens_in, tokens_out, flex=effective_flex)
        parsed, parse_error = parse_analysis(raw_text)
        if parse_error:
            logger.warning("LLM parse failed for %s: len=%d, tokens_out=%d, model=%s",
                           resource or "alert", len(raw_text) if raw_text else 0, tokens_out, model)
        _log_llm_call(
            call_type="alert", provider=provider, model=model, resource=resource,
            context_bytes=context_bytes,
            section_bytes=None,
            sections=list(context.keys()) if isinstance(context, dict) else [],
            tokens_in=tokens_in, tokens_out=tokens_out, cached_tokens=cached_tokens,
            cost_usd=cost, latency_ms=latency_ms,
            truncated=truncated, truncation_notes=trunc_notes,
        )
        _log_llm_debug(
            call_type="alert", resource=resource,
            system_prompt=system, user_content=json_payload,
            response_text=raw_text,
        )
        central_push.push_llm_usage({
            "called_at": time.time(),
            "call_type": "alert",
            "provider": provider,
            "model": model,
            "resource": resource,
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "cost_usd": cost or 0.0,
            "latency_ms": latency_ms,
            "error": False,
        })
        return AnalysisResult(
            raw_text=raw_text, parsed=parsed, parse_error=parse_error,
            model=model, tokens_in=tokens_in, tokens_out=tokens_out,
            cost_usd=cost, latency_ms=latency_ms,
        )
    except Exception as exc:
        logger.exception("LLM analysis failed for %s", resource or "alert")
        _log_llm_call(
            call_type="alert", provider=provider, model=model, resource=resource,
            context_bytes=context_bytes,
            section_bytes=None,
            sections=list(context.keys()) if isinstance(context, dict) else [],
            tokens_in=0, tokens_out=0, cost_usd=None, latency_ms=0,
            truncated=truncated, truncation_notes=trunc_notes, error=True,
        )
        central_push.push_llm_usage({
            "called_at": time.time(),
            "call_type": "alert",
            "provider": provider,
            "model": model,
            "resource": resource,
            "tokens_in": 0,
            "tokens_out": 0,
            "cost_usd": 0.0,
            "latency_ms": 0.0,
            "error": True,
        })
        return AnalysisResult(
            raw_text=_format_llm_error(exc, "analysis"),
            parsed=None, parse_error=True, model=model, tokens_in=0, tokens_out=0, cost_usd=None,
        )


def analyze_daily_report(context: dict) -> AnalysisResult:
    """Analyze daily report — accepts structured dict, returns AnalysisResult."""
    from src.engine.sanitizer import sanitize_dict
    from src.engine.context_budget import build_report_payload, measure_report_data

    context = sanitize_dict(context)
    measured = measure_report_data(context)
    json_payload, truncated, trunc_notes = build_report_payload(
        context, config.CLUSTER_NAME, config.MAX_CONTEXT_BYTES_REPORT)

    context_bytes = len(json_payload.encode("utf-8"))

    if not _check_rate_limit():
        logger.warning("Skipped daily report analysis — rate limit exhausted")
        return AnalysisResult(
            raw_text=f"Rate limit reached ({config.MAX_LLM_CALLS_PER_HOUR}/hr). "
                     f"Raw context:\n\n{json_payload[:2000]}",
            parsed=None, parse_error=True, model="", tokens_in=0, tokens_out=0, cost_usd=None,
        )

    provider, client = _get_client()
    model = _get_model(provider, tier="report")
    system = DAILY_REPORT_SYSTEM_PROMPT.format(cluster_name=config.CLUSTER_NAME)

    use_flex = config.GEMINI_FLEX_ENABLED
    logger.info("Sending daily report to %s (%s), context=%dB%s%s",
                provider, model, context_bytes, " [TRUNCATED]" if truncated else "",
                " [FLEX]" if use_flex else "")
    try:
        raw_text, tokens_in, tokens_out, latency_ms, cached_tokens, effective_flex = _call_llm_with_retry(
            provider, client, model, system, json_payload, config.REPORT_MAX_OUTPUT_TOKENS, flex=use_flex)
        cost = _estimate_cost(model, tokens_in, tokens_out, flex=effective_flex)
        parsed, parse_error = parse_daily_report(raw_text)
        if parse_error:
            logger.warning("LLM returned non-JSON for daily report, using raw text fallback")
        _log_llm_call(
            call_type="report", provider=provider, model=model, resource="daily_report",
            context_bytes=context_bytes,
            section_bytes=measured["section_bytes"],
            sections=measured["sections"],
            tokens_in=tokens_in, tokens_out=tokens_out, cached_tokens=cached_tokens,
            cost_usd=cost, latency_ms=latency_ms,
            truncated=truncated, truncation_notes=trunc_notes,
        )
        _log_llm_debug(
            call_type="report", resource="daily_report",
            system_prompt=system, user_content=json_payload,
            response_text=raw_text,
        )
        central_push.push_llm_usage({
            "called_at": time.time(),
            "call_type": "report",
            "provider": provider,
            "model": model,
            "resource": "daily_report",
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "cost_usd": cost or 0.0,
            "latency_ms": latency_ms,
            "error": False,
        })
        return AnalysisResult(
            raw_text=raw_text, parsed=parsed, parse_error=parse_error,
            model=model, tokens_in=tokens_in, tokens_out=tokens_out,
            cost_usd=cost, latency_ms=latency_ms,
        )
    except Exception as exc:
        logger.exception("LLM daily report failed")
        _log_llm_call(
            call_type="report", provider=provider, model=model, resource="daily_report",
            context_bytes=context_bytes,
            section_bytes=measured["section_bytes"],
            sections=measured["sections"],
            tokens_in=0, tokens_out=0, cost_usd=None, latency_ms=0,
            truncated=truncated, truncation_notes=trunc_notes, error=True,
        )
        central_push.push_llm_usage({
            "called_at": time.time(),
            "call_type": "report",
            "provider": provider,
            "model": model,
            "resource": "daily_report",
            "tokens_in": 0,
            "tokens_out": 0,
            "cost_usd": 0.0,
            "latency_ms": 0.0,
            "error": True,
        })
        return AnalysisResult(
            raw_text=_format_llm_error(exc, "daily report"),
            parsed=None, parse_error=True, model=model, tokens_in=0, tokens_out=0, cost_usd=None,
            llm_error=True,
        )


_WEEKLY_REPORT_DEFAULTS = {
    "overall_trend": "stable",
    "summary": "",
    "recurring_issues": [],
    "trends": [],
    "recommendations": [],
    "cost_summary": {},
}


def parse_weekly_report(raw: str) -> tuple[dict, bool]:
    """Parse structured JSON from weekly report LLM response."""
    text = raw.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        end_idx = len(lines)
        for i in range(len(lines) - 1, 0, -1):
            if lines[i].startswith("```"):
                end_idx = i
                break
        text = "\n".join(lines[1:end_idx])

    try:
        data = json.loads(text)
        if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict):
            data = data[0]
        if not isinstance(data, dict):
            raise ValueError("Expected JSON object")
        for key, default in _WEEKLY_REPORT_DEFAULTS.items():
            data.setdefault(key, default)
        if data["overall_trend"] not in ("improving", "stable", "degrading"):
            data["overall_trend"] = "stable"
        if not isinstance(data.get("recurring_issues"), list):
            data["recurring_issues"] = []
        if not isinstance(data.get("trends"), list):
            data["trends"] = []
        if not isinstance(data.get("recommendations"), list):
            data["recommendations"] = []
        for rec in data["recommendations"]:
            if isinstance(rec, dict):
                rec.setdefault("action", "")
                rec.setdefault("impact", "")
                try:
                    rec["priority"] = max(1, min(3, int(rec.get("priority", 2))))
                except (ValueError, TypeError):
                    rec["priority"] = 2
        if not isinstance(data.get("cost_summary"), dict):
            data["cost_summary"] = {}
        return data, False
    except (json.JSONDecodeError, ValueError, TypeError):
        return {
            "overall_trend": "stable",
            "summary": raw,
            "recurring_issues": [],
            "trends": [],
            "recommendations": [],
            "cost_summary": {},
            "_parse_error": True,
        }, True


def analyze_weekly_report(context: dict) -> AnalysisResult:
    """Analyze weekly report — accepts structured dict, returns AnalysisResult."""
    from src.engine.sanitizer import sanitize_dict

    context = sanitize_dict(context)
    payload = {"cluster": config.CLUSTER_NAME, "weekly_data": context}
    json_payload = json.dumps(payload, default=str)
    context_bytes = len(json_payload.encode("utf-8"))

    # Progressive trim if over budget (byte-aware, mirrors build_report_payload)
    max_bytes = config.MAX_CONTEXT_BYTES_REPORT
    truncated = False
    weekly = payload.get("weekly_data", {})
    if context_bytes > max_bytes and isinstance(weekly, dict):
        truncated = True
        # 1. Trim incident_details to 20
        if "incident_details" in weekly and len(weekly["incident_details"]) > 20:
            weekly["incident_details"] = weekly["incident_details"][:20]
            json_payload = json.dumps(payload, default=str)
        # 2. Drop incident_details entirely
        if len(json_payload.encode("utf-8")) > max_bytes and "incident_details" in weekly:
            del weekly["incident_details"]
            json_payload = json.dumps(payload, default=str)
        # 3. Trim daily_reports to 3
        if len(json_payload.encode("utf-8")) > max_bytes and "daily_reports" in weekly and len(weekly["daily_reports"]) > 3:
            weekly["daily_reports"] = weekly["daily_reports"][:3]
            json_payload = json.dumps(payload, default=str)
        # 4. Final hard truncation (byte-safe)
        if len(json_payload.encode("utf-8")) > max_bytes:
            json_payload = json_payload.encode("utf-8")[:max_bytes].decode("utf-8", errors="ignore")
        context_bytes = len(json_payload.encode("utf-8"))

    if not _check_rate_limit():
        logger.warning("Skipped weekly report analysis — rate limit exhausted")
        return AnalysisResult(
            raw_text=f"Rate limit reached ({config.MAX_LLM_CALLS_PER_HOUR}/hr).",
            parsed=None, parse_error=True, model="", tokens_in=0, tokens_out=0, cost_usd=None,
        )

    provider, client = _get_client()
    model = _get_model(provider, tier="report")
    system = WEEKLY_REPORT_SYSTEM_PROMPT.format(cluster_name=config.CLUSTER_NAME)

    use_flex = config.GEMINI_FLEX_ENABLED
    logger.info("Sending weekly report to %s (%s), context=%dB%s%s",
                provider, model, context_bytes, " [TRUNCATED]" if truncated else "",
                " [FLEX]" if use_flex else "")
    try:
        raw_text, tokens_in, tokens_out, latency_ms, cached_tokens, effective_flex = _call_llm_with_retry(
            provider, client, model, system, json_payload, config.REPORT_MAX_OUTPUT_TOKENS, flex=use_flex)
        cost = _estimate_cost(model, tokens_in, tokens_out, flex=effective_flex)
        parsed, parse_error = parse_weekly_report(raw_text)
        if parse_error:
            logger.warning("LLM returned non-JSON for weekly report, using raw text fallback")
        _log_llm_call(
            call_type="report", provider=provider, model=model, resource="weekly_report",
            context_bytes=context_bytes, section_bytes=None,
            sections=list(context.keys()) if isinstance(context, dict) else [],
            tokens_in=tokens_in, tokens_out=tokens_out, cached_tokens=cached_tokens,
            cost_usd=cost, latency_ms=latency_ms,
            truncated=truncated, truncation_notes=["weekly context truncated"] if truncated else [],
        )
        _log_llm_debug(
            call_type="report", resource="weekly_report",
            system_prompt=system, user_content=json_payload,
            response_text=raw_text,
        )
        central_push.push_llm_usage({
            "called_at": time.time(),
            "call_type": "report",
            "provider": provider,
            "model": model,
            "resource": "weekly_report",
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "cost_usd": cost or 0.0,
            "latency_ms": latency_ms,
            "error": False,
        })
        return AnalysisResult(
            raw_text=raw_text, parsed=parsed, parse_error=parse_error,
            model=model, tokens_in=tokens_in, tokens_out=tokens_out,
            cost_usd=cost, latency_ms=latency_ms,
        )
    except Exception as exc:
        logger.exception("LLM weekly report failed")
        _log_llm_call(
            call_type="report", provider=provider, model=model, resource="weekly_report",
            context_bytes=context_bytes, section_bytes=None,
            sections=list(context.keys()) if isinstance(context, dict) else [],
            tokens_in=0, tokens_out=0, cost_usd=None, latency_ms=0,
            truncated=truncated, truncation_notes=[], error=True,
        )
        central_push.push_llm_usage({
            "called_at": time.time(),
            "call_type": "report",
            "provider": provider,
            "model": model,
            "resource": "weekly_report",
            "tokens_in": 0,
            "tokens_out": 0,
            "cost_usd": 0.0,
            "latency_ms": 0.0,
            "error": True,
        })
        return AnalysisResult(
            raw_text=_format_llm_error(exc, "weekly report"),
            parsed=None, parse_error=True, model=model, tokens_in=0, tokens_out=0, cost_usd=None,
            llm_error=True,
        )


INVESTIGATION_SYSTEM_PROMPT = """You are a Kubernetes SRE assistant. You receive multi-source investigation data (K8s API, Prometheus metrics, Elasticsearch logs, Uptrace traces, incident history) for a namespace/pod.

Analyze all data sources and return STRICT JSON only. No text outside JSON.

{{
  "summary": "1-2 sentence overview of current state",
  "timeline": [
    {{"time": "relative or absolute", "event": "what happened"}}
  ],
  "root_cause": "most likely root cause based on all evidence",
  "confidence": 0.0-1.0,
  "affected_services": ["service1", "service2"],
  "correlations": [
    {{"sources": ["logs", "metrics"], "finding": "correlation description"}}
  ],
  "suggested_actions": [
    {{"action": "concrete step", "priority": 1-3}}
  ]
}}

Rules:
- Cross-reference data sources: correlate log errors with metric spikes, trace errors with pod restarts
- timeline: chronological, most recent first
- suggested_actions: priority 1=immediate, 2=short-term, 3=preventive
- confidence: based on how much data was available and how consistent the signals are
- If data sources are missing/empty, note that and lower confidence
- JSON only, no fences

Cluster: {cluster_name}"""

_INVESTIGATION_DEFAULTS = {
    "summary": "",
    "timeline": [],
    "root_cause": "Unknown",
    "confidence": 0.3,
    "affected_services": [],
    "correlations": [],
    "suggested_actions": [],
}


def parse_investigation(raw: str) -> tuple[dict, bool]:
    """Parse structured JSON from investigation LLM response."""
    text = raw.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        end_idx = len(lines)
        for i in range(len(lines) - 1, 0, -1):
            if lines[i].startswith("```"):
                end_idx = i
                break
        text = "\n".join(lines[1:end_idx])

    try:
        data = json.loads(text)
        if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict):
            data = data[0]
        if not isinstance(data, dict):
            raise ValueError("Expected JSON object")
        for key, default in _INVESTIGATION_DEFAULTS.items():
            data.setdefault(key, default)
        try:
            data["confidence"] = max(0.0, min(1.0, float(data.get("confidence", 0.3))))
        except (ValueError, TypeError):
            data["confidence"] = 0.3
        if not isinstance(data.get("timeline"), list):
            data["timeline"] = []
        if not isinstance(data.get("affected_services"), list):
            data["affected_services"] = []
        if not isinstance(data.get("correlations"), list):
            data["correlations"] = []
        if not isinstance(data.get("suggested_actions"), list):
            data["suggested_actions"] = []
        for sa in data["suggested_actions"]:
            if isinstance(sa, dict):
                sa.setdefault("action", "")
                try:
                    sa["priority"] = max(1, min(3, int(sa.get("priority", 2))))
                except (ValueError, TypeError):
                    sa["priority"] = 2
        return data, False
    except (json.JSONDecodeError, ValueError, TypeError):
        return {
            **_INVESTIGATION_DEFAULTS,
            "summary": raw,
            "_parse_error": True,
        }, True


def analyze_investigation(context: dict, namespace: str, since_minutes: int = 30) -> AnalysisResult:
    """Analyze investigation context via LLM. Multi-source data analysis."""
    from src.engine.sanitizer import sanitize_dict

    context = sanitize_dict(context)
    resource = f"investigation:{namespace}"
    payload = {"cluster": config.CLUSTER_NAME, "namespace": namespace,
               "since_minutes": since_minutes, "investigation_data": context}
    json_payload = json.dumps(payload, default=str)
    context_bytes = len(json_payload.encode("utf-8"))

    # Truncate if over budget
    max_bytes = config.MAX_CONTEXT_BYTES_REPORT
    truncated = False
    if context_bytes > max_bytes:
        truncated = True
        json_payload = json_payload.encode("utf-8")[:max_bytes].decode("utf-8", errors="ignore")
        context_bytes = max_bytes

    if not _check_rate_limit():
        logger.warning("Skipped investigation analysis — rate limit exhausted")
        return AnalysisResult(
            raw_text=f"Rate limit reached ({config.MAX_LLM_CALLS_PER_HOUR}/hr).",
            parsed=None, parse_error=True, model="", tokens_in=0, tokens_out=0, cost_usd=None,
        )

    provider, client = _get_client()
    model = _get_model(provider, tier="report")
    system = INVESTIGATION_SYSTEM_PROMPT.format(cluster_name=config.CLUSTER_NAME)

    logger.info("Investigation analysis via %s (%s), context=%dB%s",
                provider, model, context_bytes, " [TRUNCATED]" if truncated else "")
    try:
        raw_text, tokens_in, tokens_out, latency_ms, cached_tokens, _effective_flex = _call_llm_with_retry(
            provider, client, model, system, json_payload, 4096)
        cost = _estimate_cost(model, tokens_in, tokens_out)
        parsed, parse_error = parse_investigation(raw_text)
        if parse_error:
            logger.warning("LLM returned non-JSON for investigation, using raw text fallback")
        _log_llm_call(
            call_type="investigation", provider=provider, model=model, resource=resource,
            context_bytes=context_bytes, section_bytes=None,
            sections=list(context.keys()) if isinstance(context, dict) else [],
            tokens_in=tokens_in, tokens_out=tokens_out, cached_tokens=cached_tokens,
            cost_usd=cost, latency_ms=latency_ms,
            truncated=truncated, truncation_notes=["investigation context truncated"] if truncated else [],
        )
        _log_llm_debug(
            call_type="investigation", resource=resource,
            system_prompt=system, user_content=json_payload,
            response_text=raw_text,
        )
        return AnalysisResult(
            raw_text=raw_text, parsed=parsed, parse_error=parse_error,
            model=model, tokens_in=tokens_in, tokens_out=tokens_out,
            cost_usd=cost, latency_ms=latency_ms,
        )
    except Exception as exc:
        logger.exception("LLM investigation analysis failed for %s", namespace)
        _log_llm_call(
            call_type="investigation", provider=provider, model=model, resource=resource,
            context_bytes=context_bytes, section_bytes=None,
            sections=list(context.keys()) if isinstance(context, dict) else [],
            tokens_in=0, tokens_out=0, cost_usd=None, latency_ms=0,
            truncated=truncated, truncation_notes=[], error=True,
        )
        return AnalysisResult(
            raw_text=_format_llm_error(exc, "investigation"),
            parsed=None, parse_error=True, model=model, tokens_in=0, tokens_out=0, cost_usd=None,
        )



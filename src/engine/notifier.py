"""Slack posting — extracted from slack.py.

Two delivery paths:

  * Bot API (primary when configured) — ``chat.postMessage`` returns
    ``ts``, enabling ``thread_ts`` replies for recurring / resolved
    alerts. Activated when a bot token is resolvable (env var or
    ``slack-bot-token`` Secret) and the target channel ID is set.
  * Incoming Webhook (fallback) — legacy, can't thread, no ts returned.
    Kept as back-compat fallback so clusters without a bot Secret stay
    working unchanged.

``post_alert`` / ``post_resolved`` try bot API first when the token +
channel resolve; fall back to webhook on any failure. Each cluster
migrates independently by rolling out its own ``slack-bot-token`` Secret.
"""
import json
import logging
from typing import Any

import requests


from src import config

logger = logging.getLogger(__name__)

# Bot-token resolver state — mirrors the Uptrace resolver pattern in
# src/collectors/uptrace.py:40-143. Empty-lookup results are NOT cached
# so an RBAC hiccup / not-yet-created Secret at boot doesn't permanently
# disable the bot path.
_BOT_API_TIMEOUT = 10

SEVERITY_COLORS = {
    "critical": "#FF0000",
    "warning": "#FFA500",
    "info": "#36A64F",
}

_SEVERITY_ICON = {"critical": "\033[1;31m\U0001f534 CRITICAL", "warning": "\033[33m\U0001f7e1 WARNING", "info": "\033[32m\U0001f7e2 INFO"}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[90m"
_CYAN = "\033[36m"


def format_context_summary(context: dict) -> str:
    """Format collected context dict as Slack-readable text without LLM.

    Extracts key fields: status, events, logs, resources, diagnostics.
    Falls back to JSON dump for unknown context shapes.
    Max ~20 lines.
    """
    if not context:
        return "No context collected"

    # Simple string-wrapped context
    if list(context.keys()) == ["raw"] and isinstance(context["raw"], str):
        raw = context["raw"]
        return raw[:2000] if len(raw) > 2000 else raw

    lines: list[str] = []

    # Pod status info
    pod_status = context.get("pod_status") or context.get("status") or {}
    if isinstance(pod_status, dict):
        phase = pod_status.get("phase", "")
        reason = pod_status.get("reason", "")
        ready = pod_status.get("ready")
        parts = []
        if phase:
            parts.append(f"Phase: {phase}")
        if reason:
            parts.append(f"Reason: {reason}")
        if ready is not None:
            parts.append(f"Ready: {ready}")
        if parts:
            lines.append(f"*Status:* {' | '.join(parts)}")

    # Container states
    containers = context.get("container_states") or context.get("containers") or []
    if isinstance(containers, list):
        for cs in containers[:3]:
            if isinstance(cs, dict):
                name = cs.get("name", "?")
                state = cs.get("state", cs.get("status", ""))
                restarts = cs.get("restart_count", cs.get("restarts", ""))
                line = f"`{name}`: {state}"
                if restarts:
                    line += f" (restarts: {restarts})"
                lines.append(line)

    # Diagnostics (OOM, crash, scheduling, etc.) — type-aware rendering
    # instead of a generic json.dumps so scheduling-heavy alerts read well.
    diag = context.get("diagnostics") or {}
    if isinstance(diag, dict) and diag:
        for key, val in list(diag.items())[:10]:
            rendered = _format_diagnostic(key, val)
            if rendered:
                lines.append(rendered)

    # Events
    events = context.get("events") or context.get("warning_events") or []
    if isinstance(events, list) and events:
        lines.append("*Recent Events:*")
        for ev in events[:5]:
            if isinstance(ev, dict):
                reason = ev.get("reason") or ev.get("type") or ""
                msg = ev.get("message") or ev.get("msg") or ""
                count = ev.get("count", "")
                line = f"  {reason}: {msg[:240]}"
                if count:
                    line += f" (x{count})"
                lines.append(line)
            elif isinstance(ev, str):
                lines.append(f"  {ev[:240]}")

    # Logs
    logs = context.get("logs") or context.get("recent_logs") or ""
    if isinstance(logs, str) and logs.strip():
        log_lines = logs.strip().splitlines()
        lines.append("*Logs (last lines):*")
        for ll in log_lines[-10:]:
            lines.append(f"  {ll[:200]}")
    elif isinstance(logs, list) and logs:
        lines.append("*Logs (last lines):*")
        for ll in logs[-10:]:
            lines.append(f"  {str(ll)[:200]}")

    # Resource usage
    resources = context.get("resources") or context.get("resource_usage") or {}
    if isinstance(resources, dict) and resources:
        parts = []
        for k, v in list(resources.items())[:4]:
            parts.append(f"{k}: {v}")
        if parts:
            lines.append(f"*Resources:* {', '.join(parts)}")

    # Event-only context (non-pod events like Flux)
    event_info = context.get("event")
    if isinstance(event_info, dict) and not lines:
        for k, v in event_info.items():
            lines.append(f"*{k}:* {v}")

    # Fallback: dump keys for unknown shapes
    if not lines:
        dumped = json.dumps(context, indent=2, default=str)
        if len(dumped) > 2000:
            dumped = dumped[:2000] + "\n…(truncated)"
        return dumped

    return "\n".join(lines[:40])


def _format_diagnostic(key: str, val: Any) -> str | None:
    """Render a single diagnostic entry for Slack in a human-readable form.

    Each key gets a bespoke renderer so scheduling/oom/pdb alerts don't
    degrade into a truncated JSON string. Unknown keys fall through to a
    compact JSON line (still truncated to keep the Slack body bounded).
    """
    if val in (None, "", [], {}):
        return None

    if key == "hpa" and isinstance(val, dict):
        name = val.get("name", "?")
        target = val.get("target", "")
        current = val.get("current", "?")
        desired = val.get("desired", "?")
        min_r = val.get("min")
        max_r = val.get("max")
        bounds = []
        if min_r is not None:
            bounds.append(f"min {min_r}")
        if max_r is not None:
            bounds.append(f"max {max_r}")
        bounds_str = f" ({', '.join(bounds)})" if bounds else ""
        line = f"*HPA:* `{name}` \u2192 {target} \u2014 {current}/{desired} replicas{bounds_str}"
        if val.get("at_max"):
            line += " \u26a0\ufe0f AT MAX"
        return line

    if key == "pdb" and isinstance(val, dict):
        name = val.get("name", "?")
        parts = []
        if val.get("min_available") is not None:
            parts.append(f"minAvailable={val['min_available']}")
        if val.get("max_unavailable") is not None:
            parts.append(f"maxUnavailable={val['max_unavailable']}")
        if val.get("current_healthy") is not None:
            parts.append(f"healthy={val['current_healthy']}/{val.get('desired_healthy', '?')}")
        if val.get("disruptions_allowed") is not None:
            parts.append(f"disruptionsAllowed={val['disruptions_allowed']}")
        line = f"*PDB:* `{name}` \u2014 {', '.join(parts)}"
        if val.get("blocking"):
            line += " \u26a0\ufe0f blocking eviction"
        return line

    if key == "scheduling_constraints" and isinstance(val, dict):
        bits = []
        if val.get("node_selector"):
            sel = val["node_selector"]
            bits.append("nodeSelector=" + ",".join(f"{k}={v}" for k, v in sel.items()))
        if val.get("tolerations"):
            tols = []
            for t in val["tolerations"][:4]:
                k = t.get("key", "?")
                v = t.get("value")
                eff = t.get("effect", "any")
                tols.append(f"{k}={v}:{eff}" if v else f"{k}:{eff}")
            more = len(val["tolerations"]) - 4
            tol_str = ", ".join(tols) + (f" (+{more} more)" if more > 0 else "")
            bits.append(f"tolerations=[{tol_str}]")
        if val.get("topology_spread"):
            ts = val["topology_spread"]
            bits.append("topologySpread=" + ",".join(f"{t.get('key','?')}/{t.get('max_skew','?')}" for t in ts))
        if val.get("affinity"):
            bits.append("affinity=yes")
        if not bits:
            return None
        return "*Scheduling constraints:* " + " | ".join(bits)

    if key == "node_capacity" and isinstance(val, list):
        total = len(val)
        ready_sched = sum(1 for n in val if n.get("ready") == "True" and n.get("schedulable"))
        cordoned = sum(1 for n in val if not n.get("schedulable"))
        sel_match = [n for n in val if n.get("selector_match")]
        parts = [f"{total} total", f"{ready_sched} ready+schedulable"]
        if cordoned:
            parts.append(f"{cordoned} cordoned")
        if val and "selector_match" in val[0]:
            parts.append(f"{len(sel_match)} match selector")
        return "*Nodes:* " + ", ".join(parts)

    if key == "cordoned_nodes" and isinstance(val, list):
        shown = ", ".join(val[:5])
        more = len(val) - 5
        if more > 0:
            shown += f" (+{more} more)"
        return f"*Cordoned:* {shown}"

    if key == "cluster_autoscaler" and isinstance(val, dict):
        bits = []
        recent = val.get("recent_events") or []
        if recent:
            # Group by reason for a compact summary
            from collections import Counter
            counter: Counter = Counter(ev.get("reason", "?") for ev in recent)
            reason_parts = [f"{r}(x{c})" for r, c in counter.most_common(3)]
            bits.append("events=[" + ", ".join(reason_parts) + "]")
            # Show the freshest message for context
            msg = (recent[0].get("message") or "").strip()
            if msg:
                bits.append(f"last: \"{msg[:160]}\"")
        prov = val.get("provisioning_nodes") or []
        if prov:
            bits.append(f"provisioning={len(prov)}")
        if not bits:
            return None
        return "*Autoscaler:* " + " | ".join(bits)

    if key == "resource_limits" and isinstance(val, list):
        parts = []
        for c in val[:3]:
            chunks = []
            if c.get("cpu_req") or c.get("cpu_lim"):
                chunks.append(f"cpu {c.get('cpu_req','?')}/{c.get('cpu_lim','?')}")
            if c.get("mem_req") or c.get("mem_lim"):
                chunks.append(f"mem {c.get('mem_req','?')}/{c.get('mem_lim','?')}")
            if c.get("note"):
                chunks.append(c["note"])
            if chunks:
                parts.append(f"`{c.get('container','?')}` " + ", ".join(chunks))
        if not parts:
            return None
        return "*Limits (req/lim):* " + " | ".join(parts)

    if key == "current_usage" and isinstance(val, list):
        parts = []
        for c in val[:3]:
            parts.append(
                f"`{c.get('container','?')}` cpu={c.get('cpu','?')} mem={c.get('mem','?')}"
            )
        if not parts:
            return None
        return "*Usage:* " + " | ".join(parts)

    if key == "oom_details" and isinstance(val, list):
        parts = []
        for d in val[:3]:
            chunk = f"`{d.get('container','?')}` exit={d.get('exit_code','?')}"
            if d.get("signal"):
                chunk += f" signal={d['signal']}"
            parts.append(chunk)
        if not parts:
            return None
        return "*OOMKilled:* " + " | ".join(parts)

    if key == "node_memory" and isinstance(val, dict):
        return (f"*Node memory ({val.get('node','?')}):* "
                f"capacity={val.get('capacity','?')}, "
                f"allocatable={val.get('allocatable','?')}")

    if key == "node_pressure" and isinstance(val, dict):
        pressures = val.get("pressures") or []
        if not pressures:
            return None
        parts = []
        for p in pressures[:3]:
            ptype = p.get("type", "?")
            status = p.get("status", "?")
            msg = (p.get("message") or "").strip()
            chunk = f"{ptype}={status}"
            if msg:
                chunk += f" (\"{msg[:80]}\")"
            parts.append(chunk)
        return f"*Node pressure ({val.get('node','?')}):* " + " | ".join(parts)

    if key == "restart_history" and isinstance(val, list):
        parts = []
        for r in val[:3]:
            chunk = f"`{r.get('container','?')}` restarts={r.get('restarts','?')}"
            if r.get("exit_code") is not None:
                chunk += f", last exit={r['exit_code']}"
            if r.get("reason"):
                chunk += f" ({r['reason']})"
            if r.get("signal"):
                chunk += f" signal={r['signal']}"
            parts.append(chunk)
        if not parts:
            return None
        return "*Restart history:* " + " | ".join(parts)

    if key == "probe_config" and isinstance(val, list):
        # Only show probes that are configured OR explicitly flagged as
        # missing — an unconfigured probe is only interesting for liveness,
        # and even then only when relevant to the alert. Trim noise by
        # dropping fully-absent probes.
        probes: list[dict] = [p for p in val
                              if isinstance(p, dict)
                              and (p.get("type") or p.get("configured") is False)]
        if not probes:
            return None
        parts = []
        for p in probes[:4]:
            container = p.get("container", "?")
            probe = p.get("probe", "?")
            if p.get("configured") is False:
                parts.append(f"`{container}`/{probe}: not set")
                continue
            bits = [p.get("type", "?")]
            if p.get("path"):
                bits.append(p["path"])
            if p.get("port"):
                bits.append(str(p["port"]))
            tunes = []
            if p.get("period") is not None:
                tunes.append(f"period={p['period']}s")
            if p.get("timeout") is not None:
                tunes.append(f"timeout={p['timeout']}s")
            if p.get("failures") is not None:
                tunes.append(f"failures={p['failures']}")
            tail = f" [{', '.join(tunes)}]" if tunes else ""
            parts.append(f"`{container}`/{probe}: {' '.join(bits)}{tail}")
        return "*Probes:* " + " | ".join(parts)

    if key == "pull_secrets" and isinstance(val, list):
        parts = []
        for s in val[:4]:
            name = s.get("name", "?")
            if s.get("exists") is True:
                parts.append(f"`{name}` ok")
            elif s.get("exists") is False:
                parts.append(f"`{name}` \u26a0\ufe0f MISSING")
            elif s.get("check_failed"):
                parts.append(f"`{name}` check-failed")
            else:
                parts.append(f"`{name}`")
        if not parts:
            return None
        return "*Pull secrets:* " + ", ".join(parts)

    if key == "pull_secrets_configured" and val is False:
        return "*Pull secrets:* \u26a0\ufe0f none configured"

    if key == "pvcs" and isinstance(val, list):
        lines_out = []
        for pvc in val[:3]:
            name = pvc.get("name", "?")
            phase = pvc.get("phase", "?")
            marker = " \u26a0\ufe0f" if phase not in ("Bound",) else ""
            line = f"  `{name}`: {phase}{marker}"
            events = pvc.get("events") or []
            if events:
                ev = events[-1]
                reason = ev.get("reason", "?")
                msg = (ev.get("message") or "")[:160]
                line += f"\n    \u2192 {reason}: {msg}"
            lines_out.append(line)
        if not lines_out:
            return None
        return "*PVCs:*\n" + "\n".join(lines_out)

    if key == "images" and isinstance(val, list):
        parts = []
        for c in val[:3]:
            parts.append(
                f"`{c.get('container','?')}`: {c.get('image','?')}"
                + (f" (pullPolicy={c['pull_policy']})" if c.get("pull_policy") else "")
            )
        if not parts:
            return None
        return "*Images:* " + " | ".join(parts)

    # Generic fallback — compact JSON, bounded length, but clearly labelled.
    if isinstance(val, str):
        return f"*{key}:* {val[:220]}"
    if isinstance(val, (dict, list)):
        return f"*{key}:* {json.dumps(val, default=str)[:220]}"
    return f"*{key}:* {val}"


def format_structured_analysis(analysis: dict) -> str:
    """Format structured analysis dict for Slack mrkdwn."""
    if analysis.get("_parse_error"):
        return analysis.get("root_cause") or "Analysis unavailable"

    conf = analysis.get("confidence", 0)
    conf_icon = "\U0001f7e2" if conf >= 0.8 else "\U0001f7e1" if conf >= 0.5 else "\U0001f534"

    lines = [
        f"*Root Cause* {conf_icon} _{conf*100:.0f}% confidence_",
        analysis.get("root_cause", "Unknown"), "",
        "*Impact*", analysis.get("impact", "Unknown"), "",
    ]

    # New schema: hypotheses
    if analysis.get("hypotheses"):
        lines.append("*Hypotheses*")
        for i, h in enumerate(analysis["hypotheses"], 1):
            ev = ", ".join(h.get("evidence", [])[:3])
            lines.append(f"{i}. {h.get('cause', '?')} _({h.get('confidence', 0)*100:.0f}%)_ \u2014 {ev}")
        lines.append("")

    # New schema: complete_elimination_plan with priority icons
    if analysis.get("complete_elimination_plan"):
        lines.append("*\u2705 Elimination Plan*")
        icons = {1: "\U0001f534", 2: "\U0001f7e1", 3: "\U0001f7e2"}
        for ep in analysis["complete_elimination_plan"]:
            p = ep.get("priority", 2)
            step = ep.get("step", "?")
            desc = ep.get("description", "")
            line = f"{icons.get(p, '\U0001f7e1')} `{step}`"
            if desc:
                line += f"\n   _{desc}_"
            lines.append(line)
        lines.append("")

    # Schema: suggested_actions (fallback)
    elif analysis.get("suggested_actions"):
        lines.append("*Suggested Actions*")
        icons = {1: "\U0001f534", 2: "\U0001f7e1", 3: "\U0001f7e2"}
        for sa in analysis["suggested_actions"]:
            lines.append(f"{icons.get(sa.get('priority', 2), '\U0001f7e1')} {sa.get('action', '?')}")
        lines.append("")

    # Backward compat: old schema
    elif analysis.get("action_plan"):
        lines.append("*Action Plan*")
        for i, step in enumerate(analysis["action_plan"], 1):
            lines.append(f"{i}. {step}")
        lines.append("")
    if not analysis.get("hypotheses") and analysis.get("evidence"):
        lines.append("*Evidence*")
        for ev in analysis["evidence"]:
            lines.append(f"\u2022 {ev}")
        lines.append("")

    if analysis.get("human_needed"):
        lines.append("\u26a0\ufe0f _Human review recommended_")
    return "\n".join(lines)


def _console_alert(title: str, analysis: str, severity: str, resource: str, namespace: str,
                   node: str = "", node_metrics: str = "", app_metrics: str = ""):
    icon = _SEVERITY_ICON.get(severity, _SEVERITY_ICON["info"])
    width = 72
    print(f"\n{_DIM}{'\u2501' * width}{_RESET}")
    print(f"  {icon} {_BOLD}{title}{_RESET}")
    node_info = f"  {_CYAN}Node:{_RESET} {node}" if node else ""
    print(f"  {_CYAN}Cluster:{_RESET} {config.CLUSTER_NAME}  {_CYAN}Namespace:{_RESET} {namespace}  {_CYAN}Resource:{_RESET} {resource}{node_info}")
    if node_metrics:
        print(f"  {_CYAN}Metrics:{_RESET} {node_metrics}")
    if app_metrics:
        print(f"  {_CYAN}App:{_RESET}     {app_metrics}")
    print(f"{_DIM}{'\u2500' * width}{_RESET}")
    print(analysis)
    print(f"{_DIM}{'\u2501' * width}{_RESET}\n")


def get_webhook_for_namespace(namespace: str) -> str | None:
    if config.is_nonprod_namespace(namespace):
        return config.SLACK_WEBHOOK_URL_NONPROD or None
    return config.SLACK_WEBHOOK_URL or None


# ── Bot API token resolution + posting ──────────────────────────────────

def _resolve_bot_token() -> str:
    """The Slack bot token - from the SLACK_BOT_TOKEN env var only.

    The monitor reads no Kubernetes Secrets (least privilege): the Deployment
    injects the token as an env var from its own Secret. Empty = webhook path.
    """
    return config.SLACK_BOT_TOKEN


def _channel_for_namespace(namespace: str) -> str:
    if config.is_nonprod_namespace(namespace):
        return config.SLACK_CHANNEL_ID_NONPROD or ""
    return config.SLACK_CHANNEL_ID or ""


def _bot_api_available(namespace: str) -> bool:
    """True when we have both a token and a channel for this namespace."""
    return bool(_resolve_bot_token() and _channel_for_namespace(namespace))


# Slack API error codes that indicate a permanent misconfiguration —
# the bot token is invalid, the channel doesn't exist, the bot isn't in
# the channel, etc. Webhook fallback will still send the message but
# threading is silently broken and the operator doesn't know until they
# look at logs. We log these at ERROR level (vs WARNING for transient
# issues like rate_limited / service_unavailable) so they surface in
# Loki / log dashboards.
_PERMANENT_BOT_ERRORS = frozenset({
    "invalid_auth", "account_inactive", "token_revoked", "token_expired",
    "no_permission", "missing_scope", "not_allowed_token_type",
    "channel_not_found", "not_in_channel", "is_archived",
    "restricted_action",
})


def _post_via_bot_api(
    channel: str, text: str, blocks: list[dict[str, Any]] | None = None,
    attachments: list[dict[str, Any]] | None = None,
    thread_ts: str | None = None,
) -> str | None:
    """Call chat.postMessage. Returns the message `ts` on success, None
    on any failure (caller then falls back to webhook)."""
    token = _resolve_bot_token()
    if not token or not channel:
        return None
    payload: dict[str, Any] = {"channel": channel, "text": text}
    if blocks:
        payload["blocks"] = blocks
    if attachments:
        payload["attachments"] = attachments
    if thread_ts:
        payload["thread_ts"] = thread_ts
    try:
        resp = requests.post(
            f"{config.SLACK_BOT_API_URL}/chat.postMessage",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json; charset=utf-8",
            },
            json=payload, timeout=_BOT_API_TIMEOUT,
        )
        data = resp.json() if resp.content else {}
    except requests.RequestException as exc:
        logger.warning("Slack chat.postMessage request failed: %s", exc)
        return None
    except Exception:
        logger.warning("Slack chat.postMessage unexpected failure", exc_info=True)
        return None
    if not data.get("ok"):
        error = data.get("error", "")
        if error in _PERMANENT_BOT_ERRORS:
            # Permanent misconfig — webhook fallback will still deliver
            # but threading is broken and recurring alerts lose
            # in-thread grouping. Operator must fix the bot config.
            logger.error(
                "Slack chat.postMessage PERMANENT error: %s (channel=%s). "
                "Bot is misconfigured — threading is broken until fixed. "
                "Check bot token validity, channel ID, and that the bot "
                "is invited to the channel. Delivery continues via webhook "
                "fallback.",
                error, channel,
            )
        else:
            logger.warning(
                "Slack chat.postMessage returned ok=false: %s",
                error or data,
            )
        return None
    return data.get("ts") or None


def post_alert(title: str, analysis: str, severity: str, resource: str, namespace: str,
               event_reason: str = "", node: str = "", node_metrics: str = "",
               app_metrics: str = "", model: str = "", webhook_url: str | None = None,
               thread_ts: str | None = None, skip_ai_mention: bool = False) -> str | None:
    """Post an alert to Slack. Returns:
      - posted message `ts` (non-empty str) on bot API success
      - empty str on webhook delivery success (webhooks don't return ts)
      - `None` when NEITHER transport delivered (console fallback only)

    Callers that only care whether Slack got the message should check
    `if posted is not None`. Callers that need a ts for threading must
    check `if posted` (truthy non-empty ts).

    Bot API path activates when a bot token resolves AND a channel ID is
    configured for this namespace. Bot failure (network / ok=false) falls
    back to webhook automatically. Caller can stash the returned ts via
    `store.set_last_slack_ts(incident_id, ts)` when non-empty to enable
    thread_ts replies on recurrences.
    """
    if not (webhook_url or config.SLACK_WEBHOOK_URL) and not _bot_api_available(namespace):
        _console_alert(title, analysis, severity, resource, namespace, node=node,
                       node_metrics=node_metrics, app_metrics=app_metrics)
        return None

    color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["info"])
    fields = [
        {"type": "mrkdwn", "text": f"*Cluster:*\n{config.CLUSTER_NAME}"},
        {"type": "mrkdwn", "text": f"*Namespace:*\n{namespace}"},
        {"type": "mrkdwn", "text": f"*Resource:*\n{resource}"},
        {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
    ]
    if node:
        fields.append({"type": "mrkdwn", "text": f"*Node:*\n{node}"})
    if event_reason:
        fields.append({"type": "mrkdwn", "text": f"*Event:*\n`{event_reason}`"})

    icon = '\U0001f534' if severity == 'critical' else '\U0001f7e1' if severity == 'warning' else '\U0001f7e2'
    header_text = f"{icon} [{config.CLUSTER_NAME}/{namespace}] {title}"
    if len(header_text) > 150:
        header_text = header_text[:147] + "..."
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": header_text},
        },
    ]
    # Place the critical mention at the TOP of the message so the follow-up
    # bot sees it as the leading text. Include cluster + namespace + resource
    # inline so the bot has self-contained context (some bots only parse the
    # first plain-text section, not Slack `fields`).
    #
    # `skip_ai_mention` is set by the pipeline to honour the @ai cooldown
    # window (AI_MENTION_REMINDER_HOURS) for chronic re-fires: alert still
    # posts as critical so the operator sees it, but the bot isn't re-tagged
    # every cooldown cycle for an incident it already analysed.
    include_mention = (severity == "critical"
                       and config.SLACK_CRITICAL_MENTION
                       and not skip_ai_mention)
    if include_mention:
        ping_text = (
            f"{config.SLACK_CRITICAL_MENTION} CRITICAL on "
            f"`{config.CLUSTER_NAME}/{namespace}` — `{resource}`: {title}. "
            "Please run a deeper investigation of the root cause based on the alert below."
        )
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": ping_text},
        })
    blocks.append({
        "type": "section",
        "fields": fields,
    })
    if node_metrics:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"\U0001f4ca *Node Metrics:* {node_metrics}"}],
        })
    if app_metrics:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"\U0001f4c8 *App Metrics:* {app_metrics}"}],
        })
    if model:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"\U0001f916 *Model:* {model}"}],
        })
    blocks.append({"type": "divider"})
    # Mention block (when severity=critical) already added at top.
    blocks.extend(_split_text_blocks(analysis, max_blocks=39))

    payload: dict = {
        "attachments": [
            {
                "color": color,
                "blocks": blocks,
            }
        ]
    }
    # Slack only triggers app_mention (and exposes event.text to the bot) when
    # the mention is in the TOP-LEVEL message text — not buried in attachments.
    # The follow-up bot reads the full message (including attachments and
    # blocks), so `text` is kept short: just the mention, the identity line,
    # and a one-line focus reminder. Full detail lives in the blocks below.
    top_text = ""
    if include_mention:
        directives = config.SLACK_CRITICAL_INVESTIGATION_DIRECTIVES
        tail = f"\n{directives}" if directives else ""
        top_text = (
            f"{config.SLACK_CRITICAL_MENTION} CRITICAL on "
            f"`{config.CLUSTER_NAME}/{namespace}` — `{resource}`: {title}"
            f"{tail}"
        )
        payload["text"] = top_text

    # Bot API first (enables threading) — fall back to webhook on failure.
    channel = _channel_for_namespace(namespace)
    bot_attempted = False
    if _resolve_bot_token() and channel:
        bot_attempted = True
        # chat.postMessage takes blocks / attachments at the top level;
        # wrap the legacy attachment-based payload into that shape.
        ts = _post_via_bot_api(
            channel=channel,
            text=top_text or header_text,
            attachments=payload.get("attachments"),
            thread_ts=thread_ts,
        )
        if ts:
            return ts
        logger.info("Falling back to Slack webhook after chat.postMessage failure")

    # Webhook fallback — detect silent-drop scenarios:
    #   (a) bot path attempted and failed AND no webhook configured
    #   (b) webhook _send returns False (no URL, 5xx, network error)
    # In both cases, log a clear non-silent ERROR and emit console
    # output so the alert is observable somewhere. Previously this path
    # returned "" without logging, effectively dropping alerts silently.
    effective_webhook = webhook_url or config.SLACK_WEBHOOK_URL
    if not effective_webhook:
        logger.error(
            "Slack alert DROPPED — bot path %s and no webhook configured; "
            "console fallback only. severity=%s resource=%s namespace=%s title=%r",
            "failed" if bot_attempted else "unavailable",
            severity, resource, namespace, title,
        )
        _console_alert(title, analysis, severity, resource, namespace, node=node,
                       node_metrics=node_metrics, app_metrics=app_metrics)
        return None

    if not _send(payload, webhook_url=webhook_url):
        logger.error(
            "Slack webhook delivery FAILED after %s; console fallback only. "
            "severity=%s resource=%s namespace=%s title=%r",
            "bot fallback" if bot_attempted else "direct path",
            severity, resource, namespace, title,
        )
        _console_alert(title, analysis, severity, resource, namespace, node=node,
                       node_metrics=node_metrics, app_metrics=app_metrics)
        return None
    return ""


_STATUS_ICON = {"healthy": "\U0001f7e2", "degraded": "\U0001f7e1", "critical": "\U0001f534"}
_STATUS_COLOR = {"healthy": "#36A64F", "degraded": "#FFA500", "critical": "#FF0000"}
_SEVERITY_ICON_SLACK = {"critical": "\U0001f534", "warning": "\U0001f7e1", "info": "\U0001f7e2"}
_PRIORITY_ICON = {1: "\U0001f534", 2: "\U0001f7e1", 3: "\U0001f7e2"}


def format_daily_report(parsed: dict) -> list[dict]:
    """Format parsed daily report dict into Slack Block Kit blocks."""
    # Daily report: header(1) + divider(1) + up to 4 sections with dividers
    # Budget ~10 blocks per section to stay under 50 total
    section_budget = 10

    if parsed.get("_parse_error"):
        return _split_text_blocks(parsed.get("summary", "Analysis unavailable"), max_blocks=section_budget)

    blocks: list[dict[str, Any]] = []

    # Status + summary
    status = parsed.get("overall_status", "degraded")
    icon = _STATUS_ICON.get(status, "\U0001f7e1")
    summary = parsed.get("summary", "")
    status_text = f"{icon} *Status: {status.upper()}*"
    if summary:
        status_text += f"\n{summary}"
    blocks.extend(_split_text_blocks(status_text, max_blocks=section_budget))

    # Issues
    issues = parsed.get("issues", [])
    if issues:
        lines = ["*Issues*"]
        for issue in issues:
            sev = issue.get("severity", "info")
            sev_icon = _SEVERITY_ICON_SLACK.get(sev, "\U0001f7e2")
            desc = issue.get("description", "")
            affected = issue.get("affected", "")
            line = f"{sev_icon} {desc}"
            if affected:
                line += f" \u2014 _{affected}_"
            lines.append(line)
        blocks.append({"type": "divider"})
        blocks.extend(_split_text_blocks("\n".join(lines), max_blocks=section_budget))

    # Trends
    trends = parsed.get("trends", [])
    if trends:
        lines = ["*Trends*"]
        for trend in trends:
            desc = trend.get("description", str(trend)) if isinstance(trend, dict) else str(trend)
            lines.append(f"\u2022 {desc}")
        blocks.append({"type": "divider"})
        blocks.extend(_split_text_blocks("\n".join(lines), max_blocks=section_budget))

    # Recommendations
    recs = parsed.get("recommendations", [])
    if recs:
        lines = ["*Recommendations*"]
        for rec in recs:
            p = rec.get("priority", 2) if isinstance(rec, dict) else 2
            action = rec.get("action", str(rec)) if isinstance(rec, dict) else str(rec)
            icon = _PRIORITY_ICON.get(p, "\U0001f7e1")
            lines.append(f"{icon} {action}")
        blocks.append({"type": "divider"})
        blocks.extend(_split_text_blocks("\n".join(lines), max_blocks=section_budget))

    return blocks


_TREND_ICON = {"improving": "\U0001f4c8", "stable": "\u2796", "degrading": "\U0001f4c9"}
_TREND_COLOR = {"improving": "#36A64F", "stable": "#FFA500", "degrading": "#FF0000"}
_DIRECTION_ICON = {"improving": "\U0001f4c8", "worsening": "\U0001f4c9", "stable": "\u2796"}


def format_weekly_report(parsed: dict) -> list[dict]:
    """Format parsed weekly report dict into Slack Block Kit blocks."""
    section_budget = 10

    if parsed.get("_parse_error"):
        return _split_text_blocks(parsed.get("summary", "Analysis unavailable"), max_blocks=section_budget)

    blocks: list[dict] = []

    # Overall trend + summary
    trend = parsed.get("overall_trend", "stable")
    icon = _TREND_ICON.get(trend, "\u2796")
    summary = parsed.get("summary", "")
    status_text = f"{icon} *Trend: {trend.upper()}*"
    if summary:
        status_text += f"\n{summary}"
    blocks.extend(_split_text_blocks(status_text, max_blocks=section_budget))

    # Recurring issues
    recurring = parsed.get("recurring_issues", [])
    if recurring:
        lines = ["*Recurring Issues*"]
        for issue in recurring:
            desc = issue.get("description", "") if isinstance(issue, dict) else str(issue)
            freq = issue.get("frequency", "?") if isinstance(issue, dict) else "?"
            services = issue.get("services_affected", []) if isinstance(issue, dict) else []
            line = f"\U0001f504 {desc} \u2014 _{freq}x_"
            if services:
                line += f" ({', '.join(services[:5])})"
            lines.append(line)
        blocks.append({"type": "divider"})
        blocks.extend(_split_text_blocks("\n".join(lines), max_blocks=section_budget))

    # Trends
    trends = parsed.get("trends", [])
    if trends:
        lines = ["*Trends*"]
        for t in trends:
            if isinstance(t, dict):
                desc = t.get("description", "")
                direction = t.get("direction", "stable")
                d_icon = _DIRECTION_ICON.get(direction, "\u2796")
                lines.append(f"{d_icon} {desc}")
            else:
                lines.append(f"\u2022 {t}")
        blocks.append({"type": "divider"})
        blocks.extend(_split_text_blocks("\n".join(lines), max_blocks=section_budget))

    # Recommendations
    recs = parsed.get("recommendations", [])
    if recs:
        lines = ["*Recommendations*"]
        for rec in recs:
            p = rec.get("priority", 2) if isinstance(rec, dict) else 2
            action = rec.get("action", str(rec)) if isinstance(rec, dict) else str(rec)
            impact = rec.get("impact", "") if isinstance(rec, dict) else ""
            p_icon = _PRIORITY_ICON.get(p, "\U0001f7e1")
            line = f"{p_icon} {action}"
            if impact:
                line += f" \u2014 _{impact}_"
            lines.append(line)
        blocks.append({"type": "divider"})
        blocks.extend(_split_text_blocks("\n".join(lines), max_blocks=section_budget))

    # Cost summary
    cost = parsed.get("cost_summary", {})
    if cost:
        cost_text = (
            f"*Cost Summary*\n"
            f"\u2022 LLM cost: ${cost.get('total_llm_cost_usd', 0):.4f}\n"
            f"\u2022 Total alerts: {cost.get('total_alerts', 0)}\n"
            f"\u2022 Total reports: {cost.get('total_reports', 0)}"
        )
        blocks.append({"type": "divider"})
        blocks.extend(_split_text_blocks(cost_text, max_blocks=3))

    return blocks


def _post_notice(text: str, payload: dict) -> bool:
    """Bot-first delivery for non-alert Slack notices (daily / weekly
    reports, maintenance notices). Mirrors the dual-path logic in
    `post_alert` so a cluster running on bot-only transport (no
    `SLACK_WEBHOOK_URL`) keeps receiving summaries and maintenance
    notices — otherwise they'd fall through to a silent console print
    after webhook retirement.

    Notices are cluster-wide (no per-namespace target like alerts have)
    and always go to `SLACK_CHANNEL_ID`. No threading — each notice
    posts top-level.

    Returns True when Slack delivery succeeded via EITHER transport,
    False when neither is configured OR both failed. Callers use the
    return to decide whether to fall back to a formatted console
    render as last-resort visibility.
    """
    bot_attempted = False
    if _resolve_bot_token() and config.SLACK_CHANNEL_ID:
        bot_attempted = True
        ts = _post_via_bot_api(
            channel=config.SLACK_CHANNEL_ID,
            text=text,
            attachments=payload.get("attachments"),
        )
        if ts:
            return True
        logger.info(
            "Falling back to Slack webhook for notice after "
            "chat.postMessage failure",
        )

    if not config.SLACK_WEBHOOK_URL:
        logger.warning(
            "Slack notice not delivered — bot path %s and no webhook "
            "configured; rendering to console instead. Text: %r",
            "failed" if bot_attempted else "unavailable",
            text[:120],
        )
        return False

    if _send(payload):
        return True

    logger.error(
        "Slack webhook delivery FAILED for notice after %s; "
        "rendering to console instead. Text: %r",
        "bot fallback" if bot_attempted else "direct path",
        text[:120],
    )
    return False


def _console_weekly_report(parsed: dict) -> None:
    """Last-resort console render when no Slack transport is reachable."""
    width = 72
    trend = parsed.get("overall_trend", "stable")
    trend_icon = _TREND_ICON.get(trend, "?")
    print(f"\n{_DIM}{'\u2501' * width}{_RESET}")
    print(f"  \033[34m\U0001f4ca {_BOLD}Weekly Report \u2014 {config.CLUSTER_NAME}{_RESET}")
    print(f"{_DIM}{'\u2500' * width}{_RESET}")
    print(f"  Trend: {trend_icon} {trend.upper()}")
    if parsed.get("summary"):
        print(f"  {parsed['summary']}")
    for issue in parsed.get("recurring_issues", []):
        if isinstance(issue, dict):
            print(f"  [RECURRING] {issue.get('description', '')}")
    for t in parsed.get("trends", []):
        desc = t.get("description", str(t)) if isinstance(t, dict) else str(t)
        print(f"  - {desc}")
    for rec in parsed.get("recommendations", []):
        action = rec.get("action", str(rec)) if isinstance(rec, dict) else str(rec)
        print(f"  > {action}")
    print(f"{_DIM}{'\u2501' * width}{_RESET}\n")


def post_weekly_report(result):
    """Post weekly report to Slack via bot API (preferred) or webhook
    (fallback); console print if neither transport is reachable."""
    # Branch on parse_error, NOT `if result.parsed` — a failed parse still returns
    # a truthy dict (raw text as summary), which would dump raw JSON to the channel.
    if result.parse_error:
        parsed = {
            "_parse_error": True,
            "summary": "⚠️ Weekly report generation failed — model output was truncated "
                       "or not valid JSON (raw output in the monitor LLM debug log).",
        }
    else:
        parsed = result.parsed or {}
    trend = parsed.get("overall_trend", "stable")
    color = _TREND_COLOR.get(trend, _TREND_COLOR["stable"])

    report_blocks = format_weekly_report(parsed)
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"\U0001f4ca Weekly Report \u2014 {config.CLUSTER_NAME}"},
        },
        {"type": "divider"},
    ] + report_blocks
    if result.model:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"\U0001f916 *Model:* {result.model}"}],
        })

    payload = {"attachments": [{"color": color, "blocks": blocks}]}
    if not _post_notice(f"\U0001f4ca Weekly Report — {config.CLUSTER_NAME}", payload):
        _console_weekly_report(parsed)


def post_daily_report(result):
    # Backward compat: if plain string, use old path
    if isinstance(result, str):
        _post_daily_report_str(result)
        return

    # AnalysisResult path. Branch on parse_error, NOT `if result.parsed` — a
    # failed parse still returns a dict (with _parse_error + raw text as summary),
    # so `if result.parsed` is truthy and would dump the raw (often truncated)
    # JSON into the channel. On any parse failure post a clean degraded notice;
    # the raw output stays in the LLM debug log for diagnosis.
    if result.parse_error:
        parsed = {
            "_parse_error": True,
            "overall_status": "degraded",
            "summary": "⚠️ Report generation failed — model output was truncated or "
                       "not valid JSON (raw output in the monitor LLM debug log).",
        }
    else:
        parsed = result.parsed or {}
    status = parsed.get("overall_status", "degraded")
    color = _STATUS_COLOR.get(status, _STATUS_COLOR["degraded"])

    report_blocks = format_daily_report(parsed)
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"\U0001f4ca Daily Report \u2014 {config.CLUSTER_NAME}"},
        },
        {"type": "divider"},
    ] + report_blocks
    if result.model:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"\U0001f916 *Model:* {result.model}"}],
        })

    payload = {"attachments": [{"color": color, "blocks": blocks}]}
    if not _post_notice(f"\U0001f4ca Daily Report — {config.CLUSTER_NAME}", payload):
        _console_daily_report(parsed)


def _console_daily_report(parsed: dict) -> None:
    """Last-resort console render when no Slack transport is reachable."""
    width = 72
    status = parsed.get("overall_status", "degraded")
    icon = _STATUS_ICON.get(status, "?")
    print(f"\n{_DIM}{'\u2501' * width}{_RESET}")
    print(f"  \033[34m\U0001f4ca {_BOLD}Daily Report \u2014 {config.CLUSTER_NAME}{_RESET}")
    print(f"{_DIM}{'\u2500' * width}{_RESET}")
    print(f"  Status: {icon} {status.upper()}")
    if parsed.get("summary"):
        print(f"  {parsed['summary']}")
    for issue in parsed.get("issues", []):
        sev = issue.get("severity", "info")
        print(f"  [{sev.upper()}] {issue.get('description', '')}")
    for trend in parsed.get("trends", []):
        desc = trend.get("description", str(trend)) if isinstance(trend, dict) else str(trend)
        print(f"  - {desc}")
    for rec in parsed.get("recommendations", []):
        action = rec.get("action", str(rec)) if isinstance(rec, dict) else str(rec)
        print(f"  > {action}")
    print(f"{_DIM}{'\u2501' * width}{_RESET}\n")


def _post_daily_report_str(report: str):
    """Legacy path for plain string reports."""
    payload = {
        "attachments": [
            {
                "color": SEVERITY_COLORS["info"],
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": f"\U0001f4ca Daily Report \u2014 {config.CLUSTER_NAME}"},
                    },
                    {"type": "divider"},
                ] + _split_text_blocks(report),
            }
        ]
    }
    if not _post_notice(f"\U0001f4ca Daily Report — {config.CLUSTER_NAME}", payload):
        width = 72
        print(f"\n{_DIM}{'\u2501' * width}{_RESET}")
        print(f"  \033[34m\U0001f4ca {_BOLD}Daily Report \u2014 {config.CLUSTER_NAME}{_RESET}")
        print(f"{_DIM}{'\u2500' * width}{_RESET}")
        print(report)
        print(f"{_DIM}{'\u2501' * width}{_RESET}\n")


def post_maintenance_notice(activated: bool, reason: str, duration_hours: float = 0) -> None:
    """Post a maintenance mode start/end notice to Slack."""
    if activated:
        icon = "\U0001f6e0\ufe0f"
        title = f"{icon} Maintenance Mode Activated — {config.CLUSTER_NAME}"
        text = f"*Reason:* {reason}\n*Duration:* {duration_hours:.1f}h\nLLM analysis will be skipped. Alerts will still be posted with `[Maintenance]` prefix."
        color = "#FFA500"
    else:
        icon = "\u2705"
        title = f"{icon} Maintenance Mode Ended — {config.CLUSTER_NAME}"
        text = f"*Reason:* {reason}\nNormal alerting resumed."
        color = "#36A64F"

    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": title},
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": text},
                    },
                ],
            }
        ]
    }
    if not _post_notice(title, payload):
        print(f"\n  {title}\n  {text}\n")


def post_resolved(state_key: str, namespace: str, resource: str, duration_min: float,
                   last_seen_at: float | None = None, webhook_url: str | None = None,
                   thread_ts: str | None = None):
    """Post a green 'resolved' message to Slack for critical incidents.

    When ``thread_ts`` is provided and the bot API is available, the
    resolved message is posted as a thread reply to the original alert.
    """
    if not (webhook_url or config.SLACK_WEBHOOK_URL) and not _bot_api_available(namespace):
        print(f"  \033[32m\u2705 RESOLVED: {state_key} (after {duration_min:.0f}m)\033[0m")
        return

    fields = [
        {"type": "mrkdwn", "text": f"*Resource:*\n{resource}"},
        {"type": "mrkdwn", "text": f"*Recovery time:*\n{duration_min:.0f} min"},
    ]
    if last_seen_at is not None:
        from datetime import datetime, timezone
        last_fail = datetime.fromtimestamp(last_seen_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        fields.append({"type": "mrkdwn", "text": f"*Last failure:*\n{last_fail}"})

    header_text = f"\u2705 [{config.CLUSTER_NAME}/{namespace}] Resolved"
    payload = {
        "attachments": [
            {
                "color": "#36A64F",
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": header_text},
                    },
                    {
                        "type": "section",
                        "fields": fields,
                    },
                ],
            }
        ]
    }
    channel = _channel_for_namespace(namespace)
    if _resolve_bot_token() and channel:
        ts = _post_via_bot_api(
            channel=channel, text=header_text,
            attachments=payload.get("attachments"), thread_ts=thread_ts,
        )
        if ts:
            return
        logger.info("Falling back to Slack webhook after chat.postMessage resolved failure")
    _send(payload, webhook_url=webhook_url)


def _split_text_blocks(text: str, max_len: int = 2900, max_blocks: int = 45) -> list[dict]:
    """Split long text into multiple Slack section blocks at paragraph boundaries.

    Enforces max_blocks to stay within Slack's 50-block-per-attachment limit
    (leaving room for header, fields, context, dividers added by callers).
    """
    if not text or not text.strip():
        text = "Analysis unavailable"
    # Remove null bytes and control chars (except newline/tab) that break Slack
    text = "".join(c for c in text if c in ('\n', '\t') or (ord(c) >= 32))
    if len(text) <= max_len:
        return [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]

    blocks: list[dict[str, Any]] = []
    remaining = text
    while remaining:
        if len(blocks) >= max_blocks - 1 and len(remaining) > max_len:
            # Last allowed block — truncate remaining
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": remaining[:max_len - 20] + "\n\n…(truncated)"}})
            break
        if len(remaining) <= max_len:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": remaining}})
            break
        # Find split point at paragraph boundary
        split_at = remaining.rfind("\n\n", 0, max_len)
        if split_at <= 0:
            split_at = remaining.rfind("\n", 0, max_len)
        if split_at <= 0:
            split_at = max_len
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": remaining[:split_at]}})
        remaining = remaining[split_at:].lstrip("\n")
    return blocks


def _truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _send(payload: dict, webhook_url: str | None = None) -> bool:
    """Post a Slack payload. Returns True on 2xx (or after a successful
    fallback), False on any failure.

    Existing callers can ignore the return value — failures are still logged
    and the function never raises. Callers that need to surface failures
    upstream (e.g. the LLM spend report) check the return.
    """
    url = webhook_url or config.SLACK_WEBHOOK_URL
    if not url:
        return False
    try:
        resp = requests.post(
            url,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if 200 <= resp.status_code < 300:
            return True
        logger.error("Slack webhook returned %s: %s", resp.status_code, resp.text)
        # Retry with simplified plain-text fallback for malformed payloads
        if resp.status_code == 400:
            return _send_fallback(payload, webhook_url=webhook_url)
        return False
    except Exception:
        logger.exception("Failed to send Slack message")
        return False


def _send_fallback(original_payload: dict, webhook_url: str | None = None) -> bool:
    """Send a simplified plain-text message when Block Kit payload fails.
    Returns True on success, False otherwise.
    """
    url = webhook_url or config.SLACK_WEBHOOK_URL
    if not url:
        return False
    try:
        # Extract text content from blocks
        parts = []
        for att in original_payload.get("attachments", []):
            for block in att.get("blocks", []):
                if block.get("type") == "header":
                    parts.append(block["text"]["text"])
                elif block.get("type") == "section":
                    if "text" in block:
                        parts.append(block["text"].get("text", ""))
                    for f in block.get("fields", []):
                        parts.append(f.get("text", ""))
        text = "\n".join(p for p in parts if p)
        if len(text) > 3900:
            text = text[:3900] + "\n…(truncated)"
        fallback_payload = {"text": text}
        resp = requests.post(
            url,
            data=json.dumps(fallback_payload),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if resp.status_code == 200:
            logger.info("Slack fallback (plain text) sent successfully")
            return True
        logger.error("Slack fallback also failed: %s: %s", resp.status_code, resp.text)
        return False
    except Exception:
        logger.exception("Slack fallback send failed")
        return False

"""Context budget — measure sections and enforce byte cap before LLM call.

Supports both dict-based (alerts) and markdown-based (daily reports) contexts.
"""
import json
import logging
import re

logger = logging.getLogger(__name__)

# --- Error-priority patterns for log line filtering ---
_ERROR_RE = re.compile(
    r"ERROR|WARN|FATAL|Exception|Traceback|panic|OOM|killed|exit code",
    re.IGNORECASE,
)

# --- Markdown section parsing (for backward compat with daily reports) ---

# Header → slug mapping
_SECTION_MAP: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^## Pod Logs", re.IGNORECASE), "logs"),
    (re.compile(r"^## Pod Metrics", re.IGNORECASE), "prom_metrics"),
    (re.compile(r"^## Pod:", re.IGNORECASE), "pod_status"),
    (re.compile(r"^## Events", re.IGNORECASE), "events"),
    (re.compile(r"^## Deployment:", re.IGNORECASE), "deployment"),
    (re.compile(r"^## StatefulSet:", re.IGNORECASE), "statefulset"),
    (re.compile(r"^## HPA:", re.IGNORECASE), "hpa"),
    (re.compile(r"^## Node Metrics", re.IGNORECASE), "node_metrics"),
    (re.compile(r"^## Application Metrics", re.IGNORECASE), "app_metrics"),
    (re.compile(r"^## Extended Diagnostics", re.IGNORECASE), "diagnostics"),
    (re.compile(r"^## Endpoint Health Check", re.IGNORECASE), "endpoint"),
    (re.compile(r"^## Backend", re.IGNORECASE), "backend"),
]


def _section_slug(header_line: str) -> str:
    """Map a '## ...' header line to a short slug."""
    for pattern, slug in _SECTION_MAP:
        if pattern.match(header_line):
            return slug
    return header_line.strip("#").strip().lower().replace(" ", "_")[:30]


def measure_context(context: str) -> dict:
    """Parse context by ## headers, return byte sizes per section.

    Returns: {"total_bytes": N, "section_bytes": {...}, "sections": [...]}
    """
    if not context:
        return {"total_bytes": 0, "section_bytes": {}, "sections": []}

    sections: list[tuple[str, str]] = []  # (slug, content)
    current_slug = "_preamble"
    current_lines: list[str] = []

    for line in context.split("\n"):
        if line.startswith("## "):
            # Flush previous
            if current_lines:
                sections.append((current_slug, "\n".join(current_lines)))
            current_slug = _section_slug(line)
            current_lines = [line]
        else:
            current_lines.append(line)

    # Flush last section
    if current_lines:
        sections.append((current_slug, "\n".join(current_lines)))

    section_bytes = {}
    section_names = []
    for slug, content in sections:
        b = len(content.encode("utf-8"))
        section_bytes[slug] = section_bytes.get(slug, 0) + b
        if slug not in section_names:
            section_names.append(slug)

    return {
        "total_bytes": len(context.encode("utf-8")),
        "section_bytes": section_bytes,
        "sections": section_names,
    }


# --- Dict-based budget (for alerts) ---

# Sections build_alert_payload handles by name; every other key is passed through.
_KNOWN_ALERT_SECTIONS = frozenset({
    "pod", "owner", "node_metrics", "diagnostics", "logs", "events",
    "flux_resource", "conditions", "event", "error", "raw",
})

def build_alert_payload(data: dict, resource: str, cluster: str,
                        max_bytes: int) -> tuple[str, bool, list[str]]:
    """Build JSON payload for alert LLM call with section limits.

    Returns: (json_string, truncated, notes)
    """
    notes = []
    payload = {"cluster": cluster, "resource": resource}

    # Copy structured sections
    if "pod" in data:
        payload["pod"] = data["pod"]
    if "owner" in data:
        payload["owner"] = data["owner"]
    if "node_metrics" in data:
        payload["node_metrics"] = data["node_metrics"]
    if "diagnostics" in data:
        # Diagnostics stays as-is but truncate string values to 3000 chars
        diag = data["diagnostics"]
        diag_str = json.dumps(diag, ensure_ascii=False)
        if len(diag_str) > 3000:
            notes.append(f"diagnostics: {len(diag_str)} -> 3000 chars")
            # Trim previous_logs first if present
            if isinstance(diag, dict) and "previous_logs" in diag:
                diag = dict(diag)
                diag["previous_logs"] = _prioritize_log_lines(diag["previous_logs"], 10)
        payload["diagnostics"] = diag

    # Logs: prioritize error lines, max 30, cap line lengths always.
    # 30-line cap uses the headroom we have on the 16KB budget (prod alert
    # max ~14KB); the progressive-trim loop below is the only thing that
    # ever lowers this further, and it only touches logs.
    if "logs" in data:
        # Normalize to list[str]. Some scanners / context_override paths
        # can pass a single blob string; iterating a bare string would
        # treat each character as a "line".
        raw_logs = data["logs"]
        if isinstance(raw_logs, str):
            log_lines = raw_logs.splitlines()
        else:
            log_lines = list(raw_logs)
        payload["logs"] = _cap_line_lengths(
            _prioritize_log_lines(log_lines, 30)
        )
        if len(log_lines) > 30:
            notes.append(f"logs: {len(log_lines)} -> 30 (error-prioritized)")

    # Events: max 15
    if "events" in data:
        payload["events"] = data["events"][:15]
        if len(data["events"]) > 15:
            notes.append(f"events: {len(data['events'])} -> 15")

    # Flux context (if present)
    if "flux_resource" in data:
        payload["flux_resource"] = data["flux_resource"]
    if "conditions" in data:
        payload["conditions"] = data["conditions"]

    # Simple event context
    if "event" in data:
        payload["event"] = data["event"]

    # Error message (e.g. pod not found)
    if "error" in data:
        payload["error"] = data["error"]

    # Raw string context (backward compat for scanners)
    if "raw" in data:
        payload["context"] = data["raw"]

    # Any other section goes through as is (an Alertmanager alert's summary, description
    # and labels; an SLI breach) - a section the LLM never sees cannot inform it.
    extras = [k for k in data if k not in _KNOWN_ALERT_SECTIONS and k not in payload]
    for key in extras:
        payload[key] = data[key]

    json_str = json.dumps(payload, ensure_ascii=False)

    # Progressive trim — logs only. Structured sections (pod, owner, events,
    # node_metrics, diagnostics) are the load-bearing signal for root-cause
    # analysis and must survive over-budget situations intact. The old strategy
    # dropped node_metrics/diagnostics first; that turned OOM/crash contexts
    # into useless stubs. Prod alert ceiling is well below the default 16KB
    # cap, so this only kicks in on pathological log storms.
    truncated = False
    if len(json_str.encode("utf-8")) > max_bytes:
        truncated = True

        trim_steps: list[tuple[str, int | None]] = [
            ("trim_logs", 20),
            ("trim_logs", 10),
            ("trim_logs", 5),
            ("cap_line_length", 300),
            ("drop_logs", None),
        ]
        for step, arg in trim_steps:
            if len(json_str.encode("utf-8")) <= max_bytes:
                break
            if "logs" not in payload:
                break
            log_lines = payload["logs"].split("\n") if isinstance(payload["logs"], str) else payload["logs"]
            if step == "trim_logs":
                payload["logs"] = _prioritize_log_lines(log_lines, arg or 0)
                notes.append(f"logs: trimmed to {arg} (budget)")
            elif step == "cap_line_length":
                capped = [line[:arg] for line in log_lines]
                payload["logs"] = capped
                notes.append(f"logs: lines capped to {arg} chars (budget)")
            elif step == "drop_logs":
                del payload["logs"]
                notes.append("logs: dropped (budget)")
            json_str = json.dumps(payload, ensure_ascii=False)
        # Still over: the pass-through sections go last, after the logs - the largest
        # first, so a long description goes before a one-line summary.
        for key in sorted(extras, key=lambda k: -len(json.dumps(payload[k], ensure_ascii=False))):
            if len(json_str.encode("utf-8")) <= max_bytes:
                break
            del payload[key]
            notes.append(f"{key}: dropped (budget)")
            json_str = json.dumps(payload, ensure_ascii=False)

    final_bytes = len(json_str.encode("utf-8"))
    approx_tokens = final_bytes // 4  # ~4 bytes per token for JSON
    if truncated:
        logger.warning(
            "Alert context truncated for %s: %dB ~%d tokens (cap=%dB), cuts: %s",
            resource, final_bytes, approx_tokens, max_bytes, "; ".join(notes),
        )
    if final_bytes > max_bytes:
        # Structured sections are deliberately preserved even when over budget —
        # dropping them would destroy exactly the signal the LLM needs.
        logger.warning(
            "Alert context STILL over budget for %s after log-only trim: "
            "%dB ~%d tokens > %dB cap — sending as-is to preserve "
            "pod/owner/events/node_metrics/diagnostics",
            resource, final_bytes, approx_tokens, max_bytes,
        )
        notes.append(f"OVER_BUDGET: {final_bytes}B ~{approx_tokens}tok > {max_bytes}B")

    return json_str, truncated, notes


_MAX_LINE_CHARS = 500


def _cap_line_lengths(lines: list[str]) -> list[str]:
    """Cap each line to _MAX_LINE_CHARS. Used during budget trimming."""
    return [line[:_MAX_LINE_CHARS] for line in lines]


def _prioritize_log_lines(lines: list[str], max_lines: int) -> list[str]:
    """Keep error-priority lines first, then fill from tail.

    Returns at most max_lines lines, with a note if truncated.
    """
    # Clean up any existing omission markers before re-evaluating
    clean_lines = [l for l in lines if not l.startswith("[") or not l.endswith("lines omitted]")]

    if len(clean_lines) <= max_lines:
        return clean_lines

    error_lines = []
    other_lines = []
    for line in clean_lines:
        if _ERROR_RE.search(line):
            error_lines.append(line)
        else:
            other_lines.append(line)

    # Take all error lines (up to max), fill rest from tail of other lines
    if len(error_lines) >= max_lines:
        result = error_lines[:max_lines - 1]
    else:
        remaining = max_lines - len(error_lines) - 1  # -1 for omission note
        result = error_lines + other_lines[-remaining:] if remaining > 0 else error_lines

    omitted = len(clean_lines) - len(result)
    if omitted > 0:
        result.append(f"[{omitted} lines omitted]")

    return result


def build_report_payload(data: dict, cluster: str,
                         max_bytes: int) -> tuple[str, bool, list[str]]:
    """Build JSON payload for daily report LLM call with section limits.

    Accepts structured dict from collect_daily_data(). Applies section caps
    and progressive trim to fit within max_bytes.

    Returns: (json_string, truncated, notes)
    """
    notes = []
    payload = {"cluster": cluster}

    # Section limits (always applied)
    _SECTION_LIMITS = {
        "pod_restarts": 20,
        "warning_events": 15,
        "pvc_usage": 10,
        "resource_pressure": 10,
        "last_24h_incidents": 20,
        "flux_failures": 15,
        "node_issues": 10,
        "cert_issues": 10,
    }

    for key, items in data.items():
        if key == "last_24h" and isinstance(items, dict):
            # Cap nested incidents list inside last_24h
            capped = dict(items)
            inc_limit = _SECTION_LIMITS.get("last_24h_incidents", 20)
            if "incidents" in capped and len(capped["incidents"]) > inc_limit:
                _SEV_ORDER = {"critical": 0, "warning": 1}
                capped["incidents"] = sorted(
                    capped["incidents"],
                    key=lambda i: _SEV_ORDER.get(i.get("severity", ""), 2),
                )[:inc_limit]
                notes.append(f"last_24h.incidents: {len(items['incidents'])} -> {inc_limit} (severity-sorted)")
            payload[key] = capped
            continue
        if not isinstance(items, list):
            payload[key] = items
            continue
        limit = _SECTION_LIMITS.get(key)
        if limit and len(items) > limit:
            payload[key] = items[:limit]
            notes.append(f"{key}: {len(items)} -> {limit}")
        else:
            payload[key] = items

    # Cap flux failure messages (can be 5-10KB each with full error output)
    if "flux_failures" in payload:
        for ff in payload["flux_failures"]:
            if isinstance(ff, dict) and len(ff.get("message", "")) > 300:
                ff["message"] = ff["message"][:300]

    json_str = json.dumps(payload, ensure_ascii=False)

    # Progressive trim if over budget
    truncated = False
    if len(json_str.encode("utf-8")) > max_bytes:
        truncated = True

        # 1. pod_restarts → 10
        if "pod_restarts" in payload and len(payload["pod_restarts"]) > 10:
            payload["pod_restarts"] = payload["pod_restarts"][:10]
            notes.append("pod_restarts: trimmed to 10 (budget)")
            json_str = json.dumps(payload, ensure_ascii=False)

        # 2. warning_events → 7
        if len(json_str.encode("utf-8")) > max_bytes and "warning_events" in payload and len(payload["warning_events"]) > 7:
            payload["warning_events"] = payload["warning_events"][:7]
            notes.append("warning_events: trimmed to 7 (budget)")
            json_str = json.dumps(payload, ensure_ascii=False)

        # 3. Drop resource_pressure
        if len(json_str.encode("utf-8")) > max_bytes and "resource_pressure" in payload:
            del payload["resource_pressure"]
            notes.append("resource_pressure: dropped (budget)")
            json_str = json.dumps(payload, ensure_ascii=False)

        # 4. Drop last_24h
        if len(json_str.encode("utf-8")) > max_bytes and "last_24h" in payload:
            del payload["last_24h"]
            notes.append("last_24h: dropped (budget)")
            json_str = json.dumps(payload, ensure_ascii=False)

        # 5. Drop pvc_usage
        if len(json_str.encode("utf-8")) > max_bytes and "pvc_usage" in payload:
            del payload["pvc_usage"]
            notes.append("pvc_usage: dropped (budget)")
            json_str = json.dumps(payload, ensure_ascii=False)

        # 6. Trim flux_failures to 5
        if len(json_str.encode("utf-8")) > max_bytes and "flux_failures" in payload and len(payload["flux_failures"]) > 5:
            payload["flux_failures"] = payload["flux_failures"][:5]
            notes.append("flux_failures: trimmed to 5 (budget)")
            json_str = json.dumps(payload, ensure_ascii=False)

        # 7. Drop flux_failures
        if len(json_str.encode("utf-8")) > max_bytes and "flux_failures" in payload:
            del payload["flux_failures"]
            notes.append("flux_failures: dropped (budget)")
            json_str = json.dumps(payload, ensure_ascii=False)

        # 8. Drop cert_issues
        if len(json_str.encode("utf-8")) > max_bytes and "cert_issues" in payload:
            del payload["cert_issues"]
            notes.append("cert_issues: dropped (budget)")
            json_str = json.dumps(payload, ensure_ascii=False)

        # 9. Drop node_issues
        if len(json_str.encode("utf-8")) > max_bytes and "node_issues" in payload:
            del payload["node_issues"]
            notes.append("node_issues: dropped (budget)")
            json_str = json.dumps(payload, ensure_ascii=False)

    final_bytes = len(json_str.encode("utf-8"))
    approx_tokens = final_bytes // 4
    if truncated:
        logger.warning(
            "Daily report context truncated: %dB ~%d tokens (cap=%dB), cuts: %s",
            final_bytes, approx_tokens, max_bytes, "; ".join(notes),
        )
    if final_bytes > max_bytes:
        logger.warning(
            "Daily report STILL over budget: %dB ~%d tokens > %dB cap after all trims",
            final_bytes, approx_tokens, max_bytes,
        )
        notes.append(f"OVER_BUDGET: {final_bytes}B ~{approx_tokens}tok > {max_bytes}B")

    return json_str, truncated, notes


def measure_report_data(data: dict) -> dict:
    """Measure byte sizes per section of a report dict. For logging."""
    section_bytes = {}
    total = 0
    for key, value in data.items():
        b = len(json.dumps(value, ensure_ascii=False).encode("utf-8"))
        section_bytes[key] = b
        total += b
    return {
        "total_bytes": total,
        "section_bytes": section_bytes,
        "sections": list(data.keys()),
    }

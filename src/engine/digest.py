"""Hourly digest — everything the gates withheld, in one message, or silence.

Warnings route straight to the daily report today, so anything not worth waking
someone for waits up to 24 hours. There is no middle tier, which is why the
severity promoters became the de-facto one: a chronic warning gets upgraded to
critical purely because it is old, and pages.

This is that missing tier. Alerts the pipeline withholds are marked
`batch_status='pending'` on their occurrence row and drained here, grouped by
namespace, as one message.

Two rules shape it:

- **Nothing to say means nothing is said.** No heartbeat, no "all clear". An
  empty drain returns without touching Slack. Anyone who wants a periodic
  liveness signal has the daily report.
- **Withheld is not discarded.** If this loop stops running, the gates upstream
  become silencing rather than deferral. That is why the scheduler attaches a
  failure callback rather than a bare create_task.

The `batch_status` column, `get_pending_batch_occurrences` and the
`mark_occurrences_*` writers all predate this module: they are what survived the
deletion of the LLM cold-path batcher (docs/roadmap.md). Reused as-is, minus the
LLM — this is a rendered list, not an analysis.
"""
import logging
from collections import defaultdict

from src import config
from src.engine.notifier import _post_notice, _SEVERITY_ICON_SLACK, _split_text_blocks

logger = logging.getLogger(__name__)

# Per namespace, before collapsing into "… +N more". Keeps one noisy namespace
# from crowding out the others and the message under Slack's block ceiling.
_LINES_PER_NAMESPACE = 8


def _describe(state_key: str) -> tuple[str, str]:
    """Split `"Kind:ns/name:alias"` into a display name and the alias.

    Synthetic keys (`Collective:production`, `Node:worker-1`) have no alias
    segment; they render as-is rather than being mangled into one.
    """
    parts = state_key.split(":")
    if len(parts) < 3:
        return state_key, ""
    name = parts[1].split("/", 1)[-1]
    return name, parts[-1]


def build_blocks(pending: list[dict]) -> tuple[str, list[dict]]:
    """Render drained occurrences into (summary_text, slack_blocks)."""
    by_ns: dict[str, dict[tuple[str, str], list[str]]] = defaultdict(
        lambda: defaultdict(list))
    for row in pending:
        ns = row.get("namespace") or "?"
        name, alias = _describe(row.get("state_key", ""))
        by_ns[ns][(name, alias)].append(row.get("original_severity") or "warning")

    lines: list[str] = []
    for ns in sorted(by_ns):
        groups = by_ns[ns]
        events = sum(len(v) for v in groups.values())
        lines.append(f"*{ns}* — {events} events, {len(groups)} workloads")
        ordered = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0][0]))
        for (name, alias), sevs in ordered[:_LINES_PER_NAMESPACE]:
            # Worst severity in the group decides the icon: a group is as
            # serious as its most serious member.
            sev = "critical" if "critical" in sevs else sevs[0]
            icon = _SEVERITY_ICON_SLACK.get(sev, _SEVERITY_ICON_SLACK["warning"])
            count = f" ×{len(sevs)}" if len(sevs) > 1 else ""
            lines.append(f"  {icon} `{name}` {alias}{count}")
        if len(ordered) > _LINES_PER_NAMESPACE:
            lines.append(f"  … +{len(ordered) - _LINES_PER_NAMESPACE} more workloads")
        lines.append("")

    total = len(pending)
    header = f"\U0001f552 Hourly digest — {config.CLUSTER_NAME}"
    footer = (f"{total} alert{'s' if total != 1 else ''} withheld from Slack "
              f"across {len(by_ns)} namespace{'s' if len(by_ns) != 1 else ''}. "
              "None of these took a shop down.")

    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": header}},
        {"type": "divider"},
    ]
    blocks.extend(_split_text_blocks("\n".join(lines).strip()))
    blocks.append({"type": "context",
                   "elements": [{"type": "mrkdwn", "text": footer}]})
    return f"{header}\n{footer}", blocks


def run_once(store) -> bool:
    """Drain and post. Returns True only when a message was actually sent.

    Never raises: it runs on a background loop whose death would silently turn
    the upstream gates into suppression.
    """
    try:
        pending = store.get_pending_batch_occurrences()
    except Exception:
        logger.warning("Hourly digest: could not read pending occurrences", exc_info=True)
        return False

    if not pending:
        logger.debug("Hourly digest: nothing to report")
        return False

    ids = [row["id"] for row in pending if row.get("id") is not None]
    try:
        text, blocks = build_blocks(pending)
    except Exception:
        logger.warning("Hourly digest: could not render %d occurrences", len(pending),
                       exc_info=True)
        return False

    try:
        delivered = _post_notice(text, {
            "attachments": [{"color": "#FFA500", "blocks": blocks}],
        })
    except Exception:
        # The notifier reaches the network; it can raise as well as return
        # False. Both mean the same thing here — nobody saw it — and neither
        # may escape, or the loop's tick handler swallows it as an opaque
        # failure and this function's "never raises" contract is a lie.
        logger.warning("Hourly digest: delivery raised, %d occurrences stay pending",
                       len(ids), exc_info=True)
        return False
    if not delivered:
        # Leave the rows pending so the next tick retries. A digest nobody
        # received must not be marked as sent.
        logger.warning("Hourly digest: delivery failed, %d occurrences stay pending",
                       len(ids))
        return False

    try:
        store.mark_occurrences_notified(ids)
    except Exception:
        logger.warning("Hourly digest: posted but could not mark %d occurrences",
                       len(ids), exc_info=True)
    logger.info("Hourly digest: posted %d withheld alerts", len(pending))
    return True


def pending_burst(store) -> bool:
    """True when enough has piled up that waiting out the hour is wrong.

    A cascade is itself signal. Counted across the whole queue rather than per
    namespace: the threshold is about how much the operator has not been told,
    and that total is what matters.
    """
    try:
        return len(store.get_pending_batch_occurrences(
            limit=config.DIGEST_BURST_THRESHOLD)) >= config.DIGEST_BURST_THRESHOLD
    except Exception:
        logger.debug("Hourly digest: burst check failed", exc_info=True)
        return False

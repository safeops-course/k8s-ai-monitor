"""Open-incidents digest — everything still open, at fixed hours, in one message.

The hourly digest (`digest.py`) drains withheld alerts and stays silent when
empty. This one is the opposite contract: a wall-clock snapshot of every
incident that is still `active` or `acknowledged`, posted at each hour listed
in `OPEN_DIGEST_HOURS` (local `REPORT_TIMEZONE` — e.g. "8,18" for a morning
what's-still-broken view and an end-of-day one), and it ALWAYS posts —
"nothing is open" is an answer worth hearing, and the green message doubles as
a daily liveness signal for the monitor itself.

Why it exists: alerts fire at the moment of breakage, but incidents that never
auto-resolve (a pod replaced under a stale state_key, a chronic flapper riding
its 12h cooldown) quietly pile up as `active` with nobody looking. A once-a-day
"still open" list is the cheapest way to make that rot visible before the
7-day startup sweep catches it.

No LLM anywhere in this path — it is a rendered list straight from the store.
"""
import logging
import time

from src import config
from src.engine.notifier import _post_notice, _SEVERITY_ICON_SLACK, _split_text_blocks

logger = logging.getLogger(__name__)

# Keeps the message under Slack's block ceiling; anything past this collapses
# into a "+N more" line. Criticals sort first so they are never the ones cut.
_MAX_LINES = 25


def _fmt_age(seconds: float) -> str:
    if seconds < 3600:
        return f"{seconds / 60:.0f}m"
    if seconds < 48 * 3600:
        return f"{seconds / 3600:.0f}h"
    return f"{seconds / 86400:.0f}d"


def build_blocks(incidents: list, now: float) -> tuple[str, list[dict], str]:
    """Render open incidents into (summary_text, slack_blocks, color)."""
    criticals = [i for i in incidents if i.severity == "critical"]
    header = f"\U0001f4cb Open incidents — {config.CLUSTER_NAME}"

    if not incidents:
        text = "✅ No open incidents. Clean board."
        blocks: list[dict] = [
            {"type": "header", "text": {"type": "plain_text", "text": header}},
            {"type": "section", "text": {"type": "mrkdwn", "text": text}},
        ]
        return f"{header}\n{text}", blocks, "#36A64F"

    # Criticals first, then most recently active. `active_since` is the start
    # of the CURRENT active cycle, so age reads as "open for", not lifetime.
    ordered = sorted(
        incidents,
        key=lambda i: (0 if i.severity == "critical" else 1, -i.last_seen_at),
    )

    lines: list[str] = []
    for inc in ordered[:_MAX_LINES]:
        icon = _SEVERITY_ICON_SLACK.get(inc.severity, _SEVERITY_ICON_SLACK["warning"])
        open_for = _fmt_age(max(0.0, now - (inc.active_since or inc.first_seen_at)))
        seen = _fmt_age(max(0.0, now - inc.last_seen_at))
        acked = "  _(acknowledged)_" if inc.status == "acknowledged" else ""
        lines.append(
            f"{icon} `{inc.state_key}` — open {open_for}, "
            f"last seen {seen} ago, ×{inc.occurrence_count}{acked}"
        )
    if len(ordered) > _MAX_LINES:
        lines.append(f"… +{len(ordered) - _MAX_LINES} more open incidents")

    footer = (
        f"{len(incidents)} open incident{'s' if len(incidents) != 1 else ''} "
        f"({len(criticals)} critical). Anything stale here needs a resolve "
        f"or a suppression — it will not clean itself up."
    )
    open_blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": header}},
        {"type": "divider"},
    ]
    open_blocks.extend(_split_text_blocks("\n".join(lines)))
    open_blocks.append({"type": "context",
                    "elements": [{"type": "mrkdwn", "text": footer}]})
    color = "#D00000" if criticals else "#FFA500"
    return f"{header}\n{footer}", open_blocks, color


def run_once(store) -> bool:
    """Snapshot and post. Returns True only when a message was actually sent.

    Never raises: it runs on a background loop; a crash here must not take the
    scheduler down and silently end the daily snapshots.
    """
    try:
        incidents = [
            i for i in store.list_incidents(status=None)
            if i.status in ("active", "acknowledged")
        ]
    except Exception:
        logger.warning("Open digest: could not read incidents", exc_info=True)
        return False

    now = time.time()
    try:
        text, blocks, color = build_blocks(incidents, now)
    except Exception:
        logger.warning("Open digest: could not render %d incidents",
                       len(incidents), exc_info=True)
        return False

    try:
        delivered = _post_notice(text, {
            "attachments": [{"color": color, "blocks": blocks}],
        })
    except Exception:
        logger.warning("Open digest: delivery raised", exc_info=True)
        return False
    if not delivered:
        logger.warning("Open digest: delivery failed (%d open incidents unsent)",
                       len(incidents))
        return False

    logger.info("Open digest: posted (%d open incidents)", len(incidents))
    return True

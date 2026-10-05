"""Time-based escalation logic for recurring/persistent incidents."""
import time
from dataclasses import dataclass

from src import config
from src.engine.store import Incident


@dataclass
class EscalationResult:
    level: str | None    # None | "recurring" | "persistent"
    should_alert: bool
    prefix: str          # "" | "RECURRING: " | "PERSISTENT: "


def check_escalation(incident: Incident, *, count_offset: int = 0) -> EscalationResult:
    """Determine if an existing incident should fire an escalation alert.

    Logic:
    - In cooldown → skip
    - 2nd occurrence within ESCALATION_RECURRING_WINDOW_H → "recurring"
    - 3+ occurrences, first seen > ESCALATION_PERSISTENT_MIN_AGE_H ago → "persistent"
    - Stale reoccurrence (> window since last) → new alert, no escalation level
    - Recent but not enough for escalation → skip

    count_offset is added to occurrence_count: the pipeline checks escalation BEFORE it
    records the current occurrence, so it passes count_offset=1. Without it the
    persistent threshold fired one occurrence late (on the 4th, not the 3rd, with
    ESCALATION_PERSISTENT_MIN_COUNT=3).
    """
    now = time.time()
    effective_count = incident.occurrence_count + count_offset

    # In cooldown → skip
    if incident.cooldown_until and now < incident.cooldown_until:
        return EscalationResult(level=None, should_alert=False, prefix="")

    hours_since_last = (now - incident.last_seen_at) / 3600
    hours_since_first = (now - incident.first_seen_at) / 3600

    # Stale reoccurrence (> window since last) → new alert, no escalation
    if hours_since_last > config.ESCALATION_RECURRING_WINDOW_H:
        return EscalationResult(level=None, should_alert=True, prefix="")

    # 2nd occurrence within window → "recurring"
    # (one recorded occurrence + this one; does not depend on count_offset)
    if incident.occurrence_count == 1:
        return EscalationResult(level="recurring", should_alert=True,
                                prefix="\U0001f501 RECURRING: ")

    # 3+ occurrences, first seen long enough ago → "persistent"
    if (effective_count >= config.ESCALATION_PERSISTENT_MIN_COUNT
            and hours_since_first >= config.ESCALATION_PERSISTENT_MIN_AGE_H):
        return EscalationResult(level="persistent", should_alert=True,
                                prefix="\U0001f525 PERSISTENT: ")

    # Recent but not enough for escalation → skip (will be caught by cooldown next time)
    return EscalationResult(level=None, should_alert=False, prefix="")

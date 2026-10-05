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

    count_offset: add this to occurrence_count before evaluating thresholds.
    Callers pass count_offset=1 when the current occurrence hasn't been
    recorded yet (the normal case — escalation is checked before
    record_occurrence). Without this, the persistent threshold triggers
    one tick late (e.g. on the 4th occurrence instead of the 3rd when
    ESCALATION_PERSISTENT_MIN_COUNT=3).

    Logic:
    - In cooldown → skip
    - 2nd occurrence within ESCALATION_RECURRING_WINDOW_H → "recurring"
    - 3+ occurrences, first seen > ESCALATION_PERSISTENT_MIN_AGE_H ago → "persistent"
    - Stale reoccurrence (> window since last) → new alert, no escalation level
    - Recent but not enough for escalation → skip
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
    # effective_count includes the current (not-yet-recorded) occurrence via
    # count_offset, so the 2nd detection has effective_count=2.
    if effective_count == 2:
        return EscalationResult(level="recurring", should_alert=True,
                                prefix="\U0001f501 RECURRING: ")

    # 3+ occurrences, first seen long enough ago → "persistent"
    if (effective_count >= config.ESCALATION_PERSISTENT_MIN_COUNT
            and hours_since_first >= config.ESCALATION_PERSISTENT_MIN_AGE_H):
        return EscalationResult(level="persistent", should_alert=True,
                                prefix="\U0001f525 PERSISTENT: ")

    # Recent but not enough for escalation → skip (will be caught by cooldown next time)
    return EscalationResult(level=None, should_alert=False, prefix="")

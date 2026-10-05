"""Incident store — SQLite backend.

Provides the Incident dataclass and SqliteStore for full incident lifecycle
with occurrences, escalation, suppressions, LLM cost tracking, and daily reports.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Incident:
    id: int
    state_key: str
    fingerprint: str
    issue_type: str
    severity: str
    owner_ref: str
    first_seen_at: float
    last_seen_at: float
    active_since: float
    occurrence_count: int
    cooldown_until: float | None
    last_slack_ts: str
    status: str  # "active", "acknowledged", "resolved"
    namespace: str = ""
    last_ai_mention_at: float = 0.0  # 0 = never mentioned
    # "" (unknown/legacy) | "operator" | "auto" | "sweep" | "reaper"
    # — see set_resolved_by; "reaper" is the periodic >7d stale close in
    # SqliteStore.cleanup(), which stamps it via UPDATE ... RETURNING.
    resolved_by: str = ""

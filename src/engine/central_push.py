"""Push data to central ClickHouse via HTTP interface."""
import json
import logging
import time
from datetime import datetime, timezone

import requests

from src import config

logger = logging.getLogger(__name__)

# Fields that contain Unix timestamps and need conversion to ISO format for DateTime64
# Anything here is a Unix float on the way in and an ISO string on the way out.
# Missing a field does not degrade it — ClickHouse rejects the fractional part
# outright ("Cannot parse input: expected ',' before: '.770317'") and _push
# swallows the error, so one unconverted timestamp silently kills the whole
# INSERT and the board just stops receiving that cluster.
_TIMESTAMP_FIELDS = {"first_seen_at", "active_since", "last_seen_at", "resolved_at",
                     "called_at", "created_at"}


def _convert_timestamps(row: dict) -> dict:
    """Convert float Unix timestamps to ISO 8601 strings for ClickHouse DateTime64."""
    for key in _TIMESTAMP_FIELDS:
        val = row.get(key)
        if isinstance(val, (int, float)) and val > 0:
            row[key] = datetime.fromtimestamp(val, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )[:-3]  # trim to milliseconds
    return row


def _push(table: str, rows: list[dict]) -> None:
    if not config.CENTRAL_AGGREGATE or not rows:
        return
    rows = [_convert_timestamps(r) for r in rows]
    body = "\n".join(json.dumps(r, default=str) for r in rows)
    try:
        resp = requests.post(
            f"{config.CENTRAL_CH_URL}/",
            params={
                "query": f"INSERT INTO {config.CENTRAL_CH_DATABASE}.{table} FORMAT JSONEachRow",
                "async_insert": "1",
                "wait_for_async_insert": "0",
            },
            data=body.encode(),
            auth=(config.CENTRAL_CH_USER, config.CENTRAL_CH_PASSWORD),
            timeout=10,
        )
        if resp.status_code != 200:
            logger.warning("CH push %s failed: %s %s", table, resp.status_code, resp.text[:200])
        else:
            logger.debug("CH push %s OK: %d rows", table, len(rows))
    except (requests.RequestException, ValueError, TypeError, KeyError):
        logger.warning("CH push %s error", table, exc_info=True)


def push_incident(data: dict) -> None:
    data["cluster"] = config.CLUSTER_NAME
    _push("incidents", [data])


def _status_row(inc, status: str, resolved_by: str) -> dict:
    return {
        "state_key": inc.state_key,
        "fingerprint": inc.fingerprint,
        "issue_type": inc.issue_type,
        "severity": inc.severity,
        "owner_ref": inc.owner_ref,
        "namespace": inc.namespace,
        "resource": "",
        "title": "",
        "status": status,
        "event_type": status,
        "auto_resolved": resolved_by in ("auto", "sweep", "reaper"),
        "occurrence_count": inc.occurrence_count,
        "first_seen_at": inc.first_seen_at,
        "active_since": getattr(inc, "active_since", 0) or inc.first_seen_at,
        "last_seen_at": inc.last_seen_at,
        "resolved_at": time.time() if status == "resolved" else 0,
        "analysis_json": "",
        "llm_model": "",
        "cluster": config.CLUSTER_NAME,
    }


def push_incident_statuses(incs: list, status: str, resolved_by: str = "") -> None:
    """Batch variant for sweeps: one HTTP request for the whole batch, so a
    cleanup loop never pays per-incident round-trips (or per-incident 10s
    timeouts when the central ClickHouse is down)."""
    if incs:
        _push("incidents", [_status_row(i, status, resolved_by) for i in incs])


def push_incident_status(inc, status: str, resolved_by: str = "") -> None:
    """Push a status-change snapshot for an existing incident row.

    The pipeline pushes rich snapshots on scan events, but resolves that happen
    OUTSIDE the pipeline (Slack/API resolve, startup sweeps, disabled-scanner
    sweeps) previously never reached the central ClickHouse — the fleet board
    kept them "open" forever. Central identity is (cluster, state_key) with the
    latest pushed_at winning; resource/title are not stored on the local
    incident row and go empty (resolved rows are filtered off the open board).
    """
    _push("incidents", [_status_row(inc, status, resolved_by)])


def push_occurrence_hour(state_key: str, when: float | None = None) -> None:
    """Record one occurrence into its hour bucket on the central board.

    `incidents` is a ReplacingMergeTree keyed on (cluster, state_key): it keeps
    the latest snapshot and nothing else, so `occurrence_count` is a lifetime
    total and the board cannot answer "how often today". This can. The table is
    a SummingMergeTree on (cluster, state_key, hour), so writing count=1 per
    occurrence is enough — the server does the adding and the monitor keeps no
    state. Bounded by construction: at most 24 rows per incident per day.

    Best-effort like every other push here; a lost row costs one tick of
    resolution, not correctness of the incident itself.
    """
    ts = when if when is not None else time.time()
    hour = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:00:00")
    _push("incident_occurrence_hours", [{
        "cluster": config.CLUSTER_NAME,
        "state_key": state_key,
        "hour": hour,
        "count": 1,
    }])


def push_report(data: dict) -> None:
    data["cluster"] = config.CLUSTER_NAME
    _push("daily_reports", [data])


def push_llm_usage(data: dict) -> None:
    data["cluster"] = config.CLUSTER_NAME
    _push("llm_usage", [data])


def _central_open_keys() -> list[str] | None:
    """state_keys this cluster has open on the central board, or None if the
    board cannot be read (then nothing is decided from it)."""
    query = (
        f"SELECT state_key FROM {config.CENTRAL_CH_DATABASE}.incidents FINAL "
        "WHERE cluster = {cluster:String} AND status IN ('active', 'acknowledged') "
        "FORMAT TSV"
    )
    try:
        resp = requests.post(
            f"{config.CENTRAL_CH_URL}/",
            params={"query": query, "param_cluster": config.CLUSTER_NAME},
            auth=(config.CENTRAL_CH_USER, config.CENTRAL_CH_PASSWORD),
            timeout=10,
        )
    except requests.RequestException:
        logger.warning("CH open-board read failed", exc_info=True)
        return None
    if resp.status_code != 200:
        logger.warning("CH open-board read failed: %s %s",
                       resp.status_code, resp.text[:200])
        return None
    return [line for line in resp.text.splitlines() if line]


def sync_resolved_to_central(store) -> int:
    """Close on the fleet board what the local store has already resolved.

    Every resolve pushes once, fire-and-forget: async_insert without waiting,
    a 10s timeout, no retry. A push lost to a blip leaves the incident "open"
    on the board for good — an OOM incident resolved locally still read
    active centrally three days later; the
    CLI resolve path never pushed at all. This compares the board with the
    local store and re-pushes the resolve for every key the store no longer
    has open. The local store is the source of truth; it never re-opens
    anything on the board. Returns how many keys it re-pushed.
    """
    if not config.CENTRAL_AGGREGATE:
        return 0
    keys = _central_open_keys()
    if not keys:
        return 0
    stale = []
    for key in keys:
        inc = store.get_incident(key)
        if inc is not None and inc.status == "resolved":
            stale.append(inc)
    if stale:
        push_incident_statuses(stale, "resolved", "sync")
        logger.info("Central sync: re-pushed %d resolve(s) the board missed: %s",
                    len(stale), ", ".join(i.state_key for i in stale[:10]))
    return len(stale)

"""SQLite-based incident store backend."""
import fnmatch
import hashlib
import json
import logging
import sqlite3
import time
import threading

from src import config
from src.engine.store import Incident

logger = logging.getLogger(__name__)

_SCHEMA = """
-- One row, written and rolled back by ping(): proves the store is writable.
CREATE TABLE IF NOT EXISTS store_health (
    id INTEGER PRIMARY KEY,
    checked_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    state_key TEXT NOT NULL UNIQUE,
    fingerprint TEXT NOT NULL,
    issue_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    namespace TEXT NOT NULL DEFAULT '',
    owner_ref TEXT NOT NULL DEFAULT '',
    first_seen_at REAL NOT NULL,
    last_seen_at REAL NOT NULL,
    -- Start of the CURRENT active cycle. Reset when the incident reopens
    -- after a resolved state, so MTTR on auto-resolve reports the duration
    -- of this flap, not the lifetime of the state_key (which can be months
    -- for recurring flappy incidents like public endpoints).
    active_since REAL NOT NULL DEFAULT 0,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    cooldown_until REAL,
    last_slack_ts TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS incident_occurrences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    seen_at REAL NOT NULL,
    context_hash TEXT NOT NULL,
    raw_context TEXT,
    analysis TEXT,
    analysis_json TEXT,
    analysis_error BOOLEAN DEFAULT FALSE,
    llm_model TEXT,
    tokens_in INTEGER,
    tokens_out INTEGER,
    cost_usd REAL,
    batch_status TEXT NOT NULL DEFAULT 'immediate',
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS context_store (
    hash TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS llm_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    called_at REAL NOT NULL,
    call_type TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    resource TEXT DEFAULT '',
    context_bytes INTEGER,
    section_bytes_json TEXT,
    sections_json TEXT,
    tokens_in INTEGER,
    tokens_out INTEGER,
    cached_tokens INTEGER DEFAULT 0,
    cost_usd REAL,
    latency_ms REAL,
    truncated BOOLEAN DEFAULT FALSE,
    truncation_notes TEXT,
    error BOOLEAN DEFAULT FALSE,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS daily_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    cluster TEXT NOT NULL,
    collector_data_json TEXT NOT NULL,
    overall_status TEXT,
    analysis_json TEXT,
    analysis_raw TEXT,
    parse_error BOOLEAN DEFAULT FALSE,
    llm_model TEXT,
    tokens_in INTEGER,
    tokens_out INTEGER,
    cost_usd REAL,
    latency_ms REAL,
    context_bytes INTEGER,
    truncated BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_incidents_fingerprint ON incidents(fingerprint);

CREATE TABLE IF NOT EXISTS suppressions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_type TEXT NOT NULL DEFAULT '',
    namespace TEXT NOT NULL DEFAULT '',
    name_pattern TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    expires_at REAL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS llm_debug_payloads (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    called_at     REAL NOT NULL,
    call_type     TEXT NOT NULL,
    resource      TEXT DEFAULT '',
    system_prompt TEXT NOT NULL,
    user_content  TEXT NOT NULL,
    response_text TEXT,
    created_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_llm_debug_called_at ON llm_debug_payloads(called_at);

CREATE TABLE IF NOT EXISTS scheduler_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS maintenance_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'manual',
    affected_nodes TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_maintenance_log_created ON maintenance_log(created_at);

-- Root-cause correlation markers: when a critical-service incident
-- (postgres OOM, redis down, etc.) fires, we record it here so dependent
-- alerts in the same namespace can show a "correlates with active
-- root" hint. Alerts are NOT suppressed — the cascade is useful signal
-- about which services need better dep handling. Cleared on the root's
-- auto-resolve or when expires_at passes, whichever is sooner.
CREATE TABLE IF NOT EXISTS active_root_causes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    namespace TEXT NOT NULL,
    root_fingerprint TEXT NOT NULL,
    root_state_key TEXT NOT NULL,
    root_incident_id INTEGER NOT NULL,
    started_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    UNIQUE(namespace, root_fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_root_causes_ns_exp
    ON active_root_causes(namespace, expires_at);

-- SLI breach state tracks ongoing SLO violations. A breach
-- must last `duration_seconds` before emitting a ScanResult; we track
-- (first_breach_at, last_seen_at, alerted) so subsequent scan ticks
-- know whether the duration threshold has been met and whether we've
-- already fired. Row is DELETED on recovery (metric back under
-- threshold) so next breach starts a fresh duration window.
CREATE TABLE IF NOT EXISTS sli_breach_state (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sli_name TEXT NOT NULL,
    labels_hash TEXT NOT NULL DEFAULT '',
    first_breach_at REAL NOT NULL,
    last_seen_at REAL NOT NULL,
    alerted INTEGER NOT NULL DEFAULT 0,
    current_value REAL,
    created_at REAL NOT NULL,
    UNIQUE(sli_name, labels_hash)
);
CREATE INDEX IF NOT EXISTS idx_sli_breach_alerted
    ON sli_breach_state(alerted);
CREATE INDEX IF NOT EXISTS idx_sli_breach_created
    ON sli_breach_state(created_at);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_owner_ref ON incidents(owner_ref);
CREATE INDEX IF NOT EXISTS idx_occurrences_incident ON incident_occurrences(incident_id);
CREATE INDEX IF NOT EXISTS idx_llm_calls_called_at ON llm_calls(called_at);
CREATE INDEX IF NOT EXISTS idx_daily_reports_created ON daily_reports(created_at);
"""


class SqliteStore:
    """SQLite backend implementing both Store and IncidentStore protocols."""

    def __init__(self, db_path: str | None = None):
        self._db_path = db_path or config.SQLITE_PATH
        self._local = threading.local()
        # Initialize schema on the creating thread
        self._init_schema()
        logger.info("SQLite store initialized: %s", self._db_path)

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local connection (sqlite3 connections are not thread-safe)."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            # busy_timeout: how long a writer waits for the write lock before
            # raising "database is locked". WAL gives us 1-writer/N-reader
            # concurrency, but the periodic maintenance loop takes the lock
            # for seconds at a time — full VACUUM rewrites the whole file with
            # an EXCLUSIVE lock, and the big cleanup DELETEs (orphan
            # context_store GC, per-incident occurrence pruning) hold the
            # write lock across full-table scans. At 5s, scanner threads
            # writing concurrently (set_status auto-resolve, etc.) lost the
            # race and threw — real bursts: 175 and 60 in 72h.
            # 30s comfortably outlasts maintenance on these monitoring-sized
            # DBs while staying well under the 300s scanner wait_for budget,
            # so a contended write stalls instead of failing.
            self._local.conn.execute("PRAGMA busy_timeout=30000")
            # This is a monitoring store, not a financial ledger. A crash
            # or power loss may cost us the last few hundred ms of alert
            # metadata (the source of truth is the cluster itself + the
            # central ClickHouse aggregator, both of which we re-derive
            # from on restart). Trade durability for throughput:
            #  - synchronous=NORMAL: fsync on WAL checkpoint only, not on
            #    every commit. Standard recommendation for WAL mode.
            #  - temp_store=MEMORY: per-connection temp tables / sorters
            #    live in RAM instead of hitting /data.
            #  - wal_autocheckpoint=1000 (default): already fine.
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn.execute("PRAGMA temp_store=MEMORY")
        return self._local.conn

    def ping(self) -> None:
        """Lightweight liveness check — raises if the DB is unreachable.

        Used by the /healthz handler so the kubelet can restart a pod whose
        store has wedged (stale RWO volume handle at startup, disk full or
        read-only remount mid-life). A fresh mode=rw connection never creates a
        missing file; it reads a real table and writes one row that it rolls
        back, so a read-only store fails here - SELECT 1 passes on both.
        """
        conn = sqlite3.connect(f"file:{self._db_path}?mode=rw", uri=True, timeout=5)
        try:
            conn.execute("SELECT 1 FROM incidents LIMIT 1").fetchone()
            # A real write, rolled back: BEGIN IMMEDIATE alone passes on a
            # read-only WAL database; an INSERT does not.
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("INSERT OR REPLACE INTO store_health (id, checked_at) VALUES (1, ?)", (time.time(),))
            conn.execute("ROLLBACK")
        finally:
            conn.close()

    def _init_schema(self):
        conn = self._get_conn()
        # Enable INCREMENTAL auto_vacuum BEFORE any table exists so
        # `PRAGMA incremental_vacuum` at cleanup time can reclaim free
        # pages (cheap, no full rewrite). Setting the pragma on a fresh
        # DB requires a subsequent VACUUM to commit the setting into the
        # db header — after that, it's persistent. On existing DBs with
        # tables already created the pragma is silently ignored and we
        # fall back to the weekly full VACUUM.
        has_tables = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
        ).fetchone()[0] > 0
        if not has_tables:
            conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
            conn.execute("VACUUM")
        conn.executescript(_SCHEMA)
        self._run_migrations(conn)
        conn.commit()

    def _run_migrations(self, conn: sqlite3.Connection):
        """Apply schema migrations that can't be expressed in CREATE IF NOT EXISTS."""
        # Add report_type column to daily_reports (added for weekly reports)
        try:
            conn.execute("SELECT report_type FROM daily_reports LIMIT 0")
        except sqlite3.OperationalError:
            conn.execute("ALTER TABLE daily_reports ADD COLUMN report_type TEXT DEFAULT 'daily'")
            logger.info("Migration: added report_type column to daily_reports")

        # Add cached_tokens column to llm_calls (Gemini context cache hit ratio)
        try:
            conn.execute("SELECT cached_tokens FROM llm_calls LIMIT 0")
        except sqlite3.OperationalError:
            conn.execute("ALTER TABLE llm_calls ADD COLUMN cached_tokens INTEGER DEFAULT 0")
            logger.info("Migration: added cached_tokens column to llm_calls")

        # Add batch_status column to incident_occurrences
        try:
            conn.execute("SELECT batch_status FROM incident_occurrences LIMIT 0")
        except sqlite3.OperationalError:
            conn.execute("ALTER TABLE incident_occurrences ADD COLUMN batch_status TEXT NOT NULL DEFAULT 'immediate'")
            logger.info("Migration: added batch_status column to incident_occurrences")

        # Add namespace column to incidents
        try:
            conn.execute("SELECT namespace FROM incidents LIMIT 0")
        except sqlite3.OperationalError:
            conn.execute("ALTER TABLE incidents ADD COLUMN namespace TEXT NOT NULL DEFAULT ''")
            logger.info("Migration: added namespace column to incidents")

        # Add active_since column to incidents (start of current active cycle).
        # Backfill with first_seen_at for existing rows so we have something
        # reasonable until the first reopen updates it.
        try:
            conn.execute("SELECT active_since FROM incidents LIMIT 0")
        except sqlite3.OperationalError:
            conn.execute("ALTER TABLE incidents ADD COLUMN active_since REAL NOT NULL DEFAULT 0")
            conn.execute("UPDATE incidents SET active_since = first_seen_at WHERE active_since = 0")
            logger.info("Migration: added active_since column to incidents (backfilled with first_seen_at)")

        # Add last_ai_mention_at column to incidents (Sprint: @ai cooldown).
        # Tracks the last time the @ai bot was mentioned for this incident.
        # Pipeline uses it to skip re-mentioning @ai on every re-fire of a
        # chronic incident — @ai wastes context re-analyzing known issues.
        # Default 0 means "never mentioned"; existing rows naturally qualify
        # for a mention on their next alert.
        try:
            conn.execute("SELECT last_ai_mention_at FROM incidents LIMIT 0")
        except sqlite3.OperationalError:
            conn.execute("ALTER TABLE incidents ADD COLUMN last_ai_mention_at REAL NOT NULL DEFAULT 0")
            logger.info("Migration: added last_ai_mention_at column to incidents")

        # Add resolved_by column to incidents. Records WHO closed an incident,
        # so the reopen path can tell "an operator fixed this and it came back"
        # from "a scanner closed something it never should have". The default is
        # deliberately the empty string, which the pipeline treats exactly as it
        # treats an operator resolve — an unmigrated or legacy row must not
        # silently start swallowing reopens.
        try:
            conn.execute("SELECT resolved_by FROM incidents LIMIT 0")
        except sqlite3.OperationalError:
            conn.execute("ALTER TABLE incidents ADD COLUMN resolved_by TEXT NOT NULL DEFAULT ''")
            logger.info("Migration: added resolved_by column to incidents")

    # --- Incident lifecycle ---

    def _row_to_incident(self, row: sqlite3.Row) -> Incident:
        return Incident(
            id=row["id"],
            state_key=row["state_key"],
            fingerprint=row["fingerprint"],
            issue_type=row["issue_type"],
            severity=row["severity"],
            namespace=row["namespace"] if "namespace" in row.keys() else "",
            owner_ref=row["owner_ref"],
            first_seen_at=row["first_seen_at"],
            last_seen_at=row["last_seen_at"],
            # active_since defaults to first_seen_at for rows that predate
            # the migration (backfilled there); new rows always write now().
            active_since=(row["active_since"] if "active_since" in row.keys()
                           and row["active_since"] else row["first_seen_at"]),
            occurrence_count=row["occurrence_count"],
            cooldown_until=row["cooldown_until"],
            last_slack_ts=row["last_slack_ts"] or "",
            status=row["status"],
            last_ai_mention_at=(row["last_ai_mention_at"]
                                 if "last_ai_mention_at" in row.keys()
                                 else 0.0),
            resolved_by=(row["resolved_by"] if "resolved_by" in row.keys()
                         else ""),
        )

    def get_incident(self, state_key: str) -> Incident | None:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM incidents WHERE state_key = ?", (state_key,)
        ).fetchone()
        return self._row_to_incident(row) if row else None

    def get_incident_by_id(self, incident_id: int) -> Incident | None:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        return self._row_to_incident(row) if row else None

    def is_fingerprint_known(self, fingerprint: str) -> bool:
        """Return True if any incident (active or resolved) shares this fingerprint."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT 1 FROM incidents WHERE fingerprint = ? LIMIT 1",
            (fingerprint,),
        ).fetchone()
        return row is not None

    def create_incident(self, *, state_key: str, fingerprint: str, issue_type: str,
                        severity: str, namespace: str, owner_ref: str) -> Incident:
        """Create an incident, race-safe.

        state_key has a UNIQUE constraint, so two concurrent writers (e.g.
        the pod and endpoint scanners both reacting to the same outage)
        could collide: both call `get_incident()` → None, both call
        `create_incident()`, the second one normally raises IntegrityError
        and crashes its scanner. Catch that case and return the row the
        winner inserted instead.
        """
        now = time.time()
        conn = self._get_conn()
        try:
            cur = conn.execute(
                """INSERT INTO incidents
                   (state_key, fingerprint, issue_type, severity, namespace, owner_ref,
                    first_seen_at, last_seen_at, active_since, occurrence_count,
                    cooldown_until, last_slack_ts, status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, '', 'active', ?, ?)""",
                (state_key, fingerprint, issue_type, severity, namespace, owner_ref,
                 now, now, now, now, now),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            # Another writer won the race. Return their row so the caller
            # works with consistent state.
            conn.rollback()
            existing = self.get_incident(state_key)
            if existing is None:
                # Truly unexpected — UNIQUE failed but the row isn't there.
                # Re-raise so the caller doesn't silently lose the alert.
                raise
            logger.debug("create_incident race for %s — returning existing row #%d",
                         state_key, existing.id)
            return existing
        row_id: int = cur.lastrowid  # type: ignore[assignment]  # always set after INSERT
        return Incident(
            id=row_id,
            state_key=state_key,
            fingerprint=fingerprint,
            issue_type=issue_type,
            severity=severity,
            owner_ref=owner_ref,
            first_seen_at=now,
            last_seen_at=now,
            active_since=now,
            occurrence_count=0,
            cooldown_until=None,
            last_slack_ts="",
            status="active",
            namespace=namespace,
        )

    def record_occurrence(self, incident_id: int, *, context_hash: str,
                          raw_context: str | None = None, analysis: str | None = None,
                          analysis_json: str | None = None, analysis_error: bool = False,
                          llm_model: str | None = None, tokens_in: int | None = None,
                          tokens_out: int | None = None, cost_usd: float | None = None,
                          batch_status: str = "immediate") -> int | None:
        # `raw_context` is accepted for backward compatibility but intentionally
        # NOT inserted inline anymore — callers already pass the same payload to
        # `store_context(raw_context)` which places it in context_store keyed by
        # hash (deduplicated across occurrences). Storing it twice doubled the
        # SQLite size for no benefit; readers JOIN via context_hash instead.
        _ = raw_context  # silence "unused" intent — kept in signature
        now = time.time()
        conn = self._get_conn()
        cur = conn.execute(
            """INSERT INTO incident_occurrences
               (incident_id, seen_at, context_hash, raw_context, analysis,
                analysis_json, analysis_error, llm_model, tokens_in, tokens_out,
                cost_usd, batch_status, created_at)
               VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (incident_id, now, context_hash, analysis,
             analysis_json, analysis_error, llm_model, tokens_in, tokens_out,
             cost_usd, batch_status, now),
        )
        # Bump occurrence count + last_seen_at
        conn.execute(
            """UPDATE incidents
               SET occurrence_count = occurrence_count + 1,
                   last_seen_at = ?, updated_at = ?
               WHERE id = ?""",
            (now, now, incident_id),
        )
        conn.commit()
        # Returned so callers can address exactly this row later — the Slack
        # decision is made after the insert, and re-finding the row by
        # "newest for this incident" races other writers.
        return cur.lastrowid

    def get_pending_batch_occurrences(self, limit: int = 200) -> list[dict]:
        """Return occurrences awaiting batch processing.

        Returns both 'pending' rows (new, needs LLM + Slack) and 'analyzed'
        rows (LLM done, Slack post failed, needs retry). The batcher
        distinguishes them by `batch_status` so it can skip the LLM call on
        retry candidates.
        """
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT o.*, i.state_key, i.issue_type, i.severity as original_severity,
                       i.owner_ref, i.namespace
                FROM incident_occurrences o
                JOIN incidents i ON i.id = o.incident_id
                WHERE o.batch_status IN ('pending', 'analyzed')
                ORDER BY o.seen_at ASC
                LIMIT ?""",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def mark_occurrence_pending(self, occurrence_id: int) -> None:
        """Flag one occurrence for the hourly digest, by id.

        The row is written before the Slack decision is made, so its status is
        corrected afterwards rather than restructuring that flow. Addressed by
        id rather than "newest for this incident": scanners run in an executor
        pool and the event handler writes too, so two occurrences of the same
        incident can be inserted between the write and this call, and the
        newest-row heuristic would then flag the wrong one.
        """
        if occurrence_id is None:
            return
        conn = self._get_conn()
        conn.execute(
            "UPDATE incident_occurrences SET batch_status = 'pending' WHERE id = ?",
            (occurrence_id,),
        )
        conn.commit()

    def mark_occurrences_analyzed(self, occurrence_ids: list[int], *,
                                  analysis: str | None = None,
                                  analysis_json: str | None = None,
                                  model: str | None = None,
                                  tokens_in: int | None = None,
                                  tokens_out: int | None = None,
                                  cost_usd: float | None = None) -> None:
        """Persist the LLM analysis result and move rows to 'analyzed'.

        This is phase 1 of the two-phase batch commit. The rows remain in
        `get_pending_batch_occurrences` as retry candidates until they are
        successfully notified (phase 2 via `mark_occurrences_notified`).
        """
        if not occurrence_ids:
            return
        conn = self._get_conn()
        rows = [
            (analysis, analysis_json, model, tokens_in, tokens_out, cost_usd, oid)
            for oid in occurrence_ids
        ]
        conn.executemany(
            """UPDATE incident_occurrences
               SET batch_status = 'analyzed',
                   analysis = ?,
                   analysis_json = ?,
                   llm_model = ?,
                   tokens_in = ?,
                   tokens_out = ?,
                   cost_usd = ?
               WHERE id = ?""",
            rows,
        )
        conn.commit()

    def mark_occurrences_notified(self, occurrence_ids: list[int]) -> None:
        """Phase 2 of the two-phase batch commit: flip 'analyzed' rows to
        'processed' after a successful Slack post."""
        if not occurrence_ids:
            return
        conn = self._get_conn()
        conn.executemany(
            "UPDATE incident_occurrences SET batch_status = 'processed' WHERE id = ?",
            [(oid,) for oid in occurrence_ids],
        )
        conn.commit()

    def mark_occurrences_skipped(self, occurrence_ids: list[int]) -> None:
        """Mark rows as 'skipped' so they stop being re-fetched by
        `get_pending_batch_occurrences`. Used when a row cannot be batched
        (e.g. missing namespace, malformed state)."""
        if not occurrence_ids:
            return
        conn = self._get_conn()
        conn.executemany(
            "UPDATE incident_occurrences SET batch_status = 'skipped' WHERE id = ?",
            [(oid,) for oid in occurrence_ids],
        )
        conn.commit()

    def mark_occurrences_processed(self, occurrence_ids: list[int],
                                   analysis: str | None = None,
                                   analysis_json: str | None = None,
                                   model: str | None = None,
                                   tokens_in: int | None = None,
                                   tokens_out: int | None = None,
                                   cost_usd: float | None = None) -> None:
        """Backward-compat shortcut: analyze + notify in one call.

        Prefer the two-phase path (`mark_occurrences_analyzed` +
        `mark_occurrences_notified`) in new code so that Slack post failures
        leave rows as retry candidates. Kept so existing tests keep
        working without churn.
        """
        self.mark_occurrences_analyzed(
            occurrence_ids, analysis=analysis, analysis_json=analysis_json,
            model=model, tokens_in=tokens_in, tokens_out=tokens_out,
            cost_usd=cost_usd,
        )
        self.mark_occurrences_notified(occurrence_ids)

    def bump_incident(self, incident_id: int, cooldown_until: float | None = None) -> None:
        now = time.time()
        conn = self._get_conn()
        conn.execute(
            """UPDATE incidents SET cooldown_until = ?, updated_at = ? WHERE id = ?""",
            (cooldown_until, now, incident_id),
        )
        conn.commit()

    def set_last_slack_ts(self, incident_id: int, ts: str) -> None:
        """Stash the Slack message ts of the first-fire post so recurring
        alerts for the same incident can thread_ts-reply to it. Called
        from the pipeline right after ``post_alert`` returns a non-empty
        ts (i.e., the bot API path succeeded)."""
        if not ts:
            return
        conn = self._get_conn()
        conn.execute(
            "UPDATE incidents SET last_slack_ts = ?, updated_at = ? WHERE id = ?",
            (ts, time.time(), incident_id),
        )
        conn.commit()

    def clear_last_slack_ts(self, incident_id: int) -> None:
        """Clear the stored Slack ts for an incident. Called on reopen
        (status: resolved → active) so the fresh active cycle posts a
        new top-level message rather than threading into a stale one."""
        conn = self._get_conn()
        conn.execute(
            "UPDATE incidents SET last_slack_ts = '', updated_at = ? WHERE id = ?",
            (time.time(), incident_id),
        )
        conn.commit()

    def bump_ai_mention(self, incident_id: int) -> None:
        """Record that @ai was just mentioned for this incident. Used by
        the pipeline's AI_MENTION_REMINDER_HOURS cooldown to suppress
        re-mentions on chronic re-fires. Called only when the alert
        actually carried the mention (skipped mentions don't bump)."""
        conn = self._get_conn()
        conn.execute(
            "UPDATE incidents SET last_ai_mention_at = ?, updated_at = ? WHERE id = ?",
            (time.time(), time.time(), incident_id),
        )
        conn.commit()

    # --- Status management ---

    def set_status(self, incident_id: int, status: str, *,
                    clear_cooldown: bool = False,
                    reset_active_since: bool = False) -> bool:
        """Update incident status. Returns True when a row was actually
        modified, False when the incident_id does not exist (HTTP / CLI
        callers can surface 404 / "not found" instead of pretending the
        update succeeded).

        When ``reset_active_since`` is True the active_since timestamp is
        set to now so the NEXT auto-resolve reports the duration of this
        flap, not the lifetime of the state_key. Use when reopening a
        resolved incident (resolved → active transition).

        When ``clear_cooldown`` is True the cooldown_until is reset to 0
        so the owner-level cooldown guard no longer blocks new alerts
        for this state_key. Use this for manual operator resolves where
        the intent is "give me a fresh alert next time"; auto-resolve
        keeps the existing cooldown so we don't immediately re-alert on
        a flapping problem.
        """
        now = time.time()
        conn = self._get_conn()
        # Explicit, fully-parameterized UPDATE per flag combination. Previously
        # built via f-string join over a fixed set of hard-coded fragments;
        # switched to four literal branches to satisfy the "no SQL string
        # interpolation, ever" house rule (CLAUDE.md) even though the joined
        # fragments held no user input.
        if clear_cooldown and reset_active_since:
            cur = conn.execute(
                "UPDATE incidents SET status = ?, updated_at = ?, "
                "cooldown_until = 0, active_since = ? WHERE id = ?",
                (status, now, now, incident_id),
            )
        elif clear_cooldown:
            cur = conn.execute(
                "UPDATE incidents SET status = ?, updated_at = ?, "
                "cooldown_until = 0 WHERE id = ?",
                (status, now, incident_id),
            )
        elif reset_active_since:
            cur = conn.execute(
                "UPDATE incidents SET status = ?, updated_at = ?, "
                "active_since = ? WHERE id = ?",
                (status, now, now, incident_id),
            )
        else:
            cur = conn.execute(
                "UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?",
                (status, now, incident_id),
            )
        conn.commit()
        return cur.rowcount > 0

    def touch_incident(self, incident_id: int) -> None:
        """Mark an incident as still observed, without recording an occurrence.

        The stale reaper in cleanup() closes active incidents whose last_seen_at
        is over 7 days old, reasoning that "a scanner would have re-detected
        them". That holds only for incidents a scanner can re-detect. An
        event-driven one whose source has gone quiet is never re-detected and
        gets closed on an assumption that does not apply to it.

        This is the counter-signal: proof that the problem is still there,
        recorded without inflating occurrence_count or waking anybody.
        """
        now = time.time()
        conn = self._get_conn()
        conn.execute(
            "UPDATE incidents SET last_seen_at = ?, updated_at = ? WHERE id = ?",
            (now, now, incident_id),
        )
        conn.commit()

    def set_resolved_by(self, incident_id: int, who: str) -> None:
        """Record who closed this incident: "operator", "auto" or "sweep".

        Kept out of set_status rather than added as a fifth flag: that method
        already spells out four literal UPDATE branches to satisfy the
        no-SQL-interpolation rule, and another dimension would double them.
        """
        conn = self._get_conn()
        conn.execute(
            "UPDATE incidents SET resolved_by = ? WHERE id = ?",
            (who, incident_id),
        )
        conn.commit()

    def set_severity(self, incident_id: int, severity: str) -> None:
        """Update incident severity (e.g. following LLM re-evaluation)."""
        now = time.time()
        conn = self._get_conn()
        conn.execute(
            "UPDATE incidents SET severity = ?, updated_at = ? WHERE id = ?",
            (severity, now, incident_id),
        )
        conn.commit()

    def list_incidents(self, status: str | None = "active") -> list[Incident]:
        conn = self._get_conn()
        if status:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE status = ? ORDER BY last_seen_at DESC",
                (status,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM incidents ORDER BY last_seen_at DESC"
            ).fetchall()
        return [self._row_to_incident(r) for r in rows]

    def get_occurrences(self, incident_id: int) -> list[dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM incident_occurrences WHERE incident_id = ? ORDER BY seen_at DESC",
            (incident_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # --- Recent incidents for daily report ---

    def get_recent_incidents(self, hours: int = 24) -> list[dict]:
        """Return incidents with activity in the last `hours`, capped at 50."""
        cutoff = time.time() - (hours * 3600)
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT state_key, issue_type, severity, owner_ref,
                      first_seen_at, last_seen_at, occurrence_count, status
               FROM incidents
               WHERE last_seen_at >= ?
               ORDER BY CASE severity
                   WHEN 'critical' THEN 0
                   WHEN 'warning'  THEN 1
                   ELSE 2
               END, last_seen_at DESC
               LIMIT 50""",
            (cutoff,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_recent_prod_incidents(self, hours: int = 24,
                                  exclude_namespaces: set[str] | None = None,
                                  ) -> list[dict]:
        """Return incidents from production only — excluding any incident
        whose state_key references one of `exclude_namespaces`.

        Used by the daily/weekly reports so non-prod noise never reaches the
        LLM. State keys follow `<Type>:<ns>/<name>…` (or `EndpointBatch:<ns>`);
        both shapes are matched with `:{ns}/%` + `:{ns}` NOT LIKE filters.
        """
        cutoff = time.time() - (hours * 3600)
        conn = self._get_conn()
        params: list = [cutoff]
        query = ("SELECT state_key, issue_type, severity, owner_ref, "
                 "first_seen_at, last_seen_at, occurrence_count, status "
                 "FROM incidents "
                 "WHERE last_seen_at >= ?")
        if exclude_namespaces:
            clauses = []
            for ns in sorted(exclude_namespaces):
                clauses.append("state_key NOT LIKE ?")
                params.append(f"%:{ns}/%")
                clauses.append("state_key NOT LIKE ?")
                params.append(f"%:{ns}")
            query += " AND " + " AND ".join(clauses)

        query += (" ORDER BY CASE severity "
                  "WHEN 'critical' THEN 0 "
                  "WHEN 'warning'  THEN 1 "
                  "ELSE 2 "
                  "END, last_seen_at DESC "
                  "LIMIT 50")
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_active_incidents_by_prefix(self, prefixes: list[str]) -> list[Incident]:
        """Return active incidents whose state_key starts with any of the given prefixes."""
        if not prefixes:
            return []
        conn = self._get_conn()
        conditions = " OR ".join("state_key LIKE ?" for _ in prefixes)
        params = [f"{p}%" for p in prefixes]
        rows = conn.execute(
            f"SELECT * FROM incidents WHERE status = 'active' AND ({conditions})",
            params,
        ).fetchall()
        return [self._row_to_incident(r) for r in rows]

    # --- Context dedup ---

    def store_context(self, content: str) -> str:
        h = hashlib.sha256(content.encode()).hexdigest()
        conn = self._get_conn()
        conn.execute(
            "INSERT OR IGNORE INTO context_store (hash, content, created_at) VALUES (?, ?, ?)",
            (h, content, time.time()),
        )
        conn.commit()
        return h

    def get_context(self, hash: str) -> str | None:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT content FROM context_store WHERE hash = ?", (hash,)
        ).fetchone()
        return row["content"] if row else None

    def is_owner_in_cooldown(self, owner_key: str) -> bool:
        """Check if ANY incident for this owner is currently in cooldown.

        Includes both active AND resolved incidents — a recently resolved
        incident with unexpired cooldown should still block new alerts for
        the same owner to prevent re-alerting on a problem that was just
        fixed. Without this, resolved incidents with active cooldown let
        new events through immediately, causing 4-5× LLM calls for the
        same deployment that was already addressed.
        """
        now = time.time()
        conn = self._get_conn()
        row = conn.execute(
            "SELECT 1 FROM incidents WHERE state_key LIKE ? "
            "AND status IN ('active', 'resolved') AND cooldown_until > ? LIMIT 1",
            (f"{owner_key}:%", now),
        ).fetchone()
        return row is not None

    def cleanup(self, max_age_hours: int | None = None) -> list[Incident]:
        """Periodic maintenance: delete old rows + compact free pages.

        Resolved incidents older than ``max_age_hours`` are hard-deleted,
        along with their occurrences and any orphan context_store rows.
        Other tables honour their own retention (``cleanup_llm_calls``,
        ``cleanup_llm_debug``, ``cleanup_daily_reports``). Ends with a WAL
        checkpoint + incremental_vacuum so the on-disk file doesn't grow
        unbounded between full VACUUMs.

        Returns the incidents closed by the stale reaper so the caller can
        mirror the resolve to the central board; the store itself stays free
        of transport concerns.
        """
        if max_age_hours is None:
            max_age_hours = config.DB_RETENTION_DAYS * 24
        cutoff = time.time() - (max_age_hours * 3600)
        conn = self._get_conn()
        # Get IDs of old resolved incidents
        old_ids = conn.execute(
            "SELECT id FROM incidents WHERE status = 'resolved' AND updated_at < ?",
            (cutoff,),
        ).fetchall()
        if old_ids:
            ids = [(r["id"],) for r in old_ids]
            conn.executemany(
                "DELETE FROM incident_occurrences WHERE incident_id = ?", ids
            )
            conn.executemany(
                "DELETE FROM incidents WHERE id = ?", ids
            )
            # Clean orphaned contexts
            conn.execute("""
                DELETE FROM context_store WHERE hash NOT IN (
                    SELECT DISTINCT context_hash FROM incident_occurrences
                )
            """)
            conn.commit()
            logger.info("SQLite cleanup: removed %d resolved incidents older than %dh", len(ids), max_age_hours)
        # Stale reaper: active incidents with last_seen > 7 days are clearly
        # not current problems (scanner would have re-detected them). Resolve
        # them so they don't sit as false-positive active incidents forever.
        #
        # One conditional UPDATE rather than SELECT-then-UPDATE-by-id: the
        # predicate has to be evaluated at write time. touch_incident runs from
        # the reconcile scanner on a different thread, and between a SELECT that
        # saw an incident as stale and the UPDATE that closes it, that touch can
        # land — resolving an incident we had just confirmed is still failing,
        # and which nothing will raise again.
        #
        # RETURNING keeps that single-statement property while still naming the
        # rows that were closed, so the caller can mirror them to the central
        # board. Without it this path resolved locally and left the central board
        # showing the incident as active forever; resolved_by is stamped for the same reason the other
        # sweeps stamp theirs — an unattributed resolve is indistinguishable
        # from a legacy row.
        stale_cutoff = time.time() - (7 * 86400)
        cur = conn.execute(
            "UPDATE incidents SET status = 'resolved', updated_at = ?, "
            "resolved_by = 'reaper' "
            "WHERE status = 'active' AND last_seen_at < ? "
            "RETURNING *",
            (time.time(), stale_cutoff),
        )
        reaped = [self._row_to_incident(r) for r in cur.fetchall()]
        conn.commit()
        if reaped:
            logger.info("Stale reaper: resolved %d active incidents older than 7d", len(reaped))
        self.cleanup_suppressions()
        self.cleanup_expired_root_causes()
        self.cleanup_daily_reports()
        self.cleanup_llm_calls(max_age_days=config.LLM_CALLS_RETENTION_DAYS)
        self.cleanup_llm_debug(max_age_days=config.LLM_DEBUG_RETENTION_DAYS)
        self.cleanup_sli_breaches(max_age_days=config.DB_RETENTION_DAYS)
        # Trim per-incident occurrence history. A single flappy incident
        # (e.g. a critical_endpoint incident at 892 occurrences) used to grow
        # its occurrences row by row with no cap. Keep the last N (oldest
        # rows are mostly duplicate context hashes already in context_store).
        self.cleanup_occurrences(keep_per_incident=config.OCCURRENCE_HISTORY_CAP)
        # WAL checkpoint + incremental vacuum so the on-disk footprint stays
        # bounded between full VACUUMs. Without this, a long-lived process
        # can accumulate a multi-hundred-MB WAL (real incident: a
        # k8s-ai-monitor filled its 1Gi PVC with a 426M WAL) and freelist
        # pages never get reclaimed.
        self._post_cleanup_compact()
        return reaped

    def _post_cleanup_compact(self) -> None:
        """Truncate the WAL and reclaim INCREMENTAL auto-vacuum free pages.

        Cheap (no full rewrite, minimal locking). incremental_vacuum is a
        no-op when auto_vacuum is off — legacy DBs rely on the weekly
        ``full_vacuum()`` pass for fragmentation cleanup.
        """
        conn = self._get_conn()
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        except sqlite3.Error:
            logger.warning("wal_checkpoint(TRUNCATE) failed", exc_info=True)
        try:
            conn.execute("PRAGMA incremental_vacuum").fetchall()
        except sqlite3.Error:
            logger.warning("incremental_vacuum failed", exc_info=True)

    def full_vacuum(self) -> None:
        """Run a full ``VACUUM`` to compact the DB file.

        Heavier than ``_post_cleanup_compact`` — rewrites the whole file —
        so this is scheduled separately (weekly by default). Also the only
        way to reclaim free pages on DBs created before auto_vacuum was
        enabled. Needs up to DB-size free disk because VACUUM writes to a
        temp copy first; callers must ensure headroom exists.
        """
        conn = self._get_conn()
        try:
            conn.execute("VACUUM")
            logger.info("SQLite full VACUUM complete")
        except sqlite3.Error:
            logger.warning("full VACUUM failed", exc_info=True)

    def cleanup_occurrences(self, keep_per_incident: int) -> None:
        """Delete all but the newest `keep_per_incident` rows per incident.

        Also garbage-collects `context_store` rows no longer referenced by
        any remaining occurrence — occurrences hold the only live pointer
        to a context hash, so pruning them without GC would leak the
        deduplicated bodies indefinitely.
        """
        if keep_per_incident <= 0:
            return
        conn = self._get_conn()
        cur = conn.execute(
            # Window function: rank newest-first per incident, delete rank > N.
            "DELETE FROM incident_occurrences WHERE id IN ("
            "  SELECT id FROM ("
            "    SELECT id, ROW_NUMBER() OVER ("
            "      PARTITION BY incident_id ORDER BY seen_at DESC"
            "    ) AS rn FROM incident_occurrences"
            "  ) WHERE rn > ?"
            ")",
            (keep_per_incident,),
        )
        pruned_occurrences = cur.rowcount
        # GC orphaned context blobs on the same connection so both prunes
        # land in one transaction.
        ctx_cur = conn.execute(
            "DELETE FROM context_store WHERE NOT EXISTS ("
            "  SELECT 1 FROM incident_occurrences io "
            "  WHERE io.context_hash = context_store.hash"
            ")"
        )
        pruned_contexts = ctx_cur.rowcount
        conn.commit()
        if pruned_occurrences > 0 or pruned_contexts > 0:
            logger.info(
                "Occurrence retention: pruned %d occurrences past %d-per-incident cap, "
                "%d orphaned context_store rows",
                pruned_occurrences, keep_per_incident, pruned_contexts,
            )

    def read_all(self) -> dict:
        """Return state summary for /state endpoint."""
        incidents = self.list_incidents(status=None)
        seen = {}
        for inc in incidents:
            seen[inc.state_key] = {
                "ts": inc.last_seen_at,
                "count": inc.occurrence_count,
                "status": inc.status,
                "severity": inc.severity,
            }
        return {"seen": seen}

    # --- Suppressions ---

    def create_suppression(self, *, resource_type: str = "", namespace: str = "",
                           name_pattern: str = "", reason: str = "",
                           expires_at: float | None = None) -> int:
        now = time.time()
        conn = self._get_conn()
        cur = conn.execute(
            """INSERT INTO suppressions
               (resource_type, namespace, name_pattern, reason, expires_at, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (resource_type, namespace, name_pattern, reason, expires_at, now, now),
        )
        conn.commit()
        return cur.lastrowid  # type: ignore[return-value]  # always set after INSERT

    def list_suppressions(self) -> list[dict]:
        """Return active, non-expired suppressions."""
        now = time.time()
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM suppressions WHERE expires_at IS NULL OR expires_at > ?",
            (now,),
        ).fetchall()
        return [dict(r) for r in rows]

    def delete_suppression(self, suppression_id: int) -> bool:
        conn = self._get_conn()
        cur = conn.execute("DELETE FROM suppressions WHERE id = ?", (suppression_id,))
        conn.commit()
        return cur.rowcount > 0

    # --- Maintenance mode ---

    def is_maintenance_active(self) -> bool:
        """Check if a maintenance window is currently active."""
        now = time.time()
        conn = self._get_conn()
        row = conn.execute(
            "SELECT 1 FROM suppressions WHERE resource_type = '__maintenance__' "
            "AND (expires_at IS NULL OR expires_at > ?)", (now,),
        ).fetchone()
        return row is not None

    def get_maintenance_window(self) -> dict | None:
        """Return the active maintenance window, or None."""
        now = time.time()
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM suppressions WHERE resource_type = '__maintenance__' "
            "AND (expires_at IS NULL OR expires_at > ?) ORDER BY created_at DESC LIMIT 1", (now,),
        ).fetchone()
        return dict(row) if row else None

    def activate_auto_maintenance(self, reason: str, duration_hours: float) -> int | None:
        """Activate auto-detected maintenance mode. Returns suppression ID, or None if already active."""
        if self.is_maintenance_active():
            return None
        expires_at = time.time() + duration_hours * 3600
        return self.create_suppression(
            resource_type="__maintenance__",
            name_pattern="auto:gke-node-maintenance",
            reason=reason,
            expires_at=expires_at,
        )

    def end_maintenance(self) -> int:
        """End all active maintenance windows. Returns number of rows deleted."""
        conn = self._get_conn()
        cur = conn.execute("DELETE FROM suppressions WHERE resource_type = '__maintenance__'")
        conn.commit()
        return cur.rowcount

    def log_maintenance_event(self, event_type: str, reason: str,
                              source: str = "manual",
                              affected_nodes: list[str] | None = None) -> int:
        """Log a maintenance activation/deactivation event for report history."""
        now = time.time()
        nodes_str = ",".join(affected_nodes) if affected_nodes else ""
        conn = self._get_conn()
        cur = conn.execute(
            """INSERT INTO maintenance_log
               (event_type, reason, source, affected_nodes, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (event_type, reason, source, nodes_str, now),
        )
        conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def get_maintenance_events(self, hours: int = 24) -> list[dict]:
        """Return maintenance events within the last `hours`."""
        cutoff = time.time() - (hours * 3600)
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM maintenance_log WHERE created_at >= ? ORDER BY created_at DESC",
            (cutoff,),
        ).fetchall()
        return [dict(r) for r in rows]

    def is_suppressed(self, state_key: str, namespace: str, issue_type: str) -> bool:
        """Check if a result matches any active suppression rule."""
        for s in self.list_suppressions():
            if s["resource_type"] and s["resource_type"] != issue_type:
                continue
            if s["namespace"] and s["namespace"] != namespace:
                continue
            if s["name_pattern"] and not fnmatch.fnmatch(state_key, s["name_pattern"]):
                continue
            return True
        return False

    def cleanup_suppressions(self) -> None:
        """Delete expired suppressions."""
        now = time.time()
        conn = self._get_conn()
        cur = conn.execute(
            "DELETE FROM suppressions WHERE expires_at IS NOT NULL AND expires_at <= ?",
            (now,),
        )
        conn.commit()
        if cur.rowcount:
            logger.info("Suppression cleanup: removed %d expired entries", cur.rowcount)

    # --- Root-cause correlation markers ---

    def record_root_cause(
        self, *, namespace: str, root_fingerprint: str,
        root_state_key: str, root_incident_id: int,
        ttl_seconds: float,
    ) -> None:
        """Register a critical-service incident as the active root-cause
        marker for its namespace. Dependent alerts within ``ttl_seconds``
        gain a correlation hint that points at this root, but they
        STILL post normally — the cascade is deliberately visible so
        operators can see which services are fragile to dep outages.
        """
        if ttl_seconds <= 0:
            return
        now = time.time()
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO active_root_causes ("
            "  namespace, root_fingerprint, root_state_key, root_incident_id,"
            "  started_at, expires_at"
            ") VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(namespace, root_fingerprint) DO UPDATE SET "
            # Refresh the full payload on re-record so the correlation
            # hint reports the current started_at ("fired 3m ago") and
            # the latest state_key / incident_id rather than stale
            # values from an earlier re-fire of the same fingerprint.
            "  started_at = excluded.started_at, "
            "  expires_at = excluded.expires_at, "
            "  root_state_key = excluded.root_state_key, "
            "  root_incident_id = excluded.root_incident_id",
            (namespace, root_fingerprint, root_state_key, root_incident_id,
             now, now + ttl_seconds),
        )
        conn.commit()

    def get_active_root_cause(self, namespace: str) -> dict | None:
        """Return the most recent non-expired root-cause marker for a
        namespace, or None.
        """
        if not namespace:
            return None
        conn = self._get_conn()
        row = conn.execute(
            "SELECT namespace, root_fingerprint, root_state_key, "
            "       root_incident_id, started_at, expires_at "
            "FROM active_root_causes "
            "WHERE namespace = ? AND expires_at > ? "
            "ORDER BY started_at DESC LIMIT 1",
            (namespace, time.time()),
        ).fetchone()
        if not row:
            return None
        return {
            "namespace": row["namespace"],
            "root_fingerprint": row["root_fingerprint"],
            "root_state_key": row["root_state_key"],
            "root_incident_id": row["root_incident_id"],
            "started_at": row["started_at"],
            "expires_at": row["expires_at"],
        }

    def clear_root_cause(self, namespace: str, root_fingerprint: str) -> None:
        """Remove a specific root-cause marker (e.g. on auto-resolve)."""
        conn = self._get_conn()
        conn.execute(
            "DELETE FROM active_root_causes "
            "WHERE namespace = ? AND root_fingerprint = ?",
            (namespace, root_fingerprint),
        )
        conn.commit()

    def cleanup_expired_root_causes(self) -> None:
        """Drop expired rows. Called from the periodic cleanup loop."""
        conn = self._get_conn()
        cur = conn.execute(
            "DELETE FROM active_root_causes WHERE expires_at <= ?",
            (time.time(),),
        )
        conn.commit()
        if cur.rowcount:
            logger.debug(
                "Root-cause cleanup: removed %d expired rows",
                cur.rowcount,
            )

    # --- SLI breach state ---

    def record_sli_breach(self, sli_name: str, labels_hash: str,
                          current_value: float | None) -> dict:
        """Record/refresh a breach row. Returns the current state as dict
        with keys: first_breach_at, last_seen_at, alerted, current_value.

        Idempotent: first call INSERTs with `first_breach_at=now`,
        subsequent calls only UPDATE `last_seen_at` + `current_value` so
        the duration window is preserved.
        """
        now = time.time()
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO sli_breach_state
               (sli_name, labels_hash, first_breach_at, last_seen_at,
                alerted, current_value, created_at)
               VALUES (?, ?, ?, ?, 0, ?, ?)
               ON CONFLICT(sli_name, labels_hash) DO UPDATE SET
                   last_seen_at = excluded.last_seen_at,
                   current_value = excluded.current_value""",
            (sli_name, labels_hash, now, now, current_value, now),
        )
        conn.commit()
        row = conn.execute(
            """SELECT first_breach_at, last_seen_at, alerted, current_value
               FROM sli_breach_state
               WHERE sli_name = ? AND labels_hash = ?""",
            (sli_name, labels_hash),
        ).fetchone()
        return dict(row) if row else {
            "first_breach_at": now, "last_seen_at": now,
            "alerted": 0, "current_value": current_value,
        }

    def clear_sli_breach(self, sli_name: str, labels_hash: str) -> None:
        """Delete the breach row — metric is back under threshold. Next
        breach starts a fresh duration window."""
        conn = self._get_conn()
        conn.execute(
            "DELETE FROM sli_breach_state WHERE sli_name = ? AND labels_hash = ?",
            (sli_name, labels_hash),
        )
        conn.commit()

    def get_sli_breach(self, sli_name: str, labels_hash: str) -> dict | None:
        conn = self._get_conn()
        row = conn.execute(
            """SELECT first_breach_at, last_seen_at, alerted, current_value
               FROM sli_breach_state
               WHERE sli_name = ? AND labels_hash = ?""",
            (sli_name, labels_hash),
        ).fetchone()
        return dict(row) if row else None

    def mark_sli_alerted(self, sli_name: str, labels_hash: str) -> None:
        """Flip alerted=1 after emitting a ScanResult for this breach.
        Prevents re-emission on subsequent scan ticks while breach is
        sustained."""
        conn = self._get_conn()
        conn.execute(
            """UPDATE sli_breach_state SET alerted = 1
               WHERE sli_name = ? AND labels_hash = ?""",
            (sli_name, labels_hash),
        )
        conn.commit()

    def cleanup_sli_breaches(self, max_age_days: int = 30) -> int:
        """Drop stale breach rows not re-seen within the retention window.

        Filters on `last_seen_at` rather than `created_at` so a chronic
        breach that's still being observed (scanner updates last_seen_at
        every tick via record_sli_breach's ON CONFLICT DO UPDATE) is NOT
        deleted just because it first appeared 30+ days ago. Deletion
        only kicks in when the scanner hasn't seen the breach (clear or
        never re-checked) for the retention window — acts as a garbage
        collector for rows that somehow escaped clear_sli_breach().
        """
        cutoff = time.time() - (max_age_days * 86400)
        conn = self._get_conn()
        cur = conn.execute(
            "DELETE FROM sli_breach_state WHERE last_seen_at < ?",
            (cutoff,),
        )
        conn.commit()
        return cur.rowcount

    # --- LLM usage reporting ---

    def get_llm_usage(self, hours: int = 24) -> list[dict]:
        """Return all LLM calls within the last `hours`."""
        cutoff = time.time() - (hours * 3600)
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM llm_calls WHERE called_at >= ? ORDER BY called_at DESC",
            (cutoff,),
        ).fetchall()
        result = []
        for r in rows:
            entry = dict(r)
            # Parse JSON fields for the API response
            try:
                entry["section_bytes"] = json.loads(entry.pop("section_bytes_json", "{}") or "{}")
            except (json.JSONDecodeError, TypeError):
                entry["section_bytes"] = {}
            try:
                entry["sections"] = json.loads(entry.pop("sections_json", "[]") or "[]")
            except (json.JSONDecodeError, TypeError):
                entry["sections"] = []
            result.append(entry)
        return result

    # --- Scheduler checkpoints ---

    def save_last_daily_run(self, run_date: str) -> None:
        """Persist the date (YYYY-MM-DD) of the last successful daily run.

        Decoupled from `daily_reports` so a successful Slack post survives
        across restarts even if `_save_report` failed silently.
        """
        now = time.time()
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO scheduler_state (key, value, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                              updated_at = excluded.updated_at""",
            ("last_daily_run", run_date, now),
        )
        conn.commit()

    def set_scheduler_state(self, key: str, value: str) -> None:
        """Write an arbitrary checkpoint into the generic key/value table.

        `save_last_daily_run` predates this and writes the same table with a
        fixed key; new checkpoints should use this rather than growing another
        bespoke method per key.
        """
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO scheduler_state (key, value, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                              updated_at = excluded.updated_at""",
            (key, value, time.time()),
        )
        conn.commit()

    def get_scheduler_state(self, key: str) -> tuple[str, float] | None:
        """Return (value, updated_at) or None if the key was never written.

        `updated_at` is returned alongside the value because callers that treat
        a checkpoint as a live signal need to know how stale it is — a verdict
        nobody has refreshed is not the same as a verdict of "fine".
        """
        conn = self._get_conn()
        row = conn.execute(
            "SELECT value, updated_at FROM scheduler_state WHERE key = ?",
            (key,),
        ).fetchone()
        return (row["value"], row["updated_at"]) if row else None

    def count_occurrences_since(self, state_key: str, since_ts: float) -> int:
        """Return the number of occurrences for a given incident state_key
        that happened on or after `since_ts`.
        """
        conn = self._get_conn()
        row = conn.execute(
            """SELECT COUNT(*) as count
               FROM incident_occurrences o
               JOIN incidents i ON i.id = o.incident_id
               WHERE i.state_key = ?
                 AND o.seen_at >= ?""",
            (state_key, since_ts),
        ).fetchone()
        return row["count"] if row else 0

    def get_last_daily_run(self) -> str | None:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT value FROM scheduler_state WHERE key = ?",
            ("last_daily_run",),
        ).fetchone()
        return row["value"] if row else None

    def get_latest_analysis_by_state_key(self, state_key: str,
                                         max_age_hours: float | None = None) -> dict | None:
        """Return the most recent occurrence with parsed analysis for a given
        incident state_key.

        Used by the daily report enrichment to attach AI analysis to incident
        entries. Returns a dict with `analysis` (raw text) and `analysis_json`
        (parsed dict if available), or None when no analysis exists.

        max_age_hours bounds how far back we look — passing 24 from the daily
        report avoids attaching week-old analyses to a freshly reopened incident.
        """
        if not state_key:
            return None
        params: list = [state_key]
        query = ("SELECT o.analysis, o.analysis_json, o.llm_model, o.seen_at "
                 "FROM incident_occurrences o "
                 "JOIN incidents i ON i.id = o.incident_id "
                 "WHERE i.state_key = ? "
                 "AND (o.analysis IS NOT NULL OR o.analysis_json IS NOT NULL) "
                 "AND o.analysis_error = 0")
        if max_age_hours is not None:
            query += " AND o.seen_at >= ?"
            params.append(time.time() - max_age_hours * 3600)
        query += " ORDER BY o.seen_at DESC LIMIT 1"

        conn = self._get_conn()
        row = conn.execute(query, params).fetchone()
        if not row:
            return None
        result = dict(row)
        raw = result.get("analysis_json")
        if raw:
            try:
                result["analysis_json"] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                result["analysis_json"] = None
        return result

    def get_first_analysis_by_state_key(self, state_key: str,
                                        max_age_hours: float | None = None,
                                        ) -> dict | None:
        """Return the *earliest* occurrence within the window that carries a
        parsed, non-errored LLM analysis for this state_key.

        Mirrors `get_latest_analysis_by_state_key` but flips the ORDER BY —
        used by the daily report enrichment to attach the initial diagnosis
        (not whatever happened most recently), so the LLM can reason about
        "analyzed once, then recurred N times without re-analysis".
        """
        if not state_key:
            return None
        params: list = [state_key]
        query = ("SELECT o.analysis, o.analysis_json, o.llm_model, o.seen_at "
                 "FROM incident_occurrences o "
                 "JOIN incidents i ON i.id = o.incident_id "
                 "WHERE i.state_key = ? "
                 "AND (o.analysis IS NOT NULL OR o.analysis_json IS NOT NULL) "
                 "AND o.analysis_error = 0")
        if max_age_hours is not None:
            query += " AND o.seen_at >= ?"
            params.append(time.time() - max_age_hours * 3600)
        query += " ORDER BY o.seen_at ASC LIMIT 1"

        conn = self._get_conn()
        row = conn.execute(query, params).fetchone()
        if not row:
            return None
        result = dict(row)
        raw = result.get("analysis_json")
        if raw:
            try:
                result["analysis_json"] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                result["analysis_json"] = None
        return result

    def get_latest_raw_context_by_state_key(self, state_key: str,
                                            max_age_hours: float | None = None,
                                            ) -> dict | None:
        """Return the most recent occurrence for `state_key` with a non-empty
        context, even if no LLM analysis was attached.

        Used by the daily report enrichment to capture the *current* snapshot
        of an incident (restart count, phase, reason, endpoint status code,
        etc.) so the LLM can compare it against the initial diagnosis and
        decide whether the situation is stable or evolving.

        Reads the context body from the deduplicated `context_store` via
        `o.context_hash`. Legacy rows that still have an inline
        `o.raw_context` take precedence when present (pre-migration data).
        """
        if not state_key:
            return None
        params: list = [state_key]
        # COALESCE: prefer inline raw_context (legacy rows) over the
        # hash-joined context_store body (new rows write NULL inline).
        query = (
            "SELECT COALESCE(o.raw_context, cs.content) AS raw_context, "
            "o.seen_at "
            "FROM incident_occurrences o "
            "JOIN incidents i ON i.id = o.incident_id "
            "LEFT JOIN context_store cs ON cs.hash = o.context_hash "
            "WHERE i.state_key = ? "
            "AND ("
            "    (o.raw_context IS NOT NULL AND o.raw_context != '')"
            " OR (cs.content IS NOT NULL AND cs.content != '')"
            ")"
        )
        if max_age_hours is not None:
            query += " AND o.seen_at >= ?"
            params.append(time.time() - max_age_hours * 3600)
        query += " ORDER BY o.seen_at DESC LIMIT 1"

        conn = self._get_conn()
        row = conn.execute(query, params).fetchone()
        if not row:
            return None
        result = dict(row)
        raw = result.get("raw_context")
        if raw:
            try:
                result["raw_context"] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                result["raw_context"] = None
        return result

    def get_recent_analysis_by_fingerprint(self, fingerprint: str,
                                           max_age_hours: float = 6) -> dict | None:
        """Return the most recent occurrence that has a parsed analysis for a
        given incident fingerprint, within max_age_hours. Used to short-circuit
        repeat LLM calls on persistent incidents.
        """
        if not fingerprint:
            return None
        cutoff = time.time() - max_age_hours * 3600
        conn = self._get_conn()
        row = conn.execute(
            """SELECT o.analysis, o.analysis_json, o.llm_model, o.seen_at
               FROM incident_occurrences o
               JOIN incidents i ON i.id = o.incident_id
               WHERE i.fingerprint = ?
                 AND o.analysis_json IS NOT NULL
                 AND o.analysis_error = 0
                 AND o.seen_at >= ?
               ORDER BY o.seen_at DESC
               LIMIT 1""",
            (fingerprint, cutoff),
        ).fetchone()
        return dict(row) if row else None

    def get_llm_usage_summary(self, hours: int = 24) -> dict:
        """Return aggregate stats for LLM calls within the last `hours`."""
        cutoff = time.time() - (hours * 3600)
        conn = self._get_conn()
        row = conn.execute(
            """SELECT
                   COUNT(*) as total_calls,
                   COALESCE(SUM(tokens_in), 0) as total_tokens_in,
                   COALESCE(SUM(tokens_out), 0) as total_tokens_out,
                   COALESCE(SUM(cost_usd), 0) as total_cost_usd,
                   COALESCE(AVG(tokens_in), 0) as avg_tokens_in,
                   COALESCE(MAX(tokens_in), 0) as max_tokens_in,
                   COALESCE(AVG(latency_ms), 0) as avg_latency_ms,
                   COALESCE(MAX(latency_ms), 0) as max_latency_ms
               FROM llm_calls WHERE called_at >= ?""",
            (cutoff,),
        ).fetchone()
        return {
            "total_calls": row["total_calls"],
            "total_tokens_in": row["total_tokens_in"],
            "total_tokens_out": row["total_tokens_out"],
            "total_cost_usd": round(row["total_cost_usd"], 6),
            "avg_tokens_in": round(row["avg_tokens_in"]),
            "max_tokens_in": row["max_tokens_in"],
            "avg_latency_ms": round(row["avg_latency_ms"]),
            "max_latency_ms": round(row["max_latency_ms"]),
            "period_hours": hours,
        }

    # --- Daily reports ---

    def save_daily_report(self, *, cluster: str, collector_data: dict, result,
                          report_type: str = "daily") -> int:
        """Persist a daily/weekly report. `result` is an AnalysisResult."""
        now = time.time()
        overall_status = None
        analysis_json_str = None
        if result.parsed:
            overall_status = result.parsed.get("overall_status")
            analysis_json_str = json.dumps(result.parsed, default=str)

        collector_json = json.dumps(collector_data, default=str)
        context_bytes = len(collector_json.encode("utf-8"))

        conn = self._get_conn()
        cur = conn.execute(
            """INSERT INTO daily_reports
               (created_at, cluster, collector_data_json, overall_status,
                analysis_json, analysis_raw, parse_error,
                llm_model, tokens_in, tokens_out, cost_usd,
                latency_ms, context_bytes, truncated, report_type)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (now, cluster, collector_json, overall_status,
             analysis_json_str, result.raw_text, result.parse_error,
             result.model, result.tokens_in, result.tokens_out, result.cost_usd,
             result.latency_ms, context_bytes, False, report_type),
        )
        conn.commit()
        return cur.lastrowid  # type: ignore[return-value]  # always set after INSERT

    def list_daily_reports(self, limit: int = 30,
                           report_type: str | None = None) -> list[dict]:
        """Return recent reports without heavy fields.

        If report_type is given, filter by it. Otherwise returns all types.
        """
        conn = self._get_conn()
        if report_type:
            rows = conn.execute(
                """SELECT id, created_at, cluster, overall_status,
                          analysis_json, llm_model, cost_usd, parse_error, report_type
                   FROM daily_reports
                   WHERE report_type = ?
                   ORDER BY created_at DESC LIMIT ?""",
                (report_type, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT id, created_at, cluster, overall_status,
                          analysis_json, llm_model, cost_usd, parse_error, report_type
                   FROM daily_reports
                   ORDER BY created_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        result = []
        for r in rows:
            summary = None
            if r["analysis_json"]:
                try:
                    parsed = json.loads(r["analysis_json"])
                    summary = parsed.get("summary")
                except (json.JSONDecodeError, TypeError):
                    pass
            result.append({
                "id": r["id"],
                "created_at": r["created_at"],
                "cluster": r["cluster"],
                "overall_status": r["overall_status"],
                "summary": summary,
                "model": r["llm_model"],
                "cost_usd": r["cost_usd"],
                "parse_error": bool(r["parse_error"]),
                "report_type": r["report_type"] or "daily",
            })
        return result

    def get_daily_report(self, report_id: int) -> dict | None:
        """Return full report detail with parsed JSON fields."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM daily_reports WHERE id = ?", (report_id,)
        ).fetchone()
        if not row:
            return None

        # Parse JSON fields
        collector_data = None
        if row["collector_data_json"]:
            try:
                collector_data = json.loads(row["collector_data_json"])
            except (json.JSONDecodeError, TypeError):
                collector_data = row["collector_data_json"]

        analysis = None
        summary = None
        if row["analysis_json"]:
            try:
                analysis = json.loads(row["analysis_json"])
                summary = analysis.get("summary")
            except (json.JSONDecodeError, TypeError):
                analysis = None

        # report_type column may not exist in very old DBs before migration runs
        try:
            rtype = row["report_type"] or "daily"
        except (IndexError, KeyError):
            rtype = "daily"

        return {
            "id": row["id"],
            "created_at": row["created_at"],
            "cluster": row["cluster"],
            "overall_status": row["overall_status"],
            "summary": summary,
            "model": row["llm_model"],
            "cost_usd": row["cost_usd"],
            "parse_error": bool(row["parse_error"]),
            "report_type": rtype,
            "collector_data": collector_data,
            "analysis": analysis,
            "analysis_raw": row["analysis_raw"],
            "tokens_in": row["tokens_in"],
            "tokens_out": row["tokens_out"],
            "latency_ms": row["latency_ms"],
            "context_bytes": row["context_bytes"],
            "truncated": bool(row["truncated"]),
        }

    def cleanup_llm_calls(self, max_age_days: int = 30) -> int:
        """Delete llm_calls rows older than `max_age_days`."""
        if max_age_days <= 0:
            return 0
        cutoff = time.time() - (max_age_days * 86400)
        conn = self._get_conn()
        cur = conn.execute(
            "DELETE FROM llm_calls WHERE called_at < ?", (cutoff,),
        )
        conn.commit()
        deleted = cur.rowcount
        if deleted:
            logger.info("LLM calls cleanup: removed %d records older than %dd",
                        deleted, max_age_days)
        return deleted

    def cleanup_llm_debug(self, max_age_days: int = 7) -> int:
        """Delete llm_debug_payloads rows older than `max_age_days`.

        Debug payloads carry full system + user prompts and are only useful
        for short-term investigation, so they age out faster than llm_calls.
        """
        if max_age_days <= 0:
            return 0
        cutoff = time.time() - (max_age_days * 86400)
        conn = self._get_conn()
        cur = conn.execute(
            "DELETE FROM llm_debug_payloads WHERE called_at < ?", (cutoff,),
        )
        conn.commit()
        deleted = cur.rowcount
        if deleted:
            logger.info("LLM debug cleanup: removed %d records older than %dd",
                        deleted, max_age_days)
        return deleted

    def cleanup_daily_reports(self, max_age_days: int = 30) -> int:
        """Delete daily reports older than max_age_days."""
        cutoff = time.time() - (max_age_days * 86400)
        conn = self._get_conn()
        cur = conn.execute(
            "DELETE FROM daily_reports WHERE created_at < ?", (cutoff,)
        )
        conn.commit()
        deleted = cur.rowcount
        if deleted:
            logger.info("Daily reports cleanup: removed %d records older than %dd", deleted, max_age_days)
        return deleted

    # --- LLM debug payloads ---

    def log_llm_debug(self, *, called_at: float, call_type: str, resource: str,
                      system_prompt: str, user_content: str,
                      response_text: str | None) -> int:
        """Insert an LLM debug payload row."""
        now = time.time()
        conn = self._get_conn()
        cur = conn.execute(
            """INSERT INTO llm_debug_payloads
               (called_at, call_type, resource, system_prompt, user_content,
                response_text, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (called_at, call_type, resource, system_prompt, user_content,
             response_text, now),
        )
        conn.commit()
        return cur.lastrowid  # type: ignore[return-value]  # always set after INSERT

    def get_llm_debug(self, hours: int = 24) -> list[dict]:
        """List recent LLM debug entries with truncated previews."""
        cutoff = time.time() - (hours * 3600)
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT id, called_at, call_type, resource,
                      LENGTH(system_prompt) as system_prompt_bytes,
                      LENGTH(user_content) as user_content_bytes,
                      LENGTH(response_text) as response_bytes,
                      SUBSTR(response_text, 1, 120) as response_preview,
                      created_at
               FROM llm_debug_payloads
               WHERE called_at >= ?
               ORDER BY called_at DESC""",
            (cutoff,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_llm_debug_detail(self, debug_id: int) -> dict | None:
        """Return full payload for one LLM debug entry."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM llm_debug_payloads WHERE id = ?", (debug_id,)
        ).fetchone()
        return dict(row) if row else None

    # --- Incident context for daily reports ---

    def get_recent_incident_contexts(self, hours: int = 24, limit: int = 20) -> list[dict]:
        """Get latest occurrence context for recent incidents (single JOIN query).

        Returns [{state_key, issue_type, severity, occurrences, raw_context, ...}].

        New inserts write `incident_occurrences.raw_context = NULL` — the
        actual body lives in `context_store` keyed by `context_hash`. We
        COALESCE inline raw_context (legacy rows) with the hash-joined body
        so both pre- and post-migration occurrences surface.
        """
        cutoff = time.time() - (hours * 3600)
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT i.state_key, i.issue_type, i.severity, i.status,
                      i.occurrence_count AS occurrences,
                      i.first_seen_at, i.last_seen_at,
                      COALESCE(o.raw_context, cs.content) AS raw_context
               FROM incidents i
               JOIN incident_occurrences o ON o.incident_id = i.id
               LEFT JOIN context_store cs ON cs.hash = o.context_hash
               WHERE i.last_seen_at >= ?
                 AND (
                     (o.raw_context IS NOT NULL AND o.raw_context != '')
                     OR (cs.content IS NOT NULL AND cs.content != '')
                 )
                 AND o.id = (
                     SELECT o2.id FROM incident_occurrences o2
                     LEFT JOIN context_store cs2 ON cs2.hash = o2.context_hash
                     WHERE o2.incident_id = i.id
                       AND (
                           (o2.raw_context IS NOT NULL AND o2.raw_context != '')
                           OR (cs2.content IS NOT NULL AND cs2.content != '')
                       )
                     ORDER BY o2.seen_at DESC LIMIT 1
                 )
               ORDER BY i.last_seen_at DESC
               LIMIT ?""",
            (cutoff, limit),
        ).fetchall()
        return [dict(r) for r in rows]

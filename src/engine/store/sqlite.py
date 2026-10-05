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
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    state_key TEXT NOT NULL UNIQUE,
    fingerprint TEXT NOT NULL,
    issue_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    owner_ref TEXT NOT NULL DEFAULT '',
    first_seen_at REAL NOT NULL,
    last_seen_at REAL NOT NULL,
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
    tokens_in INTEGER NOT NULL,
    tokens_out INTEGER NOT NULL,
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

CREATE TABLE IF NOT EXISTS maintenance_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'manual',
    affected_nodes TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_maintenance_log_created ON maintenance_log(created_at);

-- One row, written and rolled back by ping(): proves the store is writable.
CREATE TABLE IF NOT EXISTS store_health (
    id INTEGER PRIMARY KEY,
    checked_at REAL NOT NULL
);

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

    def ping(self) -> None:
        """Raise unless the existing database can be read AND written - /healthz uses it.

        A fresh connection in mode=rw: it never creates a missing file (a cached
        connection, or a plain connect, would open or create one and look healthy).
        It reads a real table, then writes one row and rolls it back - a store that
        went read-only (disk full, read-only remount) fails here. SELECT 1 passes on both.
        """
        conn = sqlite3.connect(f"file:{self._db_path}?mode=rw", uri=True, timeout=5)
        try:
            conn.execute("SELECT 1 FROM incidents LIMIT 1").fetchone()
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("INSERT OR REPLACE INTO store_health (id, checked_at) VALUES (1, ?)", (time.time(),))
            conn.execute("ROLLBACK")
        finally:
            conn.close()

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local connection (sqlite3 connections are not thread-safe)."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA busy_timeout=5000")
        return self._local.conn

    def _init_schema(self):
        conn = self._get_conn()
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

    # --- Incident lifecycle ---

    def _row_to_incident(self, row: sqlite3.Row) -> Incident:
        return Incident(
            id=row["id"],
            state_key=row["state_key"],
            fingerprint=row["fingerprint"],
            issue_type=row["issue_type"],
            severity=row["severity"],
            owner_ref=row["owner_ref"],
            first_seen_at=row["first_seen_at"],
            last_seen_at=row["last_seen_at"],
            occurrence_count=row["occurrence_count"],
            cooldown_until=row["cooldown_until"],
            last_slack_ts=row["last_slack_ts"] or "",
            status=row["status"],
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

    def create_incident(self, *, state_key: str, fingerprint: str, issue_type: str,
                        severity: str, owner_ref: str) -> Incident:
        now = time.time()
        conn = self._get_conn()
        cur = conn.execute(
            """INSERT INTO incidents
               (state_key, fingerprint, issue_type, severity, owner_ref,
                first_seen_at, last_seen_at, occurrence_count,
                cooldown_until, last_slack_ts, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, '', 'active', ?, ?)""",
            (state_key, fingerprint, issue_type, severity, owner_ref,
             now, now, now, now),
        )
        conn.commit()
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
            occurrence_count=0,
            cooldown_until=None,
            last_slack_ts="",
            status="active",
        )

    def record_occurrence(self, incident_id: int, *, context_hash: str,
                          raw_context: str | None = None, analysis: str | None = None,
                          analysis_json: str | None = None, analysis_error: bool = False,
                          llm_model: str | None = None, tokens_in: int | None = None,
                          tokens_out: int | None = None, cost_usd: float | None = None) -> None:
        now = time.time()
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO incident_occurrences
               (incident_id, seen_at, context_hash, raw_context, analysis,
                analysis_json, analysis_error, llm_model, tokens_in, tokens_out,
                cost_usd, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (incident_id, now, context_hash, raw_context, analysis,
             analysis_json, analysis_error, llm_model, tokens_in, tokens_out,
             cost_usd, now),
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

    def bump_incident(self, incident_id: int, cooldown_until: float | None = None) -> None:
        now = time.time()
        conn = self._get_conn()
        conn.execute(
            """UPDATE incidents SET cooldown_until = ?, updated_at = ? WHERE id = ?""",
            (cooldown_until, now, incident_id),
        )
        conn.commit()

    # --- Status management ---

    def set_status(self, incident_id: int, status: str) -> None:
        now = time.time()
        conn = self._get_conn()
        conn.execute(
            "UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?",
            (status, now, incident_id),
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

    # --- Store protocol backward compat ---

    def is_seen(self, key: str) -> bool:
        incident = self.get_incident(key)
        if incident is None:
            return False
        if incident.status == "resolved":
            return False
        # Check cooldown
        if incident.cooldown_until and time.time() < incident.cooldown_until:
            return True
        return False

    def mark_seen(self, key: str, *, issue_type: str = "unknown",
                  severity: str = "warning", debounce_multiplier: int = 1) -> None:
        """Backward compat: create a minimal incident or bump existing."""
        incident = self.get_incident(key)
        if incident is None:
            try:
                self.create_incident(
                    state_key=key, fingerprint="", issue_type=issue_type,
                    severity=severity, owner_ref="",
                )
            except sqlite3.IntegrityError:
                pass  # another thread won the race
            incident = self.get_incident(key)
            if incident is None:
                return
        # Record occurrence (bumps count + last_seen_at)
        self.record_occurrence(incident.id, context_hash="")
        # Set cooldown with exponential backoff
        new_count = incident.occurrence_count + 1  # incident object is stale; +1 accounts for the occurrence just recorded
        cooldown = min(config.DEBOUNCE_SECONDS * debounce_multiplier * (2 ** new_count), 43200)
        self.bump_incident(incident.id, cooldown_until=time.time() + cooldown)

    def clear_key(self, key: str) -> None:
        incident = self.get_incident(key)
        if incident:
            self.set_status(incident.id, "resolved")

    def cleanup(self, max_age_hours: int = 168) -> None:
        """Clean up resolved incidents older than max_age_hours (default 7 days)."""
        cutoff = time.time() - (max_age_hours * 3600)
        conn = self._get_conn()
        # Get IDs of old resolved incidents
        old_ids = conn.execute(
            "SELECT id FROM incidents WHERE status = 'resolved' AND updated_at < ?",
            (cutoff,),
        ).fetchall()
        if old_ids:
            ids = [r["id"] for r in old_ids]
            placeholders = ",".join("?" * len(ids))
            conn.execute(f"DELETE FROM incident_occurrences WHERE incident_id IN ({placeholders})", ids)
            conn.execute(f"DELETE FROM incidents WHERE id IN ({placeholders})", ids)
            # Clean orphaned contexts
            conn.execute("""
                DELETE FROM context_store WHERE hash NOT IN (
                    SELECT DISTINCT context_hash FROM incident_occurrences
                )
            """)
            conn.commit()
            logger.info("SQLite cleanup: removed %d resolved incidents older than %dh", len(ids), max_age_hours)
        self.cleanup_suppressions()
        self.cleanup_daily_reports()

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

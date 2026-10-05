"""SLI scanner — user-visible SLO breach detection with dependency
chain correlation (Sprint 12).

Reads SLI definitions from a ConfigMap-mounted YAML file. On each scan
tick (default 120s) queries Prometheus for the current value of every
SLI, determines whether each is breaching, gates by duration, then
emits a `ScanResult` through the shared pipeline when the duration
threshold is reached.

The distinguishing feature vs a generic threshold scanner is
**dependency chain correlation**: when a user-facing SLI breaches
(e.g. `frontend_p99_latency`), the scanner walks the YAML-declared
`upstream_slis` and checks if any of those are ALSO breaching. It
keeps descending along the first breaching upstream until it hits a
non-breaching sibling or a leaf. The deepest breaching SLI = the
root cause. The emitted alert carries the full chain so the operator
sees "frontend slow BECAUSE backend slow BECAUSE postgres_query_latency
breach" instead of three separate pages.
"""
from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from src import config
from src.collectors.metrics_range import prom_range_query
from src.collectors.prometheus import prom_scalar
from src.scanners._base import ScanResult

logger = logging.getLogger(__name__)


_COMPARISON_OPS = {
    ">": lambda val, thr: val > thr,
    ">=": lambda val, thr: val >= thr,
    "<": lambda val, thr: val < thr,
    "<=": lambda val, thr: val <= thr,
}


@dataclass
class SliDefinition:
    """Parsed representation of a single SLI entry from the YAML config."""
    name: str
    query: str
    threshold: float
    comparison: str                       # ">" | ">=" | "<" | "<="
    duration_seconds: int
    severity: str                         # "warning" | "critical"
    description: str = ""
    upstream_slis: list[str] = field(default_factory=list)
    namespaces: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)

    def is_breaching(self, value: float | None) -> bool:
        """True when the observed value violates the threshold per the
        configured comparison. None values mean "Prometheus returned no
        data" — treat as non-breaching so we don't alert on missing
        metrics (that's a separate category handled by the monitor's
        own health probes)."""
        if value is None:
            return False
        op = _COMPARISON_OPS.get(self.comparison)
        if op is None:
            logger.warning("SLI %s has invalid comparison %r — treating as non-breaching",
                           self.name, self.comparison)
            return False
        return op(value, self.threshold)


def _parse_slis(raw: Any) -> list[SliDefinition]:
    """Parse the `slis:` top-level list from the loaded YAML document."""
    if not isinstance(raw, dict):
        raise ValueError("SLI config root must be a mapping")
    items = raw.get("slis", [])
    if not isinstance(items, list):
        raise ValueError("`slis:` must be a list")
    parsed: list[SliDefinition] = []
    for idx, entry in enumerate(items):
        if not isinstance(entry, dict):
            raise ValueError(f"SLI #{idx}: entry must be a mapping")
        missing = [k for k in ("name", "query", "threshold", "comparison",
                                "duration_seconds", "severity") if k not in entry]
        if missing:
            raise ValueError(f"SLI #{idx} missing required fields: {missing}")
        if entry["comparison"] not in _COMPARISON_OPS:
            raise ValueError(
                f"SLI {entry['name']!r}: unsupported comparison "
                f"{entry['comparison']!r} (want one of {sorted(_COMPARISON_OPS)})"
            )
        if entry["severity"] not in ("warning", "critical"):
            raise ValueError(
                f"SLI {entry['name']!r}: severity must be 'warning' or 'critical'"
            )
        parsed.append(SliDefinition(
            name=entry["name"],
            query=str(entry["query"]).strip(),
            threshold=float(entry["threshold"]),
            comparison=entry["comparison"],
            duration_seconds=int(entry["duration_seconds"]),
            severity=entry["severity"],
            description=str(entry.get("description", "")),
            upstream_slis=list(entry.get("upstream_slis", []) or []),
            namespaces=list(entry.get("namespaces", []) or []),
            labels=list(entry.get("labels", []) or []),
        ))
    # Sanity: names must be unique — duplicate would make chain walks ambiguous.
    names = [s.name for s in parsed]
    if len(set(names)) != len(names):
        dupes = [n for n in names if names.count(n) > 1]
        raise ValueError(f"SLI config has duplicate names: {sorted(set(dupes))}")
    return parsed


def _labels_hash(labels: dict[str, str] | None) -> str:
    """Stable hash of label key-value pairs for per-combination breach tracking.
    Empty labels → empty hash so scalar (no-label) SLIs share a single row.
    """
    if not labels:
        return ""
    items = sorted(labels.items())
    payload = "|".join(f"{k}={v}" for k, v in items)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


class SliScanner:
    name = "sli"
    startup_delay = 60

    def __init__(self) -> None:
        self._config_mtime: float | None = None
        self._slis: list[SliDefinition] = []
        self._by_name: dict[str, SliDefinition] = {}

    @property
    def enabled(self) -> bool:
        return config.SCANNER_SLI_ENABLED

    @property
    def interval_seconds(self) -> int:
        return config.SCANNER_SLI_INTERVAL_SECONDS

    # ── config loading ─────────────────────────────────────────────────

    def _load_config(self) -> list[SliDefinition]:
        """Load SLI config, with mtime-based cache invalidation so a
        ConfigMap update gets picked up on next scan tick without
        restart (Kubernetes propagates ConfigMap changes to the pod
        filesystem — the mount reflects new content within ~seconds)."""
        path = Path(config.SLI_CONFIG_PATH)
        if not path.is_file():
            if self._slis:
                logger.warning("SLI config path %s disappeared — keeping cached definitions", path)
                return self._slis
            logger.info("SLI config path %s not present — scanner will no-op", path)
            return []
        try:
            mtime = path.stat().st_mtime
        except OSError as exc:
            logger.warning("SLI config stat failed: %s", exc)
            return self._slis
        if self._config_mtime == mtime and self._slis:
            return self._slis
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            logger.error("SLI config parse failed at %s: %s — keeping previous definitions", path, exc)
            return self._slis
        try:
            slis = _parse_slis(raw or {})
        except ValueError as exc:
            logger.error("SLI config invalid: %s — keeping previous definitions", exc)
            return self._slis
        self._slis = slis
        self._by_name = {s.name: s for s in slis}
        self._config_mtime = mtime
        logger.info("SLI config loaded: %d definitions", len(slis))
        return slis

    # ── scan entrypoint ────────────────────────────────────────────────

    def scan(self) -> list[ScanResult]:
        from src.handlers.startup import get_store
        store = get_store()
        slis = self._load_config()
        if not slis:
            return []

        # Cache PromQL results within a single scan tick — chain walks
        # re-query upstream SLIs, and without caching we'd hit Prometheus
        # O(N*M) times. With caching, each SLI's query runs once per tick.
        query_cache: dict[str, float | None] = {}
        results: list[ScanResult] = []

        for sli in slis:
            value = self._get_value(sli, query_cache)
            labels_hash = ""  # Label-partitioned tracking is a future feature

            # Prometheus unreachable / no data — do NOT clear breach
            # state. "None" means "we don't know", not "healthy". Clearing
            # here would destroy an active breach's duration window;
            # skipping lets the scanner try again next tick.
            if value is None:
                logger.debug("SLI %s: Prometheus returned None; skipping tick", sli.name)
                continue

            breaching = sli.is_breaching(value)

            if not breaching:
                # Metric genuinely back under threshold. If there's an
                # active breach row, the incident has recovered —
                # emit an auto_resolve ScanResult so the pipeline flips
                # incident.status to resolved + posts a Slack recovery
                # (for critical-severity incidents). THEN clear the
                # breach row so the next breach starts a fresh
                # duration window.
                existing = store.get_sli_breach(sli.name, labels_hash)
                if existing is not None:
                    logger.info(
                        "SLI breach resolved: %s (value=%s, threshold=%s)",
                        sli.name, value, sli.threshold,
                    )
                    results.append(ScanResult(
                        state_key=self._state_key(sli, labels_hash),
                        title=f"SLO breach resolved: {sli.name}",
                        severity="info",
                        resource=f"SLI/{sli.name}",
                        namespace=sli.namespaces[0] if sli.namespaces else "",
                        issue_type="sli_breach",
                        auto_resolve=True,
                    ))
                    store.clear_sli_breach(sli.name, labels_hash)
                continue

            breach = store.record_sli_breach(sli.name, labels_hash, value)
            duration = time.time() - breach["first_breach_at"]
            if duration < sli.duration_seconds:
                # Not long enough yet — keep tracking, don't emit.
                continue
            if breach["alerted"]:
                # Already fired for this breach cycle; silent until recovery.
                continue

            chain = self._walk_chain(sli, query_cache)
            root_cause_name = chain[-1]["name"] if chain else sli.name

            results.append(ScanResult(
                state_key=self._state_key(sli, labels_hash),
                title=f"SLO breach: {sli.name}",
                severity=sli.severity,
                resource=f"SLI/{sli.name}",
                namespace=sli.namespaces[0] if sli.namespaces else "",
                issue_type="sli_breach",
                context_override={
                    "sli": {
                        "name": sli.name,
                        "description": sli.description,
                        "query": sli.query,
                        "threshold": sli.threshold,
                        "comparison": sli.comparison,
                        "current_value": value,
                        "duration_seconds": round(duration, 1),
                    },
                    "chain": chain,
                    "root_cause": root_cause_name,
                },
                event_reason=f"{sli.name}: {sli.comparison} {sli.threshold} for {int(duration)}s",
                skip_llm=True,
                # The YAML severity is the answer, not a suggestion.
                #
                # This branch originally leaned on the pipeline's promoters as
                # "the paging safety net". Four months later the HPA scanner
                # shipped and showed what that means in practice: every
                # fingerprint is new the first time it is seen, so its entire
                # first wave arrived as CRITICAL with an @ai tag, for workloads
                # that were serving normally.
                #
                # The same would happen here, and worse — the starter bundle
                # defines seven SLOs, all severity: warning, so the operator's
                # choice would be overridden exactly once per SLO, on the first
                # and most confusing occasion. An SLO that deserves a page
                # should say so in the YAML.
                never_promote=True,
                metadata={
                    "sli_name": sli.name,
                    "labels_hash": labels_hash,
                    "root_cause": root_cause_name,
                    "threshold": sli.threshold,
                    "source": "sli",
                },
            ))
            store.mark_sli_alerted(sli.name, labels_hash)
            logger.info(
                "SLI breach alert: %s (root=%s, chain_depth=%d)",
                sli.name, root_cause_name, len(chain),
            )

        if results:
            logger.info("SLI scanner: %d breaches emitted", len(results))
        else:
            logger.debug("SLI scanner: no new breaches")
        return results

    def collect_daily_data(self) -> str | None:
        """Did the cluster hold its SLOs for the last 24 hours, and if not, how
        long and where did it start.

        Attainment is computed from Prometheus rather than from the incident
        table on purpose. Incidents record what was *alerted*, which is a
        damped view: a breach shorter than duration_seconds never fires, an
        already-alerted breach stays silent until it recovers, and the breach
        row is deleted on recovery so its length is gone. None of that is the
        question a daily report asks. Re-running each SLI over the window and
        counting samples under threshold answers it directly.

        Every number here is a measurement. The recommendations belong to the
        report's own analysis, which reads this section — a scanner should not
        invent optimisations it cannot verify.
        """
        try:
            slis = self._load_config()
        except Exception:
            logger.debug("SLI daily: config unreadable", exc_info=True)
            return None
        if not slis:
            return None

        window_min = 24 * 60
        lines: list[str] = []
        breached: list[str] = []
        unknown: list[str] = []

        for sli in slis:
            series = prom_range_query(sli.query, since_minutes=window_min, step="5m")
            if not series:
                # No data is not compliance. Say so rather than counting it as
                # a pass — an SLO nobody can measure is the one most likely to
                # be quietly broken.
                unknown.append(sli.name)
                continue

            values = [float(v) for _, v in series[0].get("values", [])]
            if not values:
                unknown.append(sli.name)
                continue

            bad = [v for v in values if sli.is_breaching(v)]
            attainment = 100.0 * (len(values) - len(bad)) / len(values)
            # Samples are 5m apart, so each breaching sample is 5 minutes.
            minutes = len(bad) * 5

            if not bad:
                lines.append(f"- {sli.name}: met, 100% of 24h (threshold "
                             f"{sli.comparison} {sli.threshold})")
                continue

            worst = max(values) if sli.comparison in (">", ">=") else min(values)
            hours, mins = divmod(minutes, 60)
            spent = f"{hours}h{mins:02d}m" if hours else f"{mins}m"
            lines.append(
                f"- {sli.name}: MISSED, {attainment:.1f}% of 24h — breached for "
                f"{spent}, worst {worst:g} against {sli.comparison} {sli.threshold}"
            )
            breached.append(sli.name)

        if not lines and not unknown:
            return None

        header = ["## SLO attainment (last 24h)"]
        if breached:
            header.append(f"{len(breached)} of {len(slis)} SLOs missed: "
                          f"{', '.join(breached)}")
        elif not unknown:
            header.append(f"All {len(slis)} SLOs met for the full window.")
        out = header + [""] + lines

        if unknown:
            out += ["", "Not measurable — Prometheus returned no data for these, "
                        "which is not the same as compliance:",
                    "- " + ", ".join(unknown)]

        # The chain is what turns "missed" into "why". Only walk it for SLOs
        # that actually missed, and only once per report.
        if breached:
            cache: dict[str, float | None] = {}
            roots = []
            for sli in slis:
                if sli.name not in breached:
                    continue
                chain = self._walk_chain(sli, cache)
                # _walk_chain includes the SLI itself as the first hop; it is
                # already the line's subject, so drop it rather than print it
                # twice.
                downstream = [c["name"] for c in chain if c["name"] != sli.name]
                if downstream:
                    roots.append(f"- {sli.name} -> " + " -> ".join(downstream))
            if roots:
                out += ["", "Dependency chains, deepest breaching SLI last:"] + roots

        return "\n".join(out) + "\n"

    # ── helpers ────────────────────────────────────────────────────────

    def _get_value(self, sli: SliDefinition,
                   cache: dict[str, float | None]) -> float | None:
        """Cached Prometheus query — one call per SLI per scan tick."""
        if sli.name in cache:
            return cache[sli.name]
        val = prom_scalar(sli.query)
        cache[sli.name] = val
        return val

    def _state_key(self, sli: SliDefinition, labels_hash: str) -> str:
        """Build a pipeline-conformant state_key.

        Convention (see CLAUDE.md AI guidelines): the pipeline's
        owner_cooldown check does `rsplit(":", 1)[0]` on state_key, so
        the last colon-separated segment is the issue sub-type and
        everything before is the "owner key". For SLIs we encode:

            SLI:{sli_name}:{ns_or_-}/{resource_or_-}

        Owner_key then becomes `SLI:{sli_name}` — each SLI owns its
        own cooldown, independent of other SLIs. The ns/resource tail
        is where label-partitioned tracking will slot in later.
        """
        ns = sli.namespaces[0] if sli.namespaces else "-"
        resource = labels_hash or "-"
        return f"SLI:{sli.name}:{ns}/{resource}"

    def _walk_chain(self, sli: SliDefinition,
                    cache: dict[str, float | None],
                    visited: set[str] | None = None,
                    depth: int = 0) -> list[dict[str, Any]]:
        """Walk upstream_slis recursively. Stops at:
        - A leaf (`upstream_slis == []`)
        - First non-breaching upstream (chain root-cause is THIS node)
        - A cycle (name already visited)
        - Max depth exceeded (`SLI_DEPENDENCY_MAX_DEPTH`, default 5)

        Returns a list of dicts [{name, value, level, threshold, comparison,
        breaching}] describing the chain from the root SLI down to the
        deepest breaching upstream. The last element is the root cause.
        """
        if visited is None:
            visited = set()
        if sli.name in visited or depth >= config.SLI_DEPENDENCY_MAX_DEPTH:
            return []
        visited.add(sli.name)

        current_value = self._get_value(sli, cache)
        chain: list[dict[str, Any]] = [{
            "name": sli.name,
            "level": depth,
            "value": current_value,
            "threshold": sli.threshold,
            "comparison": sli.comparison,
            "breaching": sli.is_breaching(current_value),
        }]

        for upstream_name in sli.upstream_slis:
            upstream = self._by_name.get(upstream_name)
            if upstream is None:
                logger.debug("SLI %s references unknown upstream %s — skipping",
                             sli.name, upstream_name)
                continue
            upstream_value = self._get_value(upstream, cache)
            if upstream.is_breaching(upstream_value):
                child = self._walk_chain(upstream, cache, visited, depth + 1)
                chain.extend(child)
                # First breaching upstream wins. Don't continue siblings —
                # we want the single root-cause path, not a fan-out tree
                # of every breaching dependency.
                break

        return chain

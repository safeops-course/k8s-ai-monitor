"""Shared helpers for deciding whether an alert targets a critical service.

Two tiers:
  - INFRA_CRITICAL_SERVICES: stateful deps (postgres, redis...).
    Outage affects everything — forced severity=critical + root-cause.
  - IMPORTANT_SERVICES: business services (backend, frontend, ...).
    Scanner severity respected — no blanket promotion. Shorter debounce
    than default.

Algorithm:
  - Tokenize every blob on non-alphanumerics, lowercase.
  - Tokenize every service entry the same way.
  - An entry matches when ALL of its tokens appear in the alert token set
    (subset match). Single-token entries reduce to exact-token membership.

Examples with INFRA_CRITICAL_SERVICES = {"redis", "api-gateway"}:
  "Deployment:prod/redis-master:OOM"     -> match (redis)
  "Deployment:prod/predis-worker:OOM"    -> no match (predis != redis)
  "Deployment:prod/api-gateway:crash"    -> match (api & gateway)
  "Deployment:prod/api-server:crash"     -> no match (gateway missing)
"""
import re

from src import config


_TOKEN_RE = re.compile(r"[^a-zA-Z0-9]+")


def _tokenize(*blobs: str) -> set[str]:
    tokens: set[str] = set()
    for blob in blobs:
        if not blob:
            continue
        for tok in _TOKEN_RE.split(blob.lower()):
            if tok:
                tokens.add(tok)
    return tokens


def _matches_any(alert_tokens: set[str], services: set[str]) -> bool:
    if not alert_tokens:
        return False
    for svc in services:
        svc_tokens = _tokenize(svc)
        if svc_tokens and svc_tokens <= alert_tokens:
            return True
    return False


def matches_infra_critical(*blobs: str) -> bool:
    """Match ONLY infra-critical services (stateful deps).

    Use this gate when the decision is "promote severity to critical"
    or "mark as root cause candidate". Application-tier services don't
    belong here — they fail BECAUSE their deps fail, they're not roots.
    """
    return _matches_any(_tokenize(*blobs), config.INFRA_CRITICAL_SERVICES)


def matches_important(*blobs: str) -> bool:
    """Match ONLY important (business) services, not infra.

    Use this when the decision is tier-dependent (e.g. debounce base).
    Returns False for infra services — call matches_infra_critical for
    those, or matches_critical_service for the union.
    """
    return _matches_any(_tokenize(*blobs), config.IMPORTANT_SERVICES)


def matches_critical_service(*blobs: str) -> bool:
    """Match infra OR important services (the union).

    Back-compat gate for callsites that ask "is this workload
    attention-worthy at all?" — event handler severity, Flux stall
    handling, LLM watchlist. These decisions apply
    to both tiers.

    For "force severity=critical" decisions, use matches_infra_critical
    instead — that's the narrower, severity-promoting gate.
    """
    return _matches_any(
        _tokenize(*blobs),
        config.INFRA_CRITICAL_SERVICES | config.IMPORTANT_SERVICES,
    )

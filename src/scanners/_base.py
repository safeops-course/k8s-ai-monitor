"""Scanner protocol and ScanResult dataclass."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class ScanResult:
    state_key: str          # dedup key: "Deployment:ns/name:oom"
    title: str              # "Pod Issue: OOMKilled"
    severity: str           # "critical" | "warning"
    resource: str           # "Pod/my-pod"
    namespace: str
    issue_type: str         # diagnostic alias: "oom", "crash", etc.
    pod_name: str = ""
    node_name: str = ""
    context_override: str | dict[str, Any] = ""  # scanners that build own context
    event_reason: str = ""
    auto_resolve: bool = False  # clear state when healthy
    skip_llm: bool = False      # post to Slack without LLM analysis
    # Keep the scanner's severity, whatever the promoters think.
    #
    # Two rules in the pipeline raise a warning to critical: a fingerprint
    # nobody has seen before, and an incident that has persisted. Both exist to
    # surface the unknown and the chronic, and both assume that a warning left
    # alone might be an outage nobody noticed.
    #
    # For some signals that assumption is simply false. An autoscaler sitting
    # at its ceiling is one: the workload is serving, on fewer pods than it
    # asked for, and no amount of persistence turns that into an outage. Worse,
    # a brand-new scanner has no known fingerprints by definition, so its
    # entire first wave would page on novelty alone.
    never_promote: bool = False
    metadata: dict = field(default_factory=dict)


@runtime_checkable
class Scanner(Protocol):
    name: str
    enabled: bool
    interval_seconds: int
    startup_delay: int

    def scan(self) -> list[ScanResult]: ...
    def collect_daily_data(self) -> str | None: ...

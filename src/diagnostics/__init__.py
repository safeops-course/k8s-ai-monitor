"""Diagnostics registry and dispatcher."""
import logging

from kubernetes import client as k8s

from src.diagnostics._base import DiagnosticPlugin
from src.diagnostics._helpers import diag_current_usage, diag_resource_limits
from src.diagnostics.oom import OomDiagnostic
from src.diagnostics.crash import CrashDiagnostic
from src.diagnostics.image_pull import ImagePullDiagnostic
from src.diagnostics.scheduling import SchedulingDiagnostic
from src.diagnostics.mount import MountDiagnostic
from src.diagnostics.error import ErrorDiagnostic
from src.diagnostics.unhealthy import UnhealthyDiagnostic
from src.diagnostics.evicted import EvictedDiagnostic

logger = logging.getLogger(__name__)

ALL_PLUGINS: list[DiagnosticPlugin] = [
    OomDiagnostic(),
    CrashDiagnostic(),
    ImagePullDiagnostic(),
    SchedulingDiagnostic(),
    MountDiagnostic(),
    ErrorDiagnostic(),
    UnhealthyDiagnostic(),
    EvictedDiagnostic(),
]

_PLUGIN_MAP = {p.issue_type: p for p in ALL_PLUGINS}


def collect_diagnostics(pod, namespace: str, issue_type: str) -> dict:
    """Run diagnostics for an already-fetched pod object based on issue type.

    Accepts the V1Pod from the caller (the scanner / collector) so we don't
    re-issue a `get pod` request that the upstream code has already made —
    important under K8s API rate limits when many pods are in trouble at once.
    Returns a structured dict.
    """
    if pod is None:
        return {}
    core = k8s.CoreV1Api()

    data = {}

    # Common diagnostics.
    # NOTE: previous_logs used to be collected here; it's now fetched by
    # _get_logs() in collectors/pod.py for every restarted container and
    # delivered via the `logs` field prefixed with [previous/<container>].
    # Pulling it again here was a genuine duplicate — same K8s calls, same
    # text in context twice, which both wasted LLM tokens and pushed useful
    # signal out of the context window.
    current_usage = diag_current_usage(pod)
    if current_usage:
        data["current_usage"] = current_usage

    resource_limits = diag_resource_limits(pod)
    if resource_limits:
        data["resource_limits"] = resource_limits

    # Issue-specific
    plugin = _PLUGIN_MAP.get(issue_type)
    if plugin:
        plugin_data = plugin.diagnose(core, pod)
        if plugin_data:
            data.update(plugin_data)

    return data

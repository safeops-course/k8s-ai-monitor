"""Pod context collection — extracted from Collector."""
import logging
import threading
import time
from datetime import datetime, timezone

from kubernetes import client as k8s

from src import config
from src.collectors._formatters import parse_cpu, parse_memory_mi, fmt_mem, fmt_bytes
from src.collectors.prometheus import prom_scalar, prom_query

logger = logging.getLogger(__name__)

# Error-priority patterns for log line prioritization
_ERROR_PATTERNS = (
    "ERROR", "WARN", "FATAL", "Exception", "Traceback",
    "panic", "OOM", "killed", "exit code",
)


def collect_pod_context(pod_name: str, namespace: str, core: k8s.CoreV1Api,
                         apps: k8s.AppsV1Api, pod=None) -> dict:
    """Collect pod context as structured dict for LLM.

    The caller may pass a pre-fetched ``pod`` (V1Pod) to avoid an extra
    ``read_namespaced_pod`` round-trip. When omitted, the pod is fetched
    here as before.
    """
    data = {}

    # Pod status
    if pod is None:
        try:
            pod = core.read_namespaced_pod(pod_name, namespace)
        except k8s.ApiException as e:
            if e.status == 404:
                logger.debug("Pod %s/%s no longer exists, skipping context collection", namespace, pod_name)
                return {"error": f"Pod {namespace}/{pod_name} no longer exists (deleted or recreated)"}
            logger.exception("Failed to read pod %s/%s", namespace, pod_name)
            return data
        except Exception:
            logger.exception("Failed to read pod %s/%s", namespace, pod_name)
            return data
    data["pod"] = _extract_pod_status(pod, core)

    # Pod logs — current + previous (when container has restarted), per container.
    # Lines are prefixed with "[current/<container>]" or "[previous/<container>]"
    # so the LLM sees the structure without breaking the existing list-of-strings
    # contract that downstream formatters depend on.
    data["logs"] = _get_logs(core, pod, namespace)

    # Events — as list of dicts
    data["events"] = _get_events(core, pod_name, namespace)

    # Owner (Deployment/StatefulSet)
    data["owner"] = _get_owner_status(pod, apps, namespace)

    # Node metrics
    data["node_metrics"] = _get_node_metrics(pod, core)

    # Application metrics (Node.js event loop, heap, RSS, CPU, GC) from Prometheus
    try:
        app_metrics = _get_app_metrics(pod_name, namespace)
        if app_metrics:
            data["app_metrics"] = app_metrics
    except Exception:
        logger.warning("Failed to collect app metrics for %s/%s", namespace, pod_name, exc_info=True)

    return {k: v for k, v in data.items() if v}


# Common Linux exit codes that show up on a crashed container. The signal
# half (>= 128) gives us "killed by signal N" — operators care most about
# OOMKilled (137 = 128 + SIGKILL when cgroup OOM fires), SIGSEGV (139), and
# SIGTERM (143, usually graceful shutdown). Everything else lands in the
# generic "application error" bucket.
_EXIT_CODE_MEANINGS: dict[int, str] = {
    0: "clean exit",
    1: "application error (uncaught exception or exit(1))",
    2: "shell builtin misuse / bad CLI args",
    126: "command invoked but not executable (permissions)",
    127: "command not found in image (wrong path or missing binary)",
    130: "killed by SIGINT (Ctrl-C)",
    137: "killed by SIGKILL (almost always cgroup OOM — check memory limit)",
    139: "killed by SIGSEGV (native crash / segfault)",
    143: "killed by SIGTERM (graceful shutdown — pod was likely evicted/scaled)",
}


def _exit_code_meaning(code: int | None) -> str:
    """Return a short human-readable explanation for a container exit code."""
    if code is None:
        return ""
    if code in _EXIT_CODE_MEANINGS:
        return _EXIT_CODE_MEANINGS[code]
    if code > 128:
        return f"killed by signal {code - 128}"
    return f"exit code {code} (non-zero application error)"


def _extract_pod_status(pod, core: k8s.CoreV1Api) -> dict:
    """Extract pod status as structured dict."""
    result = {
        "name": pod.metadata.name,
        "namespace": pod.metadata.namespace,
        "phase": pod.status.phase,
    }
    if pod.spec.node_name:
        result["node"] = pod.spec.node_name

    # Pod age — used by enrichment to correlate issues with recent deploys
    created = pod.metadata.creation_timestamp
    if created:
        from datetime import datetime, timezone
        age = (datetime.now(timezone.utc) - created).total_seconds()
        result["age_seconds"] = max(0, age)

    # Container statuses
    status_map = {cs.name: cs for cs in (pod.status.container_statuses or [])}
    containers = []
    for c in (pod.spec.containers or []):
        cinfo = {"name": c.name, "image": c.image}

        cs = status_map.get(c.name)
        if cs:
            if cs.state.running:
                cinfo["state"] = "running"
            elif cs.state.waiting:
                cinfo["state"] = "waiting"
                cinfo["reason"] = cs.state.waiting.reason or ""
            elif cs.state.terminated:
                cinfo["state"] = "terminated"
                cinfo["reason"] = cs.state.terminated.reason or ""
                cinfo["exit_code"] = cs.state.terminated.exit_code
                meaning = _exit_code_meaning(cs.state.terminated.exit_code)
                if meaning:
                    cinfo["exit_code_meaning"] = meaning
            else:
                cinfo["state"] = "unknown"
            cinfo["restarts"] = cs.restart_count

            # Exit code from last termination (for CrashLoop) — only if not
            # currently terminated. Surface the human reason alongside the
            # raw code so the LLM doesn't have to guess what 137 means.
            if cs.last_state and cs.last_state.terminated:
                if not (cs.state and cs.state.terminated):
                    last_code = cs.last_state.terminated.exit_code
                    cinfo["exit_code"] = last_code
                    cinfo["last_terminated_reason"] = cs.last_state.terminated.reason or ""
                    meaning = _exit_code_meaning(last_code)
                    if meaning:
                        cinfo["exit_code_meaning"] = meaning

        # Resources
        res = c.resources
        if res and (res.requests or res.limits):
            req = res.requests or {}
            lim = res.limits or {}
            resources = {}
            if req.get("cpu"):
                resources["cpu_req"] = req["cpu"]
            if req.get("memory"):
                resources["mem_req"] = req["memory"]
            if lim.get("cpu"):
                resources["cpu_lim"] = lim["cpu"]
            if lim.get("memory"):
                resources["mem_lim"] = lim["memory"]
            if resources:
                cinfo["resources"] = resources

        containers.append(cinfo)
    if containers:
        result["containers"] = containers

    # Init containers (only if any have issues)
    init_containers = []
    for ic in (pod.spec.init_containers or []):
        ic_status = None
        for ics in (pod.status.init_container_statuses or []):
            if ics.name == ic.name:
                ic_status = ics
                break
        icinfo = {"name": ic.name, "image": ic.image}
        if ic_status:
            if ic_status.state.terminated:
                t = ic_status.state.terminated
                icinfo["state"] = "terminated"
                icinfo["reason"] = t.reason or ""
                icinfo["exit_code"] = t.exit_code
                meaning = _exit_code_meaning(t.exit_code)
                if meaning:
                    icinfo["exit_code_meaning"] = meaning
            elif ic_status.state.running:
                icinfo["state"] = "running"
            elif ic_status.state.waiting:
                icinfo["state"] = "waiting"
                icinfo["reason"] = ic_status.state.waiting.reason or ""
        init_containers.append(icinfo)
    if init_containers:
        result["init_containers"] = init_containers

    # Node conditions
    if pod.spec.node_name:
        try:
            node = core.read_node(pod.spec.node_name)
            for cond in (node.status.conditions or []):
                if cond.type == "Ready":
                    result["node_ready"] = cond.status == "True"
                elif cond.status == "True" and cond.type in ("MemoryPressure", "DiskPressure", "PIDPressure"):
                    result.setdefault("node_pressure", []).append(cond.type)
        except Exception:
            logger.debug("Failed to read node %s for pod context", pod.spec.node_name)

    return result


def _strip_timestamp(line: str) -> str:
    """Strip RFC3339 timestamp prefix added by `timestamps=True` to save tokens."""
    parts = line.split(" ", 1)
    if len(parts) == 2 and len(parts[0]) > 18 and "T" in parts[0]:
        return parts[1]
    return line


def _read_container_log(core: k8s.CoreV1Api, pod_name: str, namespace: str,
                         container: str, *, previous: bool, tail_lines: int) -> list[str]:
    """Single read_namespaced_pod_log call wrapped to swallow common errors.

    Returns a list of timestamp-stripped lines, prefixed with a `[current/...]`
    or `[previous/...]` marker so the consumer can tell them apart.
    """
    try:
        raw = core.read_namespaced_pod_log(
            pod_name, namespace,
            container=container, previous=previous,
            tail_lines=tail_lines, timestamps=True,
        )
    except Exception as exc:
        # `previous=True` returns 400 when the container has never restarted
        # (no prior instance to read) — that's expected, not a warning case.
        msg = str(exc).lower()
        if previous and ("previous terminated container" in msg or "not found" in msg):
            logger.debug("No previous instance for %s/%s/%s", namespace, pod_name, container)
        else:
            logger.debug("Failed to read %s logs for %s/%s/%s: %s",
                         "previous" if previous else "current",
                         namespace, pod_name, container, exc)
        return []
    if not raw or not raw.strip():
        return []
    tag = "previous" if previous else "current"
    return [f"[{tag}/{container}] {_strip_timestamp(line)}"
            for line in raw.strip().split("\n")]


def _get_logs(core: k8s.CoreV1Api, pod, namespace: str) -> list[str]:
    """Collect current + previous logs for every container in the pod.

    Multi-container pods always use container=<name> in the API (the K8s
    log endpoint rejects ambiguous calls), and previous logs are pulled
    automatically when restart_count > 0 — this is the most common
    "actual cause was in the previous instance" case for CrashLoopBackOff
    diagnoses.
    """
    if pod is None or not pod.spec or not pod.spec.containers:
        return []
    pod_name = pod.metadata.name
    tail = config.POD_LOG_LINES
    status_map = {cs.name: cs for cs in (pod.status.container_statuses or [])}

    out: list[str] = []
    for c in pod.spec.containers:
        out.extend(_read_container_log(core, pod_name, namespace, c.name,
                                        previous=False, tail_lines=tail))
        cs = status_map.get(c.name)
        if cs and (cs.restart_count or 0) > 0:
            out.extend(_read_container_log(core, pod_name, namespace, c.name,
                                            previous=True,
                                            tail_lines=min(tail, 50)))
    return out


def _get_events(core: k8s.CoreV1Api, pod_name: str, namespace: str) -> list[dict]:
    """Get pod events as list of dicts, sorted newest first."""
    try:
        events = core.list_namespaced_event(
            namespace,
            field_selector=f"involvedObject.name={pod_name}",
        )
        if not events.items:
            return []
        sorted_events = sorted(
            events.items,
            key=lambda x: x.last_timestamp or x.event_time or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )[:20]
        result = []
        for e in sorted_events:
            ev = {
                "type": e.type,
                "reason": e.reason,
                "message": e.message or "",
            }
            ts = e.last_timestamp or e.event_time
            if ts:
                age = _format_age(ts)
                if age:
                    ev["age"] = age
            if e.count and e.count > 1:
                ev["count"] = e.count
            result.append(ev)
        return result
    except Exception:
        logger.debug("Failed to list events for %s/%s", namespace, pod_name)
        return []


def _format_age(ts) -> str:
    """Format a timestamp as relative age string."""
    try:
        if hasattr(ts, 'tzinfo') and ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        delta = now - ts
        total_seconds = int(delta.total_seconds())
        if total_seconds < 60:
            return f"{total_seconds}s"
        if total_seconds < 3600:
            return f"{total_seconds // 60}m"
        if total_seconds < 86400:
            return f"{total_seconds // 3600}h"
        return f"{total_seconds // 86400}d"
    except Exception:
        return ""


def _get_owner_status(pod, apps: k8s.AppsV1Api, namespace: str) -> dict | None:
    """Get owner (Deployment/StatefulSet) status as dict."""
    try:
        for owner in (pod.metadata.owner_references or []):
            if owner.kind == "ReplicaSet":
                rs = apps.read_namespaced_replica_set(owner.name, namespace)
                for rs_owner in (rs.metadata.owner_references or []):
                    if rs_owner.kind == "Deployment":
                        dep = apps.read_namespaced_deployment(rs_owner.name, namespace)
                        return _extract_deployment_status(dep)
            elif owner.kind == "StatefulSet":
                sts = apps.read_namespaced_stateful_set(owner.name, namespace)
                return _extract_statefulset_status(sts)
    except Exception:
        logger.debug("Failed to get owner for %s/%s", namespace, pod.metadata.name)
    return None


def _extract_deployment_status(dep) -> dict:
    """Extract deployment status as dict."""
    s = dep.status
    result = {
        "kind": "Deployment",
        "name": dep.metadata.name,
        "desired": s.replicas or 0,
        "ready": s.ready_replicas or 0,
        "updated": s.updated_replicas or 0,
        "unavailable": s.unavailable_replicas or 0,
    }
    warnings = []
    if s.observed_generation and dep.metadata.generation:
        if s.observed_generation < dep.metadata.generation:
            warnings.append(f"observedGeneration={s.observed_generation} < generation={dep.metadata.generation}")
    for cond in (s.conditions or []):
        if cond.type == "Progressing" and cond.status != "True":
            warnings.append(f"Progressing={cond.status}")
        elif cond.type == "Available" and cond.status != "True":
            warnings.append(f"Available={cond.status}")
        elif cond.type == "ReplicaFailure" and cond.status == "True":
            warnings.append(f"ReplicaFailure: {cond.message}")
    if warnings:
        result["warnings"] = warnings
    return result


def _extract_statefulset_status(sts) -> dict:
    """Extract statefulset status as dict."""
    s = sts.status
    result = {
        "kind": "StatefulSet",
        "name": sts.metadata.name,
        "desired": s.replicas or 0,
        "ready": s.ready_replicas or 0,
        "current": s.current_replicas or 0,
        "updated": s.updated_replicas or 0,
    }
    warnings = []
    if s.current_revision and s.update_revision and s.current_revision != s.update_revision:
        warnings.append(f"rollout in progress: {s.current_revision} -> {s.update_revision}")
    if s.observed_generation and sts.metadata.generation:
        if s.observed_generation < sts.metadata.generation:
            warnings.append(f"observedGeneration={s.observed_generation} < generation={sts.metadata.generation}")
    for cond in (s.conditions or []):
        if cond.status == "True" and cond.type not in ("Ready",):
            warnings.append(f"{cond.type}: {cond.message}")
    if warnings:
        result["warnings"] = warnings
    return result


# In-memory cache for node metrics to avoid hammering Prometheus during
# mass alerts. Uses per-node single-flight: the first thread for a node
# acquires the per-node lock, fetches, and populates the cache; concurrent
# threads block on the same lock and read the cached value when it's released.
_NODE_METRICS_TTL_SEC = 300  # 5 minutes — fresh window
_NODE_METRICS_STALE_MAX_AGE_SEC = 1800  # 30 minutes — hard cap on serving stale
_NODE_SINGLEFLIGHT_TIMEOUT_SEC = 60  # don't block forever on a stuck fetch
_node_metrics_cache: dict[str, tuple[float, dict]] = {}  # {node: (ts, metrics)}
_node_inflight_locks: dict[str, threading.Lock] = {}
_node_cache_lock = threading.Lock()  # guards both maps above


def _node_singleflight_lock(node_name: str) -> threading.Lock:
    with _node_cache_lock:
        lock = _node_inflight_locks.get(node_name)
        if lock is None:
            lock = threading.Lock()
            _node_inflight_locks[node_name] = lock
        return lock


def _drop_inflight_lock(node_name: str) -> None:
    """Best-effort cleanup of the per-node lock once the cache is populated.

    Safe under races: if a waiter still holds a reference to the popped lock,
    they'll release it normally and a fresh lock will be created on demand.
    """
    with _node_cache_lock:
        _node_inflight_locks.pop(node_name, None)


def _read_cached_node_metrics(node_name: str, *, allow_stale: bool = False) -> dict | None:
    with _node_cache_lock:
        entry = _node_metrics_cache.get(node_name)
        if entry is None:
            return None
        ts, cached = entry
        age = time.time() - ts
        if age < _NODE_METRICS_TTL_SEC:
            return cached
        # Beyond fresh TTL: only allow if stale fetch is requested AND we
        # haven't exceeded the hard stale cap. Beyond the stale cap, even
        # stale serving is refused so the caller falls back to the Metrics API.
        if allow_stale and age < _NODE_METRICS_STALE_MAX_AGE_SEC:
            return cached
    return None


def _get_node_metrics(pod, core: k8s.CoreV1Api) -> dict | None:
    """Get node metrics as dict with per-node single-flight 5-min caching."""
    if not pod.spec.node_name:
        return None

    node_name = pod.spec.node_name

    # Fast path: fresh cache hit, no lock contention beyond the dict read.
    cached = _read_cached_node_metrics(node_name)
    if cached is not None:
        return cached

    # Single-flight with bounded wait — never block forever on a stuck fetch.
    lock = _node_singleflight_lock(node_name)
    acquired = lock.acquire(timeout=_NODE_SINGLEFLIGHT_TIMEOUT_SEC)
    if not acquired:
        logger.warning("Node metrics single-flight timed out for %s after %ds — proceeding without coordination",
                       node_name, _NODE_SINGLEFLIGHT_TIMEOUT_SEC)
        # Fall through and fetch directly; better to make a redundant
        # Prometheus call than to block the alert pipeline.
        return _fetch_node_metrics_uncached(node_name, core)

    try:
        # Re-check after acquiring — another thread may have populated it.
        cached = _read_cached_node_metrics(node_name)
        if cached is not None:
            return cached
        result = _fetch_node_metrics_uncached(node_name, core)
        if result:
            with _node_cache_lock:
                _node_metrics_cache[node_name] = (time.time(), result)
            return result
        # Fetch failed — return stale data (if still within stale_max cap)
        # WITHOUT touching the cache entry. Re-aging the timestamp here would
        # let the same payload live forever as long as Prometheus stays down.
        # The stale_max cap in _read_cached_node_metrics is the upper bound on
        # how long the original entry can keep being served.
        stale = _read_cached_node_metrics(node_name, allow_stale=True)
        return stale
    finally:
        lock.release()
        # Drop the inflight lock after release so the dict doesn't grow
        # unbounded with one Lock object per node ever seen. Safe under races
        # because waiters held a strong reference before we popped.
        _drop_inflight_lock(node_name)


def _fetch_node_metrics_uncached(node_name: str, core: k8s.CoreV1Api) -> dict | None:
    """Resolve node IP and query Prometheus / Metrics API. No caching."""
    node_ip = ""
    try:
        node = core.read_node(node_name)
        for addr in (node.status.addresses or []):
            if addr.type == "InternalIP":
                node_ip = addr.address
                break
    except Exception:
        logger.debug("Failed to resolve internal IP for node %s", node_name)

    prom = _query_node_exporter_metrics_dict(node_name, node_ip)
    if prom:
        return prom

    logger.warning(
        "Prometheus node_exporter metrics unavailable for node %s (ip=%s, prometheus_url=%s), falling back to Metrics API",
        node_name, node_ip or "<empty>", config.PROMETHEUS_URL,
    )
    return _query_metrics_api_node(node_name, core, node_ip)


def _query_node_exporter_metrics_dict(node_name: str, node_ip: str) -> dict | None:
    """Query node_exporter metrics from Prometheus, return dict."""
    if not config.PROMETHEUS_URL or not node_ip:
        return None

    inst = f"{node_ip}:.*"
    result = {}

    cpu_pct = prom_scalar(
        f'100 - (avg(rate(node_cpu_seconds_total{{mode="idle",instance=~"{inst}"}}[5m])) * 100)'
    )
    if cpu_pct is not None:
        result["cpu_pct"] = round(cpu_pct, 1)

    mem_total = prom_scalar(f'node_memory_MemTotal_bytes{{instance=~"{inst}"}}')
    mem_avail = prom_scalar(f'node_memory_MemAvailable_bytes{{instance=~"{inst}"}}')
    if mem_total and mem_avail is not None:
        mem_used = mem_total - mem_avail
        result["mem_pct"] = round(mem_used / mem_total * 100, 1)
        result["mem_used"] = fmt_bytes(mem_used)
        result["mem_total"] = fmt_bytes(mem_total)

    fs_size = prom_scalar(f'node_filesystem_size_bytes{{instance=~"{inst}",mountpoint="/",fstype!~"tmpfs|overlay"}}')
    fs_avail = prom_scalar(f'node_filesystem_avail_bytes{{instance=~"{inst}",mountpoint="/",fstype!~"tmpfs|overlay"}}')
    if fs_size and fs_avail is not None:
        fs_used = fs_size - fs_avail
        result["disk_pct"] = round(fs_used / fs_size * 100, 1)
    else:
        btrfs_total = prom_scalar(f'node_btrfs_device_size_bytes{{instance=~"{inst}"}}')
        btrfs_used = prom_scalar(f'sum(node_btrfs_used_bytes{{instance=~"{inst}"}})')
        if btrfs_total and btrfs_used is not None:
            result["disk_pct"] = round(btrfs_used / btrfs_total * 100, 1)

    return result if result else None


def _query_metrics_api_node(node_name: str, core: k8s.CoreV1Api, node_ip: str) -> dict | None:
    """Fallback: query Metrics API for node usage."""
    alloc_cpu_m = None
    alloc_mem_mi = None
    try:
        node = core.read_node(node_name)
        alloc = node.status.allocatable or {}
        alloc_cpu_m = parse_cpu(alloc.get("cpu", ""))
        alloc_mem_mi = parse_memory_mi(alloc.get("memory", ""))
    except Exception:
        logger.warning("Failed to read node allocatable for %s", node_name, exc_info=True)

    try:
        metrics_api = k8s.CustomObjectsApi()
        node_metrics = metrics_api.get_cluster_custom_object(
            "metrics.k8s.io", "v1beta1", "nodes", node_name,
        )
        usage = node_metrics.get("usage", {})
        usage_cpu_m = parse_cpu(usage.get("cpu", ""))
        usage_mem_mi = parse_memory_mi(usage.get("memory", ""))
        result = {}
        if usage_cpu_m is not None and alloc_cpu_m:
            result["cpu_pct"] = round(usage_cpu_m / alloc_cpu_m * 100, 1)
        if usage_mem_mi is not None and alloc_mem_mi:
            result["mem_pct"] = round(usage_mem_mi / alloc_mem_mi * 100, 1)
            result["mem_used"] = fmt_mem(usage_mem_mi)
            result["mem_total"] = fmt_mem(alloc_mem_mi)
        return result if result else None
    except Exception:
        logger.warning("Metrics API also failed for node %s", node_name, exc_info=True)
        return None


def _get_app_metrics(pod_name: str, namespace: str) -> dict | None:
    """Query app metrics from Prometheus as structured dict for LLM context.

    Returns dict with event loop, heap, RSS, CPU, GC metrics — or None.
    """
    if not config.PROMETHEUS_URL:
        return None

    labels = f'namespace="{namespace}",pod="{pod_name}"'
    result: dict = {}

    el_lag = prom_scalar(f'nodejs_eventloop_lag_p99_seconds{{{labels}}}')
    if el_lag is not None:
        result["eventloop_p99_ms"] = round(el_lag * 1000, 1)

    heap_used = prom_scalar(f'nodejs_heap_size_used_bytes{{{labels}}}')
    heap_total = prom_scalar(f'nodejs_heap_size_total_bytes{{{labels}}}')
    if heap_used is not None:
        result["heap_used"] = fmt_bytes(heap_used)
        if heap_total is not None:
            result["heap_total"] = fmt_bytes(heap_total)
            result["heap_pct"] = round(heap_used / heap_total * 100, 1) if heap_total else 0.0
            # Heap trend over 1h
            heap_1h = prom_scalar(f'nodejs_heap_size_used_bytes{{{labels}}} offset 1h')
            if heap_1h and heap_1h > 0:
                change = (heap_used - heap_1h) / heap_1h * 100
                if abs(change) > 20:
                    result["heap_1h_change_pct"] = round(change, 0)

    rss = prom_scalar(f'process_resident_memory_bytes{{{labels}}}')
    if rss is not None:
        result["rss"] = fmt_bytes(rss)

    cpu = prom_scalar(f'rate(process_cpu_seconds_total{{{labels}}}[5m])')
    if cpu is not None:
        result["cpu_cores"] = round(cpu, 2)

    gc = prom_scalar(f'rate(nodejs_gc_duration_seconds_sum{{{labels}}}[5m])')
    if gc is not None:
        result["gc_ms_per_sec"] = round(gc * 1000, 1)

    return result if result else None


def query_app_metrics(pod_name: str, namespace: str) -> str | None:
    """Query Node.js application metrics from Prometheus.

    Kept for backward compat (used by get_app_metrics_summary which is separate).
    Not used in the LLM alert path anymore.
    """
    if not config.PROMETHEUS_URL:
        return None

    labels = f'namespace="{namespace}",pod="{pod_name}"'
    lines = []
    has_data = False

    el_lag = prom_scalar(f'nodejs_eventloop_lag_p99_seconds{{{labels}}}')
    if el_lag is not None:
        lines.append(f"Event Loop p99: {el_lag * 1000:.1f}ms")
        has_data = True

    heap_used = prom_scalar(f'nodejs_heap_size_used_bytes{{{labels}}}')
    heap_total = prom_scalar(f'nodejs_heap_size_total_bytes{{{labels}}}')
    if heap_used is not None and heap_total:
        heap_pct = heap_used / heap_total * 100
        lines.append(f"Heap: {fmt_bytes(heap_used)}/{fmt_bytes(heap_total)} ({heap_pct:.1f}%)")
        has_data = True
        heap_used_1h_ago = prom_scalar(f'nodejs_heap_size_used_bytes{{{labels}}} offset 1h')
        if heap_used_1h_ago and heap_used_1h_ago > 0:
            heap_change_pct = (heap_used - heap_used_1h_ago) / heap_used_1h_ago * 100
            if abs(heap_change_pct) > 20:
                lines.append(f"Heap trend (1h): {fmt_bytes(heap_used_1h_ago)} \u2192 {fmt_bytes(heap_used)} ({heap_change_pct:+.0f}%)")
    elif heap_used is not None:
        lines.append(f"Heap: {fmt_bytes(heap_used)}")
        has_data = True

    rss = prom_scalar(f'process_resident_memory_bytes{{{labels}}}')
    if rss is not None:
        lines.append(f"RSS: {fmt_bytes(rss)}")
        has_data = True

    cpu = prom_scalar(f'rate(process_cpu_seconds_total{{{labels}}}[5m])')
    if cpu is not None:
        lines.append(f"CPU: {cpu:.2f} cores")
        has_data = True

    gc = prom_scalar(f'rate(nodejs_gc_duration_seconds_sum{{{labels}}}[5m])')
    if gc is not None:
        lines.append(f"GC: {gc * 1000:.1f}ms/s")
        has_data = True

    active_result = prom_query(f'nodejs_active_resources{{{labels}}}')
    if active_result:
        resource_counts = []
        for r in active_result:
            rtype = r["metric"].get("type", "unknown")
            count = int(float(r["value"][1]))
            if count > 0:
                resource_counts.append(f"{rtype}={count}")
        if resource_counts:
            lines.append(f"Active Resources: {', '.join(resource_counts)}")

    if not has_data:
        return None
    return "## Application Metrics\n" + "\n".join(lines)

"""Endpoint scanner — extracted from main._scan_endpoints."""
import logging
import re
import time
from datetime import datetime, timezone

import urllib3
import requests as http_requests

from kubernetes import client as k8s

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from src import config
from src.collectors import Collector
from src.scanners._base import ScanResult

logger = logging.getLogger(__name__)

# Type alias for node cache: node_name -> (is_ready, is_marked_for_deletion)
NodeCache = dict[str, tuple[bool, bool]]


def _build_node_cache() -> NodeCache:
    """Build a cache of node status from a single list_node() call."""
    cache: NodeCache = {}
    try:
        core = k8s.CoreV1Api()
        nodes = core.list_node()
        for node in nodes.items:
            name = node.metadata.name
            is_ready = True
            for cond in ((node.status.conditions or []) if node.status else []):
                if cond.type == "Ready":
                    is_ready = cond.status == "True"
                    break
            marked = False
            if node.metadata.deletion_timestamp is not None:
                marked = True
            else:
                for taint in (node.spec.taints or []):
                    if taint.key in ("cloud.google.com/impending-node-termination",
                                     "ToBeDeletedByClusterAutoscaler"):
                        marked = True
                        break
                if not marked and node.spec.unschedulable:
                    marked = True
            cache[name] = (is_ready, marked)
    except Exception:
        logger.warning("Endpoint scanner: failed to build node cache", exc_info=True)
    return cache


def _all_backends_on_bad_nodes(
    core: k8s.CoreV1Api, service_name: str, ns: str, node_cache: NodeCache,
) -> bool:
    """Return True if ALL backend pods for a service are on cordoned/NotReady nodes.

    Returns False on any error (safe fallback — probe will run).
    """
    if not node_cache:
        return False
    try:
        svc = core.read_namespaced_service(service_name, ns)
        selector = svc.spec.selector
        if not selector:
            return False
        label_sel = ",".join(f"{k}={v}" for k, v in selector.items())
        pods = core.list_namespaced_pod(ns, label_selector=label_sel)
        if not pods.items:
            return False
        for pod in pods.items:
            node_name = pod.spec.node_name
            if not node_name:
                return False  # unscheduled pod — can't determine
            is_ready, is_marked = node_cache.get(node_name, (True, False))
            if is_ready and not is_marked:
                return False  # at least one pod on a healthy node
        return True
    except Exception:
        logger.debug("Failed to check backends on bad nodes for %s/%s", ns, service_name, exc_info=True)
        return False


def _is_rolling_update(
    apps_api: k8s.AppsV1Api, service_name: str, ns: str, core: k8s.CoreV1Api,
) -> bool:
    """Return True if the deployment backing the service is in a rolling update."""
    try:
        svc = core.read_namespaced_service(service_name, ns)
        selector = svc.spec.selector
        if not selector:
            return False
        label_sel = ",".join(f"{k}={v}" for k, v in selector.items())
        deploys = apps_api.list_namespaced_deployment(ns, label_selector=label_sel)
        if not deploys.items:
            # Fallback: try by service name
            try:
                deploy = apps_api.read_namespaced_deployment(service_name, ns)
                deploys_list = [deploy]
            except Exception:
                logger.debug("Failed to read deployment %s/%s by name", ns, service_name, exc_info=True)
                return False
        else:
            deploys_list = deploys.items
        for deploy in deploys_list:
            for cond in (deploy.status.conditions or []):
                if cond.type == "Progressing" and cond.reason in (
                    "ReplicaSetUpdated", "NewReplicaSetCreated",
                ):
                    return True
        return False
    except Exception:
        logger.debug("Failed to check rolling update for %s/%s", ns, service_name, exc_info=True)
        return False


def _parse_status_range(range_str: str) -> tuple[int, int]:
    m = re.match(r"^(\d{3})-(\d{3})$", range_str.strip())
    if m:
        return int(m.group(1)), int(m.group(2))
    m = re.match(r"^(\d{3})$", range_str.strip())
    if m:
        code = int(m.group(1))
        return code, code
    return 200, 399


_PROBE_RETRIES = 3
_PROBE_RETRY_DELAY = 2  # seconds between retries


def _probe_url(url: str, headers: dict, verify: bool) -> tuple[int | None, str, float, str]:
    last_reason = ""
    for attempt in range(_PROBE_RETRIES):
        try:
            resp = http_requests.get(
                url,
                headers=headers,
                timeout=config.ENDPOINT_SCAN_TIMEOUT,
                verify=verify,
                allow_redirects=False,
            )
            return resp.status_code, resp.reason, resp.elapsed.total_seconds(), resp.text
        except http_requests.Timeout:
            last_reason = f"Timeout after {config.ENDPOINT_SCAN_TIMEOUT}s"
        except http_requests.ConnectionError as e:
            last_reason = f"Connection error: {e}"
        except Exception as e:
            logger.warning("Endpoint probe %s unexpected error: %s", url, e, exc_info=True)
            return None, f"Request failed: {e}", 0.0, ""
        if attempt < _PROBE_RETRIES - 1:
            logger.debug("Endpoint probe %s attempt %d failed (%s), retrying in %ds",
                         url, attempt + 1, last_reason, _PROBE_RETRY_DELAY)
            time.sleep(_PROBE_RETRY_DELAY)
    return None, f"{last_reason} (after {_PROBE_RETRIES} attempts)", 0.0, ""


def _probe_backend_pods(
    core: k8s.CoreV1Api,
    service_name: str,
    ns: str,
    limit: int = 3,
) -> list[tuple[str, str, int | None, str, float]]:
    """Probe backend pods directly on their first container port.

    Returns a list of (pod_name, pod_ip, status_code, reason, elapsed) — at
    most ``limit`` entries. Returns an empty list on any lookup failure; the
    caller then skips the pod section entirely.
    """
    results: list[tuple[str, str, int | None, str, float]] = []
    try:
        svc = core.read_namespaced_service(service_name, ns)
        selector = svc.spec.selector
        if not selector:
            return results
        label_sel = ",".join(f"{k}={v}" for k, v in selector.items())
        pods = core.list_namespaced_pod(ns, label_selector=label_sel)
    except Exception as exc:
        logger.debug(
            "Failed to list backend pods for chain probe %s/%s: %s",
            ns, service_name, exc, exc_info=True,
        )
        return results

    timeout = min(config.ENDPOINT_SCAN_TIMEOUT, 5)
    for pod in (pods.items or [])[:limit]:
        pod_ip = pod.status.pod_ip if pod.status else ""
        if not pod_ip:
            continue
        port: int | None = None
        for c in (pod.spec.containers or []):
            for cp in (c.ports or []):
                if cp.container_port:
                    port = cp.container_port
                    break
            if port:
                break
        if not port:
            continue
        url = f"http://{pod_ip}:{port}/"
        start = time.time()
        try:
            resp = http_requests.get(url, timeout=timeout, allow_redirects=False)
            elapsed = time.time() - start
            results.append((pod.metadata.name, pod_ip, resp.status_code,
                            resp.reason or "", elapsed))
        except http_requests.Timeout:
            results.append((pod.metadata.name, pod_ip, None,
                            f"timeout after {timeout}s", time.time() - start))
        except http_requests.ConnectionError as exc:
            results.append((pod.metadata.name, pod_ip, None,
                            f"connect error: {exc}", time.time() - start))
        except Exception as exc:
            logger.debug("Backend pod probe %s/%s failed: %s",
                         pod.metadata.name, pod_ip, exc, exc_info=True)
            # Record the failed attempt so the Probe Chain still shows which
            # pod was tried and why — otherwise unexpected failures disappear
            # silently from the alert while Timeout/ConnectionError don't.
            results.append((pod.metadata.name, pod_ip, None,
                            f"probe error: {exc}", time.time() - start))
    return results


def _build_probe_chain_section(
    url: str, status_code: int | None, reason: str, elapsed: float,
    pod_probes: list[tuple[str, str, int | None, str, float]],
) -> str:
    """Render the layered probe chain (service + backend pods) as markdown."""
    lines = ["## Probe Chain"]
    svc_status = (f"HTTP {status_code} ({reason})" if status_code
                  else f"ERROR ({reason})")
    lines.append(f"  service   {url}  \u2192  {svc_status}  ({elapsed:.2f}s)")
    for pod_name, pod_ip, code, p_reason, p_elapsed in pod_probes:
        status = (f"HTTP {code}" if code
                  else (p_reason[:40] or "ERROR"))
        lines.append(
            f"    pod/{pod_name} ({pod_ip})  \u2192  {status}  ({p_elapsed:.2f}s)"
        )
    return "\n".join(lines)


def _build_endpoint_context(
    ns: str, ingress_name: str, host: str, url: str,
    status_code: int | None, reason: str, elapsed: float,
    body: str, service_name: str, service_ns: str,
    collector: Collector | None = None,
) -> str:
    sections = []

    core = k8s.CoreV1Api()
    if service_name and service_ns:
        pod_probes = _probe_backend_pods(core, service_name, service_ns)
        if pod_probes:
            sections.append(_build_probe_chain_section(
                url, status_code, reason, elapsed, pod_probes,
            ))

    lines = [
        "## Endpoint Health Check Failed",
        f"Ingress: {ns}/{ingress_name}",
        f"Host: {host}",
        f"URL: {url}",
        f"HTTP Status: {status_code} ({reason})" if status_code else f"Error: {reason}",
        f"Response Time: {elapsed:.2f}s",
    ]
    if body:
        from src.engine.sanitizer import redact_response_body
        lines.append(f"Response Body (first 500 chars):\n```\n{redact_response_body(body)}\n```")
    sections.append("\n".join(lines))

    if service_name and service_ns:
        apps = k8s.AppsV1Api()
        try:
            ep = core.read_namespaced_endpoints(service_name, service_ns)
            ep_addrs = []
            for subset in (ep.subsets or []):
                for addr in (subset.addresses or []):
                    ep_addrs.append(addr.ip)
            not_ready = []
            for subset in (ep.subsets or []):
                for addr in (subset.not_ready_addresses or []):
                    not_ready.append(addr.ip)
            ep_section = f"## Backend Service\nService: {service_ns}/{service_name}\n"
            if ep_addrs:
                ep_section += f"Ready Endpoints: {', '.join(ep_addrs)}\n"
            else:
                ep_section += "Ready Endpoints: NONE (no healthy backends!)\n"
            if not_ready:
                ep_section += f"Not-Ready Endpoints: {', '.join(not_ready)}\n"
            sections.append(ep_section)
        except Exception:
            sections.append(f"## Backend Service\nService: {service_ns}/{service_name}\nEndpoints: unavailable")

        # Service port mapping (port → targetPort)
        selector = None
        try:
            svc = core.read_namespaced_service(service_name, service_ns)
            selector = svc.spec.selector
            if svc.spec.ports:
                port_lines = []
                for sp in svc.spec.ports:
                    target = sp.target_port if sp.target_port else sp.port
                    port_lines.append(f"  {sp.name or 'unnamed'}: port={sp.port} → targetPort={target} ({sp.protocol or 'TCP'})")
                sections.append("## Service Port Mapping\n" + "\n".join(port_lines))
        except Exception:
            logger.debug("Failed to read service %s/%s", service_ns, service_name)

        # Backend pods with container ports
        try:
            if selector:
                label_selector = ",".join(f"{k}={v}" for k, v in selector.items())
                pods = core.list_namespaced_pod(service_ns, label_selector=label_selector)
                pod_lines = []
                for pod in pods.items:
                    phase = pod.status.phase if pod.status else "Unknown"
                    statuses = pod.status.container_statuses or []
                    if not statuses:
                        ready = "Unknown"
                    else:
                        ready_count = sum(1 for cs in statuses if cs.ready)
                        ready = f"{ready_count}/{len(statuses)}"
                    restarts = sum(cs.restart_count for cs in statuses)
                    # Container ports
                    container_ports = []
                    for c in (pod.spec.containers or []):
                        for cp in (c.ports or []):
                            container_ports.append(f"{cp.container_port}/{cp.protocol or 'TCP'}")
                    ports_str = f", Ports=[{', '.join(container_ports)}]" if container_ports else ""
                    pod_lines.append(f"  {pod.metadata.name}: Phase={phase}, Ready={ready}, Restarts={restarts}{ports_str}")
                if pod_lines:
                    sections.append("## Backend Pods\n" + "\n".join(pod_lines))
        except Exception:
            logger.debug("Failed to list backend pods for %s/%s", service_ns, service_name)

        # Deployment rollout status (critical for understanding deploy-related failures)
        try:
            if selector:
                label_selector = ",".join(f"{k}={v}" for k, v in selector.items())
                deploys = apps.list_namespaced_deployment(service_ns, label_selector=label_selector)
                if not deploys.items:
                    try:
                        deploy = apps.read_namespaced_deployment(service_name, service_ns)
                        deploys_list = [deploy]
                    except Exception:
                        deploys_list = []
                else:
                    deploys_list = deploys.items
                for deploy in deploys_list:
                    status = deploy.status
                    spec_replicas = deploy.spec.replicas or 1
                    ready_replicas = status.ready_replicas or 0
                    updated_replicas = status.updated_replicas or 0
                    unavailable = status.unavailable_replicas or 0
                    deploy_lines = [
                        f"Deployment: {service_ns}/{deploy.metadata.name}",
                        f"Replicas: {spec_replicas} desired, {ready_replicas} ready, {updated_replicas} updated, {unavailable} unavailable",
                    ]
                    # Check Progressing condition — most reliable rolling update signal
                    for cond in (status.conditions or []):
                        if cond.type == "Progressing":
                            # reason=NewReplicaSetAvailable → done; reason=ReplicaSetUpdated → in progress
                            if cond.reason in ("ReplicaSetUpdated", "NewReplicaSetCreated"):
                                deploy_lines.append(f"Status: ROLLING UPDATE IN PROGRESS (reason={cond.reason})")
                            elif cond.reason == "NewReplicaSetAvailable":
                                ts = cond.last_transition_time
                                if ts:
                                    age = (datetime.now(timezone.utc) - ts.replace(tzinfo=timezone.utc if ts.tzinfo is None else ts.tzinfo)).total_seconds()
                                    deploy_lines.append(f"Last deploy completed: {age:.0f}s ago ({ts.isoformat()})")
                            elif cond.reason == "ProgressDeadlineExceeded":
                                deploy_lines.append("Status: DEPLOY FAILED — ProgressDeadlineExceeded")
                        elif cond.type == "Available":
                            if cond.status != "True":
                                deploy_lines.append(f"Available: FALSE (reason={cond.reason}, message={cond.message})")
                    # Container image (helps identify what version is deployed)
                    for c in (deploy.spec.template.spec.containers or []):
                        deploy_lines.append(f"Image: {c.image}")
                    # Active ReplicaSets — shows old vs new during rollout
                    try:
                        dep_selector = deploy.spec.selector.match_labels or {}
                        rs_label_sel = ",".join(f"{k}={v}" for k, v in dep_selector.items())
                        rsets = apps.list_namespaced_replica_set(service_ns, label_selector=rs_label_sel)
                        active_rs = [rs for rs in rsets.items if (rs.status.replicas or 0) > 0]
                        if len(active_rs) > 1:
                            deploy_lines.append("MULTIPLE ACTIVE REPLICASETS (rolling update):")
                        for rs in active_rs:
                            rs_replicas = rs.status.replicas or 0
                            rs_ready = rs.status.ready_replicas or 0
                            revision = (rs.metadata.annotations or {}).get("deployment.kubernetes.io/revision", "?")
                            # Get image from RS template to show old vs new version
                            rs_images = [c.image for c in (rs.spec.template.spec.containers or [])]
                            img_str = f", image={rs_images[0]}" if rs_images else ""
                            deploy_lines.append(f"  {rs.metadata.name}: replicas={rs_replicas}, ready={rs_ready}, revision={revision}{img_str}")
                    except Exception:
                        logger.debug("Failed to inspect ReplicaSets for %s/%s", service_ns, deploy.metadata.name)
                    sections.append("## Deployment Status\n" + "\n".join(deploy_lines))
        except Exception:
            logger.debug("Failed to check deployment status for %s/%s", service_ns, service_name)

        try:
            events = core.list_namespaced_event(
                service_ns,
                field_selector=f"involvedObject.name={service_name}",
            )
            if events.items:
                ev_lines = []
                for e in sorted(events.items, key=lambda x: x.last_timestamp or x.event_time or datetime.min.replace(tzinfo=timezone.utc), reverse=True)[:10]:
                    ts = e.last_timestamp or e.event_time or "?"
                    ev_lines.append(f"  [{e.type}] {ts} \u2014 {e.reason}: {e.message}")
                sections.append("## Recent Events\n" + "\n".join(ev_lines))
        except Exception:
            logger.debug("Failed to list events for %s/%s", service_ns, service_name)

        try:
            if selector:
                label_selector = ",".join(f"{k}={v}" for k, v in selector.items())
                pods = core.list_namespaced_pod(service_ns, label_selector=label_selector)
                for pod in pods.items:
                    try:
                        logs = core.read_namespaced_pod_log(
                            pod.metadata.name, service_ns,
                            tail_lines=50, timestamps=True,
                        )
                        if logs.strip():
                            sections.append(f"## Pod Logs ({pod.metadata.name})\n```\n{logs}\n```")
                    except Exception:
                        logger.debug("Failed to read logs for pod %s/%s", service_ns, pod.metadata.name)

                    for cs in (pod.status.container_statuses or []):
                        if cs.restart_count > 0:
                            try:
                                prev = core.read_namespaced_pod_log(
                                    pod.metadata.name, service_ns,
                                    container=cs.name, previous=True, tail_lines=30,
                                )
                                if prev.strip():
                                    sections.append(f"## Previous Logs ({pod.metadata.name}/{cs.name})\n```\n{prev}\n```")
                            except Exception:
                                logger.debug("Failed to read previous logs for %s/%s/%s", service_ns, pod.metadata.name, cs.name)

                    if collector:
                        app_metrics = collector._query_app_metrics(pod.metadata.name, service_ns)
                        if app_metrics:
                            sections.append(app_metrics)

                    break
        except Exception:
            logger.debug("Failed to collect pod logs for %s/%s", service_ns, service_name)

    return "\n\n".join(sections)


def _build_batch_endpoint_context(ns: str, unhealthy: list[tuple[str, str, str, str]]) -> str:
    """Build combined context for a batch of unhealthy endpoints.

    Each item in unhealthy is (host, service_name, status_str, state_key).
    """
    lines = [f"## Batch Endpoint Alert: {len(unhealthy)} unhealthy in {ns}\n"]
    for host, service_name, status_str, _ in unhealthy:
        lines.append(f"- {host} → {service_name}: {status_str}")
    lines.append("\nMultiple endpoints failing simultaneously — likely node replacement, "
                 "ingress controller restart, or network-level issue.")
    return "\n".join(lines)


class EndpointScanner:
    name = "endpoint"
    startup_delay = 30

    @property
    def enabled(self):
        return config.ENDPOINT_SCAN_ENABLED

    @property
    def interval_seconds(self):
        return config.ENDPOINT_SCAN_INTERVAL_SECONDS

    def scan(self) -> list[ScanResult]:
        networking = k8s.NetworkingV1Api()
        core = k8s.CoreV1Api()
        apps = k8s.AppsV1Api()
        collector = Collector()
        results: list[ScanResult] = []
        probed = 0
        skipped_grpc = 0
        skipped_disabled = 0
        skipped_node = 0
        # Track which services already have an unhealthy result (service-level dedup)
        _alerted_services: set[str] = set()
        _probed_hosts: list[str] = []
        # Collect unhealthy endpoints per namespace for batching
        _unhealthy_by_ns: dict[str, list[tuple[str, str, str, str, ScanResult]]] = {}
        # Build node cache once per scan cycle
        node_cache = _build_node_cache()
        # Track which namespaces were probed (for batch auto-resolve)
        _probed_namespaces: set[str] = set()

        for ns in config.get_namespaces():
            try:
                ingresses = networking.list_namespaced_ingress(ns)
            except Exception:
                logger.exception("Endpoint scanner: failed to list ingresses in %s", ns)
                continue

            for ingress in ingresses.items:
                annotations = ingress.metadata.annotations or {}

                if annotations.get("k8s-ai-monitor/probe", "true").lower() == "false":
                    skipped_disabled += 1
                    continue

                backend_protocol = annotations.get("nginx.ingress.kubernetes.io/backend-protocol", "").upper()
                if backend_protocol in ("GRPC", "GRPCS"):
                    skipped_grpc += 1
                    continue

                custom_probe_path = annotations.get("k8s-ai-monitor/probe-path")
                expected_range = annotations.get("k8s-ai-monitor/expected-status", "200-499")
                expected_low, expected_high = _parse_status_range(expected_range)

                no_auth = annotations.get("nginx.ingress.kubernetes.io/enable-global-auth", "").lower() == "false"

                for rule in (ingress.spec.rules or []):
                    host = rule.host
                    if not host:
                        continue

                    service_name = ""
                    service_port = None
                    service_ns = ns
                    ingress_path = "/"
                    if rule.http and rule.http.paths:
                        path_entry = rule.http.paths[0]
                        ingress_path = path_entry.path or "/"
                        backend = path_entry.backend
                        if backend.service:
                            service_name = backend.service.name
                            if backend.service.port:
                                if backend.service.port.number:
                                    service_port = backend.service.port.number
                                elif backend.service.port.name:
                                    # Resolve named port to numeric via Service spec
                                    try:
                                        svc_obj = core.read_namespaced_service(service_name, ns)
                                        for sp in (svc_obj.spec.ports or []):
                                            if sp.name == backend.service.port.name:
                                                service_port = sp.port
                                                break
                                    except Exception:
                                        logger.debug("Failed to resolve named port %s for %s/%s",
                                                     backend.service.port.name, ns, service_name)

                    if not service_name:
                        continue

                    # Pre-probe skip: if ALL backend pods are on bad nodes, skip probe
                    if _all_backends_on_bad_nodes(core, service_name, ns, node_cache):
                        skipped_node += 1
                        logger.debug("Endpoint %s/%s — all backends on bad nodes, skipping probe",
                                     ns, service_name)
                        continue

                    probed += 1
                    _probed_hosts.append(f"{host}→{service_name}")
                    _probed_namespaces.add(ns)

                    probe_path = custom_probe_path if custom_probe_path is not None else ingress_path
                    port_suffix = f":{service_port}" if service_port else ""
                    url = f"http://{service_name}.{ns}.svc.cluster.local{port_suffix}{probe_path}"
                    status_code, reason, elapsed, body = _probe_url(url, {}, True)
                    logger.debug("Endpoint probe: %s/%s (%s) \u2192 %s %s (%.2fs)",
                                 ns, service_name, host, status_code or "ERR", reason, elapsed)

                    if no_auth and config.ENDPOINT_INGRESS_SERVICE:
                        ingress_url = f"https://{config.ENDPOINT_INGRESS_SERVICE}{probe_path}"
                        ing_status, ing_reason, ing_elapsed, ing_body = _probe_url(
                            ingress_url, {"Host": host}, False,
                        )
                        if status_code is not None and (ing_status is None or ing_status < 200 or ing_status > 399):
                            status_code, reason, elapsed, body = ing_status, ing_reason, ing_elapsed, ing_body
                            url = ingress_url

                    is_healthy = (
                        status_code is not None
                        and expected_low <= status_code <= expected_high
                    )

                    state_key = f"Endpoint:{ns}/{ingress.metadata.name}:{host}"
                    svc_key = f"{ns}/{service_name}"

                    if is_healthy:
                        # Auto-resolve
                        results.append(ScanResult(
                            state_key=state_key,
                            title=f"Endpoint Recovered: {host}",
                            severity="info",
                            resource=f"Ingress/{ingress.metadata.name}",
                            namespace=ns,
                            issue_type="endpoint",
                            auto_resolve=True,
                        ))
                        continue

                    # Service-level dedup: one alert per backend service
                    if svc_key in _alerted_services:
                        logger.debug("Endpoint %s/%s — skipping, already alerted for service %s",
                                     ns, host, service_name)
                        continue
                    _alerted_services.add(svc_key)

                    status_str = f"HTTP {status_code}" if status_code else reason

                    context = _build_endpoint_context(
                        ns=ns,
                        ingress_name=ingress.metadata.name,
                        host=host,
                        url=url,
                        status_code=status_code,
                        reason=reason,
                        elapsed=elapsed,
                        body=body,
                        service_name=service_name,
                        service_ns=service_ns,
                        collector=collector,
                    )

                    # App metrics from a backend pod
                    app_metrics_pod = ""
                    try:
                        svc = core.read_namespaced_service(service_name, service_ns)
                        sel = svc.spec.selector
                        if sel:
                            label_sel = ",".join(f"{k}={v}" for k, v in sel.items())
                            backend_pods = core.list_namespaced_pod(service_ns, label_selector=label_sel)
                            for bp in backend_pods.items:
                                app_metrics_pod = bp.metadata.name
                                break
                    except Exception:
                        logger.debug("Failed to list backend pods for %s/%s", ns, service_name)

                    # Rolling update detection: downgrade to warning + skip LLM
                    rolling = _is_rolling_update(apps, service_name, ns, core)
                    sev = "warning" if rolling else "critical"
                    skip = rolling

                    individual_result = ScanResult(
                        state_key=state_key,
                        title=f"Endpoint Unhealthy: {host}",
                        severity=sev,
                        resource=f"Ingress/{ingress.metadata.name}",
                        namespace=ns,
                        issue_type="endpoint",
                        pod_name=app_metrics_pod,
                        context_override=context,
                        event_reason=status_str,
                        skip_llm=skip,
                    )

                    # Collect for potential batching
                    _unhealthy_by_ns.setdefault(ns, []).append(
                        (host, service_name, status_str, state_key, individual_result)
                    )

        # Batch or individual: decide per namespace
        _batched_namespaces: set[str] = set()
        for ns, unhealthy_items in _unhealthy_by_ns.items():
            if len(unhealthy_items) >= config.ENDPOINT_BATCH_THRESHOLD:
                _batched_namespaces.add(ns)
                hosts = [item[0] for item in unhealthy_items]
                batch_tuples = [(h, svc, st, sk) for h, svc, st, sk, _ in unhealthy_items]
                combined = _build_batch_endpoint_context(ns, batch_tuples)
                host_summary = ", ".join(hosts[:5])
                if len(hosts) > 5:
                    host_summary += f"... +{len(hosts) - 5} more"
                batch_severity = "critical" if any(
                    item[4].severity == "critical" for item in unhealthy_items
                ) else "warning"
                batch_skip_llm = all(item[4].skip_llm for item in unhealthy_items)
                results.append(ScanResult(
                    state_key=f"EndpointBatch:{ns}",
                    title=f"Endpoint Batch: {len(unhealthy_items)} unhealthy in {ns}",
                    severity=batch_severity,
                    resource=f"BatchEndpoint/{len(unhealthy_items)}-endpoints",
                    namespace=ns,
                    issue_type="endpoint",
                    context_override=combined,
                    event_reason=f"{len(unhealthy_items)} endpoints down: {host_summary}",
                    skip_llm=batch_skip_llm,
                ))
                logger.info("Endpoint scanner: batched %d unhealthy endpoints in %s",
                             len(unhealthy_items), ns)
            else:
                for _, _, _, _, scan_result in unhealthy_items:
                    results.append(scan_result)

        # Auto-resolve batch incidents for namespaces that were probed but have no batch-level failures
        for ns in _probed_namespaces:
            if ns not in _batched_namespaces:
                results.append(ScanResult(
                    state_key=f"EndpointBatch:{ns}",
                    title=f"Endpoint Batch Recovered: {ns}",
                    severity="info",
                    resource=f"BatchEndpoint/{ns}",
                    namespace=ns,
                    issue_type="endpoint",
                    auto_resolve=True,
                ))

        unhealthy_count = sum(len(v) for v in _unhealthy_by_ns.values())
        logger.info("Endpoint scanner: probed %d, %d issues (skipped: %d gRPC, %d disabled, %d node) — %s",
                     probed, unhealthy_count, skipped_grpc, skipped_disabled, skipped_node,
                     ", ".join(_probed_hosts) if _probed_hosts else "none")
        return results

    def collect_daily_data(self) -> str | None:
        return None

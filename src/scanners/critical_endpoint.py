"""Critical Endpoint scanner — IngressRoute-based deep chain probing.

Discovery: Traefik IngressRoute CRs (traefik.io/v1alpha1)
Chain:     Traefik LB → IngressRoute host → backend services
"""
import logging
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone

from kubernetes import client as k8s

from src import config
from src.collectors.app_metrics import get_app_metrics_summary
from src.collectors.node import get_node_metrics_summary
from src.collectors.pod import query_app_metrics
from src.collectors.prometheus import prom_query, prom_scalar
from src.scanners._base import ScanResult
from src.scanners._probe import ProbeResult, probe, probe_external, probe_via_cluster_ip

logger = logging.getLogger(__name__)

# Patterns for detecting upstream connection strings in env vars
_UPSTREAM_PATTERNS = re.compile(
    r"(mongodb|postgres|mysql|redis|kafka|amqp|nats|typesense)"
    r"://(?:[^@/\s]+@)?([^:/@\s]+)",
    re.IGNORECASE,
)

# Pattern to extract Host(`...`) from IngressRoute match rules
_HOST_RE = re.compile(r"Host\(`([^`]+)`\)")


@dataclass
class HopResult:
    name: str
    probe: ProbeResult
    healthy: bool
    depth: int
    health_path: str


def _list_ingressroutes(ns: str) -> list[dict]:
    """List IngressRoute CRs (traefik.io/v1alpha1) in namespace."""
    api = k8s.CustomObjectsApi()
    try:
        irs = api.list_namespaced_custom_object("traefik.io", "v1alpha1", ns, "ingressroutes")
        return irs.get("items", [])
    except k8s.ApiException as e:
        if e.status == 404:
            logger.debug("IngressRoute CRD not found in %s (404)", ns)
        else:
            logger.warning("Failed to list IngressRoutes in %s: %s", ns, e.reason)
        return []
    except Exception:
        logger.exception("Failed to list IngressRoutes in %s", ns)
        return []


def _extract_hosts(ir: dict) -> list[str]:
    """Extract hostnames from IngressRoute match rules."""
    hosts: list[str] = []
    for route in ir.get("spec", {}).get("routes", []):
        match = route.get("match", "")
        for m in _HOST_RE.finditer(match):
            host = m.group(1)
            if host not in hosts:
                hosts.append(host)
    return hosts


def _extract_backend_services(ir: dict) -> list[tuple[str, int]]:
    """Extract backend service names and ports from IngressRoute routes.

    Returns: [(service_name, port), ...]
    """
    seen: set[tuple[str, int]] = set()
    backends: list[tuple[str, int]] = []
    for route in ir.get("spec", {}).get("routes", []):
        for svc in route.get("services", []):
            name = svc.get("name", "")
            port = svc.get("port", 80)
            if name and (name, port) not in seen:
                seen.add((name, port))
                backends.append((name, port))
    return backends


def _get_readiness_probe_path(ns: str, deployment_name: str) -> tuple[int, str]:
    """Read readinessProbe from a deployment spec. Returns (port, path)."""
    apps = k8s.AppsV1Api()
    try:
        deploy = apps.read_namespaced_deployment(deployment_name, ns)
        for c in (deploy.spec.template.spec.containers or []):
            if c.readiness_probe and c.readiness_probe.http_get:
                port = c.readiness_probe.http_get.port
                path = c.readiness_probe.http_get.path or "/"
                if not path.startswith("/"):
                    path = "/" + path
                if isinstance(port, str):
                    # Named port — resolve from container ports
                    for cp in (c.ports or []):
                        if cp.name == port:
                            port = cp.container_port
                            break
                    else:
                        port = 3000  # fallback
                return int(port), path
    except Exception:
        logger.debug("Failed to read readinessProbe from %s/%s", ns, deployment_name)
    return 80, "/health"


def _resolve_named_port(ns: str, deployment_name: str, port_name: str) -> int | None:
    """Resolve a named port to its numeric value from deployment containers."""
    try:
        apps = k8s.AppsV1Api()
        deploy = apps.read_namespaced_deployment(deployment_name, ns)
        for c in (deploy.spec.template.spec.containers or []):
            for cp in (c.ports or []):
                if cp.name == port_name:
                    return cp.container_port
    except Exception:
        logger.debug("Failed to resolve named port %s for %s/%s", port_name, ns, deployment_name)
    return None


def _get_health_path_for_service(ns: str, svc_name: str) -> str:
    """Get health check path reachable via the k8s service port.

    Matches service targetPort to readinessProbe port. If they match,
    uses the probe path. Otherwise falls back to /health.
    """
    target_port = None
    try:
        core = k8s.CoreV1Api()
        svc = core.read_namespaced_service(svc_name, ns)
        if svc.spec.ports:
            tp = svc.spec.ports[0].target_port
            if tp is not None:
                try:
                    target_port = int(tp)
                except (ValueError, TypeError):
                    # Named port — resolve from deployment containers
                    target_port = _resolve_named_port(ns, svc_name, str(tp))
    except Exception:
        logger.debug("Failed to read service %s/%s for health path", ns, svc_name)

    probe_port, probe_path = _get_readiness_probe_path(ns, svc_name)

    if target_port is not None and target_port == probe_port:
        return probe_path

    # targetPort unknown or differs from probe port.
    # If service port == probe port, the probe path likely works too.
    try:
        core = k8s.CoreV1Api()
        svc = core.read_namespaced_service(svc_name, ns)
        if svc.spec.ports and svc.spec.ports[0].port == probe_port:
            return probe_path
    except Exception:
        logger.debug("Failed to check service port for %s/%s", ns, svc_name)

    return "/health"


def _get_service_port(ns: str, svc_name: str) -> int:
    """Get the first port of a k8s service. Returns 80 as fallback."""
    try:
        core = k8s.CoreV1Api()
        svc = core.read_namespaced_service(svc_name, ns)
        if svc.spec.ports:
            return svc.spec.ports[0].port
    except Exception:
        pass
    return 80


def _probe_ingressroute(
    ir_name: str,
    hosts: list[str],
    backends: list[tuple[str, int]],
    ns: str,
) -> tuple[ProbeResult | None, ProbeResult | None, list[HopResult], bool]:
    """Probe the chain for an IngressRoute.

    Returns: (external_probe, cluster_ip_probe, hops, all_healthy)
    """
    timeout = config.ENDPOINT_SCAN_TIMEOUT
    all_healthy = True
    hops: list[HopResult] = []

    # Dual probes via Traefik ingress (if ingress service configured)
    external_probe = None
    cluster_ip_probe = None
    host = hosts[0] if hosts else ""

    if config.ENDPOINT_INGRESS_SERVICE and host:
        # External probe: via LoadBalancer IP (real user path)
        external_probe = probe_external(
            host=host,
            path="/",
            ingress_svc=config.ENDPOINT_INGRESS_SERVICE,
            timeout=timeout,
        )
        ext_healthy = external_probe.status_code is not None and 200 <= external_probe.status_code <= 399
        if not ext_healthy:
            all_healthy = False

        # Internal probe: via ClusterIP (in-cluster path)
        cluster_ip_probe = probe_via_cluster_ip(
            host=host,
            path="/",
            ingress_svc=config.ENDPOINT_INGRESS_SERVICE,
            timeout=timeout,
        )
        cip_healthy = cluster_ip_probe.status_code is not None and 200 <= cluster_ip_probe.status_code <= 399
        if not cip_healthy:
            all_healthy = False

    # Probe each backend service
    for i, (svc_name, svc_port) in enumerate(backends):
        health_path = _get_health_path_for_service(ns, svc_name)
        actual_port = _get_service_port(ns, svc_name)
        svc_url = f"http://{svc_name}.{ns}.svc.cluster.local:{actual_port}{health_path}"
        svc_probe = probe(svc_url, timeout=timeout)
        svc_healthy = svc_probe.status_code is not None and 200 <= svc_probe.status_code <= 399
        hops.append(HopResult(
            name=f"{svc_name}:{actual_port}",
            probe=svc_probe,
            healthy=svc_healthy,
            depth=i,
            health_path=health_path,
        ))
        if not svc_healthy:
            all_healthy = False

    return external_probe, cluster_ip_probe, hops, all_healthy


def _resolve_dns(hostname: str) -> str:
    """Resolve a hostname and return status string."""
    try:
        addrs = socket.getaddrinfo(hostname, None)
        ips = sorted({str(addr[4][0]) for addr in addrs})
        return f"OK → {', '.join(ips)}"
    except socket.gaierror as e:
        return f"FAILED — {e}"


def _collect_upstream_deps(pod_spec) -> list[tuple[str, str]]:
    """Extract upstream service hostnames from env vars in pod spec."""
    hosts: set[tuple[str, str]] = set()
    for container in (pod_spec.containers or []):
        for env in (container.env or []):
            if env.value:
                for match in _UPSTREAM_PATTERNS.finditer(env.value):
                    hosts.add((match.group(1).lower(), match.group(2)))
    return list(hosts)


def _check_upstream_service(protocol: str, host: str) -> str:
    """Check if an upstream service is reachable (TCP connect)."""
    default_ports = {
        "mongodb": 27017, "postgres": 5432, "mysql": 3306,
        "redis": 6379, "kafka": 9092, "amqp": 5672,
        "nats": 4222, "typesense": 8108,
    }
    port = default_ports.get(protocol, 80)
    if ":" in host:
        parts = host.rsplit(":", 1)
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            pass
    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.close()
        return f"OK (TCP connect to {host}:{port})"
    except Exception as e:
        return f"FAILED (TCP connect to {host}:{port}: {e})"


def _probe_spec_str(probe_spec) -> str:
    """Format a probe spec to a short string."""
    if probe_spec.http_get:
        port = probe_spec.http_get.port
        path = probe_spec.http_get.path or "/"
        return f"HTTP GET :{port}{path}"
    if probe_spec.tcp_socket:
        return f"TCP :{probe_spec.tcp_socket.port}"
    if probe_spec.exec:
        cmd = " ".join(probe_spec.exec.command or [])
        return f"exec({cmd[:40]})"
    return "unknown"


def _fmt_ms(seconds: float) -> str:
    """Format seconds as ms string."""
    if seconds <= 0:
        return "—"
    return f"{seconds * 1000:.0f}ms"


def _collect_pods_for_hop(svc_name: str, ns: str) -> list:
    """Find pods for a service by common label selectors."""
    core = k8s.CoreV1Api()
    for label in (f"app={svc_name}", f"app.kubernetes.io/name={svc_name}"):
        try:
            pods = core.list_namespaced_pod(ns, label_selector=label)
            if pods.items:
                return pods.items
        except Exception:
            logger.debug("Failed to list pods for %s in %s (label=%s)", svc_name, ns, label)
    return []


def _collect_traefik_metrics(ns: str, service_name: str) -> str | None:
    """Collect Traefik ingress metrics from Prometheus.

    Uses traefik_service_requests_total and traefik_service_request_duration_seconds_bucket.
    Label: service=~"{ns}-{service_name}-.*"
    """
    if not config.PROMETHEUS_URL:
        return None

    # Traefik service label format: <namespace>-<service>-<port>@kubernetes
    svc_label = f'{ns}-{service_name}-.*@kubernetes'
    parts = []

    # Request rate
    req_rate = prom_scalar(
        f'sum(rate(traefik_service_requests_total{{service=~"{svc_label}"}}[5m]))'
    )
    if req_rate is not None:
        parts.append(f"Request rate: {req_rate:.1f} req/s")

        # 5xx rate
        err_rate = prom_scalar(
            f'sum(rate(traefik_service_requests_total{{service=~"{svc_label}",code=~"5.."}}[5m]))'
        )
        if err_rate is not None:
            err_pct = f" ({err_rate / req_rate * 100:.1f}%)" if req_rate > 0 else ""
            parts.append(f"5xx rate: {err_rate:.2f} req/s{err_pct}")

        # 4xx rate
        err4_rate = prom_scalar(
            f'sum(rate(traefik_service_requests_total{{service=~"{svc_label}",code=~"4.."}}[5m]))'
        )
        if err4_rate is not None:
            err4_pct = f" ({err4_rate / req_rate * 100:.1f}%)" if req_rate > 0 else ""
            parts.append(f"4xx rate: {err4_rate:.2f} req/s{err4_pct}")

    # Latency p50, p99
    for pct, label in [(0.50, "p50"), (0.99, "p99")]:
        val = prom_scalar(
            f'histogram_quantile({pct}, sum(rate('
            f'traefik_service_request_duration_seconds_bucket{{service=~"{svc_label}"}}[5m]'
            f')) by (le))'
        )
        if val is not None:
            parts.append(f"{label}: {val * 1000:.0f}ms")

    if not parts:
        return None
    return " | ".join(parts)


def _collect_backend_app_metrics(ns: str, service_name: str) -> str | None:
    """Collect application-level HTTP metrics (Go backend).

    Uses app_http_requests_total{namespace, pod}, app_http_request_duration_seconds.
    Only for services that expose /metrics (backend).
    Frontend is nginx (no app metrics) — only Traefik-level metrics available.
    """
    if not config.PROMETHEUS_URL:
        return None

    labels = f'namespace="{ns}"'
    parts = []

    # Check if this service has app metrics
    test = prom_query(f'app_http_requests_total{{{labels},service="{service_name}"}}')
    if not test:
        # Try without service label (match by pod prefix)
        test = prom_query(f'app_http_requests_total{{{labels},pod=~"{service_name}-.*"}}')
        if not test:
            return None
        labels = f'{labels},pod=~"{service_name}-.*"'
    else:
        labels = f'{labels},service="{service_name}"'

    req_rate = prom_scalar(f'sum(rate(app_http_requests_total{{{labels}}}[5m]))')
    if req_rate is not None:
        parts.append(f"App req rate: {req_rate:.1f} req/s")

    p99 = prom_scalar(
        f'histogram_quantile(0.99, sum(rate(app_http_request_duration_seconds_bucket{{{labels}}}[5m])) by (le))'
    )
    if p99 is not None:
        parts.append(f"App p99: {p99 * 1000:.0f}ms")

    err_rate = prom_scalar(
        f'sum(rate(app_http_requests_total{{{labels},code=~"5.."}}[5m]))'
    )
    if err_rate is not None and err_rate > 0:
        parts.append(f"App 5xx: {err_rate:.2f} req/s")

    if not parts:
        return None
    return " | ".join(parts)


def _collect_traefik_health(core: k8s.CoreV1Api) -> str | None:
    """Collect Traefik pod health: phase, restarts, error logs."""
    ingress_namespaces = [
        ns.strip() for ns in
        config.CRITICAL_ENDPOINT_INGRESS_NAMESPACES.split(",")
        if ns.strip()
    ]

    traefik_ns = None
    traefik_pods = []
    for try_ns in ingress_namespaces:
        try:
            pods = core.list_namespaced_pod(
                try_ns, label_selector="app.kubernetes.io/name=traefik",
            )
            if pods.items:
                traefik_ns = try_ns
                traefik_pods = pods.items
                break
        except Exception:
            logger.debug("Failed to find Traefik pods in namespace %s", try_ns)
            continue

    if not traefik_ns or not traefik_pods:
        return None

    parts = []
    for pod in traefik_pods[:3]:
        phase = pod.status.phase if pod.status else "Unknown"
        restarts = sum(cs.restart_count for cs in (pod.status.container_statuses or []))
        parts.append(f"{pod.metadata.name}: Phase={phase}, Restarts={restarts}")

    # Check for error logs
    try:
        pod = traefik_pods[0]
        logs = core.read_namespaced_pod_log(
            pod.metadata.name, traefik_ns,
            since_seconds=60, timestamps=True,
        )
        if logs and logs.strip():
            all_lines = logs.strip().split("\n")
            error_lines = [
                l for l in all_lines
                if re.search(r'(?i)(error|level=error|"level":"error"|panic)', l)
            ]
            if error_lines:
                parts.append(f"Error log entries (last 60s): {len(error_lines)}")
    except Exception:
        logger.debug("Failed to read Traefik logs for health summary")

    return " | ".join(parts) if parts else None


def _collect_ingress_context(
    ir_name: str,
    host: str,
    ns: str,
    core: k8s.CoreV1Api,
) -> str | None:
    """Collect Traefik ingress context when external probe fails but backends are healthy."""
    from src.engine.sanitizer import redact_response_body

    lines = ["### Traefik Ingress Context (external-only failure)"]
    has_content = False

    # --- IngressRoute details ---
    try:
        api = k8s.CustomObjectsApi()
        ir = api.get_namespaced_custom_object("traefik.io", "v1alpha1", ns, "ingressroutes", ir_name)
        lines.append(f"#### IngressRoute: {ir_name}")
        spec = ir.get("spec", {})
        entry_points = spec.get("entryPoints", [])
        if entry_points:
            lines.append(f"  EntryPoints: {', '.join(entry_points)}")
        tls = spec.get("tls", {})
        if tls:
            secret = tls.get("secretName", "")
            if secret:
                lines.append(f"  TLS Secret: {secret}")
                # Certificate state from cert-manager, not from the Secret: reading the Secret
                # returns the private key, and the monitor has no access to Secrets by design.
                lines.append(f"    Certificate status: {_certificate_status(ns, secret)}")
            cert_resolver = tls.get("certResolver", "")
            if cert_resolver:
                lines.append(f"  CertResolver: {cert_resolver}")
        for route in spec.get("routes", []):
            match_rule = route.get("match", "")
            svcs = route.get("services", [])
            svc_str = ", ".join(f"{s.get('name')}:{s.get('port', 80)}" for s in svcs)
            lines.append(f"  Route: {match_rule} → {svc_str}")
        has_content = True
    except Exception:
        logger.debug("Failed to read IngressRoute %s/%s", ns, ir_name)

    # --- Traefik controller pod status & logs ---
    ingress_namespaces = [
        n.strip() for n in
        config.CRITICAL_ENDPOINT_INGRESS_NAMESPACES.split(",")
        if n.strip()
    ]

    traefik_ns = None
    for try_ns in ingress_namespaces:
        try:
            pods = core.list_namespaced_pod(
                try_ns, label_selector="app.kubernetes.io/name=traefik",
            )
            if pods.items:
                traefik_ns = try_ns
                break
        except Exception:
            continue

    if traefik_ns:
        try:
            pods = core.list_namespaced_pod(
                traefik_ns, label_selector="app.kubernetes.io/name=traefik",
            )
            if pods.items:
                pod = pods.items[0]
                phase = pod.status.phase if pod.status else "Unknown"
                restarts = sum(
                    cs.restart_count for cs in (pod.status.container_statuses or [])
                )
                lines.append(f"#### Traefik Controller: {pod.metadata.name}")
                lines.append(f"  Phase={phase}, Restarts={restarts}, Node={pod.spec.node_name}")
                has_content = True

                # Fetch Traefik logs filtered for the host
                try:
                    logs = core.read_namespaced_pod_log(
                        pod.metadata.name, traefik_ns,
                        tail_lines=100, timestamps=True,
                    )
                    if logs.strip():
                        all_lines = logs.strip().split("\n")
                        relevant = [
                            l for l in all_lines
                            if host in l
                            or re.search(r"(?i)(error|level=error|\"level\":\"error\"|502|503|404)", l)
                        ]
                        if relevant:
                            display = redact_response_body("\n".join(relevant[-20:]))
                            lines.append(f"#### Traefik Logs (filtered)\n```\n{display}\n```")
                            has_content = True
                except Exception:
                    logger.debug("Failed to read Traefik controller logs")
        except Exception:
            logger.debug("Failed to list Traefik controller pods in %s", traefik_ns)

    # --- Backend service endpoint status ---
    try:
        api = k8s.CustomObjectsApi()
        ir = api.get_namespaced_custom_object("traefik.io", "v1alpha1", ns, "ingressroutes", ir_name)
        for route in ir.get("spec", {}).get("routes", []):
            for svc in route.get("services", []):
                svc_name = svc.get("name", "")
                if not svc_name:
                    continue
                try:
                    endpoints = core.read_namespaced_endpoints(svc_name, ns)
                    ready_addrs = []
                    not_ready_addrs = []
                    for subset in (endpoints.subsets or []):
                        ready_addrs.extend(subset.addresses or [])
                        not_ready_addrs.extend(subset.not_ready_addresses or [])
                    lines.append(f"#### Service Endpoints: {svc_name}")
                    lines.append(f"  Ready: {len(ready_addrs)}, NotReady: {len(not_ready_addrs)}")
                    for addr in ready_addrs[:5]:
                        target = addr.target_ref
                        pod_name = target.name if target else "?"
                        lines.append(f"    {addr.ip} → {pod_name}")
                    has_content = True
                except Exception:
                    logger.debug("Failed to read endpoints for %s/%s", ns, svc_name)
    except Exception:
        logger.debug("Failed to re-read IngressRoute %s/%s for endpoints", ns, ir_name)

    return "\n".join(lines) if has_content else None


def _collect_probe_correlation(
    probe_result: ProbeResult,
    core: k8s.CoreV1Api,
) -> str | None:
    """Correlate a probe with Traefik access log entries using probe_id."""
    if not probe_result.probe_id:
        return None

    ingress_namespaces = [
        ns.strip() for ns in
        config.CRITICAL_ENDPOINT_INGRESS_NAMESPACES.split(",")
        if ns.strip()
    ]

    traefik_ns = None
    for try_ns in ingress_namespaces:
        try:
            pods = core.list_namespaced_pod(
                try_ns, label_selector="app.kubernetes.io/name=traefik",
            )
            if pods.items:
                traefik_ns = try_ns
                break
        except Exception:
            continue

    if not traefik_ns:
        return None

    try:
        pods = core.list_namespaced_pod(
            traefik_ns, label_selector="app.kubernetes.io/name=traefik",
        )
        if not pods.items:
            return None
    except Exception as e:
        logger.debug("Failed to list Traefik pods for probe correlation: %s", e)
        return None

    pod = pods.items[0]
    probe_id = probe_result.probe_id
    lines_parts = []

    try:
        logs = core.read_namespaced_pod_log(
            pod.metadata.name, traefik_ns,
            since_seconds=30, timestamps=True,
        )
        if not logs or not logs.strip():
            lines_parts.append(f"Probe ID: {probe_id}")
            lines_parts.append("Log Entry: (no logs in last 30s)")
            return "\n".join(lines_parts)

        all_lines = logs.strip().split("\n")
        matched = [l for l in all_lines if probe_id in l]

        lines_parts.append(f"Probe ID: {probe_id}")
        if matched:
            from src.engine.sanitizer import redact_response_body

            log_line = matched[-1]
            sanitized = redact_response_body(log_line[:300])
            lines_parts.append(f"Log Entry: {sanitized}")

            if probe_result.status_code is None:
                lines_parts.append("→ Request reached Traefik but probe timed out — likely slow backend")
            elif probe_result.status_code and probe_result.status_code >= 500:
                lines_parts.append("→ Request reached Traefik, upstream returned error")
        else:
            lines_parts.append("Log Entry: (not found — request may not have reached Traefik)")
            if probe_result.status_code is None:
                lines_parts.append("→ No log entry + timeout = request likely didn't reach Traefik (LB/network issue)")
    except Exception as e:
        logger.debug("Failed to read Traefik logs for probe correlation: %s", e)
        lines_parts.append(f"Probe ID: {probe_id}")
        lines_parts.append(f"Log Entry: (error reading logs: {e})")

    return "\n".join(lines_parts) if lines_parts else None


def _build_chain_context(
    ir_name: str,
    host: str,
    external_probe: ProbeResult | None,
    cluster_ip_probe: ProbeResult | None,
    hops: list[HopResult],
    ns: str,
) -> str:
    """Build full markdown context for a failing chain."""
    from src.engine.sanitizer import redact_response_body

    core = k8s.CoreV1Api()
    apps = k8s.AppsV1Api()
    sections = []

    sections.append(f"## Critical Endpoint Chain: {host} (IngressRoute: {ir_name})")

    # Explanation note
    sections.append(
        "> **External Probe** connects to the LoadBalancer IP (real user path). "
        "**Internal Ingress Probe** connects to the Traefik ClusterIP (in-cluster only). "
        "Comparing both reveals whether the issue is in the external network path or inside the cluster."
    )

    # --- External Probe (via LoadBalancer) ---
    if external_probe:
        lb_label = external_probe.ip_address or "?"
        ext_lines = [f"### External Probe (via LoadBalancer {lb_label})"]
        ext_lines.append(f"URL: {external_probe.url}")
        if external_probe.status_code:
            ext_lines.append(f"Status: {external_probe.status_code} {external_probe.reason}")
        else:
            ext_lines.append(f"Error: {external_probe.reason}")
        ext_lines.append(
            f"DNS: {_fmt_ms(external_probe.dns_time)} → {external_probe.ip_address or '?'}"
        )
        ext_lines.append(
            f"TCP: {_fmt_ms(external_probe.connect_time)} | "
            f"TLS: {_fmt_ms(external_probe.tls_time)} | "
            f"TTFB: {_fmt_ms(external_probe.ttfb)} | "
            f"Total: {_fmt_ms(external_probe.total_time)}"
        )
        if external_probe.tls_cert:
            cert = external_probe.tls_cert
            sans_str = ", ".join(cert.get("sans", [])[:5])
            ext_lines.append(
                f"TLS Cert: valid until {cert.get('expiry', '?')} "
                f"({cert.get('days_left', '?')}d), "
                f"issuer={cert.get('issuer', '?')}, SANs=[{sans_str}]"
            )
        if external_probe.headers:
            hdr_parts = [f"{k}={v}" for k, v in external_probe.headers.items()]
            ext_lines.append(f"Headers: {', '.join(hdr_parts)}")
        if external_probe.body:
            ext_lines.append(f"Body:\n```\n{redact_response_body(external_probe.body)}\n```")
        sections.append("\n".join(ext_lines))

    # --- Internal Ingress Probe (via ClusterIP) ---
    if cluster_ip_probe:
        cip_lines = [f"### Internal Ingress Probe (via ClusterIP {cluster_ip_probe.ip_address or '?'})"]
        cip_lines.append(f"URL: {cluster_ip_probe.url}")
        if cluster_ip_probe.status_code:
            cip_lines.append(f"Status: {cluster_ip_probe.status_code} {cluster_ip_probe.reason}")
        else:
            cip_lines.append(f"Error: {cluster_ip_probe.reason}")
        cip_lines.append(
            f"TCP: {_fmt_ms(cluster_ip_probe.connect_time)} | "
            f"TLS: {_fmt_ms(cluster_ip_probe.tls_time)} | "
            f"TTFB: {_fmt_ms(cluster_ip_probe.ttfb)} | "
            f"Total: {_fmt_ms(cluster_ip_probe.total_time)}"
        )
        sections.append("\n".join(cip_lines))

    # --- Probe Comparison ---
    if external_probe and cluster_ip_probe:
        cmp_lines = ["### Probe Comparison"]
        cmp_lines.append("| Metric | External (LB) | Internal (ClusterIP) | Delta |")
        cmp_lines.append("|--------|---------------|----------------------|-------|")

        ext_status = str(external_probe.status_code or external_probe.reason)
        cip_status = str(cluster_ip_probe.status_code or cluster_ip_probe.reason)
        status_match = "same" if ext_status == cip_status else "DIFFERENT"
        cmp_lines.append(f"| Status | {ext_status} | {cip_status} | {status_match} |")

        for metric, ext_val, cip_val in [
            ("TCP connect", external_probe.connect_time, cluster_ip_probe.connect_time),
            ("TLS handshake", external_probe.tls_time, cluster_ip_probe.tls_time),
            ("TTFB", external_probe.ttfb, cluster_ip_probe.ttfb),
            ("Total", external_probe.total_time, cluster_ip_probe.total_time),
        ]:
            if ext_val > 0 and cip_val > 0:
                ratio = ext_val / cip_val
                delta = f"{ratio:.1f}x" if ratio > 1.1 else "~same"
            else:
                delta = "—"
            cmp_lines.append(f"| {metric} | {_fmt_ms(ext_val)} | {_fmt_ms(cip_val)} | {delta} |")

        sections.append("\n".join(cmp_lines))

    # --- Probe Correlation (Traefik access log) ---
    for probe_result, label in [
        (external_probe, "External"),
        (cluster_ip_probe, "Internal"),
    ]:
        if probe_result:
            correlation = _collect_probe_correlation(probe_result, core)
            if correlation:
                sections.append(f"#### Probe Correlation — {label}\n{correlation}")

    # --- Traefik Health (last 60s) ---
    traefik_health = _collect_traefik_health(core)
    if traefik_health:
        sections.append(f"#### Traefik Health (last 60s)\n{traefik_health}")

    # --- Chain Health Table ---
    table_lines = ["### Chain Health"]
    table_lines.append("| # | Service | Health Path | Status | TTFB | Details |")
    table_lines.append("|---|---------|-------------|--------|------|---------|")
    for i, hop in enumerate(hops):
        if hop.healthy:
            status = f"✓ {hop.probe.status_code}"
        elif hop.probe.status_code:
            status = f"✗ {hop.probe.status_code}"
        else:
            status = "✗ ERR"
        ttfb = _fmt_ms(hop.probe.ttfb)
        details = "" if hop.healthy else hop.probe.reason
        table_lines.append(f"| {i} | {hop.name} | {hop.health_path} | {status} | {ttfb} | {details} |")
    sections.append("\n".join(table_lines))

    # --- Collect pods for ALL hops → node + app metrics ---
    hop_pods: dict[str, list] = {}  # svc_name -> pods
    node_names: dict[str, str] = {}  # node_name -> first svc that runs on it
    for hop in hops:
        svc_name = hop.name.split(":")[0]
        pods_list = _collect_pods_for_hop(svc_name, ns)
        hop_pods[svc_name] = pods_list
        for pod in pods_list:
            if pod.spec.node_name and pod.spec.node_name not in node_names:
                node_names[pod.spec.node_name] = svc_name

    # --- Node Utilization ---
    if node_names:
        node_lines = ["### Node Utilization", "| Node | Metrics |", "|------|---------|"]
        for node_name in sorted(node_names):
            summary = get_node_metrics_summary(node_name)
            if summary:
                node_lines.append(f"| {node_name} | {summary} |")
        if len(node_lines) > 3:  # has at least one data row
            sections.append("\n".join(node_lines))

    # --- Application Metrics ---
    app_metric_lines = [
        "### Application Metrics",
        "| Service | Pod | Metrics |",
        "|---------|-----|---------|",
    ]
    has_app_metrics = False
    for hop in hops:
        svc_name = hop.name.split(":")[0]
        pods_list = hop_pods.get(svc_name, [])
        if not pods_list:
            continue
        pod = pods_list[0]
        summary = get_app_metrics_summary(pod.metadata.name, ns)
        if summary:
            app_metric_lines.append(f"| {svc_name} | {pod.metadata.name} | {summary} |")
            has_app_metrics = True
    if has_app_metrics:
        sections.append("\n".join(app_metric_lines))

    # --- Traefik Ingress Metrics (from Prometheus) ---
    for hop in hops:
        svc_name = hop.name.split(":")[0]
        traefik_metrics = _collect_traefik_metrics(ns, svc_name)
        if traefik_metrics:
            sections.append(f"### Traefik Metrics: {svc_name}\n{traefik_metrics}")

    # --- Backend App Metrics (Go services with /metrics) ---
    for hop in hops:
        svc_name = hop.name.split(":")[0]
        backend_metrics = _collect_backend_app_metrics(ns, svc_name)
        if backend_metrics:
            sections.append(f"### Backend App Metrics: {svc_name}\n{backend_metrics}")

    # --- External-only failure: collect ingress/Traefik context ---
    ext_failed = (
        external_probe is not None
        and (external_probe.status_code is None or external_probe.status_code >= 400)
    )
    cip_failed = (
        cluster_ip_probe is not None
        and (cluster_ip_probe.status_code is None or cluster_ip_probe.status_code >= 400)
    )
    internal_all_ok = all(h.healthy for h in hops) and not cip_failed
    if ext_failed and internal_all_ok:
        ingress_sections = _collect_ingress_context(ir_name, host, ns, core)
        if ingress_sections:
            sections.append(ingress_sections)

    # --- All hops: collect k8s context (full for failing, lightweight for healthy) ---
    for hop in hops:
        is_failing = not hop.healthy
        header = f"### Failing: {hop.name}" if is_failing else f"### Hop: {hop.name} (healthy)"
        hop_sections = [header]
        svc_name = hop.name.split(":")[0]

        # Pods (reuse already-collected pods)
        pods_list = hop_pods.get(svc_name, [])
        try:
            if pods_list:
                pod_lines = ["#### Pods"]
                for pod in pods_list:
                    phase = pod.status.phase if pod.status else "Unknown"
                    statuses = pod.status.container_statuses or []
                    ready_count = sum(1 for cs in statuses if cs.ready)
                    total = len(statuses)
                    restarts = sum(cs.restart_count for cs in statuses)
                    pod_lines.append(
                        f"  {pod.metadata.name}: Phase={phase}, "
                        f"Ready={ready_count}/{total}, Restarts={restarts}"
                    )
                    if is_failing:
                        for cond in (pod.status.conditions or []):
                            if cond.type == "Ready" and cond.status != "True":
                                pod_lines.append(f"    NOT READY: {cond.reason}")
                        # Probes (only for failing hops)
                        for c in (pod.spec.containers or []):
                            probes = []
                            if c.readiness_probe:
                                probes.append(f"readiness={_probe_spec_str(c.readiness_probe)}")
                            if c.liveness_probe:
                                probes.append(f"liveness={_probe_spec_str(c.liveness_probe)}")
                            if probes:
                                pod_lines.append(f"    Probes: {', '.join(probes)}")
                hop_sections.append("\n".join(pod_lines))
        except Exception:
            logger.debug("Failed to list pods for %s in %s", svc_name, ns)

        # Deployment (only for failing hops)
        if is_failing:
            try:
                deploy = apps.read_namespaced_deployment(svc_name, ns)
                status = deploy.status
                spec_replicas = deploy.spec.replicas or 1
                ready_replicas = status.ready_replicas or 0
                updated_replicas = status.updated_replicas or 0
                unavailable = status.unavailable_replicas or 0
                deploy_lines = [
                    "#### Deployment",
                    f"  Replicas: {spec_replicas} desired, {ready_replicas} ready, "
                    f"{updated_replicas} updated, {unavailable} unavailable",
                ]
                for c in (deploy.spec.template.spec.containers or []):
                    deploy_lines.append(f"  Image: {c.image}")
                hop_sections.append("\n".join(deploy_lines))
            except Exception:
                logger.debug("Failed to read deployment %s in %s", svc_name, ns)

        # Events
        try:
            events = core.list_namespaced_event(
                ns, field_selector=f"involvedObject.name={svc_name}",
            )
            # Also get events for pods
            pod_events = []
            if pods_list:
                for p in pods_list[:3]:
                    pe = core.list_namespaced_event(
                        ns, field_selector=f"involvedObject.name={p.metadata.name}",
                    )
                    pod_events.extend(pe.items)

            all_events = events.items + pod_events
            if not is_failing:
                # Healthy hops: only Warning/Error events
                all_events = [e for e in all_events if e.type in ("Warning", "Error")]
            if all_events:
                all_events.sort(
                    key=lambda e: e.last_timestamp or e.event_time or datetime.min.replace(tzinfo=timezone.utc),
                    reverse=True,
                )
                ev_lines = ["#### Events"]
                for e in all_events[:10]:
                    ev_lines.append(f"  [{e.type}] {e.reason}: {e.message}")
                hop_sections.append("\n".join(ev_lines))
        except Exception:
            logger.debug("Failed to list events for %s in %s", svc_name, ns)

        # Logs (error-prioritized)
        if pods_list:
            for pod in pods_list[:2]:
                try:
                    logs = core.read_namespaced_pod_log(
                        pod.metadata.name, ns,
                        tail_lines=30, timestamps=True,
                    )
                    if logs.strip():
                        lines = logs.strip().split("\n")
                        error_lines = [
                            l for l in lines
                            if re.search(r"(?i)(error|exception|fatal|panic|traceback)", l)
                        ]
                        if error_lines:
                            display = redact_response_body("\n".join(error_lines[-15:]))
                            hop_sections.append(
                                f"#### Logs (errors) — {pod.metadata.name}\n```\n{display}\n```"
                            )
                        elif is_failing:
                            # Full logs only for failing hops
                            display = redact_response_body("\n".join(lines[-15:]))
                            hop_sections.append(
                                f"#### Logs — {pod.metadata.name}\n```\n{display}\n```"
                            )
                except Exception as e:
                    logger.warning("Failed to collect logs for pod %s: %s", pod.metadata.name, e)

        # Upstream Dependencies (only for failing hops)
        if is_failing and pods_list:
            upstream_lines = []
            svc_fqdn = f"{svc_name}.{ns}.svc.cluster.local"
            dns_result = _resolve_dns(svc_fqdn)
            upstream_lines.append(f"Service DNS ({svc_fqdn}): {dns_result}")

            for pod in pods_list[:1]:
                deps = _collect_upstream_deps(pod.spec)
                checked: set[str] = set()
                for protocol, host_dep in deps:
                    if host_dep not in checked:
                        checked.add(host_dep)
                        result = _check_upstream_service(protocol, host_dep)
                        upstream_lines.append(f"{protocol}://{host_dep}: {result}")

            if upstream_lines:
                hop_sections.append("#### Upstream Dependencies\n" + "\n".join(upstream_lines))

        # Rich application metrics for failing hops (heap trend, active resources)
        if is_failing and pods_list:
            try:
                rich_metrics = query_app_metrics(pods_list[0].metadata.name, ns)
                if rich_metrics:
                    # Strip the "## Application Metrics\n" header from query_app_metrics
                    metrics_body = rich_metrics.split("\n", 1)[1] if "\n" in rich_metrics else rich_metrics
                    hop_sections.append(f"#### Application Metrics (detailed)\n{metrics_body}")
            except Exception as e:
                logger.warning("Failed to collect app metrics for %s in %s: %s", svc_name, ns, e)

        # Only include healthy hops if they have meaningful context beyond just the header + pods
        if is_failing or len(hop_sections) > 2:
            sections.append("\n".join(hop_sections))

    return "\n\n".join(sections)


class CriticalEndpointScanner:
    name = "critical_endpoint"
    startup_delay = 15

    def __init__(self) -> None:
        # Consecutive failed / healthy probe cycles per state_key (_flap_gate).
        self._fail_streak: dict[str, int] = {}
        self._ok_streak: dict[str, int] = {}

    @property
    def enabled(self):
        return config.SCANNER_CRITICAL_ENDPOINT_ENABLED

    def _flap_gate(self, state_key: str, healthy: bool) -> str | None:
        """Hysteresis across scan cycles: "down", "recovered" or None (say nothing).

        An endpoint that flaps (fail, ok, fail, ok - e.g. during a node upgrade) used
        to open and close an incident every cycle: one healthy probe emitted
        Recovered, the next failure a new Down. Now Down needs
        CRITICAL_ENDPOINT_DOWN_CYCLES failed cycles in a row, and Recovered needs
        CRITICAL_ENDPOINT_RECOVER_CYCLES healthy cycles in a row. Once reached, the
        decision repeats every cycle (the pipeline deduplicates repeated Downs).
        """
        if healthy:
            self._fail_streak[state_key] = 0
            self._ok_streak[state_key] = self._ok_streak.get(state_key, 0) + 1
            return "recovered" if self._ok_streak[state_key] >= config.CRITICAL_ENDPOINT_RECOVER_CYCLES else None
        self._ok_streak[state_key] = 0
        self._fail_streak[state_key] = self._fail_streak.get(state_key, 0) + 1
        return "down" if self._fail_streak[state_key] >= config.CRITICAL_ENDPOINT_DOWN_CYCLES else None

    @property
    def interval_seconds(self):
        return config.CRITICAL_ENDPOINT_INTERVAL_SECONDS

    def scan(self) -> list[ScanResult]:
        results = []
        probed = 0

        for ns in config.get_namespaces():
            ingressroutes = _list_ingressroutes(ns)
            if not ingressroutes:
                continue

            ir_names = [ir.get("metadata", {}).get("name", "?") for ir in ingressroutes]
            logger.info(
                "Critical endpoint scanner: found %d IngressRoutes in %s: %s",
                len(ingressroutes), ns, ", ".join(ir_names),
            )

            for ir in ingressroutes:
                ir_name = ir.get("metadata", {}).get("name", "")
                if not ir_name:
                    continue

                if ir_name in config.CRITICAL_ENDPOINT_EXCLUDE_NAMES:
                    logger.debug("Skipping excluded IngressRoute: %s", ir_name)
                    continue

                hosts = _extract_hosts(ir)
                backends = _extract_backend_services(ir)
                host = hosts[0] if hosts else ir_name

                if not backends:
                    logger.debug("Skipping IngressRoute %s/%s with no backend services", ns, ir_name)
                    continue

                probed += 1
                state_key = f"CriticalEndpoint:{ns}/ingressroute-{ir_name}:{host}"

                try:
                    external_probe, cluster_ip_probe, hops, all_healthy = _probe_ingressroute(
                        ir_name, hosts, backends, ns,
                    )
                except Exception:
                    logger.exception(
                        "Critical endpoint scanner: failed to probe chain for %s/%s",
                        ns, ir_name,
                    )
                    continue

                # Log chain results for debugging
                hop_summary = ", ".join(
                    f"{h.name}={'OK' if h.healthy else h.probe.status_code or h.probe.reason}"
                    for h in hops
                )
                ext_status = ""
                if external_probe:
                    ext_ok_flag = external_probe.status_code is not None and 200 <= external_probe.status_code <= 399
                    ext_status = f"external={'OK' if ext_ok_flag else external_probe.status_code or external_probe.reason}, "
                logger.info("Chain %s/%s (%s): %s%s", ns, ir_name, host, ext_status, hop_summary)

                # Healthy = every hop, plus the external and cluster IP probes.
                ext_ok = (
                    external_probe is None
                    or (external_probe.status_code is not None and 200 <= external_probe.status_code <= 399)
                )
                cip_ok = (
                    cluster_ip_probe is None
                    or (cluster_ip_probe.status_code is not None and 200 <= cluster_ip_probe.status_code <= 399)
                )
                healthy = all_healthy and ext_ok and cip_ok
                decision = self._flap_gate(state_key, healthy)
                if decision is None:
                    logger.info("Chain %s/%s: %s, inside the flap window - no decision this cycle",
                                ns, ir_name, "healthy" if healthy else "failing")
                    continue
                if decision == "recovered":
                    results.append(ScanResult(
                        state_key=state_key,
                        title=f"Critical Endpoint Recovered: {host}",
                        severity="info",
                        resource=f"IngressRoute/{ir_name}",
                        namespace=ns,
                        issue_type="critical_endpoint",
                        auto_resolve=True,
                    ))
                    continue

                # Something is unhealthy — build context
                failing_names = [h.name for h in hops if not h.healthy]
                if external_probe and (external_probe.status_code is None or external_probe.status_code >= 400):
                    failing_names.insert(0, "external-lb")
                if cluster_ip_probe and (cluster_ip_probe.status_code is None or cluster_ip_probe.status_code >= 400):
                    failing_names.insert(0, "internal-clusterip")

                event_reason = ", ".join(
                    f"{h.name}: {h.probe.reason}" for h in hops if not h.healthy
                )
                if not event_reason and external_probe:
                    event_reason = f"external: {external_probe.reason}"

                full_chain_context = _build_chain_context(
                    ir_name=ir_name,
                    host=host,
                    external_probe=external_probe,
                    cluster_ip_probe=cluster_ip_probe,
                    hops=hops,
                    ns=ns,
                )

                results.append(ScanResult(
                    state_key=state_key,
                    title=f"Critical Endpoint Down: {host}",
                    severity="critical",
                    resource=f"IngressRoute/{ir_name}",
                    namespace=ns,
                    issue_type="critical_endpoint",
                    context_override=full_chain_context,
                    event_reason=event_reason,
                ))

        unhealthy = [r for r in results if not r.auto_resolve]
        if unhealthy:
            issue_details = "; ".join(f"{r.resource} ({r.event_reason})" for r in unhealthy)
            logger.info("Critical endpoint scanner: probed %d IngressRoutes, %d issues: %s", probed, len(unhealthy), issue_details)
        else:
            logger.info("Critical endpoint scanner: probed %d IngressRoutes, all healthy", probed)
        return results

    def collect_daily_data(self) -> str | None:
        return None


def _certificate_status(ns: str, secret_name: str) -> str:
    """Ready state of the cert-manager Certificate that writes secret_name (no Secret access).

    Never raises: a failure here must not hide the rest of the IngressRoute report.
    """
    try:
        certs = k8s.CustomObjectsApi().list_namespaced_custom_object("cert-manager.io", "v1", ns, "certificates")
    except k8s.ApiException as e:
        if e.status == 404:
            return "unknown (cert-manager not installed)"
        logger.warning("Failed to list cert-manager Certificates in %s: %s", ns, e.reason)
        return f"unknown (API error: {e.reason})"
    except Exception:
        logger.warning("Failed to list cert-manager Certificates in %s", ns, exc_info=True)
        return "unknown (lookup failed)"
    try:
        for cert in certs.get("items", []):
            if cert.get("spec", {}).get("secretName") != secret_name:
                continue
            name = cert.get("metadata", {}).get("name", "?")
            for cond in cert.get("status", {}).get("conditions", []):
                if cond.get("type") == "Ready":
                    ready = "ready" if cond.get("status") == "True" else "NOT READY"
                    return f"{ready} (Certificate {name}: {cond.get('message', '')})"
            return f"no Ready condition (Certificate {name})"
        return "no cert-manager Certificate writes this Secret"
    except Exception:
        logger.warning("Unexpected Certificate data in %s for secret %s", ns, secret_name, exc_info=True)
        return "unknown (unexpected Certificate data)"

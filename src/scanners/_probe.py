"""Rich HTTP probe module — timing breakdown, TLS cert inspection, diagnostic headers."""
from __future__ import annotations

import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

import httpx

logger = logging.getLogger(__name__)

_DIAGNOSTIC_HEADERS = ("server", "x-request-id", "content-type", "retry-after", "location")

# Cached LB IP with TTL
_lb_ip_cache: dict[str, tuple[str, float]] = {}  # fqdn -> (ip, expiry_time)
_LB_IP_TTL = 300  # 5 minutes


@dataclass
class ProbeResult:
    url: str
    status_code: int | None
    reason: str
    # Timing breakdown (seconds)
    dns_time: float = 0.0
    connect_time: float = 0.0
    tls_time: float = 0.0
    ttfb: float = 0.0
    total_time: float = 0.0
    # Rich info
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    tls_cert: dict | None = None
    redirect_location: str = ""
    ip_address: str = ""
    probe_id: str = ""


def _resolve_ip(hostname: str) -> tuple[str, float]:
    """Resolve hostname, return (ip, dns_time_seconds)."""
    t0 = time.perf_counter()
    try:
        addrs = socket.getaddrinfo(hostname, None, socket.AF_INET)
        elapsed = time.perf_counter() - t0
        if addrs:
            return str(addrs[0][4][0]), elapsed
        return "", elapsed
    except Exception:
        logger.debug("DNS resolution failed for %s", hostname, exc_info=True)
        return "", time.perf_counter() - t0


def _inspect_tls_cert(hostname: str, port: int = 443) -> dict | None:
    """Fetch TLS certificate info via stdlib ssl."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    # binary_form=False returns None when verify_mode=CERT_NONE
                    # Fall back to DER parsing
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        return _parse_der_cert(der, hostname)
                    return None
                return _parse_pem_cert(cert, hostname)
    except Exception as e:
        logger.debug("TLS cert inspection failed for %s:%d: %s", hostname, port, e)
        return None


def _parse_pem_cert(cert: dict, hostname: str) -> dict:
    """Parse PEM cert dict from ssl.getpeercert()."""
    not_after_str = cert.get("notAfter", "")
    issuer_parts = []
    for rdn in cert.get("issuer", ()):
        for attr_name, attr_val in rdn:
            if attr_name in ("organizationName", "commonName"):
                issuer_parts.append(attr_val)
    sans = []
    for san_type, san_val in cert.get("subjectAltName", ()):
        if san_type == "DNS":
            sans.append(san_val)

    expiry = None
    days_left = None
    if not_after_str:
        try:
            expiry_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            expiry = expiry_dt.strftime("%Y-%m-%d")
            days_left = (expiry_dt - datetime.now(timezone.utc)).days
        except Exception:
            expiry = not_after_str

    return {
        "expiry": expiry,
        "issuer": ", ".join(issuer_parts) if issuer_parts else "unknown",
        "sans": sans,
        "days_left": days_left,
    }


def _parse_der_cert(der_bytes: bytes, hostname: str) -> dict | None:
    """Parse DER certificate using ssl helpers."""
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der_bytes)
        expiry_dt = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
        expiry = expiry_dt.strftime("%Y-%m-%d")
        days_left = (expiry_dt - datetime.now(timezone.utc)).days

        issuer_parts = []
        for attr in cert.issuer:
            if attr.oid in (x509.oid.NameOID.ORGANIZATION_NAME, x509.oid.NameOID.COMMON_NAME):
                issuer_parts.append(attr.value)

        sans = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            logger.debug("Failed to extract SANs from certificate for %s", hostname)

        return {
            "expiry": expiry,
            "issuer": ", ".join(issuer_parts) if issuer_parts else "unknown",
            "sans": sans,
            "days_left": days_left,
        }
    except ImportError:
        logger.debug("cryptography not available for DER cert parsing")
        return None
    except Exception as e:
        logger.debug("DER cert parsing failed: %s", e)
        return None


def _extract_headers(resp: httpx.Response) -> dict[str, str]:
    """Extract diagnostic headers from response."""
    result = {}
    for h in _DIAGNOSTIC_HEADERS:
        val = resp.headers.get(h)
        if val:
            result[h] = val
    return result


def _measure_connection(host: str, port: int, use_tls: bool = False, sni: str = "") -> dict:
    """Measure real TCP connect + TLS handshake timing.

    Returns dict with 'connect_time', 'tls_time', 'ip', 'error'.
    """
    result = {"connect_time": 0.0, "tls_time": 0.0, "ip": "", "error": ""}

    # TCP connect
    t0 = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=5)
    except Exception as e:
        result["connect_time"] = time.perf_counter() - t0
        result["error"] = f"TCP connect failed: {e}"
        return result

    result["connect_time"] = time.perf_counter() - t0

    try:
        result["ip"] = sock.getpeername()[0]
    except OSError as e:
        logger.debug("getpeername() failed for %s:%d: %s", host, port, e)

    # TLS handshake
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t1 = time.perf_counter()
        try:
            ssock = ctx.wrap_socket(sock, server_hostname=sni or host)
            result["tls_time"] = time.perf_counter() - t1
            ssock.close()
            return result
        except Exception as e:
            result["tls_time"] = time.perf_counter() - t1
            result["error"] = f"TLS handshake failed: {e}"
            sock.close()
            return result

    sock.close()
    return result


def _discover_lb_ip(ingress_svc_fqdn: str) -> str:
    """Parse service name/namespace from FQDN, read k8s Service, extract LB IP."""
    from kubernetes import client as k8s

    # Parse FQDN: traefik.traefik.svc.cluster.local
    parts = ingress_svc_fqdn.split(".")
    if len(parts) < 2:
        logger.debug("Cannot parse service FQDN: %s", ingress_svc_fqdn)
        return ""

    svc_name = parts[0]
    svc_ns = parts[1]

    try:
        core = k8s.CoreV1Api()
        svc = core.read_namespaced_service(svc_name, svc_ns)
        if svc.status and svc.status.load_balancer and svc.status.load_balancer.ingress:
            ing = svc.status.load_balancer.ingress[0]
            return ing.ip or ing.hostname or ""
    except Exception as e:
        logger.debug("Failed to read LB IP from service %s/%s: %s", svc_ns, svc_name, e)

    return ""


def get_lb_ip(ingress_svc_fqdn: str) -> str:
    """Cached wrapper for LB IP discovery (5min TTL)."""
    # Strip port if present
    fqdn = ingress_svc_fqdn.split(":")[0]

    now = time.time()
    cached = _lb_ip_cache.get(fqdn)
    if cached and cached[1] > now:
        return cached[0]

    ip = _discover_lb_ip(fqdn)
    if ip:
        _lb_ip_cache[fqdn] = (ip, now + _LB_IP_TTL)
    else:
        # Short TTL for empty results so we retry soon
        _lb_ip_cache[fqdn] = (ip, now + 15)
    return ip


def _generate_probe_id() -> str:
    """Generate a unique probe ID for log correlation."""
    return f"k8s-ai-monitor/{uuid4().hex[:8]}"


def probe(url: str, timeout: float = 10, verify: bool = True) -> ProbeResult:
    """Probe a URL with rich timing breakdown.

    Works for both HTTP and HTTPS URLs. For in-cluster service probes use HTTP.

    `verify` defaults to True: an expired or wrong certificate on a public https
    URL is an outage and must not look healthy. The probes that reach a raw IP
    with a Host header (probe_via_cluster_ip, probe_external) keep verify=False -
    a certificate name never matches an IP.
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_https = parsed.scheme == "https"

    # DNS resolution
    ip_address, dns_time = _resolve_ip(hostname)

    # TLS cert (only for HTTPS)
    tls_cert = None
    if is_https:
        tls_cert = _inspect_tls_cert(hostname, port)

    # Real TCP/TLS timing measurement
    conn_timing = _measure_connection(hostname, port, use_tls=is_https, sni=hostname)
    measured_connect = conn_timing["connect_time"]
    measured_tls = conn_timing["tls_time"]
    if conn_timing["ip"]:
        ip_address = conn_timing["ip"]

    # HTTP request with timing
    t_start = time.perf_counter()
    probe_id = _generate_probe_id()

    try:
        transport = httpx.HTTPTransport(verify=verify, retries=0)

        with httpx.Client(
            transport=transport,
            timeout=httpx.Timeout(timeout, connect=timeout),
            follow_redirects=False,
        ) as client:
            resp = client.get(url, headers={"User-Agent": f"k8s-ai-monitor/probe ({probe_id})"})

            total_time = time.perf_counter() - t_start
            elapsed = resp.elapsed.total_seconds() if hasattr(resp, "elapsed") else total_time
            ttfb = elapsed

            status_code = resp.status_code
            reason = httpx.codes.get_reason_phrase(resp.status_code)
            headers = _extract_headers(resp)
            body = resp.text[:500] if resp.text else ""
            redirect_location = headers.get("location", "")

    except httpx.TimeoutException:
        return ProbeResult(
            url=url, status_code=None, reason=f"Timeout after {timeout}s",
            dns_time=dns_time, connect_time=measured_connect, tls_time=measured_tls,
            total_time=time.perf_counter() - t_start,
            ip_address=ip_address, tls_cert=tls_cert, probe_id=probe_id,
        )
    except httpx.ConnectError as e:
        return ProbeResult(
            url=url, status_code=None, reason=f"Connection error: {e}",
            dns_time=dns_time, connect_time=measured_connect, tls_time=measured_tls,
            total_time=time.perf_counter() - t_start,
            ip_address=ip_address, tls_cert=tls_cert, probe_id=probe_id,
        )
    except Exception as e:
        return ProbeResult(
            url=url, status_code=None, reason=f"Request failed: {e}",
            dns_time=dns_time, connect_time=measured_connect, tls_time=measured_tls,
            total_time=time.perf_counter() - t_start,
            ip_address=ip_address, tls_cert=tls_cert, probe_id=probe_id,
        )

    return ProbeResult(
        url=url,
        status_code=status_code,
        reason=reason,
        dns_time=dns_time,
        connect_time=measured_connect,
        tls_time=measured_tls,
        ttfb=ttfb,
        total_time=total_time,
        headers=headers,
        body=body,
        tls_cert=tls_cert,
        redirect_location=redirect_location,
        ip_address=ip_address,
        probe_id=probe_id,
    )


def probe_via_cluster_ip(
    host: str,
    path: str,
    ingress_svc: str,
    timeout: float = 10,
) -> ProbeResult:
    """Probe through nginx ingress ClusterIP using Host header + HTTPS.

    Sends request to the ingress service ClusterIP with the appropriate Host header.
    This tests in-cluster connectivity to nginx ingress, NOT the external network path.
    """
    # Build URL targeting the ingress controller service
    url = f"https://{ingress_svc}{path}"

    from urllib.parse import urlparse
    parsed = urlparse(f"https://{ingress_svc}")
    ingress_host = parsed.hostname or ingress_svc.split(":")[0]
    ingress_port = parsed.port or 443

    # DNS resolution for ingress service
    ip_address, dns_time = _resolve_ip(ingress_host)

    # TLS cert inspection using the actual host (SNI)
    tls_cert = _inspect_tls_cert(ingress_host, ingress_port)

    # Real TCP/TLS timing measurement
    conn_timing = _measure_connection(ingress_host, ingress_port, use_tls=True, sni=host)
    measured_connect = conn_timing["connect_time"]
    measured_tls = conn_timing["tls_time"]
    if conn_timing["ip"]:
        ip_address = conn_timing["ip"]

    t_start = time.perf_counter()
    probe_id = _generate_probe_id()
    try:
        transport = httpx.HTTPTransport(verify=False, retries=0)

        with httpx.Client(
            transport=transport,
            timeout=httpx.Timeout(timeout, connect=timeout),
            follow_redirects=False,
        ) as client:
            resp = client.get(url, headers={
                "Host": host,
                "User-Agent": f"k8s-ai-monitor/probe ({probe_id})",
            })

            total_time = time.perf_counter() - t_start
            elapsed = resp.elapsed.total_seconds() if hasattr(resp, "elapsed") else total_time
            ttfb = elapsed

            headers = _extract_headers(resp)
            body = resp.text[:500] if resp.text else ""

            return ProbeResult(
                url=f"https://{host}{path} (via ClusterIP {ingress_svc})",
                status_code=resp.status_code,
                reason=httpx.codes.get_reason_phrase(resp.status_code),
                dns_time=dns_time,
                connect_time=measured_connect,
                tls_time=measured_tls,
                ttfb=ttfb,
                total_time=total_time,
                headers=headers,
                body=body,
                tls_cert=tls_cert,
                redirect_location=headers.get("location", ""),
                ip_address=ip_address,
                probe_id=probe_id,
            )

    except httpx.TimeoutException:
        return ProbeResult(
            url=f"https://{host}{path} (via ClusterIP {ingress_svc})",
            status_code=None, reason=f"Timeout after {timeout}s",
            dns_time=dns_time, connect_time=measured_connect, tls_time=measured_tls,
            total_time=time.perf_counter() - t_start,
            ip_address=ip_address, tls_cert=tls_cert, probe_id=probe_id,
        )
    except httpx.ConnectError as e:
        return ProbeResult(
            url=f"https://{host}{path} (via ClusterIP {ingress_svc})",
            status_code=None, reason=f"Connection error: {e}",
            dns_time=dns_time, connect_time=measured_connect, tls_time=measured_tls,
            total_time=time.perf_counter() - t_start,
            ip_address=ip_address, tls_cert=tls_cert, probe_id=probe_id,
        )
    except Exception as e:
        return ProbeResult(
            url=f"https://{host}{path} (via ClusterIP {ingress_svc})",
            status_code=None, reason=f"Request failed: {e}",
            dns_time=dns_time, connect_time=measured_connect, tls_time=measured_tls,
            total_time=time.perf_counter() - t_start,
            ip_address=ip_address, tls_cert=tls_cert, probe_id=probe_id,
        )


# Keep old name as alias for backward compatibility
probe_via_ingress = probe_via_cluster_ip


def probe_external(
    host: str,
    path: str,
    ingress_svc: str,
    timeout: float = 10,
) -> ProbeResult:
    """Probe through the external LoadBalancer IP.

    Discovers the real LB IP from the ingress Service's status.loadBalancer,
    then connects to it directly — testing the actual external network path.
    Falls back to ClusterIP probe if LB IP is unavailable, labeled honestly.
    """
    lb_ip = get_lb_ip(ingress_svc)

    if not lb_ip:
        logger.debug("LB IP unavailable for %s, falling back to ClusterIP probe", ingress_svc)
        result = probe_via_cluster_ip(host, path, ingress_svc, timeout)
        result.url = f"https://{host}{path} (via ClusterIP — LB IP unavailable)"
        return result

    # Real TCP/TLS timing to the LB IP
    conn_timing = _measure_connection(lb_ip, 443, use_tls=True, sni=host)
    measured_connect = conn_timing["connect_time"]
    measured_tls = conn_timing["tls_time"]

    # TLS cert inspection via LB IP
    tls_cert = _inspect_tls_cert(lb_ip, 443)

    t_start = time.perf_counter()
    probe_id = _generate_probe_id()
    url = f"https://{lb_ip}{path}"

    try:
        transport = httpx.HTTPTransport(verify=False, retries=0)

        with httpx.Client(
            transport=transport,
            timeout=httpx.Timeout(timeout, connect=timeout),
            follow_redirects=False,
        ) as client:
            resp = client.get(url, headers={
                "Host": host,
                "User-Agent": f"k8s-ai-monitor/probe ({probe_id})",
            })

            total_time = time.perf_counter() - t_start
            elapsed = resp.elapsed.total_seconds() if hasattr(resp, "elapsed") else total_time
            ttfb = elapsed

            headers = _extract_headers(resp)
            body = resp.text[:500] if resp.text else ""

            return ProbeResult(
                url=f"https://{host}{path} (via LB {lb_ip})",
                status_code=resp.status_code,
                reason=httpx.codes.get_reason_phrase(resp.status_code),
                dns_time=0.0,  # No DNS — we use IP directly
                connect_time=measured_connect,
                tls_time=measured_tls,
                ttfb=ttfb,
                total_time=total_time,
                headers=headers,
                body=body,
                tls_cert=tls_cert,
                redirect_location=headers.get("location", ""),
                ip_address=lb_ip,
                probe_id=probe_id,
            )

    except httpx.TimeoutException:
        return ProbeResult(
            url=f"https://{host}{path} (via LB {lb_ip})",
            status_code=None, reason=f"Timeout after {timeout}s",
            connect_time=measured_connect, tls_time=measured_tls,
            total_time=time.perf_counter() - t_start,
            ip_address=lb_ip, tls_cert=tls_cert, probe_id=probe_id,
        )
    except httpx.ConnectError as e:
        return ProbeResult(
            url=f"https://{host}{path} (via LB {lb_ip})",
            status_code=None, reason=f"Connection error: {e}",
            connect_time=measured_connect, tls_time=measured_tls,
            total_time=time.perf_counter() - t_start,
            ip_address=lb_ip, tls_cert=tls_cert, probe_id=probe_id,
        )
    except Exception as e:
        return ProbeResult(
            url=f"https://{host}{path} (via LB {lb_ip})",
            status_code=None, reason=f"Request failed: {e}",
            connect_time=measured_connect, tls_time=measured_tls,
            total_time=time.perf_counter() - t_start,
            ip_address=lb_ip, tls_cert=tls_cert, probe_id=probe_id,
        )

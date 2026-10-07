# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
Port Scanner Module - TCP connect scans with async concurrency.
"""
import asyncio
import socket
import ssl
import time
import re
import sys
from dataclasses import dataclass, field
from ipaddress import IPv4Address, ip_address, ip_network
from typing import Optional

from .logger import get_logger
from .services import WELL_KNOWN_SERVICES

logger = get_logger(__name__)


@dataclass
class PortResult:
    """Result of scanning a single port."""
    port: int
    state: str  # "open", "closed", "filtered"
    service: str = ""
    banner: str = ""
    version: str = ""
    tls_info: dict = field(default_factory=dict)


@dataclass
class HostResult:
    """Aggregated scan results for a single host."""
    ip: str
    hostname: str = ""
    is_up: bool = False
    scan_time: float = 0.0
    ports: list = field(default_factory=list)
    os_guess: str = ""
    latency_ms: float = 0.0


def get_local_ip() -> str:
    """Auto-detect current active IP address on the primary network interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't actually send packets, just determines outgoing interface
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def get_local_subnet() -> str:
    """Auto-detect local network CIDR subnet (e.g., 192.168.1.0/24)."""
    ip = get_local_ip()
    if ip == "127.0.0.1":
        return "127.0.0.1"
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return ip


def resolve_targets(target: str) -> list[str]:
    """Resolve target spec into IP list. Supports IP, CIDR, hostname, range."""
    targets = []
    if "/" in target:
        try:
            network = ip_network(target, strict=False)
            if network.prefixlen < 16:
                logger.warning(f"Large range /{network.prefixlen}, limiting to 65536 hosts.")
            for i, host in enumerate(network.hosts()):
                if i >= 65536:
                    break
                targets.append(str(host))
            return targets
        except ValueError:
            pass

    if "-" in target:
        try:
            start_ip, end_ip = target.split("-", 1)
            start_ip, end_ip = start_ip.strip(), end_ip.strip()
            if "." not in end_ip:
                base = ".".join(start_ip.split(".")[:-1])
                end_ip = f"{base}.{end_ip}"
            s, e = int(ip_address(start_ip)), int(ip_address(end_ip))
            if e < s:
                s, e = e, s
            for ip_int in range(s, e + 1):
                targets.append(str(IPv4Address(ip_int)))
            return targets
        except (ValueError, TypeError):
            pass

    try:
        ip_address(target)
        targets.append(target)
    except ValueError:
        try:
            resolved = socket.gethostbyname(target)
            targets.append(resolved)
            logger.info(f"Resolved {target} -> {resolved}")
        except socket.gaierror:
            logger.error(f"Could not resolve hostname: {target}")
    return targets


def parse_ports(port_spec: str) -> list[int]:
    """Parse port spec: single, range, comma-separated, or presets."""
    from .services import PORT_PRESETS
    spec = port_spec.strip().lower()
    if spec in PORT_PRESETS:
        return sorted(set(PORT_PRESETS[spec]))
    if spec == "all":
        return list(range(1, 65536))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            try:
                s, e = part.split("-", 1)
                s, e = int(s), int(e)
                if 1 <= s <= 65535 and 1 <= e <= 65535:
                    ports.update(range(min(s, e), max(s, e) + 1))
            except ValueError:
                logger.warning(f"Invalid port range: {part}")
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                logger.warning(f"Invalid port: {part}")
    return sorted(ports)


def guess_os_from_ttl(ttl: int) -> str:
    """Infer target operating system family from network packet TTL."""
    if ttl <= 0:
        return ""
    if ttl <= 64:
        return "Linux / Unix / macOS (TTL ~64)"
    elif ttl <= 128:
        return "Windows NT/10/11/Server (TTL ~128)"
    elif ttl <= 255:
        return "Cisco / Solaris / Network Device (TTL ~255)"
    return f"Unknown OS (TTL {ttl})"


def infer_os_from_ports(ports: list) -> str:
    """Fallback OS inference from discovered open services and banners."""
    for p in ports:
        srv = (p.service or "").lower()
        bnr = (p.banner or "").lower()
        if p.port in (135, 139, 445, 3389) or "microsoft" in bnr or "iis" in srv:
            return "Windows (Inferred from SMB/RDP/IIS)"
        if "ubuntu" in bnr:
            return "Linux / Ubuntu (Inferred from banner)"
        if "debian" in bnr:
            return "Linux / Debian (Inferred from banner)"
        if "centos" in bnr or "redhat" in bnr or "rhel" in bnr:
            return "Linux / RHEL / CentOS (Inferred from banner)"
        if "openssh" in bnr:
            return "Linux / Unix (Inferred from OpenSSH)"
        if "cisco" in bnr:
            return "Cisco IOS (Inferred from banner)"
    return ""


async def grab_banner_and_tls(ip: str, port: int, timeout: float = 3.0) -> tuple[str, dict]:
    """
    Attempt to grab a service banner and SSL/TLS certificate metadata from an open port.
    Supports protocol-specific probes (HTTP/HTTPS, Redis INFO, MySQL handshake, SMTP, etc.).
    """
    use_ssl = port in (443, 8443, 9443, 6443)
    tls_info = {}
    banner_out = ""

    try:
        reader = None
        writer = None

        if use_ssl:
            try:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=ssl_context), timeout=timeout
                )
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj:
                    try:
                        tls_info["version"] = ssl_obj.version() or "TLS"
                        cipher_info = ssl_obj.cipher()
                        if cipher_info:
                            tls_info["cipher"] = cipher_info[0]
                    except Exception:
                        pass
            except Exception:
                # Fallback to plain connection if SSL fails
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=timeout
                    )
                    use_ssl = False
                except Exception:
                    return "", {}
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )

        # 1. Passive read: Services that announce themselves immediately (SSH, FTP, SMTP, MySQL)
        try:
            raw = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            if raw:
                # Check for MySQL initial handshake
                if port == 3306 and len(raw) > 5 and raw[4] == 10:
                    null_idx = raw.find(b"\x00", 5)
                    if null_idx != -1:
                        ver = raw[5:null_idx].decode("ascii", errors="replace").strip()
                        banner_out = f"MySQL Server {ver}"
                else:
                    banner_out = raw.decode("utf-8", errors="replace").strip()
        except (asyncio.TimeoutError, OSError):
            pass

        # 2. Redis Probe (port 6379)
        if port == 6379 and not banner_out:
            try:
                writer.write(b"INFO\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(2048), timeout=1.5)
                if resp:
                    resp_str = resp.decode("utf-8", errors="replace")
                    if "redis_version" in resp_str:
                        banner_out = resp_str.strip()
                    elif "-NOAUTH" in resp_str:
                        banner_out = "Redis (Authentication Required)"
            except Exception:
                pass

        # 3. HTTP / HTTPS Probes
        if (port in (80, 8080, 8000, 8888, 9090, 3000, 5000, 443, 8443, 9443) or use_ssl) and not banner_out:
            http_req = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: PVS/2.0\r\nConnection: close\r\n\r\n"
            writer.write(http_req.encode())
            await writer.drain()
            try:
                resp = await asyncio.wait_for(reader.read(2048), timeout=2.0)
                resp_text = resp.decode("utf-8", errors="replace")
                banner_out = resp_text.strip()
                title_match = re.search(r"<title>(.*?)</title>", resp_text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    title = title_match.group(1).strip()
                    banner_out = f"{banner_out}\nTitle: {title}"
            except (asyncio.TimeoutError, OSError):
                pass

        # 4. Memcached Probe (port 11211)
        if port == 11211 and not banner_out:
            try:
                writer.write(b"stats\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(1024), timeout=1.5)
                if resp and b"STAT" in resp:
                    banner_out = resp.decode("utf-8", errors="replace").strip()
            except Exception:
                pass

        # 5. Docker Daemon REST API Probe (port 2375)
        if port == 2375 and not banner_out:
            try:
                writer.write(f"GET /version HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: PVS/2.0\r\nConnection: close\r\n\r\n".encode())
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(1024), timeout=1.5)
                if resp and b"ApiVersion" in resp:
                    banner_out = f"Docker Daemon REST API: {resp.decode('utf-8', errors='replace').strip()}"
            except Exception:
                pass

        # 6. Elasticsearch Probe (port 9200)
        if port == 9200 and not banner_out:
            try:
                writer.write(f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: PVS/2.0\r\nConnection: close\r\n\r\n".encode())
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(1024), timeout=1.5)
                if resp and b"tagline" in resp:
                    banner_out = f"Elasticsearch: {resp.decode('utf-8', errors='replace').strip()}"
            except Exception:
                pass

        # 7. SMB Probe (ports 445, 139)
        if port in (445, 139) and not banner_out:
            try:
                dialects = b"\x02PC NETWORK PROGRAM 1.0\x00\x02LANMAN1.0\x00\x02NT LM 0.12\x00"
                smb_header = b"\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                smb_body = b"\x00" + len(dialects).to_bytes(2, "little") + dialects
                smb_packet = smb_header + smb_body
                netbios_hdr = b"\x00" + len(smb_packet).to_bytes(3, "big")
                writer.write(netbios_hdr + smb_packet)
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(1024), timeout=1.5)
                if resp and len(resp) >= 8 and resp[4:8] == b"\xffSMB":
                    banner_out = "Microsoft Windows SMB (SMBv1 Negotiated)"
            except Exception:
                pass

        # 8. RDP Probe (port 3389)
        if port == 3389 and not banner_out:
            try:
                rdp_cr = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\x00"
                writer.write(rdp_cr)
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(1024), timeout=1.5)
                if resp and len(resp) >= 11 and resp[5] == 0xd0:
                    banner_out = "Microsoft Remote Desktop Protocol (RDP)"
            except Exception:
                pass

        # 9. Fallback generic trigger: send newline
        if not banner_out:
            try:
                writer.write(b"\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                if resp:
                    banner_out = resp.decode("utf-8", errors="replace").strip()
            except Exception:
                pass

        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError, ConnectionResetError):
        pass

    return banner_out, tls_info


async def grab_banner(ip: str, port: int, timeout: float = 3.0) -> str:
    """Attempt to grab a service banner from an open port (backwards-compatible wrapper)."""
    banner, _ = await grab_banner_and_tls(ip, port, timeout=timeout)
    return banner


def parse_banner(banner: str, port: int) -> tuple[str, str]:
    """Extract refined service name and version from a banner."""
    service = WELL_KNOWN_SERVICES.get(port, "unknown")
    version = ""
    if not banner:
        return service, version
    bl = banner.lower()

    # SSH
    if bl.startswith("ssh-"):
        service = "ssh"
        parts = banner.split("-")
        if len(parts) >= 3:
            version = "-".join(parts[2:]).split()[0]
        return service, version

    # Web servers (Apache, Nginx, IIS, etc.)
    if "server:" in bl:
        for line in banner.split("\n"):
            line_str = line.strip()
            if line_str.lower().startswith("server:"):
                service = "http"
                version = line_str.split(":", 1)[1].strip()
                return service, version

    # Redis
    if "redis_version:" in bl:
        service = "redis"
        m = re.search(r"redis_version:([^\r\n]+)", banner)
        if m:
            version = m.group(1).strip()
        return service, version

    # MySQL
    if "mysql server" in bl or (bl.startswith("mysql") and "version" in bl):
        service = "mysql"
        m = re.search(r"(\d+\.\d+(?:\.\d+)*)", banner)
        if m:
            version = m.group(1)
        return service, version

    # Memcached
    if "stat version" in bl:
        service = "memcached"
        m = re.search(r"stat version\s+([^\r\n]+)", bl)
        if m:
            version = m.group(1).strip()
        return service, version

    # Elasticsearch
    if "you know, for search" in bl:
        service = "elasticsearch"
        m = re.search(r'"number"\s*:\s*"([^"]+)"', banner)
        if m:
            version = m.group(1).strip()
        return service, version

    # Docker
    if "apiversion" in bl or "docker" in bl:
        service = "docker"
        m = re.search(r'"Version"\s*:\s*"([^"]+)"', banner)
        if m:
            version = m.group(1).strip()
        return service, version

    # SMB / Windows
    if "microsoft windows smb" in bl or port in (445, 139):
        service = "smb"
        return service, version

    # RDP
    if "remote desktop" in bl or port == 3389:
        service = "rdp"
        return service, version

    # SMTP / FTP
    if bl.startswith("220"):
        service = "smtp" if "smtp" in bl else "ftp"
        version = banner[4:].strip()
        return service, version

    ver_match = re.search(r'(\d+\.\d+(?:\.\d+)*)', banner)
    if ver_match:
        version = ver_match.group(1)
    return service, version


async def scan_port(ip: str, port: int, timeout: float = 2.0, grab_banners: bool = True) -> Optional[PortResult]:
    """Scan a single port on a target host."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        result = PortResult(port=port, state="open", service=WELL_KNOWN_SERVICES.get(port, "unknown"))
        if grab_banners:
            banner, tls_info = await grab_banner_and_tls(ip, port, timeout=timeout)
            if banner:
                result.banner = banner[:500]
                result.service, result.version = parse_banner(banner, port)
            if tls_info:
                result.tls_info = tls_info
        return result
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def probe_host(ip: str, timeout: int = 1) -> tuple[bool, int, float]:
    """
    Probe host with ICMP and fallback TCP ping.
    Returns (is_alive: bool, ttl: int, latency_ms: float).
    """
    platform = sys.platform.lower()
    if platform == "win32":
        param = "-n"
        timeout_param = "-w"
        timeout_val = str(timeout * 1000)
    elif platform == "darwin":
        param = "-c"
        timeout_param = "-W"
        timeout_val = str(timeout * 1000)
    else:
        param = "-c"
        timeout_param = "-W"
        timeout_val = str(timeout)

    ttl = 0
    latency_ms = 0.0
    icmp_success = False

    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", param, "1", timeout_param, timeout_val, ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        if proc.returncode == 0:
            icmp_success = True
            out_str = stdout.decode("utf-8", errors="replace")
            ttl_match = re.search(r"TTL=(\d+)", out_str, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
            time_match = re.search(r"time[<=](\d+(?:\.\d+)?)ms", out_str, re.IGNORECASE)
            if time_match:
                latency_ms = float(time_match.group(1))
            return True, ttl, latency_ms
    except OSError:
        pass

    # TCP Ping Fallback (common ports: 22, 80, 443, 445, 3389)
    tcp_ports = [22, 80, 443, 445, 3389]
    for port in tcp_ports:
        t0 = time.time()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=0.5
            )
            latency_ms = round((time.time() - t0) * 1000, 1)
            writer.close()
            await writer.wait_closed()
            return True, ttl, latency_ms
        except (ConnectionRefusedError, ConnectionResetError):
            latency_ms = round((time.time() - t0) * 1000, 1)
            return True, ttl, latency_ms
        except Exception:
            continue

    return False, 0, 0.0


async def is_host_alive(ip: str, timeout: int = 1) -> bool:
    """Check if a host is alive using ICMP and fallback TCP ping (backwards-compatible)."""
    alive, _, _ = await probe_host(ip, timeout=timeout)
    return alive


async def filter_live_hosts(ips: list[str], concurrency: int = 50) -> list[str]:
    """Filter a list of IPs to only those that respond to ping."""
    live_hosts = []
    sem = asyncio.Semaphore(concurrency)

    async def _check(ip):
        async with sem:
            if await is_host_alive(ip):
                live_hosts.append(ip)

    tasks = [_check(ip) for ip in ips]
    await asyncio.gather(*tasks)
    return live_hosts


async def scan_host(ip, ports, timeout=2.0, concurrency=100, grab_banners=True, progress_cb=None):
    """Scan all specified ports on a single host with OS fingerprinting and latency tracking."""
    start = time.time()
    result = HostResult(ip=ip)
    try:
        hostname = socket.getfqdn(ip)
        if hostname != ip:
            result.hostname = hostname
    except (socket.herror, socket.gaierror):
        pass

    # Network probe for latency and TTL OS guess
    is_alive, ttl, latency_ms = await probe_host(ip, timeout=1)
    if is_alive:
        result.is_up = True
        result.latency_ms = latency_ms
        if ttl > 0:
            result.os_guess = guess_os_from_ttl(ttl)

    sem = asyncio.Semaphore(concurrency)
    scanned = 0
    total = len(ports)

    async def _scan(port):
        nonlocal scanned
        async with sem:
            r = await scan_port(ip, port, timeout, grab_banners)
            scanned += 1
            if progress_cb:
                progress_cb(scanned, total)
            return r

    tasks = [_scan(p) for p in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, PortResult):
            result.ports.append(r)
            result.is_up = True

    result.ports.sort(key=lambda p: p.port)

    # If OS not determined via TTL, infer from open service ports and banners
    if not result.os_guess and result.ports:
        inferred = infer_os_from_ports(result.ports)
        if inferred:
            result.os_guess = inferred

    result.scan_time = time.time() - start
    return result


# ────────────────────────────────────────────────────────────────────────────
# Intelligent Port Prioritization
# ────────────────────────────────────────────────────────────────────────────

# Ports that are most frequently open and security-relevant, ordered by
# empirical discovery frequency from real-world network scans.
_HIGH_PRIORITY_PORTS = [
    80, 443, 22, 445, 139, 3389, 21, 25, 53, 8080,
    23, 110, 143, 993, 995, 3306, 5432, 6379, 8443,
    27017, 9200, 2375, 5900, 11211, 8888, 9090,
]

# Related port clusters — discovering one port suggests others may be open.
_SERVICE_PORT_ASSOCIATIONS = {
    # If SSH is open, check other admin/management ports
    22:   [80, 443, 8080, 3306, 5432, 9090],
    # If HTTP is open, check HTTPS + common web app ports
    80:   [443, 8080, 8443, 8000, 3000, 5000, 9090],
    443:  [80, 8080, 8443],
    # If SMB is open, check Windows ecosystem
    445:  [139, 135, 3389, 5985, 5986, 88],
    139:  [445, 135, 3389],
    # If MySQL is open, check other DB/cache ports
    3306: [5432, 6379, 27017, 9200, 11211, 3000],
    5432: [3306, 6379, 9200, 27017],
    # If Redis, check other cache/DB ports
    6379: [11211, 3306, 5432, 27017, 9200],
    # If RDP, check other Windows services
    3389: [445, 139, 135, 5985],
    # If FTP, check related file transfer
    21:   [22, 69, 2049, 445],
    # If Docker API exposed, check K8s and management
    2375: [2376, 6443, 10250, 9090, 8080],
}


def prioritize_ports(requested_ports: list[int], discovered_open: list[int] = None) -> list[int]:
    """
    Reorder a port list for intelligent scanning priority.

    Moves high-priority / frequently-open ports to the front of the scan queue
    so results appear faster and timeout budget is spent on likely-open ports first.

    If `discovered_open` is provided (from a previous scan phase), ports
    associated with those discovered services are promoted.

    Args:
        requested_ports: The full list of ports the user requested.
        discovered_open: Optional list of already-discovered open ports.

    Returns:
        A reordered copy of requested_ports.
    """
    port_set = set(requested_ports)
    priority_score = {}

    # Base priority from empirical frequency
    for idx, p in enumerate(_HIGH_PRIORITY_PORTS):
        if p in port_set:
            priority_score[p] = priority_score.get(p, 0) + (100 - idx)

    # Boost ports associated with already-discovered services
    if discovered_open:
        for open_port in discovered_open:
            related = _SERVICE_PORT_ASSOCIATIONS.get(open_port, [])
            for rp in related:
                if rp in port_set:
                    priority_score[rp] = priority_score.get(rp, 0) + 50

    # Build ordered list: prioritised ports first, then remainder in original order
    prioritised = sorted(
        [p for p in requested_ports if p in priority_score],
        key=lambda p: priority_score.get(p, 0),
        reverse=True
    )
    remainder = [p for p in requested_ports if p not in priority_score]
    return prioritised + remainder


# ────────────────────────────────────────────────────────────────────────────
# Service Correlation Engine
# ────────────────────────────────────────────────────────────────────────────

# Service categories for correlation analysis
_SERVICE_CATEGORIES = {
    "web":       {80, 443, 8080, 8443, 8000, 8888, 9090, 3000, 5000},
    "database":  {3306, 5432, 1433, 1521, 27017, 6379, 9200, 11211, 2049},
    "remote":    {22, 23, 3389, 5900, 5985, 5986},
    "email":     {25, 110, 143, 465, 587, 993, 995},
    "file":      {20, 21, 69, 445, 139, 2049},
    "dns":       {53},
    "container": {2375, 2376, 6443, 10250},
    "monitor":   {161, 162, 9090, 9100, 3000},
}


def correlate_services(host_results: list) -> dict:
    """
    Analyze discovered services across hosts and identify service correlation
    patterns, role classifications, and dependency relationships.

    Returns a dict with:
      - host_roles: mapping of IP -> list of inferred roles
      - service_categories: mapping of category -> list of (ip, port, service)
      - network_services: summary of unique services found
      - topology_hints: list of topology observation strings
    """
    host_roles = {}
    service_categories = {cat: [] for cat in _SERVICE_CATEGORIES}
    all_services = set()
    topology_hints = []

    for hr in host_results:
        roles = set()
        open_ports = {pr.port for pr in hr.ports}

        for pr in hr.ports:
            svc = (pr.service or "").lower()
            all_services.add(svc if svc and svc != "unknown" else f"port-{pr.port}")

            # Classify into categories
            for cat, cat_ports in _SERVICE_CATEGORIES.items():
                if pr.port in cat_ports:
                    service_categories[cat].append((hr.ip, pr.port, svc))

        # Infer host roles from open ports
        web_ports = open_ports & _SERVICE_CATEGORIES["web"]
        db_ports = open_ports & _SERVICE_CATEGORIES["database"]
        remote_ports = open_ports & _SERVICE_CATEGORIES["remote"]
        container_ports = open_ports & _SERVICE_CATEGORIES["container"]

        if web_ports and db_ports:
            roles.add("application-server")
            topology_hints.append(
                f"{hr.ip} hosts both web ({sorted(web_ports)}) and database "
                f"({sorted(db_ports)}) services — likely an application server "
                f"or development environment."
            )
        elif web_ports:
            roles.add("web-server")
        if db_ports and not web_ports:
            roles.add("database-server")
        if remote_ports:
            roles.add("remote-admin")
        if container_ports:
            roles.add("container-host")
        if 53 in open_ports:
            roles.add("dns-server")
        if open_ports & {25, 465, 587}:
            roles.add("mail-server")
        if open_ports & {445, 139}:
            roles.add("file-server")

        # Gateway / router detection
        if len(open_ports) >= 5 and {80, 443, 53} <= open_ports:
            roles.add("gateway/router")
            topology_hints.append(
                f"{hr.ip} exposes HTTP, HTTPS, and DNS — likely a network "
                f"gateway or router."
            )

        host_roles[hr.ip] = sorted(roles) if roles else ["general-purpose"]

    # Cross-host correlation insights
    db_hosts = [ip for ip, roles in host_roles.items() if "database-server" in roles]
    web_hosts = [ip for ip, roles in host_roles.items() if "web-server" in roles or "application-server" in roles]
    if db_hosts and web_hosts:
        topology_hints.append(
            f"Network has {len(web_hosts)} web/app server(s) and "
            f"{len(db_hosts)} database server(s) — typical multi-tier architecture."
        )

    return {
        "host_roles": host_roles,
        "service_categories": {
            cat: entries for cat, entries in service_categories.items() if entries
        },
        "network_services": sorted(all_services),
        "topology_hints": topology_hints,
    }


def build_network_topology(host_results: list) -> dict:
    """
    Build a lightweight network topology map from scan results.

    Returns a dict with:
      - total_hosts: int
      - live_hosts: int
      - host_map: list of dicts with ip, hostname, os, role, open_ports, services
      - subnet_summary: dict mapping subnet prefix -> host count
    """
    host_map = []
    subnet_counts = {}
    correlation = correlate_services(host_results)

    for hr in host_results:
        services = []
        for pr in hr.ports:
            svc_name = pr.service or WELL_KNOWN_SERVICES.get(pr.port, f"port-{pr.port}")
            services.append({
                "port": pr.port,
                "service": svc_name,
                "version": pr.version or "",
                "has_tls": bool(getattr(pr, "tls_info", None)),
            })

        roles = correlation["host_roles"].get(hr.ip, ["general-purpose"])

        host_map.append({
            "ip": hr.ip,
            "hostname": hr.hostname or "",
            "os_guess": getattr(hr, "os_guess", ""),
            "latency_ms": getattr(hr, "latency_ms", 0.0),
            "roles": roles,
            "open_ports": len(hr.ports),
            "services": services,
        })

        # Subnet grouping
        parts = hr.ip.split(".")
        if len(parts) == 4:
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1

    return {
        "total_hosts": len(host_results),
        "live_hosts": sum(1 for hr in host_results if hr.is_up),
        "host_map": host_map,
        "subnet_summary": subnet_counts,
        "correlation": correlation,
    }


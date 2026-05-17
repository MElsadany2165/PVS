"""
Port Scanner Module - TCP connect scans with async concurrency.
"""
import asyncio
import socket
import time
import re
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


@dataclass
class HostResult:
    """Aggregated scan results for a single host."""
    ip: str
    hostname: str = ""
    is_up: bool = False
    scan_time: float = 0.0
    ports: list = field(default_factory=list)


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


async def grab_banner(ip: str, port: int, timeout: float = 3.0) -> str:
    """Attempt to grab a service banner from an open port."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            if banner:
                writer.close()
                await writer.wait_closed()
                return banner.decode("utf-8", errors="replace").strip()
        except asyncio.TimeoutError:
            pass

        if port in (80, 8080, 8000, 8888, 443, 8443):
            http_req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            writer.write(http_req.encode())
            await writer.drain()
            try:
                resp = await asyncio.wait_for(reader.read(2048), timeout=2.0)
                writer.close()
                await writer.wait_closed()
                return resp.decode("utf-8", errors="replace").strip()
            except asyncio.TimeoutError:
                pass

        writer.write(b"\r\n")
        await writer.drain()
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            await writer.wait_closed()
            return banner.decode("utf-8", errors="replace").strip()
        except asyncio.TimeoutError:
            pass
        writer.close()
        await writer.wait_closed()
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError, ConnectionResetError):
        pass
    return ""


def parse_banner(banner: str, port: int) -> tuple[str, str]:
    """Extract service name and version from a banner."""
    service = WELL_KNOWN_SERVICES.get(port, "unknown")
    version = ""
    if not banner:
        return service, version
    bl = banner.lower()
    if bl.startswith("ssh-"):
        service = "ssh"
        parts = banner.split("-")
        if len(parts) >= 3:
            version = "-".join(parts[2:]).split()[0]
        return service, version
    if "server:" in bl:
        for line in banner.split("\n"):
            if line.lower().startswith("server:"):
                service, version = "http", line.split(":", 1)[1].strip()
                return service, version
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
            banner = await grab_banner(ip, port, timeout=timeout)
            if banner:
                result.banner = banner[:500]
                result.service, result.version = parse_banner(banner, port)
        return result
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def scan_host(ip, ports, timeout=2.0, concurrency=100, grab_banners=True, progress_cb=None):
    """Scan all specified ports on a single host."""
    start = time.time()
    result = HostResult(ip=ip)
    try:
        hostname = socket.getfqdn(ip)
        if hostname != ip:
            result.hostname = hostname
    except (socket.herror, socket.gaierror):
        pass
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
    result.scan_time = time.time() - start
    return result

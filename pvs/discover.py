# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
PVS Network Subnet Sweep & Asset Intelligence Engine.
Rapidly scans local or specified CIDR subnets (e.g., 192.168.1.0/24),
resolves hostnames, fingerprints OS profiles via heuristics and service signatures,
and classifies network device roles (Routers, Windows PCs, Linux Servers, Printers, IoT).
"""

import asyncio
import socket
import time
from dataclasses import dataclass, field
from ipaddress import ip_network, ip_address
from typing import Any, Dict, List, Optional

from .logger import get_logger
from .scanner import get_local_subnet, get_local_ip, filter_live_hosts

logger = get_logger(__name__)

# Key management and identification ports to probe during discovery
DISCOVERY_PORTS = [22, 53, 80, 135, 139, 443, 445, 554, 631, 3389, 5357, 8080, 9100]


@dataclass
class DiscoveredDevice:
    """Discovered network asset with role classification and OS fingerprinting."""
    ip: str
    hostname: str = ""
    is_up: bool = True
    latency_ms: float = 0.0
    device_role: str = "Generic Network Host"
    os_guess: str = "Unknown OS"
    open_ports: List[int] = field(default_factory=list)
    services: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "is_up": self.is_up,
            "latency_ms": round(self.latency_ms, 2),
            "device_role": self.device_role,
            "os_guess": self.os_guess,
            "open_ports": self.open_ports,
            "services": self.services,
        }


async def _resolve_hostname(ip: str, timeout: float = 1.0) -> str:
    """Resolve PTR hostname in background thread with timeout."""
    loop = asyncio.get_running_loop()
    def _sync_lookup():
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""
    try:
        return await asyncio.wait_for(loop.run_in_executor(None, _sync_lookup), timeout=timeout)
    except Exception:
        return ""


async def _probe_port(ip: str, port: int, timeout: float = 0.8) -> Optional[int]:
    """Check if single port is open."""
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port
    except Exception:
        return None


def _classify_device(ip: str, hostname: str, open_ports: List[int]) -> tuple[str, str]:
    """
    Classify device role and guess OS based on IP position, hostname, and open port heuristics.
    """
    ports_set = set(open_ports)
    h_lower = hostname.lower()

    # Router / Gateway
    is_gateway_ip = ip.endswith(".1") or ip.endswith(".254")
    if is_gateway_ip or 53 in ports_set or "router" in h_lower or "gateway" in h_lower:
        return "Gateway / Router", "Embedded Linux / Network OS"

    # Network Printer
    if 9100 in ports_set or 631 in ports_set or "printer" in h_lower or "canon" in h_lower or "hp" in h_lower:
        return "Network Printer / MFD", "Embedded Printer Firmware"

    # IP Camera / CCTV / Media
    if 554 in ports_set or "cam" in h_lower or "rtsp" in h_lower or "hikvision" in h_lower or "dahua" in h_lower:
        return "IP Camera / Surveillance", "Embedded Linux / RTOS"

    # Windows Workstation / Server
    if (445 in ports_set or 139 in ports_set or 3389 in ports_set or 5357 in ports_set) or "win" in h_lower:
        os_name = "Windows Server" if (3389 in ports_set and 445 in ports_set and 80 in ports_set) else "Windows 10 / 11"
        return "Windows Workstation / PC", os_name

    # Linux / Unix Server
    if 22 in ports_set and 445 not in ports_set:
        return "Linux / Unix Server", "Linux Kernel (SSH)"

    # Web Server
    if 80 in ports_set or 443 in ports_set or 8080 in ports_set:
        return "Web / Application Server", "Linux / FreeBSD (Web)"

    # Apple device
    if "apple" in h_lower or "macbook" in h_lower or "iphone" in h_lower:
        return "Apple Device", "macOS / iOS"

    return "Generic Network Host", "Unknown OS"


async def discover_subnet(
    target_subnet: Optional[str] = None,
    timeout: float = 1.0,
    concurrency: int = 100,
    quick_ports: Optional[List[int]] = None,
) -> List[DiscoveredDevice]:
    """
    Perform a high-speed network asset discovery across a subnet or CIDR range.
    """
    if not target_subnet or target_subnet in ("local", "home", "auto"):
        target_subnet = get_local_subnet()

    probe_ports = quick_ports or DISCOVERY_PORTS

    # Resolve all host IPs
    host_ips = []
    try:
        net = ip_network(target_subnet, strict=False)
        for h in net.hosts():
            host_ips.append(str(h))
            if len(host_ips) >= 1024:  # Safety cap for sweeps
                break
    except Exception:
        # Single IP or simple range
        host_ips = [target_subnet]

    if not host_ips:
        return []

    # 1. Sweep for live hosts
    live_hosts = await filter_live_hosts(host_ips, concurrency=concurrency)

    # If ping sweep was completely blocked by local host firewall, try probing port 80/445 directly on first 10
    if not live_hosts and len(host_ips) <= 256:
        sem = asyncio.Semaphore(concurrency)
        async def check_direct(ip):
            async with sem:
                for p in [80, 445, 22, 53]:
                    if await _probe_port(ip, p, timeout=0.5):
                        return ip
            return None
        tasks = [check_direct(ip) for ip in host_ips]
        results = await asyncio.gather(*tasks)
        live_hosts = [r for r in results if r]

    discovered: List[DiscoveredDevice] = []
    sem = asyncio.Semaphore(concurrency)

    async def inspect_host(ip: str):
        async with sem:
            t0 = time.time()
            port_tasks = [_probe_port(ip, p, timeout=timeout) for p in probe_ports]
            port_results = await asyncio.gather(*port_tasks)
            open_p = [p for p in port_results if p is not None]

            latency_ms = (time.time() - t0) * 1000.0
            hostname = await _resolve_hostname(ip, timeout=1.0)
            role, os_guess = _classify_device(ip, hostname, open_p)

            discovered.append(DiscoveredDevice(
                ip=ip,
                hostname=hostname,
                is_up=True,
                latency_ms=latency_ms,
                device_role=role,
                os_guess=os_guess,
                open_ports=sorted(open_p),
                services=[f"Port {p}" for p in sorted(open_p)],
            ))

    if live_hosts:
        await asyncio.gather(*[inspect_host(ip) for ip in live_hosts])

    # Sort numerically by IP address
    def ip_sort_key(dev: DiscoveredDevice):
        try:
            return int(ip_address(dev.ip))
        except Exception:
            return 0

    return sorted(discovered, key=ip_sort_key)


def display_discovered_devices(devices: List[DiscoveredDevice], subnet: str):
    """Render discovered devices in a rich terminal table."""
    from .display import console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

    console.print(Panel(
        f"[bold white]Scanned Subnet :[/] [cyan]{subnet}[/]\n"
        f"[bold white]Discovered Assets:[/] [green]{len(devices)} active network devices[/]",
        title="[bold cyan]📡 PVS ASSET INTELLIGENCE & NETWORK MAP[/]",
        border_style="cyan",
        box=box.ROUNDED,
    ))

    if not devices:
        console.print("[yellow]No live devices responded in the specified subnet.[/]")
        return

    table = Table(box=box.ROUNDED, border_style="cyan")
    table.add_column("IP Address", style="bold white")
    table.add_column("Hostname", style="dim cyan")
    table.add_column("Device Role", style="bold yellow")
    table.add_column("OS Fingerprint", style="magenta")
    table.add_column("Latency", style="dim green", justify="right")
    table.add_column("Admin/Open Ports", style="green")

    for dev in devices:
        ports_str = ", ".join(str(p) for p in dev.open_ports) if dev.open_ports else "[dim]ICMP only[/]"
        lat_str = f"{dev.latency_ms:.1f}ms"
        h_str = dev.hostname if dev.hostname else "[dim]—[/]"
        table.add_row(
            dev.ip,
            h_str,
            dev.device_role,
            dev.os_guess,
            lat_str,
            ports_str,
        )

    console.print(table)

"""
Rich CLI Display - Beautiful terminal output using the Rich library.
"""
import sys
import os

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich import box

console = Console(force_terminal=True)

BANNER_TEXT = (
    "\n"
    "  [bold bright_cyan]██████╗ ██╗   ██╗███████╗[/]\n"
    "  [bold bright_cyan]██╔══██╗██║   ██║██╔════╝[/]    [bold]Personal Vulnerability Scanner[/]\n"
    "  [bold bright_cyan]██████╔╝██║   ██║███████╗[/]    [dim]v1.0.0[/]\n"
    "  [bold bright_cyan]██╔═══╝ ╚██╗ ██╔╝╚════██║[/]\n"
    "  [bold bright_cyan]██║      ╚████╔╝ ███████║[/]    [dim]Ethical Security Testing[/]\n"
    "  [bold bright_cyan]╚═╝       ╚═══╝  ╚══════╝[/]\n"
)

SEVERITY_STYLES = {
    "CRITICAL": "bold bright_red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
    "UNKNOWN": "dim",
}


def show_banner():
    """Display the PVS banner."""
    console.print(BANNER_TEXT)


def show_disclaimer():
    """Display the security policy and compliance disclaimer."""
    disclaimer_text = (
        "WARNING: AUTHORIZED PENETRATION AUDITING AND ETHICAL SECURITY TESTS ONLY.\n"
        "SCANNING SYSTEMS WITHOUT EXPLICIT WRITTEN CONSENT IS ILLEGAL/PUNISHABLE.\n"
        "USE RESILIENTLY. USER ASSUMES ALL CRITICAL COMPLIANCE LIABILITY."
    )
    console.print(Panel(
        disclaimer_text,
        title="[bold red]POLICY & AUDIT DISCLAIMER[/]",
        border_style="red",
        padding=(0, 2),
        expand=False
    ))


def show_scan_config(target, ports_count, options):
    """Display scan configuration in a modern profile layout."""
    config_text = Text()
    config_text.append("  Target host      : ", style="dim")
    config_text.append(f"{target}\n", style="bold bright_cyan")
    config_text.append("  Scan scope       : ", style="dim")
    config_text.append(f"{ports_count} ports\n", style="bold")
    config_text.append("  Response timeout : ", style="dim")
    config_text.append(f"{options.get('timeout', 2.0)}s\n", style="bold")
    config_text.append("  Concurrent flows : ", style="dim")
    config_text.append(f"{options.get('concurrency', 100)}\n", style="bold")
    config_text.append("  Banner recon     : ", style="dim")
    config_text.append(f"{'Enabled' if options.get('banners', True) else 'Disabled'}\n", style="bold")
    config_text.append("  Vulnerability DB : ", style="dim")
    config_text.append(f"{'Connected' if options.get('cve', False) else 'None'}\n", style="bold")

    console.print(Panel(config_text, title="[bold bright_cyan]Scan Configuration[/]",
                        border_style="bright_blue", padding=(0, 1)))


def show_host_results(host_result):
    """Display scan results for a single target host."""
    if not host_result.ports:
        console.print(f"\n  Host {host_result.ip} - no open ports detected in scope")
        return

    # Host header
    host_label = host_result.ip
    if host_result.hostname:
        host_label += f" ({host_result.hostname})"

    table = Table(
        title=f"Host Audit Details: {host_label}",
        box=box.ROUNDED,
        border_style="bright_blue",
        header_style="bold bright_cyan",
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("Port", style="bold bright_cyan", width=8, justify="right")
    table.add_column("State", width=8)
    table.add_column("Service", style="bold", width=16)
    table.add_column("Version", width=30)
    table.add_column("Captured Banner", style="dim", max_width=40, overflow="ellipsis")

    for port in host_result.ports:
        state_text = Text("open", style="bold green")
        table.add_row(
            str(port.port), state_text,
            port.service, port.version,
            port.banner[:60] if port.banner else "",
        )

    console.print()
    console.print(table)
    console.print(f"  Scan completed in {host_result.scan_time:.2f}s")


def show_cve_results(cve_results: dict):
    """Display NVD CVE lookup results."""
    if not cve_results:
        console.print("\n  No security vulnerabilities identified in service signatures.")
        return

    console.print()
    total = sum(len(v) for v in cve_results.values())
    console.print(Panel(
        f"Identified {total} potential vulnerabilities across "
        f"{len(cve_results)} active service(s).",
        title="[!] Vulnerability Assessment Summary",
        border_style="yellow",
    ))

    for key, cves in cve_results.items():
        if not cves:
            continue

        table = Table(
            title=f"Vulnerabilities for {key}",
            box=box.SIMPLE_HEAVY,
            border_style="yellow",
            header_style="bold",
            show_lines=True,
        )
        table.add_column("CVE ID", style="bold cyan", width=18)
        table.add_column("Severity", width=12, justify="center")
        table.add_column("CVSS Score", width=12, justify="center")
        table.add_column("Description", max_width=60)
        table.add_column("Published", width=12)

        for cve in cves[:10]:  # Limit display
            sev_style = SEVERITY_STYLES.get(cve.severity, "dim")
            score_style = "bold bright_red" if cve.score >= 9.0 else \
                          "bold red" if cve.score >= 7.0 else \
                          "bold yellow" if cve.score >= 4.0 else "bold green"

            table.add_row(
                Text(cve.cve_id, style="bold cyan"),
                Text(cve.severity, style=sev_style),
                Text(f"{cve.score:.1f}", style=score_style),
                cve.description[:120],
                cve.published,
            )

        console.print(table)


def show_summary(host_results, scan_time: float):
    """Display overall scan execution summary."""
    total_ports = sum(len(h.ports) for h in host_results)
    hosts_up = sum(1 for h in host_results if h.is_up)

    summary = Text()
    summary.append("\n  Scan Execution Complete\n\n", style="bold green")
    summary.append(f"  Hosts scanned:  {len(host_results)}\n", style="dim")
    summary.append(f"  Active hosts:   {hosts_up}\n", style="bold")
    summary.append(f"  Open ports:     {total_ports}\n", style="bold bright_cyan")
    summary.append(f"  Execution time: {scan_time:.2f}s\n", style="dim")

    console.print(Panel(summary, title="Scan Summary",
                        border_style="green", padding=(0, 1)))


def create_progress():
    """Create a modern progress bar for target auditing."""
    return Progress(
        SpinnerColumn(style="bright_cyan"),
        TextColumn("[bold bright_cyan]{task.description}"),
        BarColumn(bar_width=40, style="bright_blue", complete_style="bright_cyan"),
        TextColumn("[bold]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    )


def show_warning(msg: str):
    """Display a warning message."""
    console.print(f"\n  [bold yellow][!] WARNING: {msg}[/]")


def show_error(msg: str):
    """Display an error message."""
    console.print(f"\n  [bold red][X] ERROR: {msg}[/]")


def show_info(msg: str):
    """Display a status info message."""
    console.print(f"\n  [bright_cyan][*] INFO: {msg}[/]")

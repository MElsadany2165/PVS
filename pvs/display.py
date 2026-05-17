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
from rich.layout import Layout
from rich.columns import Columns
from rich import box

console = Console(force_terminal=True)

BANNER_TEXT = (
    "\n"
    "  [bold bright_cyan]+---------------------------------------------------------+[/]\n"
    "  [bold bright_cyan]|[/]                                                         [bold bright_cyan]|[/]\n"
    "  [bold bright_cyan]|[/]   [bold bright_magenta]PPPP   V   V  SSSS[/]                                  [bold bright_cyan]|[/]\n"
    "  [bold bright_cyan]|[/]   [bold bright_magenta]P   P  V   V  S[/]       Personal Vulnerability       [bold bright_cyan]|[/]\n"
    "  [bold bright_cyan]|[/]   [bold bright_magenta]PPPP    V V   SSSS[/]    Scanner v1.0.0                [bold bright_cyan]|[/]\n"
    "  [bold bright_cyan]|[/]   [bold bright_magenta]P        V       S[/]                                  [bold bright_cyan]|[/]\n"
    "  [bold bright_cyan]|[/]   [bold bright_magenta]P        V    SSSS[/]    [dim]Ethical Security Testing[/]       [bold bright_cyan]|[/]\n"
    "  [bold bright_cyan]|[/]                                                         [bold bright_cyan]|[/]\n"
    "  [bold bright_cyan]+---------------------------------------------------------+[/]\n"
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


def show_scan_config(target, ports_count, options):
    """Display scan configuration."""
    config_text = Text()
    config_text.append("  Target:       ", style="dim")
    config_text.append(f"{target}\n", style="bold cyan")
    config_text.append("  Ports:        ", style="dim")
    config_text.append(f"{ports_count}\n", style="bold")
    config_text.append("  Timeout:      ", style="dim")
    config_text.append(f"{options.get('timeout', 2.0)}s\n", style="bold")
    config_text.append("  Concurrency:  ", style="dim")
    config_text.append(f"{options.get('concurrency', 100)}\n", style="bold")
    config_text.append("  Banners:      ", style="dim")
    config_text.append(f"{'Yes' if options.get('banners', True) else 'No'}\n", style="bold")
    config_text.append("  CVE Lookup:   ", style="dim")
    config_text.append(f"{'Yes' if options.get('cve', False) else 'No'}\n", style="bold")

    console.print(Panel(config_text, title="[bold]Scan Configuration[/]",
                        border_style="bright_blue", padding=(0, 1)))


def show_host_results(host_result):
    """Display results for a single host."""
    if not host_result.ports:
        console.print(f"\n  [dim]Host {host_result.ip} - no open ports found[/]")
        return

    # Host header
    host_label = host_result.ip
    if host_result.hostname:
        host_label += f" ({host_result.hostname})"

    table = Table(
        title=f"[HOST] {host_label}",
        box=box.ROUNDED,
        border_style="bright_blue",
        header_style="bold bright_cyan",
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("Port", style="bold cyan", width=8, justify="right")
    table.add_column("State", width=8)
    table.add_column("Service", style="bold", width=16)
    table.add_column("Version", width=30)
    table.add_column("Banner", style="dim", max_width=40, overflow="ellipsis")

    for port in host_result.ports:
        state_text = Text("open", style="bold green")
        table.add_row(
            str(port.port), state_text,
            port.service, port.version,
            port.banner[:60] if port.banner else "",
        )

    console.print()
    console.print(table)
    console.print(f"  [dim]Scan completed in {host_result.scan_time:.2f}s[/]")


def show_cve_results(cve_results: dict):
    """Display CVE lookup results."""
    if not cve_results:
        console.print("\n  [dim]No CVEs found for discovered services.[/]")
        return

    console.print()
    total = sum(len(v) for v in cve_results.values())
    console.print(Panel(
        f"[bold]Found {total} potential vulnerabilities across "
        f"{len(cve_results)} service(s)[/]",
        title="[!] [bold yellow]Vulnerability Assessment[/]",
        border_style="yellow",
    ))

    for key, cves in cve_results.items():
        if not cves:
            continue

        table = Table(
            title=f"[>] {key}",
            box=box.SIMPLE_HEAVY,
            border_style="yellow",
            header_style="bold",
            show_lines=True,
        )
        table.add_column("CVE ID", style="bold", width=18)
        table.add_column("Severity", width=12, justify="center")
        table.add_column("Score", width=7, justify="center")
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
    """Display scan summary."""
    total_ports = sum(len(h.ports) for h in host_results)
    hosts_up = sum(1 for h in host_results if h.is_up)

    summary = Text()
    summary.append("\n  [+] Scan Complete\n\n", style="bold green")
    summary.append(f"  Hosts scanned:  {len(host_results)}\n", style="dim")
    summary.append(f"  Hosts up:       {hosts_up}\n", style="bold")
    summary.append(f"  Open ports:     {total_ports}\n", style="bold cyan")
    summary.append(f"  Total time:     {scan_time:.2f}s\n", style="dim")

    console.print(Panel(summary, title="[bold]Scan Summary[/]",
                        border_style="green", padding=(0, 1)))


def create_progress():
    """Create a rich progress bar for scanning."""
    return Progress(
        SpinnerColumn(style="bright_cyan"),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=40, style="bright_blue", complete_style="bright_cyan"),
        TextColumn("[bold]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    )


def show_warning(msg: str):
    """Display a warning message."""
    console.print(f"\n  [bold yellow][!] {msg}[/]")


def show_error(msg: str):
    """Display an error message."""
    console.print(f"\n  [bold red][X] {msg}[/]")


def show_info(msg: str):
    """Display an info message."""
    console.print(f"\n  [bright_cyan][i] {msg}[/]")

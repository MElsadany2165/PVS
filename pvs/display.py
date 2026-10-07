# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
Rich CLI Display - Beautiful terminal output using the Rich library.
Supports CISA KEV badges, Step-by-Step Remediation procedure panels,
and Post-Scan Action Summary for all user personas.
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

from pvs import __version__

console = Console(force_terminal=True)

BANNER_TEXT = (
    "\n"
    "  [bold cyan]██████╗ ██╗   ██╗███████╗[/]\n"
    "  [bold cyan]██╔══██╗██║   ██║██╔════╝[/]    [bold white]Personal Vulnerability Scanner[/]\n"
    f"  [bold cyan]██████╔╝██║   ██║███████╗[/]    [dim]v{__version__}[/]\n"
    "  [bold cyan]██╔═══╝ ╚██╗ ██╔╝╚════██║[/]\n"
    "  [bold cyan]██║      ╚████╔╝ ███████║[/]    [dim]Ethical Security Testing & Remediation Engine[/]\n"
    "  [bold cyan]╚═╝       ╚═══╝  ╚══════╝[/]\n"
)

SEVERITY_STYLES = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
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
        box=box.ROUNDED,
        padding=(0, 2),
        expand=False
    ))


def show_scan_config(target, ports_count, options):
    """Display scan configuration in a modern profile layout."""
    config_text = Text()
    config_text.append("  Target host      : ", style="dim")
    config_text.append(f"{target}\n", style="bold white")
    config_text.append("  Scan scope       : ", style="dim")
    config_text.append(f"{ports_count} ports\n", style="bold white")
    config_text.append("  Response timeout : ", style="dim")
    config_text.append(f"{options.get('timeout', 2.0)}s\n", style="bold white")
    config_text.append("  Concurrent flows : ", style="dim")
    config_text.append(f"{options.get('concurrency', 100)}\n", style="bold white")
    config_text.append("  Banner recon     : ", style="dim")
    config_text.append(f"{'Enabled' if options.get('banners', True) else 'Disabled'}\n", style="bold white")
    config_text.append("  Vulnerability DB : ", style="dim")
    config_text.append(f"{'Multi-Source Engine (NVD + CISA KEV + OSV)' if options.get('cve', False) else 'None'}\n", style="bold white")

    console.print(Panel(
        config_text,
        title="[bold cyan]Scan Configuration[/]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(0, 1)
    ))


def show_host_results(host_result):
    """Display scan results for a single target host with OS fingerprinting and latency."""
    if not host_result.ports:
        console.print(f"\n  [dim]Host {host_result.ip} - no open ports detected in scope[/]")
        return

    # Host header with OS guess & latency
    host_label = host_result.ip
    if host_result.hostname:
        host_label += f" ({host_result.hostname})"
    if getattr(host_result, "os_guess", ""):
        host_label += f" — [green]{host_result.os_guess}[/]"
    if getattr(host_result, "latency_ms", 0.0) > 0:
        host_label += f" [dim]({host_result.latency_ms}ms round-trip)[/]"

    table = Table(
        title=f"Host Audit Details: {host_label}",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("Port", style="bold white", width=8, justify="right")
    table.add_column("State", width=8)
    table.add_column("Service", style="bold white", width=16)
    table.add_column("Version", width=30)
    table.add_column("Captured Banner / Recon", style="dim", max_width=45, overflow="ellipsis")

    for port in host_result.ports:
        state_text = Text("open", style="green")
        banner_display = port.banner[:60] if port.banner else ""
        if getattr(port, "tls_info", None):
            tls_v = port.tls_info.get("version", "TLS")
            tls_c = port.tls_info.get("cipher", "")
            prefix = f"[{tls_v}] {tls_c} " if tls_c else f"[{tls_v}] "
            banner_display = (prefix + banner_display)[:60]

        table.add_row(
            str(port.port), state_text,
            port.service, port.version,
            banner_display,
        )

    console.print()
    console.print(table)
    console.print(f"  [dim]Scan completed in {host_result.scan_time:.2f}s[/]")


def show_cve_results(cve_results: dict, show_remediation: bool = False):
    """Display multi-source CVE lookup results, EPSS threat scores, and remediation procedures."""
    if not cve_results:
        console.print("\n  [dim]No security vulnerabilities identified in service signatures.[/]")
        return

    console.print()
    total = sum(len(v) for v in cve_results.values())
    kev_count = sum(
        1 for cves in cve_results.values() for c in cves if getattr(c, "is_kev", False) or (isinstance(c, dict) and c.get("is_kev"))
    )

    summary_text = f"Identified {total} potential vulnerabilities across {len(cve_results)} active service(s)."
    if kev_count > 0:
        summary_text += f"\n[bold red]WARNING: {kev_count} vulnerability(ies) are actively exploited in the wild (CISA KEV).[/]"

    console.print(Panel(
        summary_text,
        title="[bold cyan]Vulnerability Assessment Summary[/]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(0, 1),
    ))

    for key, cves in cve_results.items():
        if not cves:
            continue

        table = Table(
            title=f"Vulnerabilities for {key}",
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold cyan",
            show_lines=False,
        )
        table.add_column("CVE ID", style="bold white", width=18)
        table.add_column("Severity", width=12, justify="center")
        table.add_column("CVSS Score", width=12, justify="center")
        table.add_column("Threat Status / Priority", width=26, justify="center")
        table.add_column("Description", max_width=45)

        for cve in cves[:10]:
            cve_id = cve.cve_id if hasattr(cve, "cve_id") else cve.get("cve_id", "UNKNOWN")
            severity = cve.severity if hasattr(cve, "severity") else cve.get("severity", "UNKNOWN")
            score = cve.score if hasattr(cve, "score") else cve.get("score", 0.0)
            description = cve.description if hasattr(cve, "description") else cve.get("description", "")
            is_kev = cve.is_kev if hasattr(cve, "is_kev") else cve.get("is_kev", False)
            p_score = getattr(cve, "priority_score", 0.0) if hasattr(cve, "priority_score") else cve.get("priority_score", 0.0)
            p_level = getattr(cve, "priority_level", "") if hasattr(cve, "priority_level") else cve.get("priority_level", "")
            epss_val = getattr(cve, "epss_score", 0.0) if hasattr(cve, "epss_score") else cve.get("epss_score", 0.0)

            sev_style = SEVERITY_STYLES.get(severity, "dim")
            score_style = "bold red" if score >= 7.0 else "bold yellow" if score >= 4.0 else "green"

            if str(cve_id).startswith("VULN-"):
                status_text = Text(f"🔥 ACTIVE EXPOSURE ({p_score:.0f}/100)", style="bold bright_red")
            elif is_kev:
                status_text = Text(f"🚨 KEV EXPLOITED ({p_score:.0f}/100)", style="bold red")
            elif p_score > 0:
                p_style = "bold red" if p_score >= 85 else "bold yellow" if p_score >= 70 else "white"
                epss_str = f" | EPSS:{epss_val*100:.0f}%" if epss_val > 0 else ""
                status_text = Text(f"{p_level} {p_score:.0f}/100{epss_str}", style=p_style)
            else:
                status_text = Text("Standard CVE", style="dim")

            table.add_row(
                Text(cve_id, style="white"),
                Text(severity, style=sev_style),
                Text(f"{score:.1f}", style=score_style),
                status_text,
                description[:120],
            )

        console.print(table)

        # Print ONE clean service remediation procedure panel per service
        if show_remediation and cves:
            first_cve = cves[0]
            rem = first_cve.remediation if hasattr(first_cve, "remediation") else first_cve.get("remediation")
            if rem:
                summary_desc = rem.summary if hasattr(rem, "summary") else rem.get("summary", "")
                steps_list = rem.steps if hasattr(rem, "steps") else rem.get("steps", [])

                rem_text = Text()
                rem_text.append(f"{summary_desc}\n\n", style="dim")

                for step in steps_list:
                    s_num = step.step_number if hasattr(step, "step_number") else step.get("step_number", 1)
                    s_title = step.title if hasattr(step, "title") else step.get("title", "")
                    s_desc = step.description if hasattr(step, "description") else step.get("description", "")
                    s_lin = (step.command_linux if hasattr(step, "command_linux") else step.get("command_linux")) or ""
                    s_win = (step.command_windows if hasattr(step, "command_windows") else step.get("command_windows")) or ""
                    s_mac = (step.command_macos if hasattr(step, "command_macos") else step.get("command_macos")) or ""
                    s_disr = (step.disruption_level if hasattr(step, "disruption_level") else step.get("disruption_level")) or ""
                    s_est = (step.estimated_time if hasattr(step, "estimated_time") else step.get("estimated_time")) or ""

                    meta = f" [{s_disr} | {s_est}]" if (s_disr or s_est) else ""
                    rem_text.append(f"Step {s_num}: {s_title}{meta}\n", style="bold white")
                    rem_text.append(f"  {s_desc}\n", style="dim")
                    if s_lin:
                        rem_text.append(f"  Linux   : {s_lin}\n", style="white")
                    if s_win:
                        rem_text.append(f"  Windows : {s_win}\n", style="white")
                    if s_mac:
                        rem_text.append(f"  macOS   : {s_mac}\n", style="white")
                    rem_text.append("\n")

                console.print(Panel(
                    rem_text,
                    title=f"[bold cyan]Remediation Procedure for {key}[/]",
                    border_style="cyan",
                    box=box.ROUNDED,
                    padding=(0, 1),
                ))


def show_summary(host_results, scan_time: float):
    """Display overall scan execution summary."""
    total_ports = sum(len(h.ports) for h in host_results)
    hosts_up = sum(1 for h in host_results if h.is_up)

    summary = Text()
    summary.append("  Scan Execution Complete\n\n", style="bold white")
    summary.append(f"  Hosts scanned:  {len(host_results)}\n", style="dim")
    summary.append(f"  Active hosts:   {hosts_up}\n", style="bold white")
    summary.append(f"  Open ports:     {total_ports}\n", style="bold white")
    summary.append(f"  Execution time: {scan_time:.2f}s\n", style="dim")

    console.print(Panel(
        summary,
        title="[bold cyan]Scan Summary[/]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(0, 1)
    ))


def show_post_scan_actions(cve_results: dict, html_path: str = None):
    """Display concise action summary after scan completion."""
    critical = 0
    high = 0
    medium = 0
    low = 0
    total_cves = 0

    for cves in cve_results.values():
        for cve in cves:
            total_cves += 1
            sev = (cve.severity if hasattr(cve, "severity") else cve.get("severity", "")).upper()
            if sev == "CRITICAL":
                critical += 1
            elif sev == "HIGH":
                high += 1
            elif sev == "MEDIUM":
                medium += 1
            elif sev == "LOW":
                low += 1

    action_text = Text()

    if html_path:
        action_text.append(f"  Audit report generated: {html_path}\n\n", style="bold white")

    if total_cves == 0:
        action_text.append("  No security vulnerabilities detected across target services.\n", style="green")
    else:
        action_text.append(f"  Found {total_cves} vulnerability issue(s):\n\n", style="bold white")
        if critical > 0:
            action_text.append(f"    • {critical} Critical severity\n", style="bold red")
        if high > 0:
            action_text.append(f"    • {high} High severity\n", style="red")
        if medium > 0:
            action_text.append(f"    • {medium} Medium severity\n", style="yellow")
        if low > 0:
            action_text.append(f"    • {low} Low severity\n", style="green")

        action_text.append("\n  Step-by-step fix procedures are provided in the HTML report.\n", style="dim")

    console.print(Panel(
        action_text,
        title="[bold cyan]Action Summary[/]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(0, 1),
    ))


def create_progress():
    """Create a clean progress bar for target auditing."""
    return Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[dim]{task.description}"),
        BarColumn(bar_width=35, style="dim", complete_style="cyan"),
        TextColumn("[bold cyan]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    )


def show_warning(msg: str):
    """Display a warning message."""
    console.print(f"\n  [yellow][!] WARNING: {msg}[/]")


def show_error(msg: str):
    """Display an error message."""
    console.print(f"\n  [bold red][X] ERROR: {msg}[/]")


def show_info(msg: str):
    """Display a status info message."""
    console.print(f"\n  [cyan][*] INFO: {msg}[/]")


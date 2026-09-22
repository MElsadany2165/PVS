# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
PVS Interactive Security Assistant & Guided Wizard v2.0
Conversational, persona-tailored audit launcher.

- Home Users:    Plain English, zero jargon, auto-detection, one-click flow
- Students:      Educational context, learning tips, full export formats
- CyberSec Pros: Compact technical prompts, CIDR support, enterprise presets
- Custom:        Full manual control for advanced targeting
"""

import sys
import os
import argparse
import webbrowser
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.rule import Rule
from rich import box
from rich.columns import Columns
from rich.align import Align

from pvs import __version__
from .scanner import get_local_ip, get_local_subnet

console = Console(force_terminal=True)


# ─── Friendly Messages ──────────────────────────────────────────────────────

WELCOME_MSG = (
    "[bold white]Welcome to PVS — your personal security guard.[/]\n\n"
    "[dim]PVS checks your network for security problems and tells you\n"
    "exactly how to fix them, step by step. No technical knowledge needed.[/]"
)

HOME_CONFIRM_TEMPLATE = (
    "[bold white]I'll scan your home network[/] [bold cyan]({subnet})[/] [bold white]for security issues.[/]\n\n"
    "[dim]This typically takes 30–60 seconds. I'll check for:[/]\n"
    "  [green]✅[/] Open doors (ports) that attackers could use\n"
    "  [green]✅[/] Known security bugs in your software\n"
    "  [green]✅[/] Step-by-step instructions to fix any issues\n"
)

LOCAL_CONFIRM = (
    "[bold white]I'll scan this computer only[/] [bold cyan](127.0.0.1)[/] [bold white]for security issues.[/]\n\n"
    "[dim]This is a quick check of services running on your machine.[/]\n"
    "  [green]✅[/] Open doors (ports) on your PC\n"
    "  [green]✅[/] Known security bugs\n"
    "  [green]✅[/] Fix instructions for each issue\n"
)

STUDENT_TIPS = [
    "[bold cyan]💡 Learning Tip:[/] [dim]A 'port' is like a numbered door on your computer. Services like web servers (port 80) and SSH (port 22) listen behind these doors.[/]",
    "[bold cyan]💡 Learning Tip:[/] [dim]A 'CVE' (Common Vulnerabilities and Exposures) is a publicly known security bug with a unique ID like CVE-2024-1234.[/]",
    "[bold cyan]💡 Learning Tip:[/] [dim]CVSS scores range from 0.0 to 10.0. Anything above 7.0 is 'High' severity — fix it fast![/]",
    "[bold cyan]💡 Learning Tip:[/] [dim]CISA KEV = Known Exploited Vulnerabilities. These are bugs that real hackers are actively using right now.[/]",
]

PRO_HEADER_SUBTITLE = "Penetration Audit & Threat Intelligence Engine"


# ─── Wizard Header ───────────────────────────────────────────────────────────

def show_wizard_header(persona: str = ""):
    """Render status header with auto-detection dashboard."""
    local_ip = get_local_ip()
    local_subnet = get_local_subnet()
    platform_name = sys.platform.upper().replace("WIN32", "WINDOWS").replace("DARWIN", "macOS")

    header_text = Text()
    header_text.append("  ██████╗ ██╗   ██╗███████╗   ", style="bold cyan")
    header_text.append("PVS Security Assistant\n", style="bold white")
    header_text.append("  ██╔══██╗██║   ██║██╔════╝   ", style="bold cyan")
    header_text.append(f"v{__version__} | Security Scanner\n", style="dim")
    header_text.append("  ██████╔╝██║   ██║███████╗   ", style="bold cyan")
    header_text.append(f"IP: {local_ip} ({local_subnet})\n", style="dim")
    header_text.append("  ██╔═══╝ ╚██╗ ██╔╝╚════██║   ", style="bold cyan")
    header_text.append(f"OS: {platform_name}\n", style="dim")
    header_text.append("  ██║      ╚████╔╝ ███████║   ", style="bold cyan")
    header_text.append("Threat DB: SQLite + CISA KEV + OSV\n", style="dim")
    header_text.append("  ╚═╝       ╚═══╝  ╚══════╝\n", style="bold cyan")

    console.print(Panel(header_text, border_style="cyan", box=box.ROUNDED, padding=(0, 1)))


def show_pro_header():
    """Render compact professional header for CyberSec pro mode."""
    local_ip = get_local_ip()
    local_subnet = get_local_subnet()
    platform_name = sys.platform.upper().replace("WIN32", "WINDOWS").replace("DARWIN", "macOS")

    header_text = Text()
    header_text.append("  ██████╗ ██╗   ██╗███████╗   ", style="bold cyan")
    header_text.append(f"PVS {PRO_HEADER_SUBTITLE}\n", style="bold white")
    header_text.append("  ██╔══██╗██║   ██║██╔════╝   ", style="bold cyan")
    header_text.append(f"v{__version__} | Threat Intelligence Engine\n", style="dim")
    header_text.append("  ██████╔╝██║   ██║███████╗   ", style="bold cyan")
    header_text.append(f"IP: {local_ip} ({local_subnet})\n", style="dim")
    header_text.append("  ██╔═══╝ ╚██╗ ██╔╝╚════██║   ", style="bold cyan")
    header_text.append(f"OS: {platform_name}\n", style="dim")
    header_text.append("  ██║      ╚████╔╝ ███████║   ", style="bold cyan")
    header_text.append("Threat DB: SQLite + CISA KEV + NVD + OSV\n", style="dim")
    header_text.append("  ╚═╝       ╚═══╝  ╚══════╝\n", style="bold cyan")

    console.print(Panel(header_text, border_style="cyan", box=box.ROUNDED, padding=(0, 1)))


# ─── Persona Flows ────────────────────────────────────────────────────────────

def _flow_home_user() -> argparse.Namespace:
    """Home User flow — maximum simplicity, plain English, auto-detection."""
    local_subnet = get_local_subnet()

    console.print(f"\n[bold cyan]What would you like to check?[/]\n")
    console.print(f"  [bold cyan][1][/] [bold white]My Home Network[/]  [dim](scans {local_subnet})[/]")
    console.print(f"  [bold cyan][2][/] [bold white]Just This Computer[/]  [dim](checks local computer 127.0.0.1)[/]")
    console.print(f"  [bold cyan][3][/] [bold white]A Specific Host or IP[/]  [dim](enter address manually)[/]")

    choice = Prompt.ask("\n[bold cyan]Pick a number[/]", choices=["1", "2", "3"], default="1")

    if choice == "1":
        target = local_subnet
        console.print()
        console.print(Panel(
            HOME_CONFIRM_TEMPLATE.format(subnet=local_subnet),
            border_style="cyan",
            box=box.ROUNDED,
            title="[bold cyan]Home Network Scan[/]",
            padding=(1, 2),
        ))
    elif choice == "2":
        target = "127.0.0.1"
        console.print()
        console.print(Panel(
            LOCAL_CONFIRM,
            border_style="cyan",
            box=box.ROUNDED,
            title="[bold cyan]Local Computer Scan[/]",
            padding=(1, 2),
        ))
    else:
        target = Prompt.ask("\n[bold cyan]Enter the website or IP address[/]", default="scanme.nmap.org")
        console.print(f"\n  [green]✅[/] Got it — I'll scan [bold cyan]{target}[/]")

    # Simple "press Enter to start" confirmation
    try:
        input("\n  Press [Enter] to start the security check... ")
    except (KeyboardInterrupt, EOFError):
        console.print("\n  [dim]Cancelled.[/]")
        sys.exit(0)

    args = argparse.Namespace()
    args.target = target
    args.quiet = False
    args.log_level = "WARNING"
    args.log_file = None
    args.command = "scan"
    args.cve = True
    args.fix = True
    args.no_ping = False
    args.no_banner_grab = False
    args.nvd_api_key = None
    args.max_cves = 5
    args.output = None
    args.yes = True
    args.ports = "common"
    args.timeout = 2.0
    args.concurrency = 100
    args.format = "html"
    args.open = True
    args.no_cache = False
    args.clear_cache = False
    args.persona = "home"
    return args


def _flow_student() -> argparse.Namespace:
    """Student / Learner flow — simple interface + educational tips."""
    local_subnet = get_local_subnet()
    import random

    console.print(f"\n  [bold cyan]Security Learning Lab[/]\n")
    console.print(f"  [dim]This mode will scan your network AND explain what everything means,[/]")
    console.print(f"  [dim]so you can learn cybersecurity hands-on.[/]\n")

    # Show a random learning tip
    tip = random.choice(STUDENT_TIPS)
    console.print(Panel(tip, border_style="cyan", box=box.ROUNDED, padding=(0, 2)))

    console.print(f"\n[bold cyan]What do you want to scan?[/]\n")
    console.print(f"  [bold cyan][1][/] [bold white]My Home Network[/]  [dim]({local_subnet})[/]")
    console.print(f"  [bold cyan][2][/] [bold white]This Computer[/]  [dim](127.0.0.1)[/]")
    console.print(f"  [bold cyan][3][/] [bold white]Enter a Target[/]  [dim](IP, hostname, or website)[/]")

    choice = Prompt.ask("\n[bold cyan]Pick a number[/]", choices=["1", "2", "3"], default="1")

    if choice == "1":
        target = local_subnet
    elif choice == "2":
        target = "127.0.0.1"
    else:
        target = Prompt.ask("[bold cyan]Enter target[/]", default="scanme.nmap.org")

    console.print(f"\n  [green]✅[/] Target set to [bold cyan]{target}[/]")
    console.print(f"  [dim]I'll generate HTML, JSON, and CSV reports for your lab work.[/]\n")

    # Show another tip
    tip2 = random.choice([t for t in STUDENT_TIPS if t != tip])
    console.print(Panel(tip2, border_style="cyan", box=box.ROUNDED, padding=(0, 2)))

    try:
        input("\n  Press [Enter] to begin the security scan... ")
    except (KeyboardInterrupt, EOFError):
        console.print("\n  [dim]Cancelled.[/]")
        sys.exit(0)

    args = argparse.Namespace()
    args.target = target
    args.quiet = False
    args.log_level = "WARNING"
    args.log_file = None
    args.command = "scan"
    args.cve = True
    args.fix = True
    args.no_ping = False
    args.no_banner_grab = False
    args.nvd_api_key = None
    args.max_cves = 5
    args.output = None
    args.yes = True
    args.ports = "common"
    args.timeout = 2.0
    args.concurrency = 150
    args.format = "all"
    args.open = True
    args.no_cache = False
    args.clear_cache = False
    args.persona = "student"
    return args


def _flow_pro() -> argparse.Namespace:
    """CyberSec Professional flow — compact, technical, full control."""
    local_subnet = get_local_subnet()

    show_pro_header()

    console.print("[bold cyan]» Target Specification[/]")
    target = Prompt.ask(
        "  [bold white]Target[/] [dim](IP / hostname / CIDR / range)[/]",
        default=local_subnet
    )

    console.print("\n[bold cyan]» Port Scope Preset[/]")
    console.print("  [bold cyan][1][/] Common [dim](~1,000 ports)[/]")
    console.print("  [bold cyan][2][/] Enterprise [dim](~5,000 ports)[/]")
    console.print("  [bold cyan][3][/] Full [dim](1–65535)[/]")
    console.print("  [bold cyan][4][/] Custom [dim](manual spec)[/]")
    port_choice = Prompt.ask("  [bold white]Scope[/]", choices=["1", "2", "3", "4"], default="1")

    if port_choice == "1":
        ports = "common"
    elif port_choice == "2":
        ports = "enterprise"
    elif port_choice == "3":
        ports = "all"
    else:
        ports = Prompt.ask("  [bold white]Port specification[/]", default="top100")

    console.print("\n[bold cyan]» Performance Tuning[/]")
    concurrency = int(Prompt.ask("  [bold white]Concurrency[/]", default="300"))
    timeout = float(Prompt.ask("  [bold white]Timeout (sec)[/]", default="1.5"))

    console.print(f"\n  [green]✓[/] [bold white]Target:[/] {target}  |  [bold white]Ports:[/] {ports}  |  [bold white]Threads:[/] {concurrency}  |  [bold white]Timeout:[/] {timeout}s")
    console.print(f"  [dim]Output: HTML + JSON + CSV  |  CVE Engine: NVD + CISA KEV + OSV  |  Remediation: ON[/]\n")

    args = argparse.Namespace()
    args.target = target
    args.quiet = False
    args.log_level = "WARNING"
    args.log_file = None
    args.command = "scan"
    args.cve = True
    args.fix = True
    args.no_ping = False
    args.no_banner_grab = False
    args.nvd_api_key = None
    args.max_cves = 5
    args.output = None
    args.yes = True
    args.ports = ports
    args.timeout = timeout
    args.concurrency = concurrency
    args.format = "all"
    args.open = True
    args.no_cache = False
    args.clear_cache = False
    args.persona = "pro"
    return args


def _flow_custom() -> argparse.Namespace:
    """Custom targeted audit — full manual input."""
    local_subnet = get_local_subnet()

    console.print(f"\n  [bold cyan]Custom Targeted Audit[/]\n")
    console.print(f"  [dim]Full manual control over scan parameters.[/]\n")

    target = Prompt.ask("[bold cyan]Target[/] [dim](IP / hostname / CIDR / range)[/]", default="127.0.0.1")
    ports = Prompt.ask("[bold cyan]Ports[/] [dim](number, range, or preset: top20/top100/common/enterprise/all)[/]", default="top100")
    timeout = float(Prompt.ask("[bold cyan]Timeout[/] [dim](seconds)[/]", default="2.0"))
    concurrency = int(Prompt.ask("[bold cyan]Concurrency[/] [dim](max parallel connections)[/]", default="100"))
    enable_cve = Confirm.ask("[bold cyan]Enable vulnerability lookup?[/]", default=True)
    enable_fix = Confirm.ask("[bold cyan]Show fix procedures?[/]", default=True) if enable_cve else False
    fmt = Prompt.ask("[bold cyan]Report format[/]", choices=["html", "json", "csv", "all"], default="html")
    auto_open = Confirm.ask("[bold cyan]Auto-open report in browser?[/]", default=True)

    console.print(f"\n  [green]✓[/] Configuration ready for [bold cyan]{target}[/]")

    args = argparse.Namespace()
    args.target = target
    args.quiet = False
    args.log_level = "WARNING"
    args.log_file = None
    args.command = "scan"
    args.cve = enable_cve
    args.fix = enable_fix
    args.no_ping = False
    args.no_banner_grab = False
    args.nvd_api_key = None
    args.max_cves = 5
    args.output = None
    args.yes = True
    args.ports = ports
    args.timeout = timeout
    args.concurrency = concurrency
    args.format = fmt
    args.open = auto_open
    args.no_cache = False
    args.clear_cache = False
    args.persona = "custom"
    return args


# ─── Main Wizard Entry Point ─────────────────────────────────────────────────

def run_wizard_interactive() -> argparse.Namespace:
    """
    Run interactive guided wizard and map user persona selections
    into argparse scan arguments.
    """
    show_wizard_header()

    console.print(Panel(
        WELCOME_MSG,
        border_style="cyan",
        box=box.ROUNDED,
        padding=(1, 2),
    ))

    console.print("[bold cyan]Select Audit Mode:[/]\n")
    console.print("  [bold cyan][1][/] [bold white]Home Safety Check[/]")
    console.print("      [dim]Quick, simple, no technical knowledge needed[/]\n")
    console.print("  [bold cyan][2][/] [bold white]Security Learning Lab[/]")
    console.print("      [dim]Hands-on learning with explanations & full exports[/]\n")
    console.print("  [bold cyan][3][/] [bold white]CyberSec Professional Audit[/]")
    console.print("      [dim]Enterprise-grade penetration testing presets[/]\n")
    console.print("  [bold cyan][4][/] [bold white]Custom Targeted Audit[/]")
    console.print("      [dim]Full manual control over every parameter[/]\n")

    choice = Prompt.ask(
        "[bold cyan]Select mode[/]",
        choices=["1", "2", "3", "4"],
        default="1"
    )

    console.print()

    if choice == "1":
        return _flow_home_user()
    elif choice == "2":
        return _flow_student()
    elif choice == "3":
        return _flow_pro()
    else:
        return _flow_custom()


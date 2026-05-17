"""
PVS - Personal Vulnerability Scanner
Main CLI entry point using argparse.
"""
import argparse
import asyncio
import os
import sys
import time

from pvs import __version__
from pvs.scanner import resolve_targets, parse_ports, scan_host
from pvs.nvd_client import NVDClient
from pvs.reporter import (
    build_scan_data, generate_json_report,
    generate_csv_report, generate_html_report,
)
from pvs.display import (
    console, show_banner, show_scan_config, show_host_results,
    show_cve_results, show_summary, create_progress,
    show_warning, show_error, show_info,
)
from pvs.logger import setup_logging


DISCLAIMER = (
    "\n"
    "  [bold yellow]+------------------------------------------------------------+[/]\n"
    "  [bold yellow]|[/]  [bold yellow][!] IMPORTANT: LEGAL & ETHICAL NOTICE[/]                       [bold yellow]|[/]\n"
    "  [bold yellow]|[/]                                                            [bold yellow]|[/]\n"
    "  [bold yellow]|[/]  This tool is for AUTHORIZED SECURITY TESTING ONLY.         [bold yellow]|[/]\n"
    "  [bold yellow]|[/]  You must have explicit written permission to scan any       [bold yellow]|[/]\n"
    "  [bold yellow]|[/]  host or network that you do not own.                        [bold yellow]|[/]\n"
    "  [bold yellow]|[/]                                                            [bold yellow]|[/]\n"
    "  [bold yellow]|[/]  Unauthorized scanning is ILLEGAL in most jurisdictions.     [bold yellow]|[/]\n"
    "  [bold yellow]|[/]  The authors assume no liability for misuse of this tool.    [bold yellow]|[/]\n"
    "  [bold yellow]+------------------------------------------------------------+[/]\n"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pvs",
        description="PVS - Personal Vulnerability Scanner v" + __version__,
        epilog="Example: pvs scan 192.168.1.1 -p top100 --cve",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="version", version=f"PVS v{__version__}")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress banner and non-essential output")
    parser.add_argument("--log-level", default="WARNING", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Logging level (default: WARNING)")
    parser.add_argument("--log-file", help="Write logs to file")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- scan command ---
    scan_parser = subparsers.add_parser("scan", help="Scan a target for open ports and services")
    scan_parser.add_argument("target", help="Target host, IP, CIDR range, or IP range (e.g., 192.168.1.0/24)")
    scan_parser.add_argument("-p", "--ports", default="top100",
                             help="Ports to scan: number, range (1-1024), preset (top20/top100/common/all)")
    scan_parser.add_argument("-t", "--timeout", type=float, default=2.0, help="Connection timeout in seconds")
    scan_parser.add_argument("-c", "--concurrency", type=int, default=100, help="Max concurrent connections")
    scan_parser.add_argument("--no-banner-grab", action="store_true", help="Disable service banner grabbing")
    scan_parser.add_argument("--cve", action="store_true", help="Look up CVEs for discovered services (NVD API)")
    scan_parser.add_argument("--nvd-api-key", help="NVD API key for faster CVE lookups")
    scan_parser.add_argument("--max-cves", type=int, default=5, help="Max CVEs to retrieve per service")
    scan_parser.add_argument("-o", "--output", help="Output report file path")
    scan_parser.add_argument("-f", "--format", default="json", choices=["json", "csv", "html", "all"],
                             help="Report format (default: json)")
    scan_parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")

    # --- info command ---
    info_parser = subparsers.add_parser("info", help="Show information about a specific port or service")
    info_parser.add_argument("query", help="Port number or service name to look up")

    return parser


async def run_scan(args):
    """Execute the scan command."""
    # Resolve targets
    targets = resolve_targets(args.target)
    if not targets:
        show_error(f"Could not resolve target: {args.target}")
        return 1

    # Parse ports
    ports = parse_ports(args.ports)
    if not ports:
        show_error(f"No valid ports in specification: {args.ports}")
        return 1

    # Show config
    show_scan_config(args.target, len(ports), {
        "timeout": args.timeout,
        "concurrency": args.concurrency,
        "banners": not args.no_banner_grab,
        "cve": args.cve,
    })

    # Confirmation for large scans
    total_probes = len(targets) * len(ports)
    if total_probes > 10000 and not args.yes:
        show_warning(f"This scan will probe {total_probes:,} port(s) across {len(targets)} host(s).")
        try:
            resp = input("  Continue? [y/N]: ").strip().lower()
            if resp != "y":
                show_info("Scan cancelled.")
                return 0
        except (KeyboardInterrupt, EOFError):
            print()
            show_info("Scan cancelled.")
            return 0

    # Run port scanning
    host_results = []
    start_time = time.time()

    with create_progress() as progress:
        for i, ip in enumerate(targets):
            task_desc = f"Scanning {ip} ({i + 1}/{len(targets)})"
            task = progress.add_task(task_desc, total=len(ports))

            def progress_cb(scanned, total, _task=task):
                progress.update(_task, completed=scanned)

            result = await scan_host(
                ip, ports,
                timeout=args.timeout,
                concurrency=args.concurrency,
                grab_banners=not args.no_banner_grab,
                progress_cb=progress_cb,
            )
            host_results.append(result)

    # Display host results
    for hr in host_results:
        show_host_results(hr)

    # CVE lookup
    cve_results = {}
    if args.cve:
        open_services = []
        for hr in host_results:
            for pr in hr.ports:
                if pr.service and pr.service != "unknown":
                    open_services.append((hr.ip, pr))

        if open_services:
            nvd = NVDClient(api_key=args.nvd_api_key or os.environ.get("NVD_API_KEY"))
            show_info(f"Looking up CVEs for {len(open_services)} service(s)...")

            seen_services = set()
            with create_progress() as progress:
                task = progress.add_task("CVE Lookup", total=len(open_services))
                for ip, pr in open_services:
                    svc_key = f"{pr.service}:{pr.version}"
                    if svc_key not in seen_services:
                        seen_services.add(svc_key)
                        cves = nvd.lookup_service_cves(
                            pr.service, pr.version, max_results=args.max_cves
                        )
                        if cves:
                            key = f"{ip}:{pr.port}"
                            cve_results[key] = cves
                    progress.update(task, advance=1)

            show_cve_results(cve_results)

    total_time = time.time() - start_time
    show_summary(host_results, total_time)

    # Generate reports
    scan_data = build_scan_data(args.target, host_results, cve_results)

    if args.output:
        base = args.output.rsplit(".", 1)[0] if "." in args.output else args.output
        fmt = args.format

        if fmt in ("json", "all"):
            generate_json_report(scan_data, f"{base}.json")
            show_info(f"JSON report saved: {base}.json")
        if fmt in ("csv", "all"):
            generate_csv_report(scan_data, f"{base}.csv")
            show_info(f"CSV report saved: {base}.csv")
        if fmt in ("html", "all"):
            generate_html_report(scan_data, f"{base}.html")
            show_info(f"HTML report saved: {base}.html")

    return 0


def run_info(args):
    """Show info about a port or service."""
    from pvs.services import WELL_KNOWN_SERVICES
    query = args.query.strip().lower()

    try:
        port = int(query)
        svc = WELL_KNOWN_SERVICES.get(port, "unknown")
        console.print(f"\n  Port [bold cyan]{port}[/] -> Service: [bold]{svc}[/]")
    except ValueError:
        matches = [(p, s) for p, s in WELL_KNOWN_SERVICES.items() if query in s.lower()]
        if matches:
            from rich.table import Table
            table = Table(title=f"Services matching '{query}'", border_style="cyan")
            table.add_column("Port", style="bold cyan", justify="right")
            table.add_column("Service", style="bold")
            for port, svc in sorted(matches):
                table.add_row(str(port), svc)
            console.print(table)
        else:
            show_error(f"No service found matching: {query}")


def main():
    parser = build_parser()
    args = parser.parse_args()

    setup_logging(args.log_level, getattr(args, "log_file", None))

    if not args.quiet:
        show_banner()
        console.print(DISCLAIMER)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "scan":
        try:
            return asyncio.run(run_scan(args))
        except KeyboardInterrupt:
            show_info("\nScan interrupted by user.")
            return 130
    elif args.command == "info":
        return run_info(args)

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)

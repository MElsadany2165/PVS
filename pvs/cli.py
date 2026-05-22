#!/usr/bin/env python3
# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
PVS - Personal Vulnerability Scanner
Main CLI entry point using argparse.
"""
import argparse
import asyncio
import datetime
import os
import sys
import time

from pvs import __version__
from pvs.scanner import resolve_targets, parse_ports, scan_host, filter_live_hosts
from pvs.nvd_client import NVDClient
from pvs.reporter import (
    build_scan_data, generate_json_report,
    generate_csv_report, generate_html_report,
)
from pvs.display import (
    console, show_banner, show_disclaimer, show_scan_config,
    show_host_results, show_cve_results, show_summary,
    create_progress, show_warning, show_error, show_info,
)
from pvs.logger import setup_logging


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pvs",
        description="pvs - personal vulnerability scanner",
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
                             help="Ports to scan: number, range (1-1024), preset (top20/top100/common/enterprise/all)")
    scan_parser.add_argument("-t", "--timeout", type=float, default=2.0, help="Connection timeout in seconds")
    scan_parser.add_argument("-c", "--concurrency", type=int, default=100, help="Max concurrent connections")
    scan_parser.add_argument("--no-ping", action="store_true", help="Skip host discovery ping sweep")
    scan_parser.add_argument("--no-banner-grab", action="store_true", help="Disable service banner grabbing")
    scan_parser.add_argument("--cve", action="store_true", help="Look up CVEs for discovered services (NVD API)")
    scan_parser.add_argument("--nvd-api-key", help="NVD API key for faster CVE lookups")
    scan_parser.add_argument("--max-cves", type=int, default=5, help="Max CVEs to retrieve per service")
    scan_parser.add_argument("-o", "--output", help="Output report file path")
    scan_parser.add_argument("-f", "--format", default="html", choices=["json", "csv", "html", "all"],
                             help="Report format (default: html)")
    scan_parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")

    # --- info command ---
    info_parser = subparsers.add_parser("info", help="Show information about a specific port or service")
    info_parser.add_argument("query", help="Port number or service name to look up")

    return parser


async def run_scan(args):
    """Execute the scan command."""
    # Suppress Windows ProactorEventLoop WinError 10054 connection reset callback noise
    try:
        loop = asyncio.get_running_loop()
        def handle_asyncio_exception(loop, context):
            exception = context.get("exception")
            if isinstance(exception, ConnectionResetError) or (
                exception and getattr(exception, "winerror", None) == 10054
            ):
                return
            loop.default_exception_handler(context)
        loop.set_exception_handler(handle_asyncio_exception)
    except Exception:
        pass

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

    # Host Discovery (Ping sweep) for multiple targets
    if len(targets) > 1 and not args.no_ping:
        show_info(f"Running host discovery on {len(targets)} IP(s)...")
        targets = await filter_live_hosts(targets, concurrency=50)
        if not targets:
            show_error("No live hosts discovered (all pings failed). Use --no-ping to force scan.")
            return 1
        show_info(f"Found {len(targets)} live host(s).")

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

            seen_services = {}
            
            async def _lookup(ip, pr, task_id):
                svc_key = f"{pr.service}:{pr.version}"
                if svc_key in seen_services:
                    cves = seen_services[svc_key]
                else:
                    cves = await nvd.lookup_service_cves_async(
                        pr.service, pr.version, banner=pr.banner, max_results=args.max_cves
                    )
                    seen_services[svc_key] = cves
                
                if cves:
                    key = f"{ip}:{pr.port}"
                    cve_results[key] = cves
                progress.update(task_id, advance=1)

            with create_progress() as progress:
                task = progress.add_task("CVE Lookup", total=len(open_services))
                tasks = [_lookup(ip, pr, task) for ip, pr in open_services]
                await asyncio.gather(*tasks)

            show_cve_results(cve_results)

    total_time = time.time() - start_time
    show_summary(host_results, total_time)

    # Generate reports
    scan_data = build_scan_data(args.target, host_results, cve_results)

    if args.output:
        base = args.output.rsplit(".", 1)[0] if "." in args.output else args.output
    else:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        if not os.path.exists("reports"):
            try:
                os.makedirs("reports")
            except OSError:
                pass
        base = f"reports/PVS-{timestamp}"

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
        show_disclaimer()

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

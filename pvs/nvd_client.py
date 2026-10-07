# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
NVD (National Vulnerability Database) API Client.
Queries CVEs associated with detected services/products.
"""
import re
import time
import json
import urllib.request
import urllib.parse
import urllib.error
import asyncio
from dataclasses import dataclass, field
from typing import Optional

from .logger import get_logger

logger = get_logger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Connectivity check endpoints (in priority order)
_CONNECTIVITY_TEST_HOSTS = [
    ("nvd.nist.gov", 443),
    ("api.osv.dev", 443),
    ("8.8.8.8", 53),
]

# Module-level cached connectivity result (None = not yet checked)
_internet_available: "Optional[bool]" = None


def check_internet_connectivity(timeout: float = 3.0, force: bool = False) -> bool:
    """
    Check whether internet connectivity is available by probing well-known hosts.

    This is the authoritative pre-flight check that the entire vulnerability engine
    relies on.  The result is cached for the lifetime of the process so subsequent
    calls are instant (< 1 ms).

    Args:
        timeout: TCP connection timeout per probe attempt (default: 3 s).
        force:   Re-run the check even if a cached result exists.

    Returns:
        True  – at least one probe host is reachable (internet available).
        False – all probes failed (offline / blocked).
    """
    global _internet_available
    import socket as _socket

    if _internet_available is not None and not force:
        return _internet_available

    for host, port in _CONNECTIVITY_TEST_HOSTS:
        try:
            sock = _socket.create_connection((host, port), timeout=timeout)
            sock.close()
            _internet_available = True
            logger.debug(f"Internet connectivity confirmed via {host}:{port}")
            return True
        except OSError:
            continue

    _internet_available = False
    logger.warning(
        "Internet connectivity check FAILED: all probe hosts unreachable. "
        "Live NVD/OSV CVE lookups will be DISABLED this session."
    )
    return False


@dataclass
class CVEEntry:
    """Represents a single CVE entry."""
    cve_id: str
    description: str = ""
    severity: str = "UNKNOWN"
    score: float = 0.0
    vector: str = ""
    published: str = ""
    references: list = field(default_factory=list)
    affected_products: list = field(default_factory=list)

    @property
    def severity_color(self) -> str:
        colors = {
            "CRITICAL": "bright_red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green",
            "UNKNOWN": "dim",
        }
        return colors.get(self.severity, "dim")


# Service to CPE vendor/product mappings for high-fidelity CVE lookup.
CPE_MAP = {
    # Remote Access & Shell
    "ssh": ("openbsd", "openssh"),
    "openssh": ("openbsd", "openssh"),
    "dropbear": ("dropbear_project", "dropbear"),
    "telnet": ("gnu", "inetutils"),
    # Web Servers
    "http": ("apache", "http_server"),
    "https": ("apache", "http_server"),
    "apache": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "tomcat": ("apache", "tomcat"),
    "iis": ("microsoft", "internet_information_services"),
    "caddy": ("caddyserver", "caddy"),
    "haproxy": ("haproxy", "haproxy"),
    "traefik": ("traefik", "traefik"),
    # Databases
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "postgres": ("postgresql", "postgresql"),
    "mongodb": ("mongodb", "mongodb"),
    "mssql": ("microsoft", "sql_server"),
    "oracle": ("oracle", "database_server"),
    "sqlite": ("sqlite", "sqlite"),
    "couchdb": ("apache", "couchdb"),
    # Caching & Messaging
    "redis": ("redis", "redis"),
    "memcached": ("memcached", "memcached"),
    "rabbitmq": ("pivotal_software", "rabbitmq"),
    "kafka": ("apache", "kafka"),
    # Search & Analytics
    "elasticsearch": ("elastic", "elasticsearch"),
    "kibana": ("elastic", "kibana"),
    "influxdb": ("influxdata", "influxdb"),
    "grafana": ("grafana", "grafana"),
    # File Sharing & SMB
    "samba": ("samba", "samba"),
    "smb": ("microsoft", "windows"),
    "microsoft-ds": ("microsoft", "windows"),
    "nfs": ("linux", "linux_kernel"),
    # FTP
    "ftp": ("vsftpd_project", "vsftpd"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "pure-ftpd": ("pureftpd", "pure-ftpd"),
    # Mail
    "smtp": ("postfix", "postfix"),
    "postfix": ("postfix", "postfix"),
    "sendmail": ("sendmail", "sendmail"),
    "exim": ("exim", "exim"),
    "dovecot": ("dovecot", "dovecot"),
    # DNS
    "dns": ("isc", "bind"),
    "domain": ("isc", "bind"),
    "named": ("isc", "bind"),
    "dnsmasq": ("thekelleys", "dnsmasq"),
    "unbound": ("nlnetlabs", "unbound"),
    # VPN & Remote Desktop
    "openvpn": ("openvpn", "openvpn"),
    "rdp": ("microsoft", "remote_desktop_connection"),
    "vnc": ("realvnc", "vnc_server"),
    # Containers & Orchestration
    "docker": ("docker", "docker"),
    "containerd": ("linuxfoundation", "containerd"),
    "kubernetes": ("kubernetes", "kubernetes"),
    # Monitoring & SNMP
    "snmp": ("net-snmp", "net-snmp"),
    "nagios": ("nagios", "nagios"),
    "zabbix": ("zabbix", "zabbix"),
    # Other
    "jenkins": ("jenkins", "jenkins"),
    "gitlab": ("gitlab", "gitlab"),
    "jira": ("atlassian", "jira"),
    "confluence": ("atlassian", "confluence"),
    "wordpress": ("wordpress", "wordpress"),
}


def build_cpe(service: str, banner: str, version: str) -> Optional[str]:
    """
    Build a CPE 2.3 string based on service name, banner, and version.
    Returns format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
    """
    if not version:
        return None
    
    service_lower = service.lower()
    banner_lower = banner.lower() if banner else ""
    
    vendor, product = None, None
    
    # Identify vendor/product from banner contents first
    if "nginx" in banner_lower or "nginx" in service_lower:
        vendor, product = "nginx", "nginx"
    elif "apache" in banner_lower or "httpd" in banner_lower:
        vendor, product = "apache", "http_server"
    elif "openssh" in banner_lower or "openssh" in service_lower:
        vendor, product = "openbsd", "openssh"
    elif "dropbear" in banner_lower:
        vendor, product = "dropbear_project", "dropbear"
    elif "vsftpd" in banner_lower:
        vendor, product = "vsftpd_project", "vsftpd"
    elif "proftpd" in banner_lower:
        vendor, product = "proftpd", "proftpd"
    elif "mysql" in banner_lower or "mysql" in service_lower:
        vendor, product = "oracle", "mysql"
    elif "postgresql" in banner_lower or "postgresql" in service_lower:
        vendor, product = "postgresql", "postgresql"
    elif "redis" in banner_lower or "redis" in service_lower:
        vendor, product = "redis", "redis"
    elif "mariadb" in banner_lower:
        vendor, product = "mariadb", "mariadb"
    elif "microsoft-iis" in banner_lower or "iis" in service_lower:
        vendor, product = "microsoft", "iis"
    
    # Fallback to general service map
    if not product and service_lower in CPE_MAP:
        vendor, product = CPE_MAP[service_lower]
        
    if not product:
        return None
        
    # Clean version string (e.g. extract alphanumeric + dots, remove build/os tags)
    clean_version = version.strip()
    if "openssh_" in clean_version.lower():
        clean_version = re.sub(r'(?i)openssh_', '', clean_version)
    clean_version = clean_version.split()[0].split("(")[0].strip()
    if "/" in clean_version:
        clean_version = clean_version.split("/", 1)[1].strip()
    return f"cpe:2.3:a:{vendor}:{product}:{clean_version}:*:*:*:*:*:*:*"


class NVDClient:
    """Client for the NIST NVD CVE API v2.0."""

    def __init__(self, api_key: Optional[str] = None, rate_limit: float = 6.0):
        """
        Initialize the NVD API client.
        
        Args:
            api_key: Optional NVD API key for higher rate limits.
                     Get one at https://nvd.nist.gov/developers/request-an-api-key
            rate_limit: Seconds between requests (6s without key, 0.6s with key)
        """
        self.api_key = api_key
        self.rate_limit = 0.6 if api_key else rate_limit
        self._last_request = 0.0
        self._cache = {}
        self._lock = None  # Initialized lazily to avoid loop-dependency at creation

    def _rate_limit_wait(self):
        """Enforce rate limiting between API calls."""
        elapsed = time.time() - self._last_request
        if elapsed < self.rate_limit:
            wait = self.rate_limit - elapsed
            logger.debug(f"Rate limiting: waiting {wait:.1f}s")
            time.sleep(wait)
        self._last_request = time.time()

    async def _async_rate_limit_wait(self):
        """Enforce rate limiting asynchronously between API calls."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            elapsed = time.time() - self._last_request
            if elapsed < self.rate_limit:
                wait = self.rate_limit - elapsed
                logger.debug(f"Rate limiting: waiting {wait:.1f}s")
                await asyncio.sleep(wait)
            self._last_request = time.time()

    def _make_request(self, params: dict) -> Optional[dict]:
        """Make a request to the NVD API with retry backoff."""
        max_retries = 3
        backoff = 2.0

        for attempt in range(max_retries):
            self._rate_limit_wait()

            query_string = urllib.parse.urlencode(params)
            url = f"{NVD_API_BASE}?{query_string}"

            headers = {"Accept": "application/json"}
            if self.api_key:
                headers["apiKey"] = self.api_key

            req = urllib.request.Request(url, headers=headers)

            try:
                logger.debug(f"NVD API request: {url}")
                with urllib.request.urlopen(req, timeout=30) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                if e.code in (403, 429, 503):
                    if attempt < max_retries - 1:
                        sleep_time = backoff * (2 ** attempt)
                        logger.warning(f"NVD API rate limit or transient error {e.code}. Retrying in {sleep_time:.1f}s...")
                        time.sleep(sleep_time)
                        continue
                    else:
                        logger.error(f"NVD API error {e.code} after {max_retries} attempts.")
                elif e.code == 404:
                    logger.debug("No CVEs found for query.")
                    return None
                else:
                    logger.error(f"NVD API HTTP error {e.code}: {e.reason}")
                    return None
            except urllib.error.URLError as e:
                if attempt < max_retries - 1:
                    sleep_time = backoff * (2 ** attempt)
                    logger.warning(f"NVD API connection error: {e.reason}. Retrying in {sleep_time:.1f}s...")
                    time.sleep(sleep_time)
                    continue
                else:
                    logger.error(f"NVD API connection error after {max_retries} attempts: {e.reason}")
            except Exception as e:
                logger.error(f"NVD API error: {e}")
                return None

        return None

    async def _make_request_async(self, params: dict) -> Optional[dict]:
        """Asynchronously make a request to the NVD API with retry backoff."""
        max_retries = 3
        backoff = 2.0

        for attempt in range(max_retries):
            await self._async_rate_limit_wait()

            query_string = urllib.parse.urlencode(params)
            url = f"{NVD_API_BASE}?{query_string}"

            headers = {"Accept": "application/json"}
            if self.api_key:
                headers["apiKey"] = self.api_key

            req = urllib.request.Request(url, headers=headers)

            def _perform_request():
                try:
                    logger.debug(f"NVD API async request: {url}")
                    with urllib.request.urlopen(req, timeout=30) as response:
                        return json.loads(response.read().decode("utf-8"))
                except urllib.error.HTTPError as e:
                    if e.code in (403, 429, 503):
                        raise e
                    elif e.code == 404:
                        logger.debug("No CVEs found for query.")
                        return None
                    else:
                        logger.error(f"NVD API HTTP error {e.code}: {e.reason}")
                        return None
                except urllib.error.URLError as e:
                    raise e
                except Exception as e:
                    logger.error(f"NVD API error: {e}")
                    return None

            try:
                res = await asyncio.to_thread(_perform_request)
                return res
            except urllib.error.HTTPError as e:
                # Retriable errors
                if attempt < max_retries - 1:
                    sleep_time = backoff * (2 ** attempt)
                    logger.warning(f"NVD API async rate limit or transient error {e.code}. Retrying in {sleep_time:.1f}s...")
                    await asyncio.sleep(sleep_time)
                else:
                    logger.error(f"NVD API error {e.code} after {max_retries} attempts.")
                    return None
            except urllib.error.URLError as e:
                if attempt < max_retries - 1:
                    sleep_time = backoff * (2 ** attempt)
                    logger.warning(f"NVD API async connection error: {e.reason}. Retrying in {sleep_time:.1f}s...")
                    await asyncio.sleep(sleep_time)
                else:
                    logger.error(f"NVD API connection error after {max_retries} attempts: {e.reason}")
                    return None

        return None

    def _parse_cve(self, cve_item: dict) -> CVEEntry:
        """Parse a CVE item from the NVD API response."""
        cve_data = cve_item.get("cve", {})
        cve_id = cve_data.get("id", "UNKNOWN")

        # Description
        descriptions = cve_data.get("descriptions", [])
        desc = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        if not desc and descriptions:
            desc = descriptions[0].get("value", "")

        # Metrics (CVSS scores)
        severity = "UNKNOWN"
        score = 0.0
        vector = ""
        metrics = cve_data.get("metrics", {})

        # Try CVSS v3.1 first, then v3.0, then v2.0
        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(version_key, [])
            if metric_list:
                metric = metric_list[0]
                cvss_data = metric.get("cvssData", {})
                score = cvss_data.get("baseScore", 0.0)
                vector = cvss_data.get("vectorString", "")
                severity = cvss_data.get("baseSeverity", "")
                if not severity:
                    severity = metric.get("baseSeverity", "UNKNOWN")
                break

        # Published date
        published = cve_data.get("published", "")[:10]

        # References
        refs = []
        for ref in cve_data.get("references", [])[:5]:
            refs.append(ref.get("url", ""))

        return CVEEntry(
            cve_id=cve_id,
            description=desc[:300],
            severity=severity.upper(),
            score=score,
            vector=vector,
            published=published,
            references=refs,
        )

    def search_by_keyword(self, keyword: str, max_results: int = 10) -> list[CVEEntry]:
        """Search for CVEs by keyword (service name, product, etc.)."""
        cache_key = f"kw:{keyword}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(max_results, 50),
        }

        data = self._make_request(params)
        if not data:
            return []

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = self._parse_cve(item)
            cves.append(cve)

        # Sort by score descending
        cves.sort(key=lambda c: c.score, reverse=True)
        self._cache[cache_key] = cves
        return cves

    async def search_by_keyword_async(self, keyword: str, max_results: int = 10) -> list[CVEEntry]:
        """Search for CVEs asynchronously by keyword."""
        cache_key = f"kw:{keyword}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(max_results, 50),
        }

        data = await self._make_request_async(params)
        if not data:
            return []

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = self._parse_cve(item)
            cves.append(cve)

        cves.sort(key=lambda c: c.score, reverse=True)
        self._cache[cache_key] = cves
        return cves

    def search_by_cpe(self, cpe_name: str, max_results: int = 10) -> list[CVEEntry]:
        """Search for CVEs by CPE (Common Platform Enumeration) name."""
        cache_key = f"cpe:{cpe_name}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        params = {
            "cpeName": cpe_name,
            "resultsPerPage": min(max_results, 50),
        }

        data = self._make_request(params)
        if not data:
            return []

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = self._parse_cve(item)
            cves.append(cve)

        cves.sort(key=lambda c: c.score, reverse=True)
        self._cache[cache_key] = cves
        return cves

    async def search_by_cpe_async(self, cpe_name: str, max_results: int = 10) -> list[CVEEntry]:
        """Search for CVEs asynchronously by CPE name."""
        cache_key = f"cpe:{cpe_name}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        params = {
            "cpeName": cpe_name,
            "resultsPerPage": min(max_results, 50),
        }

        data = await self._make_request_async(params)
        if not data:
            return []

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = self._parse_cve(item)
            cves.append(cve)

        cves.sort(key=lambda c: c.score, reverse=True)
        self._cache[cache_key] = cves
        return cves

    def lookup_service_cves(self, service: str, version: str = "", banner: str = "",
                            max_results: int = 10) -> list[CVEEntry]:
        """
        Look up CVEs for a discovered service and optional version/banner.
        Constructs intelligent search queries based on service info.
        """
        if not service or service == "unknown":
            return []

        cpe = build_cpe(service, banner, version)
        if cpe:
            logger.info(f"Searching NVD by CPE: {cpe}")
            results = self.search_by_cpe(cpe, max_results)
            if results:
                return results

        # Fallback to keyword search
        keyword = service
        if version:
            # Clean version string
            clean_ver = version.split("(")[0].strip()
            keyword = f"{service} {clean_ver}"

        logger.info(f"Searching NVD by keyword (fallback): {keyword}")
        return self.search_by_keyword(keyword, max_results)

    async def lookup_service_cves_async(self, service: str, version: str = "", banner: str = "",
                                        max_results: int = 10) -> list[CVEEntry]:
        """
        Look up CVEs asynchronously for a service and version/banner.
        Attempts CPE match first, falling back to keyword search.
        """
        if not service or service == "unknown":
            return []

        cpe = build_cpe(service, banner, version)
        if cpe:
            logger.info(f"Searching NVD asynchronously by CPE: {cpe}")
            results = await self.search_by_cpe_async(cpe, max_results)
            if results:
                return results

        # Fallback to keyword search
        keyword = service
        if version:
            clean_ver = version.split("(")[0].strip()
            keyword = f"{service} {clean_ver}"

        logger.info(f"Searching NVD asynchronously by keyword (fallback): {keyword}")
        return await self.search_by_keyword_async(keyword, max_results)

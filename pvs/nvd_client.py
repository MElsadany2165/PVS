"""
NVD (National Vulnerability Database) API Client.
Queries CVEs associated with detected services/products.
"""
import time
import json
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, field
from typing import Optional

from .logger import get_logger

logger = get_logger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


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

    def _rate_limit_wait(self):
        """Enforce rate limiting between API calls."""
        elapsed = time.time() - self._last_request
        if elapsed < self.rate_limit:
            wait = self.rate_limit - elapsed
            logger.debug(f"Rate limiting: waiting {wait:.1f}s")
            time.sleep(wait)
        self._last_request = time.time()

    def _make_request(self, params: dict) -> Optional[dict]:
        """Make a request to the NVD API."""
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
                data = json.loads(response.read().decode("utf-8"))
                return data
        except urllib.error.HTTPError as e:
            if e.code == 403:
                logger.error("NVD API rate limit exceeded. Consider using an API key.")
            elif e.code == 404:
                logger.debug("No CVEs found for query.")
            else:
                logger.error(f"NVD API HTTP error {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            logger.error(f"NVD API connection error: {e.reason}")
        except Exception as e:
            logger.error(f"NVD API error: {e}")

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

    def lookup_service_cves(self, service: str, version: str = "",
                            max_results: int = 10) -> list[CVEEntry]:
        """
        Look up CVEs for a discovered service and optional version.
        Constructs intelligent search queries based on service info.
        """
        if not service or service == "unknown":
            return []

        # Build search keyword
        keyword = service
        if version:
            # Clean version string
            clean_ver = version.split("(")[0].strip()
            keyword = f"{service} {clean_ver}"

        logger.info(f"Searching NVD for: {keyword}")
        return self.search_by_keyword(keyword, max_results)

# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
PVS Web & API Vulnerability Auditor.
Performs protocol-accurate, non-destructive active probes for web applications:
  • Security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc.)
  • CORS misconfiguration & origin reflection
  • Sensitive file disclosure & secret leaks (/.env, /.git, actuator, swagger, config dumps)
  • Insecure HTTP methods (TRACE, PUT, DELETE, OPTIONS)
  • Cookie security flags (Missing Secure, HttpOnly, SameSite)
"""

import asyncio
import re
import socket
import ssl
from typing import List, Dict, Optional, Tuple, Any

from .logger import get_logger
from .auditor import ActiveVulnerability

logger = get_logger(__name__)

# Common sensitive web files and detection patterns
SENSITIVE_WEB_PATHS = [
    {
        "path": "/.env",
        "vuln_id": "VULN-WEB-ENV-LEAK",
        "title": "Environment Secrets File Exposed (/.env)",
        "severity": "CRITICAL",
        "score": 9.8,
        "indicator": lambda body: bool(re.search(r"(?:DB_PASSWORD|SECRET_KEY|API_KEY|AWS_SECRET|APP_KEY)=", body, re.I)),
        "description": "The server exposes an unauthenticated .env configuration file leaking database passwords, API tokens, and secret application keys.",
        "remediation_key": "web_sensitive_files",
    },
    {
        "path": "/.git/HEAD",
        "vuln_id": "VULN-WEB-GIT-EXPOSURE",
        "title": "Exposed Git Source Code Repository (/.git)",
        "severity": "HIGH",
        "score": 8.5,
        "indicator": lambda body: "ref: refs/" in body or body.strip().startswith("ref:"),
        "description": "The source code Git repository is publicly downloadable via /.git, allowing attackers to dump the entire codebase and commit history.",
        "remediation_key": "web_sensitive_files",
    },
    {
        "path": "/actuator/health",
        "vuln_id": "VULN-WEB-ACTUATOR-EXPOSED",
        "title": "Spring Boot Actuator Endpoints Unauthenticated",
        "severity": "HIGH",
        "score": 7.5,
        "indicator": lambda body: '"status":"UP"' in body or '"status":"DOWN"' in body or '"components":' in body,
        "description": "Spring Boot Actuator administrative endpoints are exposed without authentication, risking environment leakage and heap inspection.",
        "remediation_key": "web_actuator",
    },
    {
        "path": "/swagger.json",
        "vuln_id": "VULN-WEB-SWAGGER-EXPOSED",
        "title": "Swagger / OpenAPI Specification Publicly Exposed",
        "severity": "MEDIUM",
        "score": 5.3,
        "indicator": lambda body: '"swagger":' in body or '"openapi":' in body,
        "description": "Full REST API schema documentation is publicly exposed, providing attackers with detailed endpoint routing and schema maps.",
        "remediation_key": "web_swagger",
    },
    {
        "path": "/wp-config.php.bak",
        "vuln_id": "VULN-WEB-WP-CONFIG-BAK",
        "title": "WordPress Backup Configuration Leak (/wp-config.php.bak)",
        "severity": "CRITICAL",
        "score": 9.5,
        "indicator": lambda body: "DB_PASSWORD" in body or "DB_NAME" in body,
        "description": "Backup text copy of WordPress configuration is readable in cleartext, exposing database credentials and authentication salts.",
        "remediation_key": "web_sensitive_files",
    },
    {
        "path": "/phpinfo.php",
        "vuln_id": "VULN-WEB-PHPINFO-LEAK",
        "title": "PHP Environment Information Leak (/phpinfo.php)",
        "severity": "MEDIUM",
        "score": 5.8,
        "indicator": lambda body: "PHP Version" in body and "Configuration File (php.ini)" in body,
        "description": "Server diagnostic phpinfo page is accessible, leaking server software versions, loaded extensions, and system environment variables.",
        "remediation_key": "web_phpinfo",
    },
]


async def _send_raw_http_request(
    ip: str,
    port: int,
    method: str = "GET",
    path: str = "/",
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 2.5,
    use_ssl: bool = False,
) -> Tuple[int, Dict[str, str], str]:
    """
    Send a lightweight, standard-library raw HTTP request via asyncio.
    Returns (status_code, response_headers_lowercase, response_body).
    """
    if headers is None:
        headers = {}

    host_header = f"{ip}:{port}" if port not in (80, 443) else ip
    req_lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host_header}",
        "User-Agent: PVS-Security-Auditor/2.0",
        "Accept: */*",
        "Connection: close",
    ]
    for k, v in headers.items():
        req_lines.append(f"{k}: {v}")
    req_lines.append("\r\n")
    req_payload = "\r\n".join(req_lines).encode("utf-8")

    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx), timeout=timeout
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )

        writer.write(req_payload)
        await writer.drain()

        # Read response up to 64KB
        chunks = []
        total_len = 0
        while total_len < 65536:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not chunk:
                    break
                chunks.append(chunk)
                total_len += len(chunk)
            except Exception:
                break

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        raw_data = b"".join(chunks).decode("utf-8", errors="replace")
        if not raw_data:
            return 0, {}, ""

        parts = raw_data.split("\r\n\r\n", 1)
        header_section = parts[0]
        body_section = parts[1] if len(parts) > 1 else ""

        header_lines = header_section.split("\r\n")
        status_line = header_lines[0] if header_lines else ""
        status_match = re.search(r"HTTP/\d\.\d\s+(\d{3})", status_line)
        status_code = int(status_match.group(1)) if status_match else 0

        resp_headers = {}
        for line in header_lines[1:]:
            if ":" in line:
                h_name, h_val = line.split(":", 1)
                resp_headers[h_name.strip().lower()] = h_val.strip()

        return status_code, resp_headers, body_section

    except Exception:
        return 0, {}, ""


async def audit_web_security_headers(
    ip: str,
    port: int,
    use_ssl: bool = False,
    timeout: float = 2.5,
) -> List[ActiveVulnerability]:
    """Audit HTTP security headers on a target web application."""
    vulns: List[ActiveVulnerability] = []
    status, headers, _ = await _send_raw_http_request(
        ip, port, method="GET", path="/", timeout=timeout, use_ssl=use_ssl
    )

    if status == 0:
        return []

    # 1. HSTS (Strict-Transport-Security) for HTTPS
    if use_ssl and "strict-transport-security" not in headers:
        vulns.append(ActiveVulnerability(
            vuln_id="VULN-WEB-MISSING-HSTS",
            title="Missing HTTP Strict Transport Security (HSTS) Header",
            severity="MEDIUM",
            score=6.1,
            service="https",
            port=port,
            description="The HTTPS web server does not send the Strict-Transport-Security header, allowing SSL-stripping and MITM attacks.",
            remediation_key="web_headers_hsts",
            evidence=f"Port {port} returned HTTP {status} without Strict-Transport-Security",
            categories=["web", "crypto", "tls"],
            references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
        ))

    # 2. Clickjacking protection (X-Frame-Options or CSP frame-ancestors)
    has_xfo = "x-frame-options" in headers
    has_csp_fa = "frame-ancestors" in headers.get("content-security-policy", "")
    if not has_xfo and not has_csp_fa:
        vulns.append(ActiveVulnerability(
            vuln_id="VULN-WEB-CLICKJACKING",
            title="Missing Anti-Clickjacking Frame Protection",
            severity="MEDIUM",
            score=5.4,
            service="http" if not use_ssl else "https",
            port=port,
            description="The web server does not enforce X-Frame-Options or CSP frame-ancestors, enabling UI redressing and Clickjacking attacks.",
            remediation_key="web_headers_clickjacking",
            evidence=f"Missing X-Frame-Options & CSP frame-ancestors on port {port}",
            categories=["web", "headers"],
            references=["https://owasp.org/www-community/attacks/Clickjacking"],
        ))

    # 3. Content-Security-Policy (CSP)
    if "content-security-policy" not in headers:
        vulns.append(ActiveVulnerability(
            vuln_id="VULN-WEB-MISSING-CSP",
            title="Missing Content-Security-Policy (CSP) Defense",
            severity="LOW",
            score=4.3,
            service="http" if not use_ssl else "https",
            port=port,
            description="The application does not implement Content-Security-Policy, significantly increasing exposure to Cross-Site Scripting (XSS) and code injection.",
            remediation_key="web_headers_csp",
            evidence=f"Content-Security-Policy header absent on port {port}",
            categories=["web", "headers", "xss"],
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
        ))

    # 4. MIME-type sniffing (X-Content-Type-Options)
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        vulns.append(ActiveVulnerability(
            vuln_id="VULN-WEB-MIME-SNIFFING",
            title="MIME-Sniffing Defense Disabled (X-Content-Type-Options)",
            severity="LOW",
            score=3.7,
            service="http" if not use_ssl else "https",
            port=port,
            description="X-Content-Type-Options is not set to 'nosniff', allowing browsers to execute non-executable files masquerading as scripts.",
            remediation_key="web_headers_nosniff",
            evidence=f"X-Content-Type-Options header: '{headers.get('x-content-type-options', 'NONE')}'",
            categories=["web", "headers"],
            references=["https://owasp.org/www-project-secure-headers/"],
        ))

    # 5. Cookie Security Flags
    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        cookie_lower = set_cookie.lower()
        missing_flags = []
        if "httponly" not in cookie_lower:
            missing_flags.append("HttpOnly")
        if use_ssl and "secure" not in cookie_lower:
            missing_flags.append("Secure")
        if "samesite" not in cookie_lower:
            missing_flags.append("SameSite")

        if missing_flags:
            vulns.append(ActiveVulnerability(
                vuln_id="VULN-WEB-INSECURE-COOKIES",
                title=f"Insecure Cookie Flags ({', '.join(missing_flags)})",
                severity="MEDIUM" if "HttpOnly" in missing_flags else "LOW",
                score=5.0 if "HttpOnly" in missing_flags else 3.5,
                service="http" if not use_ssl else "https",
                port=port,
                description=f"Session cookies are transmitted without essential defense flags ({', '.join(missing_flags)}), increasing XSS and CSRF exposure.",
                remediation_key="web_cookies",
                evidence=f"Set-Cookie flags missing: {', '.join(missing_flags)}",
                categories=["web", "cookies", "session"],
                references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
            ))

    return vulns


async def audit_cors_misconfiguration(
    ip: str,
    port: int,
    use_ssl: bool = False,
    timeout: float = 2.5,
) -> List[ActiveVulnerability]:
    """Audit Cross-Origin Resource Sharing (CORS) origin reflection and wildcard policies."""
    test_origin = "https://evil-attacker.example.com"
    status, headers, _ = await _send_raw_http_request(
        ip,
        port,
        method="GET",
        path="/",
        headers={"Origin": test_origin},
        timeout=timeout,
        use_ssl=use_ssl,
    )

    if status == 0:
        return []

    allow_origin = headers.get("access-control-allow-origin", "")
    allow_credentials = headers.get("access-control-allow-credentials", "").lower() == "true"

    # Critical CORS: arbitrary reflected origin with credentials allowed
    if test_origin in allow_origin and allow_credentials:
        return [ActiveVulnerability(
            vuln_id="VULN-WEB-CORS-REFLECTED-CREDENTIALS",
            title="Critical CORS Origin Reflection with Credentials Allowed",
            severity="CRITICAL",
            score=9.1,
            service="http" if not use_ssl else "https",
            port=port,
            description="The web server reflects arbitrary untrusted Origins while permitting credentials (cookies/auth headers), enabling authenticated cross-site data theft.",
            remediation_key="web_cors",
            evidence=f"Reflected '{test_origin}' with Access-Control-Allow-Credentials: true",
            categories=["web", "cors", "auth"],
            references=["https://portswigger.net/web-security/cors"],
        )]
    elif test_origin in allow_origin:
        return [ActiveVulnerability(
            vuln_id="VULN-WEB-CORS-ARBITRARY-ORIGIN",
            title="Insecure CORS Policy Reflects Arbitrary Origins",
            severity="MEDIUM",
            score=5.8,
            service="http" if not use_ssl else "https",
            port=port,
            description="The API server blindly trusts arbitrary origin headers, allowing untrusted sites to read unauthenticated API responses.",
            remediation_key="web_cors",
            evidence=f"Access-Control-Allow-Origin dynamically reflected: {allow_origin}",
            categories=["web", "cors"],
            references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
        )]

    return []


async def audit_sensitive_web_files(
    ip: str,
    port: int,
    use_ssl: bool = False,
    timeout: float = 2.5,
) -> List[ActiveVulnerability]:
    """Probe for dangerous exposed files, configuration dumps, and development endpoints."""
    vulns: List[ActiveVulnerability] = []

    for entry in SENSITIVE_WEB_PATHS:
        status, _, body = await _send_raw_http_request(
            ip, port, method="GET", path=entry["path"], timeout=timeout, use_ssl=use_ssl
        )
        if status in (200, 206) and entry["indicator"](body):
            vulns.append(ActiveVulnerability(
                vuln_id=entry["vuln_id"],
                title=entry["title"],
                severity=entry["severity"],
                score=entry["score"],
                service="http" if not use_ssl else "https",
                port=port,
                description=entry["description"],
                remediation_key=entry["remediation_key"],
                evidence=f"HTTP {status} at path {entry['path']} (Snippet: {body[:60].strip()!r})",
                categories=["web", "disclosure", "secrets"],
                references=["https://cwe.mitre.org/data/definitions/200.html"],
            ))

    return vulns


async def audit_insecure_http_methods(
    ip: str,
    port: int,
    use_ssl: bool = False,
    timeout: float = 2.5,
) -> List[ActiveVulnerability]:
    """Audit HTTP methods using OPTIONS probe to flag dangerous verbs (TRACE, PUT, DELETE)."""
    status, headers, _ = await _send_raw_http_request(
        ip, port, method="OPTIONS", path="/", timeout=timeout, use_ssl=use_ssl
    )

    if status == 0:
        return []

    allow_header = headers.get("allow", "").upper()
    if not allow_header:
        allow_header = headers.get("public", "").upper()

    vulns: List[ActiveVulnerability] = []
    if "TRACE" in allow_header:
        vulns.append(ActiveVulnerability(
            vuln_id="VULN-WEB-HTTP-TRACE-ENABLED",
            title="HTTP TRACE Method Enabled (Cross-Site Tracing Exposure)",
            severity="MEDIUM",
            score=6.5,
            service="http" if not use_ssl else "https",
            port=port,
            description="The HTTP TRACE method is enabled on the web server, enabling Cross-Site Tracing (XST) attacks that bypass HttpOnly cookie protection.",
            remediation_key="web_http_methods",
            evidence=f"OPTIONS Allow header includes TRACE: {allow_header}",
            categories=["web", "methods"],
            references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
        ))

    if "PUT" in allow_header or "DELETE" in allow_header:
        vulns.append(ActiveVulnerability(
            vuln_id="VULN-WEB-INSECURE-HTTP-METHODS",
            title="Dangerous HTTP Modification Methods Enabled (PUT/DELETE)",
            severity="MEDIUM",
            score=5.9,
            service="http" if not use_ssl else "https",
            port=port,
            description=f"The server allows direct resource mutation via unauthenticated HTTP methods ({allow_header}).",
            remediation_key="web_http_methods",
            evidence=f"Allow header: {allow_header}",
            categories=["web", "methods"],
            references=["https://cwe.mitre.org/data/definitions/650.html"],
        ))

    return vulns


async def audit_web_service_full(
    ip: str,
    port: int,
    use_ssl: bool = False,
    timeout: float = 2.5,
) -> List[ActiveVulnerability]:
    """Run the complete active web and API vulnerability probe suite against a target port."""
    tasks = [
        audit_web_security_headers(ip, port, use_ssl=use_ssl, timeout=timeout),
        audit_cors_misconfiguration(ip, port, use_ssl=use_ssl, timeout=timeout),
        audit_sensitive_web_files(ip, port, use_ssl=use_ssl, timeout=timeout),
        audit_insecure_http_methods(ip, port, use_ssl=use_ssl, timeout=timeout),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    all_vulns: List[ActiveVulnerability] = []
    for res in results:
        if isinstance(res, list):
            all_vulns.extend(res)
    return all_vulns

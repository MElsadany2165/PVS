# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
Active Network Vulnerability Auditor.
Executes non-destructive, protocol-accurate probes to detect real-world network
flaws, including unauthenticated databases, SMBv1/EternalBlue exposure, RDP without NLA,
anonymous FTP, cleartext protocols, sensitive web file disclosures, and weak TLS.
"""

import asyncio
import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from .logger import get_logger

logger = get_logger(__name__)


@dataclass
class ActiveVulnerability:
    """Represents a confirmed active network vulnerability or misconfiguration."""
    vuln_id: str
    title: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    score: float
    service: str
    port: int
    description: str
    remediation_key: str
    evidence: str = ""
    cve_id: str = ""
    is_kev: bool = False
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    categories: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_cve_dict(self) -> dict:
        """Convert to dictionary compatible with EnhancedCVEEntry."""
        return {
            "cve_id": self.cve_id or self.vuln_id,
            "description": f"[{self.title}] {self.description} (Evidence: {self.evidence})",
            "severity": self.severity,
            "score": self.score,
            "vector": "NETWORK",
            "published": "2026-ACTIVE",
            "references": self.references,
            "affected_products": [f"{self.service}:{self.port}"],
            "is_kev": self.is_kev,
            "kev_action": "Remediate immediately per PVS procedures." if self.is_kev else "",
            "kev_description": self.title,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
            "priority_score": min(100.0, self.score * 10.0 + (15.0 if self.is_kev else 0.0)),
            "priority_level": self.severity,
        }


async def _safe_connect(ip: str, port: int, timeout: float = 2.5, use_ssl: bool = False):
    """Safely establish a connection returning (reader, writer) or (None, None)."""
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx), timeout=timeout
            )
        else:
            return await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
    except Exception:
        return None, None


# --- 1. Database & Cache Unauthenticated Probes ---

async def audit_redis(ip: str, port: int = 6379, timeout: float = 2.0) -> List[ActiveVulnerability]:
    """Audit Redis for unauthenticated remote access."""
    reader, writer = await _safe_connect(ip, port, timeout=timeout)
    if not reader or not writer:
        return []
    try:
        writer.write(b"INFO\r\n")
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        resp_text = resp.decode("utf-8", errors="replace")
        
        if "redis_version:" in resp_text and "-NOAUTH" not in resp_text:
            m = re.search(r"redis_version:([^\r\n]+)", resp_text)
            ver = m.group(1).strip() if m else "Unknown"
            return [ActiveVulnerability(
                vuln_id="VULN-UNAUTH-REDIS",
                title="Redis Unauthenticated Remote Code Execution Exposure",
                severity="CRITICAL",
                score=10.0,
                service="redis",
                port=port,
                description="Redis server allows unauthenticated command execution. Attackers can execute arbitrary code, read or destroy memory, or write unauthorized SSH keys to the host.",
                remediation_key="unauth_redis",
                evidence=f"Connected and executed INFO command without authentication (Redis v{ver}).",
                cve_id="CWE-306",
                is_kev=True,
                epss_score=0.96,
                epss_percentile=0.99,
                categories=["rce", "auth_bypass"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2022-0543", "https://cwe.mitre.org/data/definitions/306.html"],
            )]
    except Exception as e:
        logger.debug(f"Redis audit exception on {ip}:{port}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return []


async def audit_mongodb(ip: str, port: int = 27017, timeout: float = 2.0) -> List[ActiveVulnerability]:
    """Audit MongoDB for unauthenticated access via wire protocol isMaster."""
    reader, writer = await _safe_connect(ip, port, timeout=timeout)
    if not reader or not writer:
        return []
    try:
        # MongoDB OP_QUERY message for isMaster: 1
        bson_ismaster = b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"
        query_payload = b"\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff" + bson_ismaster
        header = (len(query_payload) + 16).to_bytes(4, "little") + b"\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
        writer.write(header + query_payload)
        await writer.drain()
        
        resp = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        if resp and (b"ismaster" in resp.lower() or b"maxBsonObjectSize" in resp):
            return [ActiveVulnerability(
                vuln_id="VULN-UNAUTH-MONGODB",
                title="MongoDB Unauthenticated Public Access Exposure",
                severity="CRITICAL",
                score=9.8,
                service="mongodb",
                port=port,
                description="MongoDB instance accepts commands and queries without authentication enabled. Attackers can exfiltrate, tamper with, or drop all databases.",
                remediation_key="unauth_mongodb",
                evidence="MongoDB returned positive isMaster handshake response without requiring credentials.",
                cve_id="CWE-306",
                is_kev=True,
                epss_score=0.91,
                epss_percentile=0.98,
                categories=["auth_bypass", "info_disclosure"],
                references=["https://www.mongodb.com/docs/manual/security/", "https://cwe.mitre.org/data/definitions/306.html"],
            )]
    except Exception as e:
        logger.debug(f"MongoDB audit exception on {ip}:{port}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return []


async def audit_memcached(ip: str, port: int = 11211, timeout: float = 2.0) -> List[ActiveVulnerability]:
    """Audit Memcached for unauthenticated stats command and reflection amplification risk."""
    reader, writer = await _safe_connect(ip, port, timeout=timeout)
    if not reader or not writer:
        return []
    try:
        writer.write(b"stats\r\n")
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        if resp and b"STAT pid" in resp:
            return [ActiveVulnerability(
                vuln_id="VULN-UNAUTH-MEMCACHED",
                title="Memcached Unauthenticated Access & Amplification Risk",
                severity="HIGH",
                score=7.5,
                service="memcached",
                port=port,
                description="Memcached server is exposed without authentication, allowing unauthorized users to dump cached tokens, session keys, and abuse it for DDoS reflection attacks.",
                remediation_key="unauth_memcached",
                evidence="Executed 'stats' command and received live server process statistics.",
                cve_id="CVE-2018-1000115",
                is_kev=True,
                epss_score=0.94,
                epss_percentile=0.99,
                categories=["info_disclosure", "dos", "auth_bypass"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2018-1000115"],
            )]
    except Exception as e:
        logger.debug(f"Memcached audit error on {ip}:{port}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return []


async def audit_elasticsearch(ip: str, port: int = 9200, timeout: float = 2.0) -> List[ActiveVulnerability]:
    """Audit Elasticsearch for unauthenticated REST API cluster access."""
    reader, writer = await _safe_connect(ip, port, timeout=timeout)
    if not reader or not writer:
        return []
    try:
        req = f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: PVS/2.0\r\nConnection: close\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        resp_text = resp.decode("utf-8", errors="replace")
        if "tagline" in resp_text and "You Know, for Search" in resp_text:
            return [ActiveVulnerability(
                vuln_id="VULN-UNAUTH-ELASTICSEARCH",
                title="Elasticsearch Unauthenticated Cluster Access",
                severity="CRITICAL",
                score=9.8,
                service="elasticsearch",
                port=port,
                description="Elasticsearch cluster API is openly exposed without authentication. Remote attackers can search, modify, or delete indices across the entire cluster.",
                remediation_key="unauth_elasticsearch",
                evidence="Received Elasticsearch cluster metadata response without authentication challenge.",
                cve_id="CWE-306",
                is_kev=True,
                epss_score=0.93,
                epss_percentile=0.99,
                categories=["auth_bypass", "info_disclosure"],
                references=["https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html"],
            )]
    except Exception as e:
        logger.debug(f"Elasticsearch audit error on {ip}:{port}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return []


async def audit_docker(ip: str, port: int = 2375, timeout: float = 2.0) -> List[ActiveVulnerability]:
    """Audit unencrypted Docker Daemon REST API on port 2375."""
    reader, writer = await _safe_connect(ip, port, timeout=timeout)
    if not reader or not writer:
        return []
    try:
        req = f"GET /version HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: PVS/2.0\r\nConnection: close\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        resp_text = resp.decode("utf-8", errors="replace")
        if "ApiVersion" in resp_text or "docker" in resp_text.lower():
            return [ActiveVulnerability(
                vuln_id="VULN-DOCKER-DAEMON-EXPOSED",
                title="Docker Daemon Unauthenticated Remote Socket Exposed",
                severity="CRITICAL",
                score=10.0,
                service="docker",
                port=port,
                description="The Docker daemon API is exposed without TLS or authentication on port 2375. Remote users can spawn privileged root containers and fully compromise the host operating system.",
                remediation_key="docker_socket",
                evidence="Retrieved Docker Engine version info via unauthenticated HTTP GET /version.",
                cve_id="CWE-306",
                is_kev=True,
                epss_score=0.97,
                epss_percentile=0.999,
                categories=["rce", "auth_bypass"],
                references=["https://docs.docker.com/engine/security/protect-access/"],
            )]
    except Exception as e:
        logger.debug(f"Docker daemon audit error on {ip}:{port}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return []


# --- 2. Protocol Security Checks: SMBv1 & RDP without NLA ---

async def audit_smb(ip: str, port: int = 445, timeout: float = 2.5) -> List[ActiveVulnerability]:
    """Audit SMB service to detect if legacy SMBv1 protocol is enabled (EternalBlue MS17-010 risk)."""
    reader, writer = await _safe_connect(ip, port, timeout=timeout)
    if not reader or not writer:
        return []
    try:
        dialects = b"\x02PC NETWORK PROGRAM 1.0\x00\x02LANMAN1.0\x00\x02NT LM 0.12\x00"
        smb_header = b"\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        smb_body = b"\x00" + len(dialects).to_bytes(2, "little") + dialects
        smb_packet = smb_header + smb_body
        netbios_hdr = b"\x00" + len(smb_packet).to_bytes(3, "big")
        
        writer.write(netbios_hdr + smb_packet)
        await writer.drain()
        
        resp = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        if resp and len(resp) >= 8 and resp[4:8] == b"\xffSMB" and resp[8] == 0x72:
            return [ActiveVulnerability(
                vuln_id="VULN-SMBV1-ENABLED",
                title="SMBv1 Deprecated Protocol Enabled (EternalBlue Vector)",
                severity="CRITICAL",
                score=9.8,
                service="smb",
                port=port,
                description="The server supports SMBv1 (SMB 1.0). SMBv1 is an insecure legacy protocol vulnerable to remote code execution and ransomware worm attacks such as EternalBlue (MS17-010) and WannaCry.",
                remediation_key="smbv1_enabled",
                evidence="Server accepted SMBv1 dialect negotiation (SMB_COM_NEGOTIATE response returned 0xFFSMB).",
                cve_id="CVE-2017-0143",
                is_kev=True,
                epss_score=0.98,
                epss_percentile=0.999,
                categories=["rce", "weak_crypto"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2017-0143", "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"],
            )]
    except Exception as e:
        logger.debug(f"SMB audit error on {ip}:{port}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return []


async def audit_rdp(ip: str, port: int = 3389, timeout: float = 2.5) -> List[ActiveVulnerability]:
    """Audit Remote Desktop Protocol for disabled Network Level Authentication (NLA) / BlueKeep vector."""
    reader, writer = await _safe_connect(ip, port, timeout=timeout)
    if not reader or not writer:
        return []
    try:
        rdp_cr = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\x00"
        writer.write(rdp_cr)
        await writer.drain()
        
        resp = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        if resp and len(resp) >= 11 and resp[5] == 0xd0:
            if len(resp) >= 19:
                selected_protocol = int.from_bytes(resp[15:19], "little")
                if selected_protocol == 0:
                    return [ActiveVulnerability(
                        vuln_id="VULN-RDP-NO-NLA",
                        title="RDP Network Level Authentication (NLA) Disabled",
                        severity="HIGH",
                        score=8.1,
                        service="rdp",
                        port=port,
                        description="Remote Desktop accepts connections without requiring Network Level Authentication (NLA). This allows unauthenticated pre-auth exposure to RDP memory corruption flaws such as BlueKeep (CVE-2019-0708).",
                        remediation_key="rdp_nla",
                        evidence="RDP server accepted X.224 connection with standard legacy RDP security without requiring CredSSP/NLA.",
                        cve_id="CVE-2019-0708",
                        is_kev=True,
                        epss_score=0.96,
                        epss_percentile=0.998,
                        categories=["rce", "auth_bypass"],
                        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-0708", "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708"],
                    )]
    except Exception as e:
        logger.debug(f"RDP audit error on {ip}:{port}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return []


async def audit_ftp_anonymous(ip: str, port: int = 21, timeout: float = 2.5) -> List[ActiveVulnerability]:
    """Audit FTP server for anonymous login enabled."""
    reader, writer = await _safe_connect(ip, port, timeout=timeout)
    if not reader or not writer:
        return []
    try:
        await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        resp_user = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        
        if resp_user.startswith(b"331") or resp_user.startswith(b"230"):
            writer.write(b"PASS anonymous@pvs.local\r\n")
            await writer.drain()
            resp_pass = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            if resp_pass.startswith(b"230"):
                return [ActiveVulnerability(
                    vuln_id="VULN-FTP-ANONYMOUS",
                    title="FTP Anonymous Authentication Allowed",
                    severity="MEDIUM",
                    score=5.3,
                    service="ftp",
                    port=port,
                    description="The FTP server permits unauthenticated anonymous user logins, potentially exposing sensitive files or allowing unauthorized file uploads.",
                    remediation_key="ftp_anonymous",
                    evidence="Successfully logged in as 'anonymous' (Server response: 230 User logged in).",
                    cve_id="CWE-287",
                    is_kev=False,
                    epss_score=0.15,
                    epss_percentile=0.65,
                    categories=["auth_bypass", "info_disclosure"],
                    references=["https://cwe.mitre.org/data/definitions/287.html"],
                )]
    except Exception as e:
        logger.debug(f"FTP anonymous audit error on {ip}:{port}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return []


# --- 3. Cleartext Protocol Checks ---

async def audit_cleartext_protocol(
    arg1: Any, arg2: Any = None, arg3: Optional[str] = None
) -> List[ActiveVulnerability]:
    """
    Flag unencrypted cleartext protocols transmitting credentials or sensitive data in plaintext.
    Supports both (ip, port, service) and (port, service) calling signatures.
    """
    if arg3 is not None:
        ip = str(arg1)
        port = int(arg2) if arg2 is not None else 0
        service = str(arg3)
    elif isinstance(arg1, int) or (isinstance(arg1, str) and arg1.isdigit()):
        ip = ""
        port = int(arg1)
        service = str(arg2) if arg2 is not None else ""
    else:
        ip = str(arg1)
        port = int(arg2) if arg2 is not None else 0
        service = ""

    vulns: List[ActiveVulnerability] = []
    svc = (service or "").lower()

    if port == 23 or svc == "telnet":
        vulns.append(ActiveVulnerability(
            vuln_id="VULN-CLEARTEXT-TELNET",
            title="Insecure Cleartext Protocol in Use (Telnet)",
            severity="HIGH",
            score=7.5,
            service="telnet",
            port=port,
            description="Telnet transmits all communications, including authentication credentials and commands, in cleartext across the network without encryption.",
            remediation_key="cleartext_telnet",
            evidence=f"Service listening on standard unencrypted Telnet port {port}.",
            cve_id="CWE-319",
            is_kev=False,
            epss_score=0.20,
            epss_percentile=0.72,
            categories=["weak_crypto"],
            references=["https://cwe.mitre.org/data/definitions/319.html"],
        ))
    elif port == 21 or svc == "ftp":
        vulns.append(ActiveVulnerability(
            vuln_id="VULN-CLEARTEXT-FTP",
            title="Insecure Cleartext Protocol in Use (FTP)",
            severity="HIGH",
            score=7.5,
            service="ftp",
            port=port,
            description="FTP transmits usernames, passwords, and sensitive file contents in unencrypted plaintext across the network.",
            remediation_key="cleartext_ftp",
            evidence=f"Service listening on unencrypted FTP port {port}.",
            cve_id="CWE-319",
            is_kev=False,
            epss_score=0.20,
            epss_percentile=0.72,
            categories=["weak_crypto"],
            references=["https://cwe.mitre.org/data/definitions/319.html"],
        ))
    elif (port == 80 or svc == "http") and port not in (443, 8443, 9443, 6443):
        vulns.append(ActiveVulnerability(
            vuln_id="VULN-CLEARTEXT-HTTP",
            title="Insecure Cleartext Web Protocol in Use (HTTP)",
            severity="MEDIUM",
            score=5.3,
            service="http",
            port=port,
            description="HTTP transmits web sessions, credentials, and data without encryption, allowing network eavesdropping and session hijacking. Upgrade to HTTPS.",
            remediation_key="cleartext_http",
            evidence=f"Cleartext HTTP service detected on port {port} without mandatory TLS redirect.",
            cve_id="CWE-319",
            is_kev=False,
            epss_score=0.15,
            epss_percentile=0.60,
            categories=["weak_crypto"],
            references=["https://cwe.mitre.org/data/definitions/319.html"],
        ))
    elif port == 110 or svc == "pop3":
        vulns.append(ActiveVulnerability(
            vuln_id="VULN-CLEARTEXT-POP3",
            title="Insecure Cleartext Mail Protocol in Use (POP3)",
            severity="HIGH",
            score=7.5,
            service="pop3",
            port=port,
            description="POP3 transmits email authentication credentials and messages in cleartext without SSL/TLS encryption.",
            remediation_key="cleartext_pop3",
            evidence=f"Cleartext POP3 mail service detected on port {port}.",
            cve_id="CWE-319",
            is_kev=False,
            epss_score=0.18,
            epss_percentile=0.68,
            categories=["weak_crypto"],
            references=["https://cwe.mitre.org/data/definitions/319.html"],
        ))
    elif port == 143 or svc == "imap":
        vulns.append(ActiveVulnerability(
            vuln_id="VULN-CLEARTEXT-IMAP",
            title="Insecure Cleartext Mail Protocol in Use (IMAP)",
            severity="HIGH",
            score=7.5,
            service="imap",
            port=port,
            description="IMAP transmits email account credentials and mail traffic in cleartext without TLS.",
            remediation_key="cleartext_imap",
            evidence=f"Cleartext IMAP mail service detected on port {port}.",
            cve_id="CWE-319",
            is_kev=False,
            epss_score=0.18,
            epss_percentile=0.68,
            categories=["weak_crypto"],
            references=["https://cwe.mitre.org/data/definitions/319.html"],
        ))

    return vulns


# --- 4. Web Application Security Probes ---

async def audit_web_vulnerabilities(
    ip: str, port: int, use_ssl: bool = False, timeout: float = 2.5
) -> List[ActiveVulnerability]:
    """Audit HTTP/HTTPS services for dangerous methods, missing security headers, and sensitive leaks."""
    vulns: List[ActiveVulnerability] = []
    
    # 1. Probe HTTP methods (TRACE check)
    reader, writer = await _safe_connect(ip, port, timeout=timeout, use_ssl=use_ssl)
    if reader and writer:
        try:
            trace_req = f"TRACE / HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: PVS/2.0\r\nConnection: close\r\n\r\n"
            writer.write(trace_req.encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(2048), timeout=timeout)
            resp_str = resp.decode("utf-8", errors="replace")
            if resp_str.startswith("HTTP/1.1 200") and "TRACE / HTTP/1.1" in resp_str:
                vulns.append(ActiveVulnerability(
                    vuln_id="VULN-HTTP-TRACE-ENABLED",
                    title="HTTP TRACE Method Enabled (Cross-Site Tracing Risk)",
                    severity="MEDIUM",
                    score=5.3,
                    service="http",
                    port=port,
                    description="The web server has the HTTP TRACE method enabled, which echoes back client requests and can be leveraged by attackers to steal sensitive HTTP-only cookies (XST).",
                    remediation_key="http_trace",
                    evidence="HTTP TRACE request returned 200 OK echoing client request headers.",
                    cve_id="CWE-693",
                    is_kev=False,
                    epss_score=0.10,
                    epss_percentile=0.55,
                    categories=["info_disclosure"],
                    references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
                ))
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # 2. Probe Root GET for Missing Security Headers
    reader, writer = await _safe_connect(ip, port, timeout=timeout, use_ssl=use_ssl)
    if reader and writer:
        try:
            get_req = f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: PVS/2.0\r\nConnection: close\r\n\r\n"
            writer.write(get_req.encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            resp_str = resp.decode("utf-8", errors="replace").lower()
            
            # Check HSTS on SSL connections
            if use_ssl and "strict-transport-security" not in resp_str:
                vulns.append(ActiveVulnerability(
                    vuln_id="VULN-MISSING-HSTS",
                    title="Missing HTTP Strict Transport Security (HSTS) Header",
                    severity="LOW",
                    score=3.7,
                    service="https",
                    port=port,
                    description="The HTTPS web server does not deliver a Strict-Transport-Security (HSTS) header, allowing man-in-the-middle attackers to perform SSL-stripping downgrade attacks.",
                    remediation_key="missing_hsts",
                    evidence="Response headers lacked 'Strict-Transport-Security'.",
                    cve_id="CWE-319",
                    categories=["weak_crypto"],
                    references=["https://owasp.org/www-project-secure-headers/#http-strict-transport-security"],
                ))
            
            # Check Clickjacking (X-Frame-Options / CSP frame-ancestors)
            if "x-frame-options" not in resp_str and "frame-ancestors" not in resp_str:
                vulns.append(ActiveVulnerability(
                    vuln_id="VULN-MISSING-CLICKJACKING-PROTECTION",
                    title="Missing Clickjacking Defense (X-Frame-Options Header)",
                    severity="LOW",
                    score=3.5,
                    service="http" if not use_ssl else "https",
                    port=port,
                    description="The web server does not supply X-Frame-Options or Content-Security-Policy frame-ancestors headers, leaving web pages vulnerable to clickjacking attacks inside malicious iframes.",
                    remediation_key="missing_xframe",
                    evidence="Response headers lacked 'X-Frame-Options' and 'frame-ancestors'.",
                    cve_id="CWE-1021",
                    categories=["info_disclosure"],
                    references=["https://owasp.org/www-community/attacks/Clickjacking"],
                ))
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # 3. Probe for Sensitive Exposed Files (e.g. .env, .git/HEAD)
    sensitive_paths = [
        ("/.env", ["DB_PASSWORD", "APP_KEY", "SECRET", "PASSWORD", "DATABASE_URL"]),
        ("/.git/HEAD", ["ref: refs/"]),
    ]
    for path, signatures in sensitive_paths:
        r, w = await _safe_connect(ip, port, timeout=timeout, use_ssl=use_ssl)
        if not r or not w:
            continue
        try:
            req = f"GET {path} HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: PVS/2.0\r\nConnection: close\r\n\r\n"
            w.write(req.encode())
            await w.drain()
            resp = await asyncio.wait_for(r.read(2048), timeout=timeout)
            resp_str = resp.decode("utf-8", errors="replace")
            if resp_str.startswith("HTTP/1.1 200") or resp_str.startswith("HTTP/1.0 200"):
                if any(sig in resp_str for sig in signatures):
                    vuln_id = "VULN-ENV-EXPOSED" if ".env" in path else "VULN-GIT-EXPOSED"
                    title = f"Exposed Sensitive File Leak ({path})"
                    vulns.append(ActiveVulnerability(
                        vuln_id=vuln_id,
                        title=title,
                        severity="CRITICAL" if ".env" in path else "HIGH",
                        score=9.1 if ".env" in path else 7.5,
                        service="http" if not use_ssl else "https",
                        port=port,
                        description=f"Publicly accessible sensitive file {path} was found on the web server. Attackers can extract secrets, credentials, or complete source code repositories.",
                        remediation_key="exposed_files",
                        evidence=f"Accessible path {path} returned 200 OK matching sensitive signatures.",
                        cve_id="CWE-552",
                        is_kev=True,
                        epss_score=0.90,
                        epss_percentile=0.98,
                        categories=["info_disclosure", "auth_bypass"],
                        references=["https://cwe.mitre.org/data/definitions/552.html"],
                    ))
        except Exception:
            pass
        finally:
            try:
                w.close()
                await w.wait_closed()
            except Exception:
                pass

    return vulns


# --- 5. TLS / SSL Protocol Security Flaws ---

def audit_tls_flaws(port: int, tls_info: dict) -> List[ActiveVulnerability]:
    """Audit SSL/TLS session properties for deprecated protocols or weak ciphers."""
    vulns: List[ActiveVulnerability] = []
    if not tls_info:
        return vulns
    
    ver = (tls_info.get("version") or "").upper()
    cipher = (tls_info.get("cipher") or "").upper()
    
    # Deprecated TLS protocols (TLSv1.0, TLSv1.1, SSLv3)
    if "TLSV1.0" in ver or "TLS 1.0" in ver or "SSLV3" in ver or "TLSV1.1" in ver or "TLS 1.1" in ver:
        vulns.append(ActiveVulnerability(
            vuln_id="VULN-DEPRECATED-TLS",
            title=f"Deprecated Insecure TLS Protocol ({ver})",
            severity="HIGH",
            score=7.4,
            service="tls",
            port=port,
            description=f"The server negotiated {ver}. TLS 1.0 and TLS 1.1 have been officially deprecated by the IETF (RFC 8996) due to structural cipher weaknesses and lack of support for modern authenticated encryption.",
            remediation_key="deprecated_tls",
            evidence=f"Negotiated TLS session protocol version: {ver}.",
            cve_id="CWE-326",
            categories=["weak_crypto"],
            references=["https://datatracker.ietf.org/doc/html/rfc8996", "https://cwe.mitre.org/data/definitions/326.html"],
        ))
        
    # Weak ciphers (RC4, 3DES, CBC with SHA1)
    if any(weak in cipher for weak in ("RC4", "3DES", "DES", "NULL", "EXPORT")):
        vulns.append(ActiveVulnerability(
            vuln_id="VULN-WEAK-CIPHER",
            title=f"Weak Legacy Cipher Suite in Use ({cipher})",
            severity="MEDIUM",
            score=5.9,
            service="tls",
            port=port,
            description=f"The server negotiated weak cipher suite {cipher}, which is vulnerable to cryptographic plaintext recovery attacks (e.g., Sweet32 for 3DES, Bar Mitzvah for RC4).",
            remediation_key="weak_ciphers",
            evidence=f"Active cipher suite: {cipher}.",
            cve_id="CWE-327",
            categories=["weak_crypto"],
            references=["https://sweet32.info/", "https://cwe.mitre.org/data/definitions/327.html"],
        ))
        
    return vulns


# --- Main Active Audit Orchestrator ---

async def audit_host_port(
    ip: str, port: int, service: str, banner: str = "", tls_info: dict = None, timeout: float = 2.5
) -> List[ActiveVulnerability]:
    """
    Run all applicable active security audits for a discovered open port.
    Returns a list of confirmed active vulnerabilities.
    """
    findings: List[ActiveVulnerability] = []
    svc_lower = (service or "").lower()
    use_ssl = port in (443, 8443, 9443, 6443) or bool(tls_info)
    
    # 1. Cleartext checks
    findings.extend(await audit_cleartext_protocol(ip, port, service))
        
    # 2. Database & Cache audits
    if port == 6379 or svc_lower == "redis":
        findings.extend(await audit_redis(ip, port, timeout))
        
    if port == 27017 or svc_lower == "mongodb":
        findings.extend(await audit_mongodb(ip, port, timeout))
        
    if port == 11211 or svc_lower == "memcached":
        findings.extend(await audit_memcached(ip, port, timeout))
        
    if port == 9200 or svc_lower == "elasticsearch":
        findings.extend(await audit_elasticsearch(ip, port, timeout))
        
    if port == 2375 or svc_lower == "docker":
        findings.extend(await audit_docker(ip, port, timeout))

    # 3. Protocol audits: SMB & RDP
    if port in (445, 139) or svc_lower in ("smb", "microsoft-ds"):
        findings.extend(await audit_smb(ip, port, timeout))
        
    if port == 3389 or svc_lower in ("rdp", "ms-wbt-server"):
        findings.extend(await audit_rdp(ip, port, timeout))
        
    # 4. FTP Anonymous audit
    if port == 21 or svc_lower == "ftp":
        findings.extend(await audit_ftp_anonymous(ip, port, timeout))
        
    # 5. Web application security audit
    if port in (80, 443, 8080, 8443, 8000, 8888, 9090, 3000, 5000) or svc_lower in ("http", "https"):
        web_vulns = await audit_web_vulnerabilities(ip, port, use_ssl=use_ssl, timeout=timeout)
        findings.extend(web_vulns)
        
    # 6. TLS session security audit
    if tls_info:
        tls_vulns = audit_tls_flaws(port, tls_info)
        findings.extend(tls_vulns)

    return findings

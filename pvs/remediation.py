# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
Remediation Engine - Generates actionable, multi-OS step-by-step fix procedures for detected vulnerabilities.
Provides real-world production-grade commands with CVE-category-aware intelligence for Linux, Windows, and macOS.

Features:
  - 25+ service-specific hardening knowledge bases
  - CVE vulnerability category analysis (RCE, AuthBypass, BufferOverflow, WeakCrypto, InfoDisclosure, DoS, Deserialization)
  - Category-tailored workaround injection
  - Port-aware dynamic fallback (no more &lt;PORT&gt; placeholders)
  - Syntactically valid shell, PowerShell, and zsh commands
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Tuple


@dataclass
class RemediationStep:
    """Represents a single step in a remediation procedure with multi-OS commands and rollback options."""
    step_number: int
    title: str
    description: str
    command_linux: str = ""
    command_windows: str = ""
    command_macos: str = ""
    category: str = "patch"  # "workaround", "patch", "firewall", "verify", "harden"
    # Smart enhancements: Operational safety & Rollback instructions
    rollback_linux: str = ""
    rollback_windows: str = ""
    rollback_macos: str = ""
    disruption_level: str = "LOW"  # "ZERO_DOWNTIME", "CONFIG_RELOAD", "SERVICE_RESTART", "READ_ONLY"
    estimated_time: str = "2-5 mins"

    @property
    def primary_command(self) -> str:
        """Returns the primary command available across OS platforms."""
        return self.command_linux or self.command_windows or self.command_macos

    @property
    def command(self) -> str:
        """Alias for primary_command."""
        return self.primary_command


@dataclass
class RemediationPlan:
    """Structured multi-OS remediation plan for a vulnerability or service issue."""
    service: str
    version: str = ""
    cve_id: str = ""
    summary: str = ""
    steps: List[RemediationStep] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "version": self.version,
            "cve_id": self.cve_id,
            "summary": self.summary,
            "steps": [
                {
                    "step_number": s.step_number,
                    "title": s.title,
                    "description": s.description,
                    "command_linux": s.command_linux,
                    "command_windows": s.command_windows,
                    "command_macos": s.command_macos,
                    "command": s.primary_command,
                    "category": s.category,
                    "rollback_linux": s.rollback_linux,
                    "rollback_windows": s.rollback_windows,
                    "rollback_macos": s.rollback_macos,
                    "disruption_level": s.disruption_level,
                    "estimated_time": s.estimated_time,
                }
                for s in self.steps
            ],
        }


# CVE VULNERABILITY CATEGORY ANALYZER

_CVE_CATEGORY_PATTERNS: Dict[str, List[str]] = {
    "rce": [
        "remote code execution", "arbitrary code", "command injection",
        "code injection", "os command", "shell injection", "eval injection",
        "arbitrary command", "execute arbitrary", "rce", "remote execution",
    ],
    "auth_bypass": [
        "authentication bypass", "auth bypass", "unauthorized access",
        "privilege escalation", "improper authentication", "broken auth",
        "missing authentication", "default credentials", "weak password",
        "improper access control", "access control", "permission bypass",
        "authorization bypass", "privilege gain", "elevation of privilege",
    ],
    "buffer_overflow": [
        "buffer overflow", "heap overflow", "stack overflow", "out-of-bounds write",
        "out-of-bounds read", "memory corruption", "use-after-free", "double free",
        "integer overflow", "format string", "null pointer dereference",
    ],
    "weak_crypto": [
        "weak cipher", "weak encryption", "deprecated algorithm", "ssl",
        "tls 1.0", "tls 1.1", "sslv3", "sslv2", "rc4", "des ", "3des",
        "md5", "sha1", "sha-1", "weak hash", "plaintext", "cleartext",
        "insecure protocol", "downgrade attack", "poodle", "beast",
        "sweet32", "logjam", "freak", "drown", "heartbleed",
        "certificate validation", "improper certificate",
    ],
    "info_disclosure": [
        "information disclosure", "information leak", "data exposure",
        "sensitive data", "directory listing", "path traversal",
        "directory traversal", "file inclusion", "local file inclusion",
        "server-side request forgery", "ssrf", "xml external entity", "xxe",
        "source code disclosure", "error message", "stack trace",
        "version disclosure", "banner grabbing",
    ],
    "dos": [
        "denial of service", "denial-of-service", "dos ", "ddos",
        "resource exhaustion", "infinite loop", "cpu exhaustion",
        "memory exhaustion", "algorithmic complexity", "regex dos",
        "redos", "slowloris", "http/2 rapid reset", "amplification",
    ],
    "deserialization": [
        "deserialization", "deserialisation", "log4j", "log4shell",
        "jndi", "java naming", "unsafe reflection", "object injection",
        "pickle", "yaml.load", "unserialize", "marshal.load",
    ],
    "sqli": [
        "sql injection", "sqli", "blind sql", "union-based", "error-based sql",
        "second-order sql", "nosql injection",
    ],
    "xss": [
        "cross-site scripting", "xss", "reflected xss", "stored xss",
        "dom-based xss", "script injection",
    ],
}


def analyze_cve_categories(cve_description: str, cve_id: str = "") -> Set[str]:
    """Analyze a CVE description to determine vulnerability categories."""
    if not cve_description:
        return set()
    text = cve_description.lower()
    cve_lower = cve_id.lower() if cve_id else ""
    categories = set()
    for category, patterns in _CVE_CATEGORY_PATTERNS.items():
        for pattern in patterns:
            if pattern in text or pattern in cve_lower:
                categories.add(category)
                break
    return categories if categories else {"general"}


def _get_category_hardening_steps(categories: Set[str], service: str, port: int) -> List[RemediationStep]:
    """Generate additional hardening steps based on detected CVE categories."""
    extra_steps = []

    if "rce" in categories:
        extra_steps.append(RemediationStep(
            step_number=0,
            title="RCE Mitigation \u2014 Restrict Process Execution Scope",
            description="Limit the service's ability to spawn child processes. Run under a dedicated low-privilege user with a nologin shell.",
            command_linux=(
                f"# Create dedicated service user with no shell access\n"
                f"sudo useradd -r -s /usr/sbin/nologin {service}_svc 2>/dev/null\n"
                f"# Restrict writable temp directories\n"
                f"sudo mount -o remount,noexec,nosuid /tmp\n"
                f"# Check for suspicious spawned processes\n"
                f"ps aux | grep -i {service} | grep -v grep"
            ),
            command_windows=(
                f"# Create restricted local service account\n"
                f"net user {service}_svc /add /active:yes\n"
                f"net localgroup Users {service}_svc /delete"
            ),
            command_macos=(
                f"# Audit running processes\n"
                f"ps aux | grep -i {service} | grep -v grep"
            ),
            category="harden",
        ))

    if "auth_bypass" in categories:
        extra_steps.append(RemediationStep(
            step_number=0,
            title="Auth Bypass Mitigation \u2014 Enforce Strong Authentication",
            description="Reset all service credentials, enforce key-based or certificate-based auth, and audit recent login attempts.",
            command_linux=(
                f"# Force password rotation\n"
                f"sudo chage -d 0 $(whoami)\n"
                f"# Audit recent authentication failures\n"
                f"sudo journalctl -u {service} --since '24 hours ago' | grep -iE 'fail|denied|invalid'\n"
                f"# Check for unauthorized SSH keys\n"
                f"find /home -name authorized_keys -exec ls -la {{}} \\;"
            ),
            command_windows=(
                f"# Review recent failed logon events (Event ID 4625)\n"
                f"Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4625}} -MaxEvents 50 | Format-Table TimeCreated, Message -Wrap"
            ),
            command_macos=(
                f"# Audit auth log for suspicious activity\n"
                f"log show --predicate 'eventMessage contains \"authentication\"' --last 24h | grep -i fail"
            ),
            category="harden",
        ))

    if "buffer_overflow" in categories:
        extra_steps.append(RemediationStep(
            step_number=0,
            title="Buffer Overflow Defense \u2014 Enable Memory Protections",
            description="Enable ASLR, DEP/NX, stack canaries and deploy intrusion detection to catch exploit attempts.",
            command_linux=(
                "# Verify ASLR is fully enabled (should return 2)\n"
                "cat /proc/sys/kernel/randomize_va_space\n"
                "# Enable ASLR if not set\n"
                "echo 2 | sudo tee /proc/sys/kernel/randomize_va_space\n"
                "# Make persistent\n"
                "echo 'kernel.randomize_va_space = 2' | sudo tee -a /etc/sysctl.d/99-security.conf\n"
                "sudo sysctl -p /etc/sysctl.d/99-security.conf"
            ),
            command_windows=(
                "# Verify DEP is enabled\n"
                "Get-CimInstance Win32_OperatingSystem | Select-Object DataExecutionPrevention_Available\n"
                "# Enable Exploit Protection (ASLR, DEP, CFG)\n"
                "Set-ProcessMitigation -System -Enable DEP,ForceRelocateImages,BottomUp,HighEntropy\n"
                "Get-ProcessMitigation -System"
            ),
            command_macos=(
                "# macOS has SIP + ASLR by default\n"
                "csrutil status\n"
                "spctl --status"
            ),
            category="harden",
        ))

    if "weak_crypto" in categories:
        extra_steps.append(RemediationStep(
            step_number=0,
            title="Cryptographic Hardening \u2014 Disable Weak Ciphers & Protocols",
            description="Disable SSLv3, TLS 1.0/1.1, RC4, 3DES, MD5, SHA-1. Enforce TLS 1.2+ with AES-GCM/ChaCha20.",
            command_linux=(
                "# Disable weak TLS system-wide\n"
                "sudo update-crypto-policies --set FUTURE 2>/dev/null\n"
                "# Or configure OpenSSL directly\n"
                "echo 'MinProtocol = TLSv1.2' | sudo tee -a /etc/ssl/openssl.cnf\n"
                f"# Scan current TLS config\n"
                f"openssl s_client -connect 127.0.0.1:{port} -tls1_2 </dev/null 2>&1 | grep -E 'Protocol|Cipher'"
            ),
            command_windows=(
                "# Disable TLS 1.0 and 1.1\n"
                "New-Item 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Force\n"
                "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Name Enabled -Value 0 -Type DWord\n"
                "New-Item 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server' -Force\n"
                "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server' -Name Enabled -Value 0 -Type DWord"
            ),
            command_macos=(
                f"openssl s_client -connect 127.0.0.1:{port} -tls1_2 </dev/null 2>&1 | grep -E 'Protocol|Cipher'"
            ),
            category="harden",
        ))

    if "dos" in categories:
        extra_steps.append(RemediationStep(
            step_number=0,
            title="DoS Resilience \u2014 Rate Limiting & Connection Controls",
            description="Apply connection rate limiting, request size caps, and timeout tuning.",
            command_linux=(
                f"# Rate limit new connections (max 25/sec per source IP)\n"
                f"sudo iptables -A INPUT -p tcp --dport {port} -m conntrack --ctstate NEW -m recent --set --name RATELIMIT\n"
                f"sudo iptables -A INPUT -p tcp --dport {port} -m conntrack --ctstate NEW -m recent --update --seconds 1 --hitcount 25 --name RATELIMIT -j DROP\n"
                f"# Harden kernel TCP stack\n"
                f"echo 'net.ipv4.tcp_syncookies = 1' | sudo tee -a /etc/sysctl.d/99-dos-hardening.conf\n"
                f"echo 'net.ipv4.tcp_max_syn_backlog = 4096' | sudo tee -a /etc/sysctl.d/99-dos-hardening.conf\n"
                f"sudo sysctl -p /etc/sysctl.d/99-dos-hardening.conf"
            ),
            command_windows=(
                f"# Configure SYN attack protection\n"
                f"Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name SynAttackProtect -Value 1 -Type DWord\n"
                f"Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name TcpMaxHalfOpen -Value 500 -Type DWord"
            ),
            command_macos=(
                f"echo 'pass in on en0 proto tcp to port {port} flags S/SA keep state (max-src-conn 100, max-src-conn-rate 25/1)' | sudo tee -a /etc/pf.anchors/ratelimit\n"
                f"sudo pfctl -f /etc/pf.conf"
            ),
            category="harden",
        ))

    if "deserialization" in categories:
        extra_steps.append(RemediationStep(
            step_number=0,
            title="Deserialization / Log4Shell Defense \u2014 Block JNDI & Restrict Classloading",
            description="Disable JNDI lookups (Log4j), restrict deserialization classes, block outbound LDAP/RMI.",
            command_linux=(
                "# Mitigate Log4Shell immediately\n"
                "export LOG4J_FORMAT_MSG_NO_LOOKUPS=true\n"
                "# Find and patch vulnerable Log4j jars\n"
                "find / -name 'log4j-core-*.jar' -type f 2>/dev/null | while read jar; do\n"
                "  echo \"Found: $jar\"\n"
                "  zip -q -d \"$jar\" org/apache/logging/log4j/core/lookup/JndiLookup.class 2>/dev/null\n"
                "done\n"
                "# Block outbound LDAP/RMI\n"
                "sudo iptables -A OUTPUT -p tcp --dport 1389 -j DROP\n"
                "sudo iptables -A OUTPUT -p tcp --dport 1099 -j DROP"
            ),
            command_windows=(
                "# Disable Log4j JNDI lookups\n"
                "[System.Environment]::SetEnvironmentVariable('LOG4J_FORMAT_MSG_NO_LOOKUPS','true','Machine')\n"
                "# Find vulnerable jars\n"
                "Get-ChildItem -Path C:\\ -Recurse -Filter 'log4j-core-*.jar' -ErrorAction SilentlyContinue | Select-Object FullName\n"
                "# Block outbound LDAP/RMI\n"
                "New-NetFirewallRule -Name 'Block-JNDI-LDAP' -DisplayName 'Block JNDI LDAP' -Direction Outbound -Protocol TCP -RemotePort 1389 -Action Block\n"
                "New-NetFirewallRule -Name 'Block-JNDI-RMI' -DisplayName 'Block JNDI RMI' -Direction Outbound -Protocol TCP -RemotePort 1099 -Action Block"
            ),
            command_macos=(
                "export LOG4J_FORMAT_MSG_NO_LOOKUPS=true\n"
                "find / -name 'log4j-core-*.jar' -type f 2>/dev/null"
            ),
            category="harden",
        ))

    if "sqli" in categories:
        extra_steps.append(RemediationStep(
            step_number=0,
            title="SQL Injection Defense \u2014 Enable Query Logging & WAF Rules",
            description="Enable database query logging, deploy ModSecurity WAF with OWASP CRS to detect SQLi payloads.",
            command_linux=(
                "# Enable MySQL general query log\n"
                "sudo mysql -e \"SET GLOBAL general_log = 'ON'; SET GLOBAL general_log_file = '/var/log/mysql/query.log';\" 2>/dev/null\n"
                "# Install ModSecurity WAF with OWASP CRS\n"
                "sudo apt install -y libapache2-mod-security2 2>/dev/null || sudo dnf install -y mod_security 2>/dev/null\n"
                "sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf 2>/dev/null\n"
                "sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf 2>/dev/null"
            ),
            command_windows=(
                "# Enable IIS Request Filtering to block common SQLi patterns\n"
                "Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering/denyUrlSequences' -name '.' -value @{sequence=\"union+select\"}\n"
                "Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering/denyUrlSequences' -name '.' -value @{sequence=\"1=1\"}"
            ),
            command_macos=(
                "# Enable PostgreSQL query logging\n"
                "sudo sed -i '' \"s/#log_statement = 'none'/log_statement = 'all'/\" /usr/local/var/postgres/postgresql.conf 2>/dev/null\n"
                "brew services restart postgresql 2>/dev/null"
            ),
            category="harden",
        ))

    if "info_disclosure" in categories:
        extra_steps.append(RemediationStep(
            step_number=0,
            title="Information Disclosure Mitigation \u2014 Suppress Banners & Error Details",
            description="Remove version strings from service banners, disable directory listings, suppress stack traces.",
            command_linux=(
                f"# Check what the service is exposing\n"
                f"curl -sI http://127.0.0.1:{port} 2>/dev/null | grep -iE 'server:|x-powered-by:'\n"
                f"# Add security headers to suppress info leaks\n"
                f"echo 'Header always set X-Content-Type-Options nosniff' | sudo tee -a /etc/apache2/conf-available/security.conf 2>/dev/null\n"
                f"echo 'Header always set X-Frame-Options DENY' | sudo tee -a /etc/apache2/conf-available/security.conf 2>/dev/null"
            ),
            command_windows=(
                f"# Remove IIS version header\n"
                f"Import-Module WebAdministration\n"
                f"Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering' -name removeServerHeader -value True\n"
                f"# Disable detailed error messages\n"
                f"Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/httpErrors' -name errorMode -value 'DetailedLocalOnly'"
            ),
            command_macos=(
                f"curl -sI http://127.0.0.1:{port} 2>/dev/null | grep -iE 'server:|x-powered-by:'"
            ),
            category="harden",
        ))

    return extra_steps


# COMPREHENSIVE SERVICE REMEDIATION KNOWLEDGE BASE
# Real-world production commands

SERVICE_REMEDIATION_KB: Dict[str, dict] = {
    "ssh": {
        "summary": "Harden OpenSSH against brute-force attacks, key exchange vulnerabilities, and weak crypto by enforcing modern algorithms, disabling root login, and restricting access.",
        "steps": [
            {
                "title": "Harden SSH Configuration \u2014 Disable Root Login, Enforce Key Auth & Modern Ciphers",
                "description": "Disable password-based root login, enforce public key authentication, set strict crypto algorithms (Ed25519/AES-GCM), limit login grace time, and restrict max auth attempts.",
                "command_linux": "sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)\nsudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config\nsudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config\nsudo sed -i 's/^#\\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config\nsudo sed -i 's/^#\\?LoginGraceTime.*/LoginGraceTime 20/' /etc/ssh/sshd_config\nsudo sed -i 's/^#\\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config\n# Enforce strong Key Exchange, Ciphers, and MACs\necho 'KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512' | sudo tee -a /etc/ssh/sshd_config\necho 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com' | sudo tee -a /etc/ssh/sshd_config\necho 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com' | sudo tee -a /etc/ssh/sshd_config\nsudo sshd -t && sudo systemctl reload sshd",
                "command_windows": "Copy-Item 'C:\\ProgramData\\ssh\\sshd_config' 'C:\\ProgramData\\ssh\\sshd_config.bak'\n$config = Get-Content 'C:\\ProgramData\\ssh\\sshd_config'\n$config = $config -replace '^#?PermitRootLogin.*', 'PermitRootLogin no'\n$config = $config -replace '^#?PasswordAuthentication.*', 'PasswordAuthentication no'\n$config = $config -replace '^#?MaxAuthTries.*', 'MaxAuthTries 3'\n$config += 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com'\n$config += 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com'\nSet-Content 'C:\\ProgramData\\ssh\\sshd_config' $config\nRestart-Service sshd",
                "command_macos": "sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)\nsudo sed -i '' 's/^#\\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config\nsudo sed -i '' 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config\necho 'KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org' | sudo tee -a /etc/ssh/sshd_config\necho 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com' | sudo tee -a /etc/ssh/sshd_config\nsudo launchctl unload /System/Library/LaunchDaemons/ssh.plist && sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist",
                "category": "workaround",
            },
            {
                "title": "Update OpenSSH to Latest Patched Release",
                "description": "Upgrade OpenSSH server and client binaries to the most recent stable security release.",
                "command_linux": "# Ubuntu/Debian\nsudo apt update && sudo apt install --only-upgrade openssh-server openssh-client -y\n# RHEL/CentOS/Fedora\nsudo dnf upgrade openssh-server openssh-clients -y\nssh -V",
                "command_windows": "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0\nwinget upgrade --id Microsoft.OpenSSH.Beta -e --accept-package-agreements\nssh -V",
                "command_macos": "brew update && brew upgrade openssh\nssh -V",
                "category": "patch",
            },
            {
                "title": "Firewall Isolation \u2014 Restrict SSH to Trusted Networks Only",
                "description": "Block SSH access from the public internet. Allow connections only from your management subnet (adjust 10.0.0.0/8 to your actual trusted network).",
                "command_linux": "sudo ufw delete allow 22/tcp 2>/dev/null\nsudo ufw allow from 10.0.0.0/8 to any port 22 proto tcp comment 'SSH management access'\nsudo ufw reload",
                "command_windows": "Remove-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue\nNew-NetFirewallRule -Name 'SSH-Mgmt-Only' -DisplayName 'SSH Management Access' -Direction Inbound -Protocol TCP -LocalPort 22 -RemoteAddress 10.0.0.0/8 -Action Allow -Profile Any\nNew-NetFirewallRule -Name 'SSH-Block-Public' -DisplayName 'Block Public SSH' -Direction Inbound -Protocol TCP -LocalPort 22 -Action Block -Profile Public",
                "command_macos": "echo 'block in on en0 proto tcp from any to any port 22' | sudo tee -a /etc/pf.anchors/ssh_restrict\necho 'pass in on en0 proto tcp from 10.0.0.0/8 to any port 22' | sudo tee -a /etc/pf.anchors/ssh_restrict\nsudo pfctl -f /etc/pf.conf && sudo pfctl -e",
                "category": "firewall",
            },
            {
                "title": "Deploy Brute-Force Protection (Fail2Ban / Account Lockout)",
                "description": "Install and configure automated intrusion prevention to ban IPs after repeated failed SSH login attempts.",
                "command_linux": "sudo apt install -y fail2ban 2>/dev/null || sudo dnf install -y fail2ban 2>/dev/null\nsudo tee /etc/fail2ban/jail.d/sshd.local << 'EOF'\n[sshd]\nenabled = true\nport = ssh\nfilter = sshd\nlogpath = /var/log/auth.log\nmaxretry = 3\nbantime = 3600\nfindtime = 600\nEOF\nsudo systemctl enable --now fail2ban\nsudo fail2ban-client status sshd",
                "command_windows": "net accounts /lockoutthreshold:3 /lockoutduration:60 /lockoutwindow:10\nnet accounts",
                "command_macos": "brew install fail2ban\nsudo cp /usr/local/etc/fail2ban/jail.conf /usr/local/etc/fail2ban/jail.local\nbrew services start fail2ban",
                "category": "harden",
            },
            {
                "title": "Verify SSH Security Posture",
                "description": "Audit the running SSH config, verify strong ciphers are active, check for weak algorithms, and confirm listening address.",
                "command_linux": "sudo sshd -T | grep -iE 'permitrootlogin|passwordauthentication|ciphers|macs|kexalgorithms|maxauthtries'\nsudo ss -tlnp | grep :22\nsudo systemctl status sshd --no-pager",
                "command_windows": "Get-Service sshd | Select-Object Name, Status, StartType\nGet-Content 'C:\\ProgramData\\ssh\\sshd_config' | Select-String -Pattern 'PermitRootLogin|PasswordAuthentication|Ciphers|MACs'\nssh -V",
                "command_macos": "sudo sshd -T 2>/dev/null | grep -iE 'permitrootlogin|passwordauthentication|ciphers|macs'\nssh -V\nsudo lsof -iTCP:22 -sTCP:LISTEN",
                "category": "verify",
            },
        ],
    },
    "http": {
        "summary": "Harden Apache HTTP Server by suppressing version banners, deploying security headers (CSP, HSTS, X-Frame-Options), disabling dangerous modules, and enforcing TLS 1.2+.",
        "steps": [
            {
                "title": "Suppress Server Banners & Deploy Security Response Headers",
                "description": "Hide Apache version, disable ServerSignature, and add critical security headers to prevent clickjacking, MIME sniffing, and XSS.",
                "command_linux": "sudo cp /etc/apache2/conf-available/security.conf /etc/apache2/conf-available/security.conf.bak 2>/dev/null\nsudo sed -i 's/^ServerTokens.*/ServerTokens Prod/' /etc/apache2/conf-available/security.conf 2>/dev/null\nsudo sed -i 's/^ServerSignature.*/ServerSignature Off/' /etc/apache2/conf-available/security.conf 2>/dev/null\nsudo a2enmod headers 2>/dev/null\nsudo tee /etc/apache2/conf-available/security-headers.conf << 'EOF'\nHeader always set X-Content-Type-Options \"nosniff\"\nHeader always set X-Frame-Options \"DENY\"\nHeader always set X-XSS-Protection \"1; mode=block\"\nHeader always set Referrer-Policy \"strict-origin-when-cross-origin\"\nHeader always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\nHeader unset X-Powered-By\nHeader unset Server\nEOF\nsudo a2enconf security-headers 2>/dev/null\nsudo sed -i 's/Options Indexes/Options -Indexes/' /etc/apache2/apache2.conf 2>/dev/null\nsudo a2dismod autoindex status info 2>/dev/null\nsudo apache2ctl configtest && sudo systemctl reload apache2",
                "command_windows": "$conf = 'C:\\Apache24\\conf\\httpd.conf'\nAdd-Content $conf \"`nServerTokens Prod\"\nAdd-Content $conf 'ServerSignature Off'\nAdd-Content $conf 'Header always set X-Content-Type-Options \"nosniff\"'\nAdd-Content $conf 'Header always set X-Frame-Options \"DENY\"'\nAdd-Content $conf 'Header always set Strict-Transport-Security \"max-age=31536000\"'\nRestart-Service Apache2.4 -ErrorAction SilentlyContinue",
                "command_macos": "sudo sed -i '' 's/^ServerTokens.*/ServerTokens Prod/' /usr/local/etc/httpd/httpd.conf\nsudo sed -i '' 's/^ServerSignature.*/ServerSignature Off/' /usr/local/etc/httpd/httpd.conf\necho 'Header always set X-Content-Type-Options \"nosniff\"' | sudo tee -a /usr/local/etc/httpd/httpd.conf\necho 'Header always set X-Frame-Options \"DENY\"' | sudo tee -a /usr/local/etc/httpd/httpd.conf\nbrew services restart httpd",
                "category": "workaround",
            },
            {
                "title": "Update Apache HTTP Server to Latest Security Release",
                "description": "Upgrade Apache2/httpd binaries to resolve all known CVEs.",
                "command_linux": "# Ubuntu/Debian\nsudo apt update && sudo apt install --only-upgrade apache2 libapache2-mod-security2 -y\n# RHEL/CentOS/Fedora\nsudo dnf upgrade httpd mod_ssl mod_security -y\napache2ctl -v 2>/dev/null || httpd -v",
                "command_windows": "winget upgrade --name 'Apache HTTP Server' --accept-package-agreements\nhttpd.exe -v",
                "command_macos": "brew update && brew upgrade httpd && httpd -v",
                "category": "patch",
            },
            {
                "title": "Enforce TLS 1.2+ & Disable Weak SSL Cipher Suites",
                "description": "Configure mod_ssl to require TLS 1.2 minimum with modern AEAD cipher suites.",
                "command_linux": "sudo a2enmod ssl 2>/dev/null\nsudo tee /etc/apache2/conf-available/ssl-hardening.conf << 'EOF'\nSSLProtocol -all +TLSv1.2 +TLSv1.3\nSSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305\nSSLHonorCipherOrder on\nSSLCompression off\nSSLSessionTickets off\nEOF\nsudo a2enconf ssl-hardening 2>/dev/null\nsudo apache2ctl configtest && sudo systemctl reload apache2",
                "command_windows": "$ssl = 'C:\\Apache24\\conf\\extra\\httpd-ssl.conf'\nAdd-Content $ssl 'SSLProtocol -all +TLSv1.2 +TLSv1.3'\nAdd-Content $ssl 'SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256'\nRestart-Service Apache2.4",
                "command_macos": "echo 'SSLProtocol -all +TLSv1.2 +TLSv1.3' | sudo tee -a /usr/local/etc/httpd/extra/httpd-ssl.conf\napachectl configtest && brew services restart httpd",
                "category": "harden",
            },
            {
                "title": "Verify Apache Security Posture",
                "description": "Validate config, confirm security headers, and verify no version leak.",
                "command_linux": "sudo apache2ctl configtest\ncurl -sI http://127.0.0.1 | grep -iE 'server:|x-powered-by:'\ncurl -sI http://127.0.0.1 | grep -iE 'x-frame-options|x-content-type|strict-transport|referrer-policy'\napache2ctl -M 2>/dev/null | grep -iE 'security|headers|ssl'",
                "command_windows": "C:\\Apache24\\bin\\httpd.exe -t\ncurl.exe -sI http://localhost | Select-String 'Server:','X-Powered-By:','X-Frame-Options:'\nGet-Service Apache2.4 | Select-Object Name, Status",
                "command_macos": "apachectl configtest\ncurl -sI http://127.0.0.1 | grep -iE 'server:|x-powered-by:|x-frame-options:|strict-transport'",
                "category": "verify",
            },
        ],
    },
    "nginx": {
        "summary": "Harden Nginx against HTTP/2 rapid reset attacks, buffer overflow exploits, and information disclosure by enforcing strict security headers, rate limiting, and TLS 1.2+ with OCSP stapling.",
        "steps": [
            {
                "title": "Suppress Version, Add Security Headers & Harden Buffer Limits",
                "description": "Hide Nginx version string, deploy HTTP security response headers, and tune buffer sizes.",
                "command_linux": "sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak.$(date +%s)\nsudo sed -i 's/# server_tokens off;/server_tokens off;/' /etc/nginx/nginx.conf\nsudo tee /etc/nginx/conf.d/security-headers.conf << 'EOF'\nadd_header X-Content-Type-Options \"nosniff\" always;\nadd_header X-Frame-Options \"DENY\" always;\nadd_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\nclient_body_buffer_size 1k;\nclient_header_buffer_size 1k;\nclient_max_body_size 10m;\nlarge_client_header_buffers 4 8k;\nclient_body_timeout 10;\nclient_header_timeout 10;\nkeepalive_timeout 15;\nsend_timeout 10;\nlimit_req_zone $binary_remote_addr zone=ratelimit:10m rate=10r/s;\nEOF\nsudo nginx -t && sudo systemctl reload nginx",
                "command_windows": "$conf = Get-Content 'C:\\nginx\\conf\\nginx.conf'\n$conf = $conf -replace '# server_tokens off;', 'server_tokens off;'\nSet-Content 'C:\\nginx\\conf\\nginx.conf' $conf\nnginx.exe -t && nginx.exe -s reload",
                "command_macos": "sudo sed -i '' 's/# server_tokens off;/server_tokens off;/' /usr/local/etc/nginx/nginx.conf\nnginx -t && brew services restart nginx",
                "category": "workaround",
            },
            {
                "title": "Update Nginx to Latest Stable Release",
                "description": "Upgrade Nginx to patch HTTP/2 rapid reset, buffer overflow, and request smuggling CVEs.",
                "command_linux": "sudo apt update && sudo apt install --only-upgrade nginx -y\nsudo dnf upgrade nginx -y 2>/dev/null\nnginx -v",
                "command_windows": "winget upgrade --name 'Nginx' --accept-package-agreements",
                "command_macos": "brew update && brew upgrade nginx && nginx -v",
                "category": "patch",
            },
            {
                "title": "Verify Nginx Security Configuration",
                "description": "Validate config, test response headers, and confirm no version disclosure.",
                "command_linux": "sudo nginx -t\ncurl -sI http://127.0.0.1 | grep -iE 'server:|x-frame-options:|strict-transport|x-content-type'\nsudo systemctl status nginx --no-pager",
                "command_windows": "nginx.exe -t\ncurl.exe -sI http://localhost | Select-String 'Server:','X-Frame-Options:'",
                "command_macos": "nginx -t\ncurl -sI http://127.0.0.1 | grep -iE 'server:|x-frame-options:|strict-transport'",
                "category": "verify",
            },
        ],
    },
    "mysql": {
        "summary": "Secure MySQL/MariaDB against unauthorized remote access, privilege escalation, and data exfiltration by enforcing localhost binding, removing anonymous users, requiring encrypted connections.",
        "steps": [
            {
                "title": "Bind to Localhost & Remove Dangerous Defaults",
                "description": "Force MySQL to listen on 127.0.0.1, remove anonymous users, drop test DB, disable LOCAL INFILE.",
                "command_linux": "sudo cp /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/mysql.conf.d/mysqld.cnf.bak 2>/dev/null\nsudo sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/mysql.conf.d/mysqld.cnf 2>/dev/null\necho '[mysqld]' | sudo tee -a /etc/mysql/conf.d/security.cnf\necho 'local-infile = 0' | sudo tee -a /etc/mysql/conf.d/security.cnf\necho 'symbolic-links = 0' | sudo tee -a /etc/mysql/conf.d/security.cnf\nsudo mysql -e \"DELETE FROM mysql.user WHERE User=''; DROP DATABASE IF EXISTS test; FLUSH PRIVILEGES;\"\nsudo systemctl restart mysql",
                "command_windows": "$ini = 'C:\\ProgramData\\MySQL\\MySQL Server 8.0\\my.ini'\n(Get-Content $ini) -replace '^bind-address.*', 'bind-address = 127.0.0.1' | Set-Content $ini\nAdd-Content $ini 'local-infile = 0'\nRestart-Service MySQL80",
                "command_macos": "sudo sed -i '' 's/^bind-address.*/bind-address = 127.0.0.1/' /usr/local/etc/my.cnf\necho 'local-infile = 0' | sudo tee -a /usr/local/etc/my.cnf\nmysql -u root -e \"DELETE FROM mysql.user WHERE User=''; DROP DATABASE IF EXISTS test; FLUSH PRIVILEGES;\"\nbrew services restart mysql",
                "category": "workaround",
            },
            {
                "title": "Update MySQL/MariaDB to Latest Patched Release",
                "description": "Upgrade database server to resolve privilege escalation, buffer overflow, and auth bypass CVEs.",
                "command_linux": "sudo apt update && sudo apt install --only-upgrade mysql-server -y\nsudo dnf upgrade mysql-server -y 2>/dev/null || sudo dnf upgrade mariadb-server -y\nmysql --version",
                "command_windows": "winget upgrade --name 'MySQL' --accept-package-agreements\nmysql --version",
                "command_macos": "brew update && brew upgrade mysql && mysql --version",
                "category": "patch",
            },
            {
                "title": "Block Remote Access to Port 3306",
                "description": "Firewall rule to deny all external connections to MySQL port 3306.",
                "command_linux": "sudo ufw deny from any to any port 3306 proto tcp comment 'Block external MySQL'\nsudo ufw allow from 127.0.0.1 to any port 3306 proto tcp comment 'Allow localhost MySQL'",
                "command_windows": "New-NetFirewallRule -Name 'Block-MySQL-External' -DisplayName 'Block External MySQL 3306' -Direction Inbound -Protocol TCP -LocalPort 3306 -Action Block -Profile Public,Private\nNew-NetFirewallRule -Name 'Allow-MySQL-Local' -DisplayName 'Allow Localhost MySQL' -Direction Inbound -Protocol TCP -LocalPort 3306 -RemoteAddress 127.0.0.1 -Action Allow",
                "command_macos": "echo 'block in proto tcp from any to any port 3306' | sudo tee -a /etc/pf.anchors/mysql\necho 'pass in proto tcp from 127.0.0.1 to any port 3306' | sudo tee -a /etc/pf.anchors/mysql\nsudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Run mysql_secure_installation & Verify Security",
                "description": "Execute MySQL security hardening wizard and verify the database is not exposed externally.",
                "command_linux": "sudo mysql_secure_installation\nsudo ss -tlnp | grep 3306\nsudo mysql -e \"SELECT User, Host FROM mysql.user WHERE User='' OR (User='root' AND Host != 'localhost');\"",
                "command_windows": "mysql_secure_installation.exe\nnetstat -an | findstr ':3306'\nmysql -u root -e \"SELECT User, Host FROM mysql.user;\"",
                "command_macos": "mysql_secure_installation\nsudo lsof -iTCP:3306 -sTCP:LISTEN\nmysql -u root -e \"SELECT User, Host FROM mysql.user;\"",
                "category": "verify",
            },
        ],
    },
    "redis": {
        "summary": "Secure Redis against unauthenticated remote code execution by binding to loopback, setting a strong password, disabling dangerous commands, and enabling protected mode.",
        "steps": [
            {
                "title": "Bind to Localhost, Enable Protected Mode & Set Authentication",
                "description": "Restrict Redis to 127.0.0.1, enable protected-mode, set requirepass, and disable dangerous commands (FLUSHALL, CONFIG, EVAL).",
                "command_linux": "sudo cp /etc/redis/redis.conf /etc/redis/redis.conf.bak.$(date +%s)\nsudo sed -i 's/^bind.*/bind 127.0.0.1 ::1/' /etc/redis/redis.conf\nsudo sed -i 's/^protected-mode.*/protected-mode yes/' /etc/redis/redis.conf\nsudo sed -i 's/^# requirepass.*/requirepass YOUR_STRONG_PASSWORD_HERE/' /etc/redis/redis.conf\necho 'rename-command FLUSHDB \"\"' | sudo tee -a /etc/redis/redis.conf\necho 'rename-command FLUSHALL \"\"' | sudo tee -a /etc/redis/redis.conf\necho 'rename-command CONFIG \"\"' | sudo tee -a /etc/redis/redis.conf\necho 'rename-command DEBUG \"\"' | sudo tee -a /etc/redis/redis.conf\nsudo systemctl restart redis-server",
                "command_windows": "(Get-Content redis.windows.conf) -replace '^bind.*', 'bind 127.0.0.1' | Set-Content redis.windows.conf\nAdd-Content redis.windows.conf 'requirepass YOUR_STRONG_PASSWORD_HERE'\nAdd-Content redis.windows.conf 'rename-command FLUSHDB \"\"'\nRestart-Service redis",
                "command_macos": "sudo sed -i '' 's/^bind.*/bind 127.0.0.1 ::1/' /usr/local/etc/redis.conf\nsudo sed -i '' 's/^protected-mode.*/protected-mode yes/' /usr/local/etc/redis.conf\nsudo sed -i '' 's/^# requirepass.*/requirepass YOUR_STRONG_PASSWORD_HERE/' /usr/local/etc/redis.conf\nbrew services restart redis",
                "category": "workaround",
            },
            {
                "title": "Update Redis Server to Latest Release",
                "description": "Upgrade Redis to patch Lua sandbox escapes, heap overflow, and integer overflow CVEs.",
                "command_linux": "sudo apt update && sudo apt install --only-upgrade redis-server -y\nredis-server --version",
                "command_windows": "winget upgrade --name 'Redis' --accept-package-agreements",
                "command_macos": "brew update && brew upgrade redis && redis-server --version",
                "category": "patch",
            },
            {
                "title": "Block External Access to Port 6379",
                "description": "Firewall rules to prevent any external connection to Redis.",
                "command_linux": "sudo ufw deny from any to any port 6379 proto tcp comment 'Block external Redis'\nsudo ufw allow from 127.0.0.1 to any port 6379 proto tcp",
                "command_windows": "New-NetFirewallRule -Name 'Block-Redis-External' -DisplayName 'Block External Redis 6379' -Direction Inbound -Protocol TCP -LocalPort 6379 -Action Block -Profile Public,Private",
                "command_macos": "echo 'block in proto tcp from any to any port 6379' | sudo tee -a /etc/pf.anchors/redis\nsudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify Redis Security",
                "description": "Confirm Redis is bound to localhost, authentication is required, and dangerous commands are disabled.",
                "command_linux": "redis-cli ping 2>&1\nsudo ss -tlnp | grep 6379\nredis-cli -a YOUR_STRONG_PASSWORD_HERE INFO server | grep -E 'redis_version|tcp_port|bind'",
                "command_windows": "redis-cli.exe ping\nnetstat -an | findstr ':6379'",
                "command_macos": "redis-cli ping\nsudo lsof -iTCP:6379 -sTCP:LISTEN",
                "category": "verify",
            },
        ],
    },
    "smb": {
        "summary": "Remediate SMB vulnerabilities (EternalBlue, SMBGhost, PrintNightmare) by disabling SMBv1, enforcing SMB signing, requiring encryption, and applying critical OS patches.",
        "steps": [
            {
                "title": "Disable SMBv1 & Enforce SMB Signing and Encryption",
                "description": "Completely disable insecure SMBv1 protocol, require SMB signing to prevent relay attacks, enforce SMB3 encryption.",
                "command_linux": "sudo sed -i '/\\[global\\]/a \\   server min protocol = SMB2_02' /etc/samba/smb.conf\nsudo sed -i '/\\[global\\]/a \\   client min protocol = SMB2_02' /etc/samba/smb.conf\nsudo sed -i '/\\[global\\]/a \\   server signing = mandatory' /etc/samba/smb.conf\nsudo sed -i '/\\[global\\]/a \\   smb encrypt = required' /etc/samba/smb.conf\nsudo testparm -s 2>/dev/null | head -20\nsudo systemctl restart smbd nmbd",
                "command_windows": "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\nDisable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart\nSet-SmbServerConfiguration -RequireSecuritySignature $true -Force\nSet-SmbClientConfiguration -RequireSecuritySignature $true -Force\nSet-SmbServerConfiguration -EncryptData $true -Force\nSet-SmbServerConfiguration -RejectUnencryptedAccess $true -Force",
                "command_macos": "sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist\necho '[default]' | sudo tee /etc/nsmb.conf\necho 'smb_neg=smb2_only' | sudo tee -a /etc/nsmb.conf\necho 'signing_required=yes' | sudo tee -a /etc/nsmb.conf",
                "category": "workaround",
            },
            {
                "title": "Apply Critical OS Security Patches",
                "description": "Install OS security updates targeting EternalBlue (MS17-010) and SMBGhost (CVE-2020-0796).",
                "command_linux": "sudo apt update && sudo apt install --only-upgrade samba samba-common smbclient -y\nsmbd --version",
                "command_windows": "Install-Module PSWindowsUpdate -Force -Scope CurrentUser\nImport-Module PSWindowsUpdate\nGet-WindowsUpdate -AcceptAll -Install -AutoReboot",
                "command_macos": "softwareupdate -i -a",
                "category": "patch",
            },
            {
                "title": "Block Internet Access to SMB Ports 139 & 445",
                "description": "SMB should never be exposed to the internet.",
                "command_linux": "sudo ufw deny from any to any port 445 proto tcp comment 'Block external SMB'\nsudo ufw deny from any to any port 139 proto tcp\nsudo ufw allow from 192.168.0.0/16 to any port 445 proto tcp comment 'LAN SMB'",
                "command_windows": "New-NetFirewallRule -Name 'Block-SMB-Public' -DisplayName 'Block Public SMB' -Direction Inbound -Protocol TCP -LocalPort 139,445 -Action Block -Profile Public",
                "command_macos": "echo 'block in proto tcp from any to any port {139, 445}' | sudo tee -a /etc/pf.anchors/smb\nsudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify SMB Security Configuration",
                "description": "Confirm SMBv1 is disabled, signing is enforced, and encryption is active.",
                "command_linux": "testparm -s 2>/dev/null | grep -iE 'min protocol|signing|encrypt'\nsudo ss -tlnp | grep -E ':445|:139'",
                "command_windows": "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, EncryptData, RejectUnencryptedAccess\nnetstat -an | findstr ':445'",
                "command_macos": "smbutil statshares -a 2>/dev/null; sudo lsof -iTCP:445",
                "category": "verify",
            },
        ],
    },
    "ftp": {
        "summary": "Secure FTP by disabling anonymous access, enforcing FTPS (TLS), chrooting users, and restricting passive port ranges.",
        "steps": [
            {
                "title": "Disable Anonymous Access & Enforce FTPS Encryption",
                "description": "Disable anonymous FTP, require TLS encryption, and chroot users to home directories.",
                "command_linux": "sudo sed -i 's/^anonymous_enable=.*/anonymous_enable=NO/' /etc/vsftpd.conf\necho 'ssl_enable=YES' | sudo tee -a /etc/vsftpd.conf\necho 'force_local_data_ssl=YES' | sudo tee -a /etc/vsftpd.conf\necho 'force_local_logins_ssl=YES' | sudo tee -a /etc/vsftpd.conf\necho 'ssl_tlsv1_2=YES' | sudo tee -a /etc/vsftpd.conf\nsudo sed -i 's/^#\\?chroot_local_user=.*/chroot_local_user=YES/' /etc/vsftpd.conf\necho 'pasv_min_port=50000' | sudo tee -a /etc/vsftpd.conf\necho 'pasv_max_port=50100' | sudo tee -a /etc/vsftpd.conf\nsudo systemctl restart vsftpd",
                "command_windows": "Import-Module WebAdministration\nSet-ItemProperty 'IIS:\\Sites\\Default FTP Site' -Name ftpServer.security.ssl.controlChannelPolicy -Value 'SslRequire'\nSet-ItemProperty 'IIS:\\Sites\\Default FTP Site' -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $false",
                "command_macos": "sudo launchctl unload -w /System/Library/LaunchDaemons/ftp.plist 2>/dev/null\n# Consider switching to SFTP instead of FTP",
                "category": "workaround",
            },
            {
                "title": "Update FTP Server Package",
                "description": "Upgrade vsftpd/ProFTPD to the latest security release.",
                "command_linux": "sudo apt update && sudo apt install --only-upgrade vsftpd -y\nsudo dnf upgrade vsftpd -y 2>/dev/null",
                "command_windows": "winget upgrade --name 'FileZilla Server' --accept-package-agreements 2>$null",
                "command_macos": "brew update && brew upgrade pure-ftpd 2>/dev/null",
                "category": "patch",
            },
            {
                "title": "Verify FTP Security",
                "description": "Confirm anonymous login is blocked and TLS is enforced.",
                "command_linux": "curl -v ftp://127.0.0.1 --user anonymous:test 2>&1 | head -10\ngrep -iE 'anonymous|ssl_enable|chroot|pasv' /etc/vsftpd.conf\nsudo systemctl status vsftpd --no-pager",
                "command_windows": "netstat -an | findstr ':21'",
                "command_macos": "sudo lsof -iTCP:21 -sTCP:LISTEN",
                "category": "verify",
            },
        ],
    },
    "postgresql": {
        "summary": "Harden PostgreSQL by restricting pg_hba.conf, enforcing SSL, disabling superuser remote access, and enabling query audit logging.",
        "steps": [
            {
                "title": "Restrict Client Authentication & Bind Localhost",
                "description": "Configure pg_hba.conf for scram-sha-256 auth, bind to localhost, enable SSL, and audit logging.",
                "command_linux": "sudo -u postgres psql -c \"ALTER SYSTEM SET listen_addresses = 'localhost';\"\nsudo -u postgres psql -c \"ALTER SYSTEM SET password_encryption = 'scram-sha-256';\"\nsudo -u postgres psql -c \"ALTER SYSTEM SET ssl = 'on';\"\nsudo -u postgres psql -c \"ALTER SYSTEM SET log_connections = 'on';\"\nsudo -u postgres psql -c \"ALTER SYSTEM SET log_disconnections = 'on';\"\nsudo systemctl restart postgresql",
                "command_windows": "$conf = 'C:\\Program Files\\PostgreSQL\\15\\data\\postgresql.conf'\n(Get-Content $conf) -replace \"#listen_addresses.*\", \"listen_addresses = 'localhost'\" | Set-Content $conf\nRestart-Service postgresql-x64-15",
                "command_macos": "psql -U postgres -c \"ALTER SYSTEM SET listen_addresses = 'localhost';\"\npsql -U postgres -c \"ALTER SYSTEM SET ssl = 'on';\"\nbrew services restart postgresql",
                "category": "workaround",
            },
            {
                "title": "Update PostgreSQL",
                "description": "Upgrade PostgreSQL to patch SQL injection and privilege escalation CVEs.",
                "command_linux": "sudo apt update && sudo apt install --only-upgrade postgresql -y\nsudo -u postgres psql -c 'SELECT version();'",
                "command_windows": "winget upgrade --name 'PostgreSQL' --accept-package-agreements",
                "command_macos": "brew update && brew upgrade postgresql && psql --version",
                "category": "patch",
            },
            {
                "title": "Block External Access to Port 5432",
                "description": "Firewall rules to prevent external PostgreSQL connections.",
                "command_linux": "sudo ufw deny from any to any port 5432 proto tcp comment 'Block external PostgreSQL'\nsudo ufw allow from 127.0.0.1 to any port 5432 proto tcp",
                "command_windows": "New-NetFirewallRule -Name 'Block-PG-External' -DisplayName 'Block External PostgreSQL' -Direction Inbound -Protocol TCP -LocalPort 5432 -Action Block -Profile Public",
                "command_macos": "echo 'block in proto tcp from any to any port 5432' | sudo tee -a /etc/pf.anchors/postgresql\nsudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify PostgreSQL Security",
                "description": "Check listening address, SSL status, authentication method, and user privileges.",
                "command_linux": "sudo -u postgres psql -c \"SHOW listen_addresses; SHOW ssl; SHOW password_encryption;\"\nsudo ss -tlnp | grep 5432",
                "command_windows": "netstat -an | findstr ':5432'\npsql -U postgres -c 'SHOW ssl;'",
                "command_macos": "psql -U postgres -c 'SHOW listen_addresses; SHOW ssl;'\nsudo lsof -iTCP:5432 -sTCP:LISTEN",
                "category": "verify",
            },
        ],
    },
    "mongodb": {
        "summary": "Secure MongoDB against unauthenticated database access by enabling authentication, binding to localhost, and deploying role-based access control.",
        "steps": [
            {
                "title": "Enable Authentication & Bind to Localhost",
                "description": "By default MongoDB has NO authentication. Enable it, create an admin user, and bind to 127.0.0.1.",
                "command_linux": "mongosh --eval 'use admin; db.createUser({user:\"admin\", pwd:\"CHANGE_THIS_STRONG_PASSWORD\", roles:[\"root\"]})'\nsudo sed -i 's/^#\\?  bindIp:.*/  bindIp: 127.0.0.1/' /etc/mongod.conf\nsudo sed -i '/^#security:/c\\security:\\n  authorization: enabled' /etc/mongod.conf\nsudo systemctl restart mongod",
                "command_windows": "mongosh --eval \"use admin; db.createUser({user:'admin', pwd:'CHANGE_THIS_STRONG_PASSWORD', roles:['root']})\"\n$cfg = 'C:\\Program Files\\MongoDB\\Server\\7.0\\bin\\mongod.cfg'\n(Get-Content $cfg) -replace 'bindIp:.*', 'bindIp: 127.0.0.1' | Set-Content $cfg\nRestart-Service MongoDB",
                "command_macos": "mongosh --eval 'use admin; db.createUser({user:\"admin\", pwd:\"CHANGE_THIS_STRONG_PASSWORD\", roles:[\"root\"]})'\nsudo sed -i '' 's/bindIp:.*/bindIp: 127.0.0.1/' /usr/local/etc/mongod.conf\nbrew services restart mongodb-community",
                "category": "workaround",
            },
            {
                "title": "Update MongoDB",
                "description": "Upgrade MongoDB to patch privilege escalation and auth bypass CVEs.",
                "command_linux": "sudo apt update && sudo apt install --only-upgrade mongodb-org -y\nmongod --version",
                "command_windows": "winget upgrade --name 'MongoDB' --accept-package-agreements",
                "command_macos": "brew update && brew upgrade mongodb-community && mongod --version",
                "category": "patch",
            },
            {
                "title": "Block External Access to Port 27017",
                "description": "MongoDB should never be exposed to the internet.",
                "command_linux": "sudo ufw deny from any to any port 27017 proto tcp comment 'Block external MongoDB'\nsudo ufw deny from any to any port 27018 proto tcp\nsudo ufw deny from any to any port 28017 proto tcp",
                "command_windows": "New-NetFirewallRule -Name 'Block-MongoDB' -DisplayName 'Block External MongoDB' -Direction Inbound -Protocol TCP -LocalPort 27017,27018,28017 -Action Block -Profile Public",
                "command_macos": "echo 'block in proto tcp from any to any port {27017, 27018, 28017}' | sudo tee -a /etc/pf.anchors/mongodb\nsudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify MongoDB Security",
                "description": "Confirm authentication is required and no anonymous access is possible.",
                "command_linux": "mongosh --eval 'db.adminCommand({listDatabases:1})' 2>&1 | head -5\nsudo ss -tlnp | grep 27017",
                "command_windows": "mongosh --eval 'db.adminCommand({listDatabases:1})' 2>&1\nnetstat -an | findstr ':27017'",
                "command_macos": "mongosh --eval 'db.adminCommand({listDatabases:1})' 2>&1\nsudo lsof -iTCP:27017 -sTCP:LISTEN",
                "category": "verify",
            },
        ],
    },
    "elasticsearch": {
        "summary": "Secure Elasticsearch against unauthenticated data access by enabling X-Pack security, HTTPS, binding to localhost, and RBAC.",
        "steps": [
            {
                "title": "Enable Security Module & Bind to Localhost",
                "description": "Enable X-Pack security, set up passwords, and restrict network binding.",
                "command_linux": "echo 'xpack.security.enabled: true' | sudo tee -a /etc/elasticsearch/elasticsearch.yml\necho 'xpack.security.transport.ssl.enabled: true' | sudo tee -a /etc/elasticsearch/elasticsearch.yml\necho 'network.host: 127.0.0.1' | sudo tee -a /etc/elasticsearch/elasticsearch.yml\nsudo systemctl restart elasticsearch\nsudo /usr/share/elasticsearch/bin/elasticsearch-setup-passwords interactive",
                "command_windows": "Add-Content 'C:\\elasticsearch\\config\\elasticsearch.yml' 'xpack.security.enabled: true'\nAdd-Content 'C:\\elasticsearch\\config\\elasticsearch.yml' 'network.host: 127.0.0.1'\nRestart-Service elasticsearch",
                "command_macos": "echo 'xpack.security.enabled: true' >> /usr/local/etc/elasticsearch/elasticsearch.yml\necho 'network.host: 127.0.0.1' >> /usr/local/etc/elasticsearch/elasticsearch.yml\nbrew services restart elasticsearch",
                "category": "workaround",
            },
            {
                "title": "Block External Access to Ports 9200/9300",
                "description": "Elasticsearch HTTP and transport ports must never be exposed externally.",
                "command_linux": "sudo ufw deny from any to any port 9200 proto tcp\nsudo ufw deny from any to any port 9300 proto tcp",
                "command_windows": "New-NetFirewallRule -Name 'Block-ES' -DisplayName 'Block External Elasticsearch' -Direction Inbound -Protocol TCP -LocalPort 9200,9300 -Action Block -Profile Public",
                "command_macos": "echo 'block in proto tcp from any to any port {9200, 9300}' | sudo tee -a /etc/pf.anchors/es\nsudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify Elasticsearch Security",
                "description": "Confirm auth is required and no anonymous access is possible.",
                "command_linux": "curl -s http://127.0.0.1:9200 | head -10\nsudo ss -tlnp | grep -E '9200|9300'",
                "command_windows": "curl.exe http://localhost:9200; netstat -an | findstr ':9200'",
                "command_macos": "curl -s http://127.0.0.1:9200; sudo lsof -iTCP:9200",
                "category": "verify",
            },
        ],
    },
    "rdp": {
        "summary": "Secure RDP against BlueKeep, brute-force attacks, and MITM by enabling NLA, enforcing TLS, and restricting access via VPN.",
        "steps": [
            {
                "title": "Enable Network Level Authentication (NLA) & Enforce TLS",
                "description": "Require NLA for all RDP connections to prevent unauthenticated exploitation (BlueKeep CVE-2019-0708).",
                "command_linux": "sudo sed -i 's/^security_layer=.*/security_layer=tls/' /etc/xrdp/xrdp.ini\nsudo sed -i 's/^ssl_protocols=.*/ssl_protocols=TLSv1.2, TLSv1.3/' /etc/xrdp/xrdp.ini\nsudo systemctl restart xrdp",
                "command_windows": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name SecurityLayer -Value 2\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name MinEncryptionLevel -Value 3\nnet accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30",
                "command_macos": "# RDP is a Windows service. macOS uses ARD instead.",
                "category": "workaround",
            },
            {
                "title": "Restrict RDP Access to Trusted Networks",
                "description": "RDP (port 3389) should never be exposed to the internet. Use VPN for remote access.",
                "command_linux": "sudo ufw deny from any to any port 3389 proto tcp\nsudo ufw allow from 10.0.0.0/8 to any port 3389 proto tcp comment 'RDP management'",
                "command_windows": "New-NetFirewallRule -Name 'RDP-Block-Public' -DisplayName 'Block Public RDP' -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block -Profile Public\nNew-NetFirewallRule -Name 'RDP-Mgmt' -DisplayName 'RDP Management Access' -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress 10.0.0.0/8 -Action Allow",
                "command_macos": "echo 'block in proto tcp from any to any port 3389' | sudo tee -a /etc/pf.anchors/rdp\nsudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify RDP Security",
                "description": "Confirm NLA is enabled, TLS is enforced, and RDP is not exposed publicly.",
                "command_linux": "grep -iE 'security_layer|ssl_protocols' /etc/xrdp/xrdp.ini\nsudo ss -tlnp | grep 3389",
                "command_windows": "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' | Select-Object UserAuthentication, SecurityLayer, MinEncryptionLevel\nnetstat -an | findstr ':3389'\nnet accounts",
                "command_macos": "sudo lsof -iTCP:3389 -sTCP:LISTEN 2>/dev/null || echo 'RDP not running'",
                "category": "verify",
            },
        ],
    },
    "telnet": {
        "summary": "Telnet transmits all data including passwords in CLEARTEXT. The only real remediation is to disable telnet entirely and migrate to SSH.",
        "steps": [
            {
                "title": "CRITICAL: Disable Telnet Service Immediately",
                "description": "Telnet sends credentials in plaintext. Disable and replace with SSH.",
                "command_linux": "sudo systemctl stop telnet.socket xinetd 2>/dev/null\nsudo systemctl disable telnet.socket xinetd 2>/dev/null\nsudo systemctl mask telnet.socket 2>/dev/null\nsudo apt purge -y telnetd inetutils-telnetd 2>/dev/null\nsudo dnf remove -y telnet-server 2>/dev/null\nsudo apt install -y openssh-server 2>/dev/null || sudo dnf install -y openssh-server 2>/dev/null\nsudo systemctl enable --now sshd",
                "command_windows": "Disable-WindowsOptionalFeature -Online -FeatureName TelnetServer -NoRestart\nStop-Service TlntSvr -ErrorAction SilentlyContinue\nSet-Service TlntSvr -StartupType Disabled -ErrorAction SilentlyContinue\nAdd-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0\nStart-Service sshd\nSet-Service sshd -StartupType Automatic",
                "command_macos": "sudo launchctl unload -w /System/Library/LaunchDaemons/telnet.plist 2>/dev/null\nsudo systemsetup -setremotelogin on",
                "category": "workaround",
            },
            {
                "title": "Block Telnet Port 23",
                "description": "Block all inbound traffic on port 23.",
                "command_linux": "sudo ufw deny 23/tcp comment 'Block Telnet' && sudo ufw reload",
                "command_windows": "New-NetFirewallRule -Name 'Block-Telnet' -DisplayName 'Block Telnet Port 23' -Direction Inbound -Protocol TCP -LocalPort 23 -Action Block",
                "command_macos": "echo 'block in proto tcp from any to any port 23' | sudo tee -a /etc/pf.anchors/telnet\nsudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify Telnet is Disabled",
                "description": "Confirm telnet is not running and port 23 is closed.",
                "command_linux": "sudo ss -tlnp | grep :23\nsudo ss -tlnp | grep :22",
                "command_windows": "Get-Service TlntSvr -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType\nnetstat -an | findstr ':23'\nGet-Service sshd | Select-Object Name, Status",
                "command_macos": "sudo lsof -iTCP:23 -sTCP:LISTEN 2>/dev/null || echo 'Telnet not running'",
                "category": "verify",
            },
        ],
    },
    "smtp": {
        "summary": "Harden SMTP by enforcing STARTTLS, restricting open relay, deploying SPF/DKIM/DMARC, and suppressing version banners.",
        "steps": [
            {
                "title": "Disable Open Relay & Enforce STARTTLS",
                "description": "Prevent open relay for spam, require TLS encryption, suppress version banner.",
                "command_linux": "sudo postconf -e 'smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination'\nsudo postconf -e 'smtpd_tls_security_level = may'\nsudo postconf -e 'smtp_tls_security_level = may'\nsudo postconf -e 'smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'\nsudo postconf -e 'smtpd_banner = $myhostname ESMTP'\nsudo systemctl reload postfix",
                "command_windows": "Set-ReceiveConnector -Identity 'Default Frontend' -RequireTLS $true",
                "command_macos": "sudo postconf -e 'smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination'\nsudo postconf -e 'smtpd_tls_security_level = may'\nsudo postfix reload",
                "category": "workaround",
            },
            {
                "title": "Update Mail Server",
                "description": "Upgrade Postfix/Sendmail/Exim to the latest patched release.",
                "command_linux": "sudo apt update && sudo apt install --only-upgrade postfix -y\npostconf mail_version",
                "command_windows": "Get-WindowsUpdate -AcceptAll -Install",
                "command_macos": "brew update && brew upgrade postfix 2>/dev/null",
                "category": "patch",
            },
            {
                "title": "Verify SMTP Security",
                "description": "Test for open relay and verify TLS is working.",
                "command_linux": "openssl s_client -starttls smtp -connect 127.0.0.1:25 </dev/null 2>&1 | grep -E 'Protocol|Cipher'\necho 'QUIT' | nc -w3 127.0.0.1 25 | head -1",
                "command_windows": "Test-NetConnection -ComputerName localhost -Port 25",
                "command_macos": "echo 'QUIT' | nc -w3 127.0.0.1 25 | head -1",
                "category": "verify",
            },
        ],
    },
    "dns": {
        "summary": "Harden DNS against cache poisoning, amplification attacks, and zone transfer leaks by restricting recursion, enabling DNSSEC, and rate-limiting.",
        "steps": [
            {
                "title": "Restrict Recursion & Disable Zone Transfers",
                "description": "Limit recursive queries to internal networks, disable zone transfers, hide version.",
                "command_linux": "# BIND: Edit /etc/bind/named.conf.options\n# Set: allow-recursion { 127.0.0.1; 10.0.0.0/8; };\n# Set: allow-transfer { none; };\n# Set: version \"not disclosed\";\nsudo named-checkconf && sudo systemctl reload named 2>/dev/null || sudo systemctl reload bind9",
                "command_windows": "Set-DnsServerRecursion -Enable $true -SecureResponse $true\nSet-DnsServerResponseRateLimiting -Mode Enable -ResponsesPerSec 10",
                "command_macos": "echo 'no-resolv' | sudo tee -a /usr/local/etc/dnsmasq.conf\nbrew services restart dnsmasq",
                "category": "workaround",
            },
            {
                "title": "Verify DNS Security",
                "description": "Confirm recursion is restricted and version is hidden.",
                "command_linux": "dig @127.0.0.1 version.bind chaos txt +short\nsudo ss -ulnp | grep :53",
                "command_windows": "nslookup -type=txt -class=chaos version.bind 127.0.0.1",
                "command_macos": "dig @127.0.0.1 version.bind chaos txt +short",
                "category": "verify",
            },
        ],
    },
    "snmp": {
        "summary": "Secure SNMP by disabling SNMPv1/v2c, migrating to SNMPv3 with authPriv, and changing default community strings.",
        "steps": [
            {
                "title": "Disable SNMPv1/v2c & Migrate to SNMPv3",
                "description": "SNMPv1/v2c uses cleartext. Migrate to SNMPv3 with authentication + encryption.",
                "command_linux": "sudo systemctl stop snmpd\nsudo sed -i '/^rocommunity.*public/d' /etc/snmp/snmpd.conf\nsudo sed -i '/^rwcommunity.*private/d' /etc/snmp/snmpd.conf\nsudo net-snmp-create-v3-user -ro -A STRONG_AUTH_PASS -X STRONG_PRIV_PASS -a SHA -x AES snmpv3user\nsudo systemctl start snmpd",
                "command_windows": "Stop-Service SNMP -ErrorAction SilentlyContinue\nSet-Service SNMP -StartupType Disabled",
                "command_macos": "sudo launchctl unload -w /System/Library/LaunchDaemons/org.net-snmp.snmpd.plist 2>/dev/null",
                "category": "workaround",
            },
            {
                "title": "Block External SNMP Access (Port 161/162)",
                "description": "SNMP should only be accessible from management networks.",
                "command_linux": "sudo ufw deny from any to any port 161 proto udp\nsudo ufw deny from any to any port 162 proto udp\nsudo ufw allow from 10.0.0.0/8 to any port 161 proto udp comment 'SNMP management'",
                "command_windows": "New-NetFirewallRule -Name 'Block-SNMP' -DisplayName 'Block External SNMP' -Direction Inbound -Protocol UDP -LocalPort 161,162 -Action Block -Profile Public",
                "command_macos": "echo 'block in proto udp from any to any port {161, 162}' | sudo tee -a /etc/pf.anchors/snmp\nsudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify SNMP Security",
                "description": "Confirm default community strings are removed.",
                "command_linux": "snmpwalk -v2c -c public 127.0.0.1 2>&1 | head -3\nsudo ss -ulnp | grep :161",
                "command_windows": "Get-Service SNMP | Select-Object Name, Status, StartType",
                "command_macos": "sudo lsof -iUDP:161 2>/dev/null || echo 'SNMP not running'",
                "category": "verify",
            },
        ],
    },
    "vnc": {
        "summary": "Secure VNC against unauthenticated remote access by enforcing password protection, tunneling over SSH, and restricting network access.",
        "steps": [
            {
                "title": "Set Strong VNC Password & Bind to Localhost (SSH Tunnel)",
                "description": "VNC traffic is unencrypted by default. Set password and access via SSH tunnel only.",
                "command_linux": "vncpasswd\nvncserver -localhost yes -geometry 1280x1024\n# Connect via: ssh -L 5901:127.0.0.1:5901 user@server",
                "command_windows": "Set-ItemProperty 'HKLM:\\SOFTWARE\\TightVNC\\Server' -Name LoopbackOnly -Value 1 -Type DWord -ErrorAction SilentlyContinue",
                "command_macos": "sudo defaults write /Library/Preferences/com.apple.RemoteManagement.plist VNCAlwaysStartOnConsole -bool true",
                "category": "workaround",
            },
            {
                "title": "Block External VNC Access (Ports 5900-5910)",
                "description": "VNC should only be accessed through SSH tunnel or VPN.",
                "command_linux": "sudo ufw deny from any to any port 5900:5910 proto tcp comment 'Block external VNC'",
                "command_windows": "New-NetFirewallRule -Name 'Block-VNC' -DisplayName 'Block External VNC' -Direction Inbound -Protocol TCP -LocalPort 5900-5910 -Action Block -Profile Public",
                "command_macos": "echo 'block in proto tcp from any to any port 5900:5910' | sudo tee -a /etc/pf.anchors/vnc\nsudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify VNC Security",
                "description": "Confirm VNC is bound to localhost and requires auth.",
                "command_linux": "sudo ss -tlnp | grep -E ':590[0-9]'",
                "command_windows": "netstat -an | findstr ':5900'",
                "command_macos": "sudo lsof -iTCP:5900 -sTCP:LISTEN",
                "category": "verify",
            },
        ],
    },
    "memcached": {
        "summary": "Secure Memcached against DDoS amplification and unauthorized access by binding to localhost, disabling UDP, and enabling SASL.",
        "steps": [
            {
                "title": "Bind to Localhost & Disable UDP (Prevents DDoS Amplification)",
                "description": "Memcached UDP amplification caused 1.7 Tbps DDoS attacks. Disable UDP immediately.",
                "command_linux": "sudo sed -i 's/^-l.*/-l 127.0.0.1/' /etc/memcached.conf\necho '-U 0' | sudo tee -a /etc/memcached.conf\necho '-S' | sudo tee -a /etc/memcached.conf\nsudo systemctl restart memcached",
                "command_windows": "memcached.exe -l 127.0.0.1 -U 0",
                "command_macos": "echo '-l 127.0.0.1' | sudo tee -a /usr/local/etc/memcached.conf\necho '-U 0' | sudo tee -a /usr/local/etc/memcached.conf\nbrew services restart memcached",
                "category": "workaround",
            },
            {
                "title": "Block External Access to Port 11211",
                "description": "Memcached should never be exposed to the internet.",
                "command_linux": "sudo ufw deny from any to any port 11211 proto tcp\nsudo ufw deny from any to any port 11211 proto udp",
                "command_windows": "New-NetFirewallRule -Name 'Block-Memcached' -DisplayName 'Block External Memcached' -Direction Inbound -Protocol TCP -LocalPort 11211 -Action Block",
                "command_macos": "echo 'block in proto {tcp, udp} from any to any port 11211' | sudo tee -a /etc/pf.anchors/memcached\nsudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify Memcached Security",
                "description": "Confirm Memcached is bound to localhost and UDP is disabled.",
                "command_linux": "sudo ss -tlnp | grep 11211\nsudo ss -ulnp | grep 11211\necho 'stats' | nc 127.0.0.1 11211 | head -5",
                "command_windows": "netstat -an | findstr ':11211'",
                "command_macos": "sudo lsof -iTCP:11211 -sTCP:LISTEN",
                "category": "verify",
            },
        ],
    },
    "docker": {
        "summary": "Secure Docker daemon against container escape and unauthorized API access by enabling TLS, running rootless, and restricting capabilities.",
        "steps": [
            {
                "title": "Disable Unauthenticated Docker API & Harden Daemon",
                "description": "Docker TCP API without TLS allows full host control. Use Unix socket only.",
                "command_linux": "sudo tee /etc/docker/daemon.json << 'EOF'\n{\n  \"hosts\": [\"unix:///var/run/docker.sock\"],\n  \"userns-remap\": \"default\",\n  \"no-new-privileges\": true,\n  \"live-restore\": true,\n  \"log-driver\": \"json-file\",\n  \"log-opts\": {\"max-size\": \"10m\", \"max-file\": \"3\"}\n}\nEOF\nsudo systemctl restart docker",
                "command_windows": "Set-Content 'C:\\ProgramData\\docker\\config\\daemon.json' '{\"hosts\": [\"npipe://\"]}'\nRestart-Service docker",
                "command_macos": "# Docker Desktop: Disable 'Expose daemon' in Preferences > General",
                "category": "workaround",
            },
            {
                "title": "Block External Docker API Access",
                "description": "Block all external access to Docker daemon ports.",
                "command_linux": "sudo ufw deny from any to any port 2375 proto tcp\nsudo ufw deny from any to any port 2376 proto tcp",
                "command_windows": "New-NetFirewallRule -Name 'Block-Docker-API' -DisplayName 'Block External Docker' -Direction Inbound -Protocol TCP -LocalPort 2375,2376 -Action Block",
                "command_macos": "echo 'block in proto tcp from any to any port {2375, 2376}' | sudo tee -a /etc/pf.anchors/docker\nsudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify Docker Security",
                "description": "Confirm Docker API is not exposed and user namespace isolation is active.",
                "command_linux": "sudo ss -tlnp | grep -E ':2375|:2376'\ndocker info 2>/dev/null | grep -iE 'security|userns|rootless'",
                "command_windows": "docker info | Select-String 'Server Version','Security'",
                "command_macos": "docker info | grep -iE 'server version|security'",
                "category": "verify",
            },
        ],
    },
    "tomcat": {
        "summary": "Harden Tomcat against Ghostcat (CVE-2020-1938), manager console exposure, and AJP exploitation.",
        "steps": [
            {
                "title": "Disable AJP Connector & Remove Default Applications",
                "description": "AJP port 8009 is exploited by Ghostcat. Disable it and remove default webapps.",
                "command_linux": "sudo sed -i 's|<Connector port=\"8009\"|<!-- <Connector port=\"8009\"|' /etc/tomcat*/server.xml 2>/dev/null\nsudo rm -rf /var/lib/tomcat*/webapps/ROOT 2>/dev/null\nsudo rm -rf /var/lib/tomcat*/webapps/examples 2>/dev/null\nsudo rm -rf /var/lib/tomcat*/webapps/docs 2>/dev/null\necho 'server.info=' | sudo tee -a /etc/tomcat*/catalina.properties 2>/dev/null\nsudo systemctl restart tomcat* 2>/dev/null",
                "command_windows": "$xml = Get-Content 'C:\\Tomcat\\conf\\server.xml'\n$xml = $xml -replace '<Connector port=\"8009\"', '<!-- <Connector port=\"8009\"'\nSet-Content 'C:\\Tomcat\\conf\\server.xml' $xml\nRemove-Item 'C:\\Tomcat\\webapps\\ROOT' -Recurse -ErrorAction SilentlyContinue\nRemove-Item 'C:\\Tomcat\\webapps\\examples' -Recurse -ErrorAction SilentlyContinue\nRestart-Service Tomcat*",
                "command_macos": "sudo sed -i '' 's|<Connector port=\"8009\"|<!-- <Connector port=\"8009\"|' /usr/local/opt/tomcat/libexec/conf/server.xml\nbrew services restart tomcat",
                "category": "workaround",
            },
            {
                "title": "Verify Tomcat Security",
                "description": "Confirm AJP is disabled, default apps removed, no version disclosed.",
                "command_linux": "sudo ss -tlnp | grep 8009\ncurl -s http://127.0.0.1:8080/nonexistent 2>/dev/null | grep -i tomcat\nsudo ss -tlnp | grep 8080",
                "command_windows": "netstat -an | findstr ':8009'\nnetstat -an | findstr ':8080'",
                "command_macos": "sudo lsof -iTCP:8080 -sTCP:LISTEN; sudo lsof -iTCP:8009 -sTCP:LISTEN 2>/dev/null",
                "category": "verify",
            },
        ],
    },
    "iis": {
        "summary": "Harden IIS by removing server header, disabling WebDAV, enabling request filtering, and deploying HTTP security headers.",
        "steps": [
            {
                "title": "Remove Server Header & Deploy Security Headers",
                "description": "Hide IIS version, disable WebDAV, add security headers.",
                "command_linux": "# IIS is Windows-only",
                "command_windows": "Import-Module WebAdministration\nSet-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering' -name removeServerHeader -value True\nAdd-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/httpProtocol/customHeaders' -name '.' -value @{name='X-Content-Type-Options';value='nosniff'}\nAdd-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/httpProtocol/customHeaders' -name '.' -value @{name='X-Frame-Options';value='DENY'}\nAdd-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/httpProtocol/customHeaders' -name '.' -value @{name='Strict-Transport-Security';value='max-age=31536000; includeSubDomains'}\nRemove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/httpProtocol/customHeaders' -name '.' -AtElement @{name='X-Powered-By'} -ErrorAction SilentlyContinue\nDisable-WindowsOptionalFeature -Online -FeatureName IIS-WebDAV-Publishing -NoRestart\nSet-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/directoryBrowse' -name enabled -value $false",
                "command_macos": "# IIS is Windows-only",
                "category": "workaround",
            },
            {
                "title": "Apply Windows Security Updates",
                "description": "Install all pending security patches for IIS.",
                "command_linux": "# Not applicable",
                "command_windows": "Install-Module PSWindowsUpdate -Force -Scope CurrentUser\nImport-Module PSWindowsUpdate\nGet-WindowsUpdate -AcceptAll -Install",
                "command_macos": "# Not applicable",
                "category": "patch",
            },
            {
                "title": "Verify IIS Security",
                "description": "Confirm server header is removed and security headers are present.",
                "command_linux": "# Not applicable",
                "command_windows": "curl.exe -sI http://localhost | Select-String 'Server:','X-Frame-Options:','Strict-Transport-Security:'\nGet-WindowsOptionalFeature -Online -FeatureName IIS-WebDAV-Publishing | Select-Object State",
                "command_macos": "# Not applicable",
                "category": "verify",
            },
        ],
    },
    "unauth_redis": {
        "summary": "Secure Redis by enabling authentication, binding exclusively to localhost, and renaming or disabling dangerous administrative commands.",
        "steps": [
            {
                "title": "Enforce Strong Password & Bind to Localhost",
                "description": "Configure requirepass and bind 127.0.0.1 in redis.conf to prevent unauthorized network access.",
                "command_linux": "sudo sed -i 's/^#\\?bind .*/bind 127.0.0.1 -::1/' /etc/redis/redis.conf\nsudo sed -i 's/^#\\?protected-mode .*/protected-mode yes/' /etc/redis/redis.conf\necho 'requirepass $(openssl rand -hex 24)' | sudo tee -a /etc/redis/redis.conf\nsudo systemctl restart redis",
                "command_windows": "$conf = 'C:\\Program Files\\Redis\\redis.windows-service.conf'\nAdd-Content $conf \"`nbind 127.0.0.1\"\nAdd-Content $conf \"protected-mode yes\"\nAdd-Content $conf \"requirepass $([System.Guid]::NewGuid().ToString())\"\nRestart-Service redis",
                "command_macos": "echo 'bind 127.0.0.1' | sudo tee -a /usr/local/etc/redis.conf\necho 'requirepass $(openssl rand -hex 24)' | sudo tee -a /usr/local/etc/redis.conf\nbrew services restart redis",
                "category": "workaround",
            },
            {
                "title": "Firewall Isolation for Port 6379",
                "description": "Block inbound connections on Redis port 6379 from untrusted networks.",
                "command_linux": "sudo ufw deny from any to any port 6379 proto tcp\nsudo ufw reload",
                "command_windows": "New-NetFirewallRule -Name 'Block-Redis-External' -DisplayName 'Block External Redis' -Direction Inbound -Protocol TCP -LocalPort 6379 -Action Block",
                "command_macos": "echo 'block in proto tcp from any to any port 6379' | sudo tee -a /etc/pf.anchors/redis\nsudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify Redis Authentication",
                "description": "Confirm that unauthenticated commands are rejected with (error) NOAUTH.",
                "command_linux": "redis-cli PING",
                "command_windows": "redis-cli.exe PING",
                "command_macos": "redis-cli PING",
                "category": "verify",
            },
        ],
    },
    "unauth_mongodb": {
        "summary": "Secure MongoDB by enabling client authorization, binding to localhost, and setting strong administrative user credentials.",
        "steps": [
            {
                "title": "Enable Authorization and Restrict Network Interface",
                "description": "Enable security.authorization in mongod.conf and bind strictly to 127.0.0.1.",
                "command_linux": "sudo sed -i 's/^#\\?bindIp:.*/  bindIp: 127.0.0.1/' /etc/mongod.conf\nsudo tee -a /etc/mongod.conf << 'EOF'\nsecurity:\n  authorization: enabled\nEOF\nsudo systemctl restart mongod",
                "command_windows": "$conf = 'C:\\Program Files\\MongoDB\\Server\\bin\\mongod.cfg'\nAdd-Content $conf \"`nsecurity:`n  authorization: enabled\"\nRestart-Service MongoDB",
                "command_macos": "sudo sed -i '' 's/bindIp:.*/bindIp: 127.0.0.1/' /usr/local/etc/mongod.conf\nbrew services restart mongodb-community",
                "category": "workaround",
            },
            {
                "title": "Firewall Isolation for Port 27017",
                "description": "Block external incoming traffic on MongoDB port 27017.",
                "command_linux": "sudo ufw deny 27017/tcp\nsudo ufw reload",
                "command_windows": "New-NetFirewallRule -Name 'Block-Mongo-External' -DisplayName 'Block External MongoDB' -Direction Inbound -Protocol TCP -LocalPort 27017 -Action Block",
                "command_macos": "echo 'block in proto tcp from any to any port 27017' | sudo tee -a /etc/pf.anchors/mongo\nsudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify MongoDB Requires Authentication",
                "description": "Confirm unauthenticated database queries are rejected.",
                "command_linux": "mongosh --eval 'db.adminCommand({ ping: 1 })'",
                "command_windows": "mongosh.exe --eval 'db.adminCommand({ ping: 1 })'",
                "command_macos": "mongosh --eval 'db.adminCommand({ ping: 1 })'",
                "category": "verify",
            },
        ],
    },
    "unauth_memcached": {
        "summary": "Protect Memcached from public exploitation and UDP reflection amplification by binding to 127.0.0.1 and disabling UDP.",
        "steps": [
            {
                "title": "Bind to Localhost and Disable UDP",
                "description": "Set -l 127.0.0.1 and -U 0 in memcached configuration.",
                "command_linux": "sudo sed -i 's/^-l .*/-l 127.0.0.1/' /etc/memcached.conf\necho '-U 0' | sudo tee -a /etc/memcached.conf\nsudo systemctl restart memcached",
                "command_windows": "Stop-Service memcached -ErrorAction SilentlyContinue",
                "command_macos": "echo '-l 127.0.0.1' | sudo tee -a /usr/local/etc/memcached.conf\nbrew services restart memcached",
                "category": "workaround",
            },
            {
                "title": "Block Port 11211",
                "description": "Block inbound traffic on Memcached port 11211.",
                "command_linux": "sudo ufw deny 11211/tcp && sudo ufw deny 11211/udp",
                "command_windows": "New-NetFirewallRule -Name 'Block-Memcached' -DisplayName 'Block Memcached' -Direction Inbound -Protocol TCP -LocalPort 11211 -Action Block",
                "command_macos": "echo 'block in proto tcp from any to any port 11211' | sudo tee -a /etc/pf.anchors/memcached\nsudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify Memcached Isolation",
                "description": "Confirm Memcached only listens on localhost.",
                "command_linux": "sudo ss -tulpn | grep 11211",
                "command_windows": "netstat -an | findstr 11211",
                "command_macos": "sudo lsof -iTCP:11211 -sTCP:LISTEN",
                "category": "verify",
            },
        ],
    },
    "unauth_elasticsearch": {
        "summary": "Secure Elasticsearch cluster by enabling X-Pack security, setting strong built-in user passwords, and restricting network exposure.",
        "steps": [
            {
                "title": "Enable X-Pack Security",
                "description": "Set xpack.security.enabled: true in elasticsearch.yml and generate passwords.",
                "command_linux": "echo 'xpack.security.enabled: true' | sudo tee -a /etc/elasticsearch/elasticsearch.yml\nsudo systemctl restart elasticsearch\nsudo /usr/share/elasticsearch/bin/elasticsearch-setup-passwords auto",
                "command_windows": "Add-Content 'C:\\Program Files\\Elastic\\Elasticsearch\\config\\elasticsearch.yml' \"`nxpack.security.enabled: true\"\nRestart-Service elasticsearch",
                "command_macos": "echo 'xpack.security.enabled: true' | sudo tee -a /usr/local/etc/elasticsearch/elasticsearch.yml\nbrew services restart elasticsearch",
                "category": "workaround",
            },
            {
                "title": "Firewall Isolation for Port 9200",
                "description": "Block public exposure of Elasticsearch port 9200.",
                "command_linux": "sudo ufw deny 9200/tcp\nsudo ufw reload",
                "command_windows": "New-NetFirewallRule -Name 'Block-Elasticsearch' -DisplayName 'Block Elasticsearch' -Direction Inbound -Protocol TCP -LocalPort 9200 -Action Block",
                "command_macos": "echo 'block in proto tcp from any to any port 9200' | sudo tee -a /etc/pf.anchors/elastic\nsudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify Authentication Required",
                "description": "Confirm that querying / returns 401 Unauthorized.",
                "command_linux": "curl -sI http://127.0.0.1:9200 | grep -i '401 Unauthorized'",
                "command_windows": "curl.exe -sI http://127.0.0.1:9200",
                "command_macos": "curl -sI http://127.0.0.1:9200",
                "category": "verify",
            },
        ],
    },
    "docker_socket": {
        "summary": "Protect the Docker daemon by disabling unencrypted TCP socket 2375, enforcing TLS authentication on 2376, or using local Unix socket only.",
        "steps": [
            {
                "title": "Disable Unencrypted TCP Socket",
                "description": "Remove -H tcp://0.0.0.0:2375 from Docker daemon configuration and bind strictly to unix:///var/run/docker.sock.",
                "command_linux": "sudo jq 'del(.\"hosts\")' /etc/docker/daemon.json 2>/dev/null > /tmp/d.json && sudo mv /tmp/d.json /etc/docker/daemon.json 2>/dev/null || true\nsudo sed -i 's|-H tcp://[0-9.:]*||g' /lib/systemd/system/docker.service 2>/dev/null\nsudo systemctl daemon-reload && sudo systemctl restart docker",
                "command_windows": "$conf = 'C:\\ProgramData\\docker\\config\\daemon.json'\nif (Test-Path $conf) { (Get-Content $conf) -replace 'tcp://.*', '' | Set-Content $conf }\nRestart-Service docker",
                "command_macos": "# Docker Desktop manages socket via Unix domain socket by default",
                "category": "workaround",
            },
            {
                "title": "Firewall Isolation for Port 2375",
                "description": "Block TCP port 2375 from all network interfaces.",
                "command_linux": "sudo ufw deny 2375/tcp\nsudo ufw reload",
                "command_windows": "New-NetFirewallRule -Name 'Block-Docker-TCP' -DisplayName 'Block Docker TCP' -Direction Inbound -Protocol TCP -LocalPort 2375 -Action Block",
                "command_macos": "echo 'block in proto tcp from any to any port 2375' | sudo tee -a /etc/pf.anchors/docker\nsudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify Socket Isolation",
                "description": "Confirm port 2375 is closed and Docker commands function via local socket.",
                "command_linux": "sudo ss -tulpn | grep 2375\ndocker ps",
                "command_windows": "netstat -an | findstr 2375",
                "command_macos": "docker ps",
                "category": "verify",
            },
        ],
    },
    "smbv1_enabled": {
        "summary": "Disable insecure legacy SMBv1 protocol to eliminate risk of EternalBlue (MS17-010) and WannaCry ransomware exploitation.",
        "steps": [
            {
                "title": "Disable SMBv1 Protocol",
                "description": "Permanently deactivate SMBv1 and enforce SMBv2/SMBv3.",
                "command_linux": "sudo sed -i '/\\[global\\]/a \\   server min protocol = SMB2_02\\n   client min protocol = SMB2' /etc/samba/smb.conf 2>/dev/null\nsudo systemctl restart smbd nmbd 2>/dev/null",
                "command_windows": "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart\nSet-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                "command_macos": "# macOS uses SMB 2/3 natively",
                "category": "workaround",
            },
            {
                "title": "Block SMB Inbound from Untrusted Networks",
                "description": "Block TCP ports 445 and 139 from external untrusted networks.",
                "command_linux": "sudo ufw deny from any to any port 445 proto tcp\nsudo ufw reload",
                "command_windows": "New-NetFirewallRule -Name 'Block-SMB-Public' -DisplayName 'Block Public SMB' -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block -Profile Public",
                "command_macos": "echo 'block in proto tcp from any to any port 445' | sudo tee -a /etc/pf.anchors/smb\nsudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify SMBv1 is Disabled",
                "description": "Confirm SMBv1 is inactive.",
                "command_linux": "testparm -s 2>/dev/null | grep -i 'protocol'",
                "command_windows": "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol",
                "command_macos": "smbutil statshares -a 2>/dev/null",
                "category": "verify",
            },
        ],
    },
    "rdp_nla": {
        "summary": "Enforce Network Level Authentication (NLA) on RDP to prevent pre-authentication remote execution attacks like BlueKeep (CVE-2019-0708).",
        "steps": [
            {
                "title": "Enforce Network Level Authentication (NLA)",
                "description": "Require NLA (UserAuthentication = 1) for all incoming RDP connections.",
                "command_linux": "# If using xrdp:\nsudo sed -i 's/^#\\?security_layer=.*/security_layer=negotiate/' /etc/xrdp/xrdp.ini 2>/dev/null\nsudo systemctl restart xrdp 2>/dev/null",
                "command_windows": "(Get-WmiObject -class Win32_TSGeneralSetting -Namespace root\\cimv2\\terminalservices -Filter \"TerminalName='RDP-Tcp'\").SetUserAuthenticationRequired(1)\nSet-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1",
                "command_macos": "# macOS screen sharing uses VNC/Apple Remote Desktop",
                "category": "workaround",
            },
            {
                "title": "Restrict RDP Port 3389 Access",
                "description": "Allow RDP connections only from trusted management IP subnets.",
                "command_linux": "sudo ufw allow from 10.0.0.0/8 to any port 3389 proto tcp",
                "command_windows": "New-NetFirewallRule -Name 'Allow-RDP-Mgmt' -DisplayName 'Allow RDP Management' -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress 10.0.0.0/8 -Action Allow\nNew-NetFirewallRule -Name 'Block-RDP-Public' -DisplayName 'Block Public RDP' -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block -Profile Public",
                "command_macos": "# Not applicable",
                "category": "firewall",
            },
            {
                "title": "Verify NLA Enforcement",
                "description": "Check that UserAuthentication is set to 1.",
                "command_linux": "# Check xrdp config",
                "command_windows": "Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication'",
                "command_macos": "# Not applicable",
                "category": "verify",
            },
        ],
    },
    "ftp_anonymous": {
        "summary": "Disable anonymous FTP login to prevent unauthorized file access, data leaks, or unauthenticated file uploads.",
        "steps": [
            {
                "title": "Disable Anonymous User Access",
                "description": "Set anonymous_enable=NO in FTP server configuration.",
                "command_linux": "sudo sed -i 's/^anonymous_enable=.*/anonymous_enable=NO/' /etc/vsftpd.conf 2>/dev/null\nsudo sed -i 's/^AnonymousEnable=.*/AnonymousEnable=NO/' /etc/proftpd/proftpd.conf 2>/dev/null\nsudo systemctl restart vsftpd 2>/dev/null || sudo systemctl restart proftpd 2>/dev/null",
                "command_windows": "Import-Module WebAdministration\nSet-ItemProperty 'IIS:\\Sites\\Default FTP Site' -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $false",
                "command_macos": "# Not applicable",
                "category": "workaround",
            },
            {
                "title": "Verify Anonymous Login is Rejected",
                "description": "Test login with anonymous user and ensure 530 Login incorrect is returned.",
                "command_linux": "curl -s ftp://anonymous:test@127.0.0.1/ 2>&1",
                "command_windows": "curl.exe -s ftp://anonymous:test@127.0.0.1/ 2>&1",
                "command_macos": "curl -s ftp://anonymous:test@127.0.0.1/ 2>&1",
                "category": "verify",
            },
        ],
    },
    "cleartext_telnet": {
        "summary": "Deactivate unencrypted Telnet service and migrate all administration to secure SSH.",
        "steps": [
            {
                "title": "Stop and Disable Telnet Daemon",
                "description": "Deactivate the telnet service and daemon from system startup.",
                "command_linux": "sudo systemctl stop telnet.socket 2>/dev/null\nsudo systemctl disable telnet.socket 2>/dev/null\nsudo apt remove -y telnetd 2>/dev/null || sudo dnf remove -y telnet-server 2>/dev/null",
                "command_windows": "Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart\nStop-Service TlntSvr -ErrorAction SilentlyContinue\nSet-Service TlntSvr -StartupType Disabled -ErrorAction SilentlyContinue",
                "command_macos": "sudo launchctl unload -w /System/Library/LaunchDaemons/telnet.plist 2>/dev/null",
                "category": "workaround",
            },
            {
                "title": "Block Telnet Port 23",
                "description": "Block incoming traffic on TCP port 23.",
                "command_linux": "sudo ufw deny 23/tcp && sudo ufw reload",
                "command_windows": "New-NetFirewallRule -Name 'Block-Telnet' -DisplayName 'Block Telnet' -Direction Inbound -Protocol TCP -LocalPort 23 -Action Block",
                "command_macos": "echo 'block in proto tcp from any to any port 23' | sudo tee -a /etc/pf.anchors/telnet\nsudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify Telnet Port is Closed",
                "description": "Confirm port 23 is closed.",
                "command_linux": "sudo ss -tulpn | grep :23",
                "command_windows": "netstat -an | findstr :23",
                "command_macos": "sudo lsof -iTCP:23 -sTCP:LISTEN",
                "category": "verify",
            },
        ],
    },
    "cleartext_ftp": {
        "summary": "Eliminate unencrypted FTP cleartext credentials by enforcing FTPS (FTP over TLS) or migrating users to secure SFTP (SSH File Transfer Protocol).",
        "steps": [
            {
                "title": "Enforce FTPS / SFTP and Disable Plaintext Authentication",
                "description": "Require TLS encryption for FTP control and data channels, or migrate file transfers to OpenSSH SFTP on port 22.",
                "command_linux": "# In vsftpd: enforce SSL/TLS for all logins and data transfers\nsudo tee -a /etc/vsftpd.conf << 'EOF'\nssl_enable=YES\nallow_anon_ssl=NO\nforce_local_data_ssl=YES\nforce_local_logins_ssl=YES\nssl_tlsv1_2=YES\nssl_tlsv1_3=YES\nEOF\nsudo systemctl restart vsftpd 2>/dev/null || sudo systemctl restart proftpd 2>/dev/null",
                "command_windows": "Import-Module WebAdministration\nSet-ItemProperty 'IIS:\\Sites\\Default FTP Site' -Name ftpServer.security.ssl.controlChannelPolicy -Value 1\nSet-ItemProperty 'IIS:\\Sites\\Default FTP Site' -Name ftpServer.security.ssl.dataChannelPolicy -Value 1",
                "command_macos": "# Migrate all file transfers to secure SFTP on port 22\nsudo launchctl unload -w /System/Library/LaunchDaemons/ftp.plist 2>/dev/null",
                "category": "workaround",
            },
            {
                "title": "Firewall Isolation \u2014 Block Cleartext Port 21",
                "description": "Prevent exposure of cleartext FTP port 21 to untrusted networks.",
                "command_linux": "sudo ufw deny 21/tcp && sudo ufw reload",
                "command_windows": "New-NetFirewallRule -Name 'Block-Cleartext-FTP' -DisplayName 'Block Cleartext FTP Port 21' -Direction Inbound -Protocol TCP -LocalPort 21 -Action Block",
                "command_macos": "echo 'block in proto tcp from any to any port 21' | sudo tee -a /etc/pf.anchors/ftp\nsudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify Secure File Transfer Encryption",
                "description": "Confirm cleartext FTP logins are rejected and encrypted SFTP/FTPS is active.",
                "command_linux": "sudo ss -tlnp | grep -E ':21|:22'\ncurl --ssl-reqd -u user:pass ftp://127.0.0.1/ 2>&1",
                "command_windows": "netstat -an | findstr :21\nTest-NetConnection -Port 22 -ComputerName 127.0.0.1",
                "command_macos": "sudo lsof -iTCP:21 -sTCP:LISTEN 2>/dev/null",
                "category": "verify",
            },
        ],
    },
    "cleartext_http": {
        "summary": "Enforce HTTPS with modern TLS 1.3 encryption and automatically redirect all unencrypted HTTP traffic to HTTPS.",
        "steps": [
            {
                "title": "Deploy TLS Certificate and Enforce HTTP-to-HTTPS Redirection",
                "description": "Obtain an automated Let's Encrypt certificate with Certbot or configure web server 301 redirection to HTTPS.",
                "command_linux": "# Obtain Let's Encrypt certificate and auto-configure HTTPS redirect\nsudo apt install -y certbot python3-certbot-apache python3-certbot-nginx 2>/dev/null\nsudo certbot --apache --redirect 2>/dev/null || sudo certbot --nginx --redirect 2>/dev/null",
                "command_windows": "# In IIS: Add HTTPS binding and URL Rewrite redirect rule\nImport-Module WebAdministration\nAdd-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/rewrite/rules' -name '.' -value @{name='Redirect to HTTPS';patternSyntax='ECMAScript';stopProcessing='True'}",
                "command_macos": "# Configure web server to redirect port 80 to 443\nbrew install certbot 2>/dev/null",
                "category": "workaround",
            },
            {
                "title": "Deploy HTTP Strict Transport Security (HSTS)",
                "description": "Send HSTS header to prevent SSL stripping attacks and instruct browsers to only connect via HTTPS.",
                "command_linux": "echo 'Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"' | sudo tee -a /etc/apache2/conf-available/hsts.conf 2>/dev/null\nsudo a2enconf hsts 2>/dev/null && sudo systemctl reload apache2 2>/dev/null",
                "command_windows": "Import-Module WebAdministration\nSet-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/httpProtocol/customHeaders' -name '.' -value @{name='Strict-Transport-Security';value='max-age=31536000; includeSubDomains'}",
                "command_macos": "echo 'Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"' | sudo tee -a /usr/local/etc/httpd/httpd.conf 2>/dev/null",
                "category": "harden",
            },
            {
                "title": "Verify Cleartext HTTP Redirection",
                "description": "Confirm that unencrypted HTTP requests receive a 301/308 redirect to HTTPS.",
                "command_linux": "curl -sIL http://127.0.0.1/ | grep -iE 'HTTP/|location:'",
                "command_windows": "curl.exe -sIL http://127.0.0.1/ | Select-String 'HTTP/|Location:'",
                "command_macos": "curl -sIL http://127.0.0.1/ | grep -iE 'HTTP/|location:'",
                "category": "verify",
            },
        ],
    },
    "cleartext_pop3": {
        "summary": "Deactivate insecure POP3 cleartext mail protocol on port 110 and enforce POP3S (POP3 over TLS) on port 995.",
        "steps": [
            {
                "title": "Enforce POP3 over TLS (POP3S Port 995)",
                "description": "Require SSL/TLS encryption for mail client authentication and retrieval.",
                "command_linux": "# In Dovecot: require SSL for POP3\nsudo sed -i 's/^#\\?ssl =.*/ssl = required/' /etc/dovecot/conf.d/10-ssl.conf 2>/dev/null\nsudo systemctl restart dovecot 2>/dev/null",
                "command_windows": "# In Windows Mail Server: disable port 110 cleartext listener and enforce port 995 POP3S",
                "command_macos": "# Enforce POP3S on port 995 with valid TLS certificates",
                "category": "workaround",
            },
            {
                "title": "Firewall Isolation \u2014 Block Cleartext Port 110",
                "description": "Block inbound unencrypted traffic on TCP port 110.",
                "command_linux": "sudo ufw deny 110/tcp && sudo ufw reload",
                "command_windows": "New-NetFirewallRule -Name 'Block-POP3-Cleartext' -DisplayName 'Block Cleartext POP3' -Direction Inbound -Protocol TCP -LocalPort 110 -Action Block",
                "command_macos": "echo 'block in proto tcp from any to any port 110' | sudo tee -a /etc/pf.anchors/pop3 && sudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify POP3S Encrypted Transport",
                "description": "Confirm port 110 is blocked and port 995 negotiates secure TLS.",
                "command_linux": "openssl s_client -connect 127.0.0.1:995 -quiet 2>/dev/null",
                "command_windows": "Test-NetConnection -Port 995 -ComputerName 127.0.0.1",
                "command_macos": "openssl s_client -connect 127.0.0.1:995 -quiet 2>/dev/null",
                "category": "verify",
            },
        ],
    },
    "cleartext_imap": {
        "summary": "Deactivate unencrypted IMAP on port 143 and mandate IMAPS (IMAP over TLS) on port 993.",
        "steps": [
            {
                "title": "Enforce IMAP over TLS (IMAPS Port 993)",
                "description": "Require SSL/TLS encryption for mailbox synchronization.",
                "command_linux": "# In Dovecot: require SSL for IMAP\nsudo sed -i 's/^#\\?ssl =.*/ssl = required/' /etc/dovecot/conf.d/10-ssl.conf 2>/dev/null\nsudo systemctl restart dovecot 2>/dev/null",
                "command_windows": "# In Windows Mail Server: enforce IMAPS on port 993 and disable unencrypted port 143",
                "command_macos": "# Enforce IMAPS on port 993 with modern TLS ciphers",
                "category": "workaround",
            },
            {
                "title": "Firewall Isolation \u2014 Block Cleartext Port 143",
                "description": "Block inbound unencrypted traffic on TCP port 143.",
                "command_linux": "sudo ufw deny 143/tcp && sudo ufw reload",
                "command_windows": "New-NetFirewallRule -Name 'Block-IMAP-Cleartext' -DisplayName 'Block Cleartext IMAP' -Direction Inbound -Protocol TCP -LocalPort 143 -Action Block",
                "command_macos": "echo 'block in proto tcp from any to any port 143' | sudo tee -a /etc/pf.anchors/imap && sudo pfctl -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify IMAPS Encrypted Transport",
                "description": "Confirm port 143 is blocked and port 993 negotiates secure TLS.",
                "command_linux": "openssl s_client -connect 127.0.0.1:993 -quiet 2>/dev/null",
                "command_windows": "Test-NetConnection -Port 993 -ComputerName 127.0.0.1",
                "command_macos": "openssl s_client -connect 127.0.0.1:993 -quiet 2>/dev/null",
                "category": "verify",
            },
        ],
    },
    "http_trace": {
        "summary": "Disable HTTP TRACE and TRACK methods to eliminate Cross-Site Tracing (XST) cookie theft vulnerabilities.",
        "steps": [
            {
                "title": "Disable TRACE in Web Server",
                "description": "Deactivate TraceEnable in Apache, return 405 in Nginx, or filter HTTP verbs in IIS.",
                "command_linux": "echo 'TraceEnable Off' | sudo tee -a /etc/apache2/conf-available/trace-off.conf 2>/dev/null\nsudo a2enconf trace-off 2>/dev/null && sudo systemctl reload apache2 2>/dev/null\n# Nginx: add to server block: if ($request_method ~ ^(TRACE|TRACK)) { return 405; }",
                "command_windows": "Import-Module WebAdministration\nAdd-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering/verbs' -name '.' -value @{verb='TRACE';allowed='false'}\nAdd-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering/verbs' -name '.' -value @{verb='TRACK';allowed='false'}",
                "command_macos": "echo 'TraceEnable Off' | sudo tee -a /usr/local/etc/httpd/httpd.conf\nbrew services restart httpd",
                "category": "workaround",
            },
            {
                "title": "Verify TRACE Method is Blocked",
                "description": "Send TRACE request and verify server returns 405 Method Not Allowed or 403 Forbidden.",
                "command_linux": "curl -sI -X TRACE http://127.0.0.1/ | head -5",
                "command_windows": "curl.exe -sI -X TRACE http://127.0.0.1/ | Select-Object -First 5",
                "command_macos": "curl -sI -X TRACE http://127.0.0.1/ | head -5",
                "category": "verify",
            },
        ],
    },
    "missing_hsts": {
        "summary": "Deploy HTTP Strict Transport Security (HSTS) header to enforce secure HTTPS connections and block SSL-stripping attacks.",
        "steps": [
            {
                "title": "Add Strict-Transport-Security Header",
                "description": "Deliver HSTS header with a minimum 1-year max-age and includeSubDomains.",
                "command_linux": "# Nginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n# Apache:\necho 'Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"' | sudo tee -a /etc/apache2/conf-available/hsts.conf\nsudo a2enconf hsts 2>/dev/null && sudo systemctl reload apache2",
                "command_windows": "Import-Module WebAdministration\nAdd-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/httpProtocol/customHeaders' -name '.' -value @{name='Strict-Transport-Security';value='max-age=31536000; includeSubDomains; preload'}",
                "command_macos": "echo 'Header always set Strict-Transport-Security \"max-age=31536000\"' | sudo tee -a /usr/local/etc/httpd/httpd.conf\nbrew services restart httpd",
                "category": "workaround",
            },
            {
                "title": "Verify HSTS Header Delivery",
                "description": "Confirm header is present on HTTPS responses.",
                "command_linux": "curl -sI https://127.0.0.1/ -k | grep -i 'Strict-Transport-Security'",
                "command_windows": "curl.exe -sI https://127.0.0.1/ -k | Select-String 'Strict-Transport-Security'",
                "command_macos": "curl -sI https://127.0.0.1/ -k | grep -i 'Strict-Transport-Security'",
                "category": "verify",
            },
        ],
    },
    "missing_xframe": {
        "summary": "Deploy X-Frame-Options or CSP frame-ancestors to prevent clickjacking attacks in unauthorized iframes.",
        "steps": [
            {
                "title": "Add X-Frame-Options Header",
                "description": "Configure web server to emit X-Frame-Options: DENY or SAMEORIGIN.",
                "command_linux": "# Nginx: add_header X-Frame-Options \"DENY\" always;\n# Apache:\necho 'Header always set X-Frame-Options \"DENY\"' | sudo tee -a /etc/apache2/conf-available/clickjack.conf\nsudo a2enconf clickjack 2>/dev/null && sudo systemctl reload apache2",
                "command_windows": "Import-Module WebAdministration\nAdd-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/httpProtocol/customHeaders' -name '.' -value @{name='X-Frame-Options';value='DENY'}",
                "command_macos": "echo 'Header always set X-Frame-Options \"DENY\"' | sudo tee -a /usr/local/etc/httpd/httpd.conf\nbrew services restart httpd",
                "category": "workaround",
            },
            {
                "title": "Verify X-Frame-Options Header",
                "description": "Check response headers for X-Frame-Options.",
                "command_linux": "curl -sI http://127.0.0.1/ | grep -i 'X-Frame-Options'",
                "command_windows": "curl.exe -sI http://127.0.0.1/ | Select-String 'X-Frame-Options'",
                "command_macos": "curl -sI http://127.0.0.1/ | grep -i 'X-Frame-Options'",
                "category": "verify",
            },
        ],
    },
    "exposed_files": {
        "summary": "Block public access to sensitive files (.env, .git, config files) in web server configuration to prevent credential and source code theft.",
        "steps": [
            {
                "title": "Block Hidden and Sensitive Files in Web Server",
                "description": "Deny all requests to dot-prefixed files and directories like .git and .env.",
                "command_linux": "# Nginx: location ~ /\\. { deny all; access_log off; log_not_found off; }\n# Apache:\nsudo tee /etc/apache2/conf-available/block-hidden.conf << 'EOF'\n<FilesMatch \"^\\.\">\n    Require all denied\n</FilesMatch>\n<DirectoryMatch \"/\\.\">\n    Require all denied\n</DirectoryMatch>\nEOF\nsudo a2enconf block-hidden && sudo systemctl reload apache2",
                "command_windows": "Import-Module WebAdministration\nAdd-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering/hiddenSegments' -name '.' -value @{segment='.env'}\nAdd-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering/hiddenSegments' -name '.' -value @{segment='.git'}",
                "command_macos": "# Block dot files in httpd.conf",
                "category": "workaround",
            },
            {
                "title": "Verify Sensitive Files are Blocked",
                "description": "Confirm requests to /.env and /.git/HEAD return 403 Forbidden.",
                "command_linux": "curl -sI http://127.0.0.1/.env | head -1\ncurl -sI http://127.0.0.1/.git/HEAD | head -1",
                "command_windows": "curl.exe -sI http://127.0.0.1/.env | Select-Object -First 1",
                "command_macos": "curl -sI http://127.0.0.1/.env | head -1",
                "category": "verify",
            },
        ],
    },
    "deprecated_tls": {
        "summary": "Deactivate deprecated TLS 1.0 and TLS 1.1 protocols and mandate TLS 1.2+ across web and application servers.",
        "steps": [
            {
                "title": "Enforce TLS 1.2 and TLS 1.3",
                "description": "Configure SSLProtocol -all +TLSv1.2 +TLSv1.3 in web servers and disable legacy protocols in Windows Schannel.",
                "command_linux": "# Apache:\necho 'SSLProtocol -all +TLSv1.2 +TLSv1.3' | sudo tee -a /etc/apache2/mods-available/ssl.conf\nsudo systemctl reload apache2\n# Nginx: ssl_protocols TLSv1.2 TLSv1.3;",
                "command_windows": "New-Item 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Force\nSet-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Name Enabled -Value 0 -Type DWord\nNew-Item 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server' -Force\nSet-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server' -Name Enabled -Value 0 -Type DWord",
                "command_macos": "# Configure web server to TLS 1.2+",
                "category": "workaround",
            },
            {
                "title": "Verify Deprecated TLS Handshake Fails",
                "description": "Confirm connection using -tls1 returns handshake failure.",
                "command_linux": "openssl s_client -connect 127.0.0.1:443 -tls1 </dev/null 2>&1 | grep -i 'handshake failure'",
                "command_windows": "openssl s_client -connect 127.0.0.1:443 -tls1 </dev/null 2>&1",
                "command_macos": "openssl s_client -connect 127.0.0.1:443 -tls1 </dev/null 2>&1",
                "category": "verify",
            },
        ],
    },
    "weak_ciphers": {
        "summary": "Disable insecure legacy cipher suites (RC4, 3DES, DES, CBC with SHA-1) and mandate modern AEAD ciphers (GCM / ChaCha20).",
        "steps": [
            {
                "title": "Enforce Strong AEAD Ciphers",
                "description": "Configure SSLCipherSuite to require modern GCM or ChaCha20 ciphers.",
                "command_linux": "# Nginx: ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';\n# Apache:\necho 'SSLCipherSuite HIGH:!aNULL:!MD5:!3DES:!RC4:!CBC' | sudo tee -a /etc/apache2/mods-available/ssl.conf\nsudo systemctl reload apache2",
                "command_windows": "Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_3DES_EDE_CBC_SHA' -ErrorAction SilentlyContinue\nDisable-TlsCipherSuite -Name 'TLS_RSA_WITH_RC4_128_SHA' -ErrorAction SilentlyContinue",
                "command_macos": "# Configure web server ciphers",
                "category": "workaround",
            },
            {
                "title": "Verify Weak Ciphers Rejected",
                "description": "Confirm server rejects connections requesting 3DES or RC4.",
                "command_linux": "openssl s_client -connect 127.0.0.1:443 -cipher '3DES' </dev/null 2>&1 | grep -i 'handshake failure'",
                "command_windows": "openssl s_client -connect 127.0.0.1:443 -cipher '3DES' </dev/null 2>&1",
                "command_macos": "openssl s_client -connect 127.0.0.1:443 -cipher '3DES' </dev/null 2>&1",
                "category": "verify",
            },
        ],
    },
}


_SERVICE_ALIAS_MAP: Dict[str, str] = {
    "https": "http", "apache": "http", "httpd": "http", "apache2": "http",
    "http-proxy": "nginx", "http-alt": "http", "https-alt": "http",
    "samba": "smb", "netbios-ssn": "smb", "netbios-ns": "smb",
    "netbios-dgm": "smb", "microsoft-ds": "smb",
    "mariadb": "mysql", "mysql-proxy": "mysql",
    "postgres": "postgresql",
    "ftp-data": "ftp", "vsftpd": "ftp", "proftpd": "ftp", "pure-ftpd": "ftp",
    "openssh": "ssh", "dropbear": "ssh",
    "submission": "smtp", "smtps": "smtp", "postfix": "smtp", "sendmail": "smtp", "exim": "smtp",
    "domain": "dns", "named": "dns", "bind": "dns", "dnsmasq": "dns", "unbound": "dns",
    "mongod": "mongodb", "memcache": "memcached",
    "mssql": "mysql", "mssql-m": "mysql", "oracle": "mysql",
    "snmp-trap": "snmp",
    "docker-proxy": "docker", "containerd": "docker", "k8s": "docker", "kubernetes": "docker",
    "web-admin": "http",
}


def _resolve_service_alias(service: str) -> str:
    """Resolve service name aliases to canonical KB key."""
    s = service.lower().strip()
    return _SERVICE_ALIAS_MAP.get(s, s)


def generate_step_rollbacks(category: str, service: str, port: int) -> Tuple[str, str, str, str, str]:
    """Auto-generate platform-specific rollback commands and disruption metadata for a remediation step."""
    s = service.lower().strip()
    p = port or 0
    if category == "firewall" and p > 0:
        lin = f"# Revert firewall isolation rule\nsudo ufw delete deny from any to any port {p} proto tcp 2>/dev/null; sudo ufw reload"
        win = f"# Revert firewall rules\nRemove-NetFirewallRule -Name 'Block-{s}-External' -ErrorAction SilentlyContinue"
        mac = f"# Revert pfctl rules\nsudo sed -i '' '/{s}/d' /etc/pf.conf 2>/dev/null; sudo pfctl -f /etc/pf.conf 2>/dev/null"
        disruption = "ZERO_DOWNTIME"
        est_time = "1 min"
    elif category in ("workaround", "harden"):
        lin = f"# Restore previous configuration backup if available:\nif [ -f /etc/{s}/{s}.conf.bak ]; then sudo cp /etc/{s}/{s}.conf.bak /etc/{s}/{s}.conf && sudo systemctl restart {s}; fi"
        win = f"# Revert service configuration changes:\nRestart-Service -Name '*{s}*' -ErrorAction SilentlyContinue"
        mac = f"brew services restart {s} 2>/dev/null"
        disruption = "CONFIG_RELOAD"
        est_time = "2 mins"
    elif category == "patch":
        lin = f"# Check available rollback package versions:\nsudo apt-cache madison {s} 2>/dev/null || sudo dnf --showduplicates list {s} 2>/dev/null"
        win = f"# Check installed package history:\nwinget list --name '{s}'"
        mac = f"brew info {s} 2>/dev/null"
        disruption = "SERVICE_RESTART"
        est_time = "3-5 mins"
    else:
        lin = f"sudo systemctl status {s} 2>/dev/null"
        win = f"Get-Service -Name '*{s}*'"
        mac = f"brew services list | grep -i {s}"
        disruption = "READ_ONLY"
        est_time = "30 secs"
    return lin, win, mac, disruption, est_time


def get_remediation_plan(
    service: str,
    version: str = "",
    cve_id: str = "",
    cve_description: str = "",
    severity: str = "HIGH",
    port: int = 0,
) -> RemediationPlan:
    """
    Generate a real-world, production-grade multi-OS step-by-step remediation plan.
    Uses service-specific KB (25+ services), CVE category analysis, automated rollbacks, and port-aware dynamic fallback.
    """
    service_lower = service.lower().strip() if service else "unknown"
    kb_key = _resolve_service_alias(service_lower)
    categories = analyze_cve_categories(cve_description, cve_id)

    if kb_key in SERVICE_REMEDIATION_KB:
        kb_entry = SERVICE_REMEDIATION_KB[kb_key]
        summary = kb_entry["summary"]
        steps = []
        for i, step_def in enumerate(kb_entry["steps"], 1):
            cat = step_def.get("category", "patch")
            d_lin, d_win, d_mac, disr, est = generate_step_rollbacks(cat, service_lower, port or 0)
            steps.append(
                RemediationStep(
                    step_number=i,
                    title=step_def["title"],
                    description=step_def["description"],
                    command_linux=step_def.get("command_linux", ""),
                    command_windows=step_def.get("command_windows", ""),
                    command_macos=step_def.get("command_macos", ""),
                    category=cat,
                    rollback_linux=step_def.get("rollback_linux") or d_lin,
                    rollback_windows=step_def.get("rollback_windows") or d_win,
                    rollback_macos=step_def.get("rollback_macos") or d_mac,
                    disruption_level=step_def.get("disruption_level") or disr,
                    estimated_time=step_def.get("estimated_time") or est,
                )
            )
        # Inject CVE-category-specific hardening steps
        extra_steps = _get_category_hardening_steps(categories, service_lower, port or 0)
        if extra_steps:
            insert_idx = 1
            for idx, step in enumerate(steps):
                if step.category == "workaround":
                    insert_idx = idx + 1
                    break
            for j, extra in enumerate(extra_steps):
                d_lin, d_win, d_mac, disr, est = generate_step_rollbacks(extra.category, service_lower, port or 0)
                extra.rollback_linux = extra.rollback_linux or d_lin
                extra.rollback_windows = extra.rollback_windows or d_win
                extra.rollback_macos = extra.rollback_macos or d_mac
                extra.disruption_level = extra.disruption_level or disr
                extra.estimated_time = extra.estimated_time or est
                steps.insert(insert_idx + j, extra)
            for i, step in enumerate(steps, 1):
                step.step_number = i

        return RemediationPlan(service=service, version=version, cve_id=cve_id, summary=summary, steps=steps)

    # Dynamic Fallback for unlisted services
    target_name = f"{service} {version}".strip() if version else service
    cve_ref = f"for {cve_id} " if cve_id else ""
    effective_port = port or 0

    summary = f"Remediate {severity} severity vulnerability {cve_ref}in {target_name} by applying security patches, restricting network exposure, and hardening service configuration."

    steps = [
        RemediationStep(
            step_number=1,
            title="Audit Service Exposure & Running Configuration",
            description=f"Identify all listening sockets and running processes for {service}.",
            command_linux=f"sudo ss -tlnp | grep -iE ':{effective_port}|{service}'\nps aux | grep -i {service} | grep -v grep\nfind /etc -name '*{service}*' -type f 2>/dev/null | head -10",
            command_windows=f"netstat -an | findstr ':{effective_port}'\nGet-Process | Where-Object {{ $_.ProcessName -like '*{service}*' }}\nGet-Service | Where-Object {{ $_.Name -like '*{service}*' }}",
            command_macos=f"sudo lsof -iTCP:{effective_port} -sTCP:LISTEN 2>/dev/null\nps aux | grep -i {service} | grep -v grep",
            category="workaround",
            rollback_linux=f"# Restore original service configuration if modified\nif [ -f /etc/{service_lower}.conf.bak ]; then sudo cp /etc/{service_lower}.conf.bak /etc/{service_lower}.conf; fi",
            rollback_windows=f"# Revert service state\nRestart-Service -Name '*{service_lower}*' -ErrorAction SilentlyContinue",
            rollback_macos=f"brew services restart {service_lower} 2>/dev/null",
            disruption_level="CONFIG_RELOAD",
            estimated_time="2 mins",
        ),
        RemediationStep(
            step_number=2,
            title=f"Update {target_name} to Latest Security Release",
            description=f"Upgrade {target_name} to the most recent vendor-supported release.",
            command_linux=f"sudo apt update && sudo apt install --only-upgrade {service_lower} -y\nsudo dnf upgrade {service_lower} -y 2>/dev/null\ndpkg -l | grep -i {service_lower} 2>/dev/null || rpm -qa | grep -i {service_lower}",
            command_windows=f"winget upgrade --name '{service}' --accept-package-agreements",
            command_macos=f"brew update && brew upgrade {service_lower} 2>/dev/null",
            category="patch",
            rollback_linux=f"# Query installed package rollback candidates:\nsudo apt-cache madison {service_lower} 2>/dev/null",
            rollback_windows=f"# Query winget installed versions:\nwinget list --name '{service}'",
            rollback_macos=f"brew info {service_lower} 2>/dev/null",
            disruption_level="SERVICE_RESTART",
            estimated_time="3-5 mins",
        ),
    ]

    if effective_port > 0:
        steps.append(RemediationStep(
            step_number=3,
            title=f"Restrict Network Access to Port {effective_port}",
            description=f"Block external access to {service} on port {effective_port}. Allow from trusted networks only.",
            command_linux=f"sudo ufw deny from any to any port {effective_port} proto tcp comment 'Block external {service}'\nsudo ufw allow from 10.0.0.0/8 to any port {effective_port} proto tcp comment 'Allow trusted {service}'\nsudo ufw reload",
            command_windows=f"New-NetFirewallRule -Name 'Block-{service_lower}-External' -DisplayName 'Block External {service} Port {effective_port}' -Direction Inbound -Protocol TCP -LocalPort {effective_port} -Action Block -Profile Public\nNew-NetFirewallRule -Name 'Allow-{service_lower}-Mgmt' -DisplayName 'Allow {service} Management' -Direction Inbound -Protocol TCP -LocalPort {effective_port} -RemoteAddress 10.0.0.0/8 -Action Allow",
            command_macos=f"echo 'block in proto tcp from any to any port {effective_port}' | sudo tee -a /etc/pf.anchors/{service_lower}\nsudo pfctl -f /etc/pf.conf",
            category="firewall",
            rollback_linux=f"sudo ufw delete deny from any to any port {effective_port} proto tcp 2>/dev/null; sudo ufw reload",
            rollback_windows=f"Remove-NetFirewallRule -Name 'Block-{service_lower}-External' -ErrorAction SilentlyContinue",
            rollback_macos=f"sudo sed -i '' '/{service_lower}/d' /etc/pf.conf 2>/dev/null; sudo pfctl -f /etc/pf.conf 2>/dev/null",
            disruption_level="ZERO_DOWNTIME",
            estimated_time="1 min",
        ))

    extra_steps = _get_category_hardening_steps(categories, service_lower, effective_port)
    for extra in extra_steps:
        d_lin, d_win, d_mac, disr, est = generate_step_rollbacks(extra.category, service_lower, effective_port)
        extra.rollback_linux = extra.rollback_linux or d_lin
        extra.rollback_windows = extra.rollback_windows or d_win
        extra.rollback_macos = extra.rollback_macos or d_mac
        extra.disruption_level = extra.disruption_level or disr
        extra.estimated_time = extra.estimated_time or est
        steps.append(extra)

    steps.append(RemediationStep(
        step_number=len(steps) + 1,
        title="Verify Patch & Service Status",
        description=f"Confirm {target_name} is patched and running securely.",
        command_linux=f"sudo systemctl status {service_lower} --no-pager 2>/dev/null\nsudo ss -tlnp | grep -iE ':{effective_port}|{service_lower}'",
        command_windows=f"Get-Service -Name '*{service_lower}*' -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType\nnetstat -an | findstr ':{effective_port}'",
        command_macos=f"brew services list 2>/dev/null | grep -i {service_lower}\nsudo lsof -iTCP:{effective_port} -sTCP:LISTEN 2>/dev/null",
        category="verify",
        rollback_linux=f"sudo systemctl status {service_lower} 2>/dev/null",
        rollback_windows=f"Get-Service -Name '*{service_lower}*'",
        rollback_macos=f"brew services list | grep -i {service_lower}",
        disruption_level="READ_ONLY",
        estimated_time="30 secs",
    ))

    for i, step in enumerate(steps, 1):
        step.step_number = i

    return RemediationPlan(service=service, version=version, cve_id=cve_id, summary=summary, steps=steps)

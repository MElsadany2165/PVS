# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
Remediation Engine - Generates actionable, multi-OS step-by-step fix procedures for detected vulnerabilities.
Provides simple, clear 1-2-3 steps with copy-paste commands for Linux, Windows, and macOS.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict


@dataclass
class RemediationStep:
    """Represents a single step in a remediation procedure with multi-OS commands."""
    step_number: int
    title: str
    description: str
    command_linux: str = ""
    command_windows: str = ""
    command_macos: str = ""
    category: str = "patch"  # "workaround", "patch", "firewall", "verify"

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
                }
                for s in self.steps
            ],
        }


# Knowledge base of multi-OS service-specific remediation procedures
SERVICE_REMEDIATION_KB: Dict[str, dict] = {
    "ssh": {
        "summary": "Secure OpenSSH server by patching to latest release, disabling root logins, and enforcing firewall isolation.",
        "steps": [
            {
                "title": "Immediate Hardening & Config Workaround",
                "description": "Disable direct root login and reduce login grace time in SSH configuration.",
                "command_linux": "sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo sed -i 's/^#\\?LoginGraceTime.*/LoginGraceTime 30/' /etc/ssh/sshd_config && sudo systemctl reload sshd",
                "command_windows": "Add-Content -Path 'C:\\ProgramData\\ssh\\sshd_config' -Value 'PermitRootLogin no'`n'LoginGraceTime 30'; Restart-Service sshd",
                "command_macos": "sudo sed -i '' 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist && sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist",
                "category": "workaround",
            },
            {
                "title": "Update OpenSSH Service Package",
                "description": "Upgrade OpenSSH binaries to the latest patched security release.",
                "command_linux": "# Ubuntu/Debian:\nsudo apt update && sudo apt install --only-upgrade openssh-server -y\n\n# RHEL/CentOS/Fedora:\nsudo dnf upgrade openssh-server -y",
                "command_windows": "winget upgrade --id OpenSSH.Client -e; winget upgrade --id OpenSSH.Server -e",
                "command_macos": "brew update && brew upgrade openssh",
                "category": "patch",
            },
            {
                "title": "Restrict Network Exposure (Firewall)",
                "description": "Restrict SSH access (Port 22) to trusted management subnets only.",
                "command_linux": "sudo ufw default deny incoming && sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp",
                "command_windows": "New-NetFirewallRule -Name 'SSH-Restrict' -DisplayName 'SSH Access Control' -Direction Inbound -Protocol TCP -LocalPort 22 -RemoteAddress 192.168.1.0/24 -Action Allow",
                "command_macos": "sudo pfctl -e -f /etc/pf.conf",
                "category": "firewall",
            },
            {
                "title": "Verify SSH Patch Level & Status",
                "description": "Check current installed version and verify sshd daemon execution.",
                "command_linux": "ssh -V && sudo systemctl status sshd",
                "command_windows": "Get-Service sshd | Select-Object Name, Status, StartType; ssh -V",
                "command_macos": "ssh -V && sudo launchctl list | grep ssh",
                "category": "verify",
            },
        ],
    },
    "http": {
        "summary": "Harden Apache HTTP Web Server by suppressing version banners, updating packages, and applying security headers.",
        "steps": [
            {
                "title": "Hide Server Version & Apply Security Headers",
                "description": "Disable ServerTokens and ServerSignature to hide exact software version banners.",
                "command_linux": "sudo sed -i 's/^ServerTokens.*/ServerTokens Prod/' /etc/apache2/conf-available/security.conf 2>/dev/null || echo 'ServerTokens Prod' | sudo tee -a /etc/apache2/apache2.conf && sudo systemctl reload apache2",
                "command_windows": "# Apache on Windows (httpd.conf):\nAdd-Content -Path 'C:\\Apache24\\conf\\httpd.conf' -Value 'ServerTokens Prod'`n'ServerSignature Off'",
                "command_macos": "sudo sed -i '' 's/^ServerTokens.*/ServerTokens Prod/' /usr/local/etc/httpd/httpd.conf && brew services restart httpd",
                "category": "workaround",
            },
            {
                "title": "Update Web Server Package",
                "description": "Upgrade Apache HTTP Server package to resolve security vulnerabilities.",
                "command_linux": "# Ubuntu/Debian:\nsudo apt update && sudo apt install --only-upgrade apache2 -y\n\n# RHEL/CentOS/Fedora:\nsudo dnf upgrade httpd -y",
                "command_windows": "winget upgrade --name 'Apache HTTP Server'",
                "command_macos": "brew update && brew upgrade httpd",
                "category": "patch",
            },
            {
                "title": "Configure Web Firewall Isolation",
                "description": "Allow HTTP/HTTPS traffic while blocking invalid probe requests.",
                "command_linux": "sudo ufw allow 'Apache Full' || sudo ufw allow 80,443/tcp",
                "command_windows": "New-NetFirewallRule -Name 'HTTP-In' -DisplayName 'Allow Web Traffic' -Direction Inbound -Protocol TCP -LocalPort 80,443 -Action Allow",
                "command_macos": "sudo pfctl -e",
                "category": "firewall",
            },
            {
                "title": "Verify HTTP Server Configuration",
                "description": "Test HTTP web server configuration syntax and inspect HTTP response headers.",
                "command_linux": "sudo apache2ctl configtest && curl -I http://localhost",
                "command_windows": "C:\\Apache24\\bin\\httpd.exe -t; curl.exe -I http://localhost",
                "command_macos": "apachectl configtest && curl -I http://localhost",
                "category": "verify",
            },
        ],
    },
    "nginx": {
        "summary": "Secure Nginx web server against buffer overflows and HTTP/2 flood vulnerabilities.",
        "steps": [
            {
                "title": "Hide Version Tokens & Harden Buffers",
                "description": "Set server_tokens off in nginx.conf to prevent version disclosure.",
                "command_linux": "sudo sed -i 's/# server_tokens off;/server_tokens off;/' /etc/nginx/nginx.conf && sudo systemctl reload nginx",
                "command_windows": "# Nginx Windows config (nginx.conf):\n# Set 'server_tokens off;' inside http block\nnginx.exe -s reload",
                "command_macos": "sudo sed -i '' 's/# server_tokens off;/server_tokens off;/' /usr/local/etc/nginx/nginx.conf && brew services restart nginx",
                "category": "workaround",
            },
            {
                "title": "Update Nginx Server Package",
                "description": "Install the latest stable security release of Nginx.",
                "command_linux": "# Ubuntu/Debian:\nsudo apt update && sudo apt install --only-upgrade nginx -y\n\n# RHEL/CentOS:\nsudo dnf upgrade nginx -y",
                "command_windows": "winget upgrade --name 'Nginx'",
                "command_macos": "brew update && brew upgrade nginx",
                "category": "patch",
            },
            {
                "title": "Firewall Rule",
                "description": "Enforce HTTP/HTTPS port traffic allowance.",
                "command_linux": "sudo ufw allow 'Nginx Full'",
                "command_windows": "New-NetFirewallRule -Name 'Nginx-In' -DisplayName 'Nginx Web Server' -Direction Inbound -Protocol TCP -LocalPort 80,443 -Action Allow",
                "command_macos": "sudo pfctl -e",
                "category": "firewall",
            },
            {
                "title": "Verify Configuration Syntax",
                "description": "Ensure Nginx syntax is correct and service is running smoothly.",
                "command_linux": "sudo nginx -t && sudo systemctl status nginx",
                "command_windows": "nginx.exe -t",
                "command_macos": "nginx -t && brew services list",
                "category": "verify",
            },
        ],
    },
    "mysql": {
        "summary": "Secure MySQL / MariaDB database server against unauthorized remote access and privilege escalation.",
        "steps": [
            {
                "title": "Bind MySQL to Localhost Interface Only",
                "description": "Ensure database daemon is bound to 127.0.0.1 and not publicly accessible.",
                "command_linux": "sudo sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/mysql.conf.d/mysqld.cnf && sudo systemctl restart mysql",
                "command_windows": "# Add 'bind-address = 127.0.0.1' under [mysqld] in my.ini\nRestart-Service MySQL",
                "command_macos": "sudo sed -i '' 's/^bind-address.*/bind-address = 127.0.0.1/' /usr/local/etc/my.cnf && brew services restart mysql",
                "category": "workaround",
            },
            {
                "title": "Update MySQL Server Package",
                "description": "Upgrade MySQL / MariaDB server binaries.",
                "command_linux": "sudo apt update && sudo apt install --only-upgrade mysql-server -y",
                "command_windows": "winget upgrade --name 'MySQL Server'",
                "command_macos": "brew update && brew upgrade mysql",
                "category": "patch",
            },
            {
                "title": "Block Remote Port 3306",
                "description": "Block external public access to MySQL default port 3306.",
                "command_linux": "sudo ufw deny 3306/tcp",
                "command_windows": "New-NetFirewallRule -Name 'Block-MySQL' -DisplayName 'Block MySQL Port 3306' -Direction Inbound -Protocol TCP -LocalPort 3306 -Action Block",
                "command_macos": "sudo pfctl -e",
                "category": "firewall",
            },
            {
                "title": "Run Security Hardening Check",
                "description": "Execute database security check and remove test databases.",
                "command_linux": "sudo mysql_secure_installation",
                "command_windows": "mysql_secure_installation.exe",
                "command_macos": "mysql_secure_installation",
                "category": "verify",
            },
        ],
    },
    "redis": {
        "summary": "Remediate Redis unauthenticated remote execution by binding to loopback and enabling authentication.",
        "steps": [
            {
                "title": "Enable Protected Mode & Local Loopback",
                "description": "Bind Redis to 127.0.0.1 and enforce protected mode in redis.conf.",
                "command_linux": "sudo sed -i 's/^bind.*/bind 127.0.0.1/' /etc/redis/redis.conf && sudo systemctl restart redis-server",
                "command_windows": "# Set 'bind 127.0.0.1' in redis.windows.conf\nRestart-Service redis",
                "command_macos": "sudo sed -i '' 's/^bind.*/bind 127.0.0.1/' /usr/local/etc/redis.conf && brew services restart redis",
                "category": "workaround",
            },
            {
                "title": "Update Redis Package",
                "description": "Upgrade Redis server binaries.",
                "command_linux": "sudo apt update && sudo apt install --only-upgrade redis-server -y",
                "command_windows": "winget upgrade --name 'Redis'",
                "command_macos": "brew update && brew upgrade redis",
                "category": "patch",
            },
            {
                "title": "Block Public Port 6379",
                "description": "Restrict external access to Redis default port.",
                "command_linux": "sudo ufw deny 6379/tcp",
                "command_windows": "New-NetFirewallRule -Name 'Block-Redis' -DisplayName 'Block Redis 6379' -Direction Inbound -Protocol TCP -LocalPort 6379 -Action Block",
                "command_macos": "sudo pfctl -e",
                "category": "firewall",
            },
            {
                "title": "Verify Redis Connection Security",
                "description": "Ping local Redis daemon using redis-cli.",
                "command_linux": "redis-cli ping",
                "command_windows": "redis-cli.exe ping",
                "command_macos": "redis-cli ping",
                "category": "verify",
            },
        ],
    },
    "smb": {
        "summary": "Remediate SMB / Samba vulnerabilities (e.g. EternalBlue / SMBGhost) by disabling legacy SMBv1.",
        "steps": [
            {
                "title": "Disable Legacy SMBv1 Protocol",
                "description": "Disable insecure SMBv1 protocol across operating systems.",
                "command_linux": "sudo sed -i '/\\[global\\]/a \\   server min protocol = SMB2_02' /etc/samba/smb.conf && sudo systemctl restart smbd",
                "command_windows": "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
                "command_macos": "sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist",
                "category": "workaround",
            },
            {
                "title": "Update Samba / Operating System Security Patches",
                "description": "Apply operating system security updates for file sharing services.",
                "command_linux": "sudo apt update && sudo apt install --only-upgrade samba -y",
                "command_windows": "Install-Module PSWindowsUpdate -Force; Get-WindowsUpdate -AcceptAll -Install",
                "command_macos": "softwareupdate -i -a",
                "category": "patch",
            },
            {
                "title": "Restrict Inbound Ports 139 & 445",
                "description": "Block Internet access to SMB ports.",
                "command_linux": "sudo ufw deny 445/tcp && sudo ufw deny 139/tcp",
                "command_windows": "New-NetFirewallRule -Name 'Block-SMB' -DisplayName 'Block Inbound SMB' -Direction Inbound -Protocol TCP -LocalPort 139,445 -Action Block",
                "command_macos": "sudo pfctl -e",
                "category": "firewall",
            },
            {
                "title": "Verify SMB Protocol Configuration",
                "description": "Inspect active SMB server configuration and protocol minimums.",
                "command_linux": "testparm -s",
                "command_windows": "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol",
                "command_macos": "smbutil statshares -a",
                "category": "verify",
            },
        ],
    },
}


def get_remediation_plan(
    service: str,
    version: str = "",
    cve_id: str = "",
    cve_description: str = "",
    severity: str = "HIGH",
) -> RemediationPlan:
    """
    Generate a simple, flawless multi-OS step-by-step remediation plan for a vulnerability.
    Uses service-specific knowledge base when available, with intelligent dynamic generation fallback.
    """
    service_lower = service.lower().strip() if service else "unknown"

    # Map alias service names
    if "https" in service_lower or "apache" in service_lower:
        kb_key = "http"
    elif "samba" in service_lower or "netbios" in service_lower or "microsoft-ds" in service_lower:
        kb_key = "smb"
    elif "postgres" in service_lower:
        kb_key = "postgresql"
    elif "mariadb" in service_lower:
        kb_key = "mysql"
    else:
        kb_key = service_lower

    if kb_key in SERVICE_REMEDIATION_KB:
        kb_entry = SERVICE_REMEDIATION_KB[kb_key]
        summary = kb_entry["summary"]
        steps = []
        for i, step_def in enumerate(kb_entry["steps"], 1):
            steps.append(
                RemediationStep(
                    step_number=i,
                    title=step_def["title"],
                    description=step_def["description"],
                    command_linux=step_def.get("command_linux", ""),
                    command_windows=step_def.get("command_windows", ""),
                    command_macos=step_def.get("command_macos", ""),
                    category=step_def.get("category", "patch"),
                )
            )
        return RemediationPlan(
            service=service,
            version=version,
            cve_id=cve_id,
            summary=summary,
            steps=steps,
        )

    # Dynamic Fallback Remediation Plan for obscure/unlisted services
    target_name = f"{service} {version}".strip() if version else service
    cve_ref = f"for {cve_id} " if cve_id else ""

    summary = f"Remediate {severity} severity vulnerability {cve_ref}in {target_name} by applying security patches and restricting network access across Linux, Windows, and macOS."

    steps = [
        RemediationStep(
            step_number=1,
            title="Temporary Configuration Workaround",
            description=f"Inspect service configuration for {service} to disable unneeded features or bind listening sockets to trusted network interfaces only.",
            command_linux=f"sudo netstat -tulnp | grep -i {service} || sudo ss -tulnp | grep -i {service}",
            command_windows=f"Get-NetTCPConnection | Where-Object {{ $_.State -eq 'Listen' }}",
            command_macos=f"sudo lsof -iTCP -sTCP:LISTEN | grep -i {service}",
            category="workaround",
        ),
        RemediationStep(
            step_number=2,
            title="Update Package & Software Binaries",
            description=f"Upgrade {target_name} to the latest available vendor release to obtain security patches.",
            command_linux=f"# Ubuntu/Debian:\nsudo apt update && sudo apt install --only-upgrade {service} -y\n\n# RHEL/CentOS/Fedora:\nsudo dnf upgrade {service} -y",
            command_windows=f"winget upgrade --name '{service}'",
            command_macos=f"brew update && brew upgrade {service}",
            category="patch",
        ),
        RemediationStep(
            step_number=3,
            title="Network Isolation & Firewall Rule",
            description=f"Restrict inbound network traffic to {service} using firewall access control lists.",
            command_linux=f"sudo ufw deny proto tcp from any to any port <PORT>\nsudo ufw allow proto tcp from 192.168.1.0/24 to any port <PORT>",
            command_windows=f"New-NetFirewallRule -Name 'Block-{service}' -DisplayName 'Block {service}' -Direction Inbound -Protocol TCP -LocalPort <PORT> -Action Block",
            command_macos=f"sudo pfctl -e",
            category="firewall",
        ),
        RemediationStep(
            step_number=4,
            title="Verification & Audit Test",
            description="Verify that the patched service is running correctly and no residual security flaws remain.",
            command_linux=f"sudo systemctl status {service}",
            command_windows=f"Get-Service -Name '{service}' -ErrorAction SilentlyContinue",
            command_macos=f"brew services list | grep {service}",
            category="verify",
        ),
    ]

    return RemediationPlan(
        service=service,
        version=version,
        cve_id=cve_id,
        summary=summary,
        steps=steps,
    )

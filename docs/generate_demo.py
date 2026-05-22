"""Generate a demo HTML report with sample scan data for showcase purposes."""
import sys
sys.path.insert(0, ".")

from pvs.reporter import generate_html_report

demo_data = {
    "scanner": "PVS",
    "version": "1.0.1",
    "scan_time": "2026-05-17T09:00:00",
    "target": "192.168.1.0/24",
    "hosts": [
        {
            "ip": "192.168.1.1",
            "hostname": "gateway.local",
            "is_up": True,
            "scan_time": 3.42,
            "ports": [
                {
                    "port": 22, "state": "open", "service": "ssh",
                    "version": "OpenSSH_8.9p1", "banner": "SSH-2.0-OpenSSH_8.9p1",
                    "cves": [
                        {"cve_id": "CVE-2023-38408", "description": "PKCS#11 feature in ssh-agent allows remote code execution via forwarded agent", "severity": "CRITICAL", "score": 9.8, "vector": "CVSS:3.1/AV:N", "published": "2023-07-20", "references": []},
                        {"cve_id": "CVE-2023-51385", "description": "OS command injection via ssh, scp, sftp shell metacharacters in host/user names", "severity": "HIGH", "score": 6.5, "vector": "CVSS:3.1/AV:N", "published": "2023-12-18", "references": []},
                    ]
                },
                {
                    "port": 80, "state": "open", "service": "http",
                    "version": "nginx/1.24.0", "banner": "",
                    "cves": [
                        {"cve_id": "CVE-2024-7347", "description": "nginx mp4 module: buffer over-read via specially crafted mp4 file", "severity": "MEDIUM", "score": 4.7, "vector": "CVSS:3.1/AV:L", "published": "2024-08-14", "references": []},
                    ]
                },
                {
                    "port": 443, "state": "open", "service": "https",
                    "version": "nginx/1.24.0", "banner": "", "cves": []
                },
            ]
        },
        {
            "ip": "192.168.1.10",
            "hostname": "webserver.local",
            "is_up": True,
            "scan_time": 2.87,
            "ports": [
                {
                    "port": 80, "state": "open", "service": "http",
                    "version": "Apache/2.4.57", "banner": "",
                    "cves": [
                        {"cve_id": "CVE-2023-43622", "description": "Apache HTTP Server: HTTP/2 stream handling DoS", "severity": "HIGH", "score": 7.5, "vector": "CVSS:3.1/AV:N", "published": "2023-10-23", "references": []},
                        {"cve_id": "CVE-2023-31122", "description": "Apache mod_macro buffer over-read vulnerability", "severity": "HIGH", "score": 7.5, "vector": "CVSS:3.1/AV:N", "published": "2023-10-23", "references": []},
                    ]
                },
                {
                    "port": 443, "state": "open", "service": "https",
                    "version": "Apache/2.4.57", "banner": "", "cves": []
                },
                {
                    "port": 3306, "state": "open", "service": "mysql",
                    "version": "8.0.35", "banner": "",
                    "cves": [
                        {"cve_id": "CVE-2024-20960", "description": "MySQL Server: Optimizer unspecified vulnerability allows low-privilege attacker DoS", "severity": "MEDIUM", "score": 6.5, "vector": "CVSS:3.1/AV:N", "published": "2024-01-16", "references": []},
                    ]
                },
                {
                    "port": 6379, "state": "open", "service": "redis",
                    "version": "7.2.3", "banner": "", "cves": []
                },
            ]
        },
        {
            "ip": "192.168.1.50",
            "hostname": "dev-machine.local",
            "is_up": True,
            "scan_time": 1.93,
            "ports": [
                {
                    "port": 22, "state": "open", "service": "ssh",
                    "version": "OpenSSH_9.5", "banner": "", "cves": []
                },
                {
                    "port": 5432, "state": "open", "service": "postgresql",
                    "version": "16.1", "banner": "", "cves": []
                },
                {
                    "port": 8080, "state": "open", "service": "http-proxy",
                    "version": "", "banner": "", "cves": []
                },
            ]
        },
    ]
}

generate_html_report(demo_data, "docs/demo_report.html")
print("Demo report generated: docs/demo_report.html")

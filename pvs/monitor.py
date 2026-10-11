# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
PVS Continuous Network Monitor & Webhook Alert Daemon.
Provides 24/7 background security monitoring, port diffing, service version change detection,
threat regression testing, and multi-channel webhook dispatching (Discord, Slack, Telegram, Generic).
"""

import asyncio
import datetime
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from pvs import __version__
from .logger import get_logger
from .scanner import parse_ports, resolve_targets, scan_host, HostResult, PortResult
from .vuln_engine import PVS_DB_PATH, VulnerabilityEngine

logger = get_logger(__name__)

# Dangerous ports that warrant elevated severity when newly opened
CRITICAL_PORTS = {
    21: "FTP (Plaintext)",
    23: "Telnet (Unencrypted remote shell)",
    445: "SMB (File sharing / lateral movement)",
    3389: "RDP (Remote Desktop)",
    5900: "VNC (Remote Framebuffer)",
    6379: "Redis (In-memory database)",
    27017: "MongoDB (NoSQL database)",
    2375: "Docker Daemon (Unauthenticated)",
    9200: "Elasticsearch (Search engine)",
    11211: "Memcached (Cache daemon)",
}


@dataclass
class PortSnapshot:
    """Snapshot representation of an open port."""
    port: int
    state: str = "open"
    service: str = ""
    banner: str = ""
    version: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "banner": self.banner,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PortSnapshot":
        return cls(
            port=d.get("port", 0),
            state=d.get("state", "open"),
            service=d.get("service", ""),
            banner=d.get("banner", ""),
            version=d.get("version", ""),
        )


@dataclass
class TargetSnapshot:
    """Snapshot representation of a target's scanned state at a point in time."""
    target: str
    timestamp: float
    is_up: bool
    ports: List[PortSnapshot] = field(default_factory=list)
    vulns: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "is_up": self.is_up,
            "ports": [p.to_dict() for p in self.ports],
            "vulns": self.vulns,
            "risk_score": self.risk_score,
            "summary": self.summary,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TargetSnapshot":
        ports = [PortSnapshot.from_dict(p) for p in d.get("ports", [])]
        return cls(
            target=d.get("target", ""),
            timestamp=d.get("timestamp", 0.0),
            is_up=d.get("is_up", False),
            ports=ports,
            vulns=d.get("vulns", []),
            risk_score=d.get("risk_score", 0.0),
            summary=d.get("summary", ""),
        )


@dataclass
class MonitorDiff:
    """Detailed difference between two scans of the same target."""
    target: str
    timestamp: float
    new_ports: List[PortSnapshot] = field(default_factory=list)
    closed_ports: List[PortSnapshot] = field(default_factory=list)
    service_changes: List[Dict[str, Any]] = field(default_factory=list)
    new_vulns: List[Dict[str, Any]] = field(default_factory=list)
    resolved_vulns: List[Dict[str, Any]] = field(default_factory=list)
    host_status_change: Optional[str] = None
    risk_delta: float = 0.0
    severity: str = "INFO"

    @property
    def has_changes(self) -> bool:
        return bool(
            self.new_ports
            or self.closed_ports
            or self.service_changes
            or self.new_vulns
            or self.resolved_vulns
            or self.host_status_change
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "has_changes": self.has_changes,
            "severity": self.severity,
            "host_status_change": self.host_status_change,
            "new_ports": [p.to_dict() for p in self.new_ports],
            "closed_ports": [p.to_dict() for p in self.closed_ports],
            "service_changes": self.service_changes,
            "new_vulns": self.new_vulns,
            "resolved_vulns": self.resolved_vulns,
            "risk_delta": round(self.risk_delta, 2),
        }


class MonitorStorage:
    """SQLite persistent storage for monitoring baselines and change events."""

    def __init__(self, db_path: Path = PVS_DB_PATH):
        self.db_path = db_path
        self._ensure_tables()

    def _ensure_tables(self):
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS monitor_snapshots (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        target TEXT NOT NULL,
                        timestamp REAL NOT NULL,
                        is_up INTEGER NOT NULL,
                        open_ports TEXT NOT NULL,
                        vulns TEXT NOT NULL,
                        risk_score REAL NOT NULL,
                        summary TEXT NOT NULL
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS monitor_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        target TEXT NOT NULL,
                        timestamp REAL NOT NULL,
                        event_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        title TEXT NOT NULL,
                        details TEXT NOT NULL
                    )
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_monitor_snapshots_target ON monitor_snapshots(target, timestamp)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_monitor_events_target ON monitor_events(target, timestamp)")
                conn.commit()
        except Exception as e:
            logger.warning(f"Could not initialize monitor database tables: {e}")

    def save_snapshot(self, snapshot: TargetSnapshot):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                ports_json = json.dumps([p.to_dict() for p in snapshot.ports])
                vulns_json = json.dumps(snapshot.vulns)
                cursor.execute("""
                    INSERT INTO monitor_snapshots (target, timestamp, is_up, open_ports, vulns, risk_score, summary)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    snapshot.target,
                    snapshot.timestamp,
                    1 if snapshot.is_up else 0,
                    ports_json,
                    vulns_json,
                    snapshot.risk_score,
                    snapshot.summary,
                ))
                conn.commit()
        except Exception as e:
            logger.warning(f"Error saving monitor snapshot for {snapshot.target}: {e}")

    def get_latest_snapshot(self, target: str) -> Optional[TargetSnapshot]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT target, timestamp, is_up, open_ports, vulns, risk_score, summary
                    FROM monitor_snapshots
                    WHERE target = ?
                    ORDER BY timestamp DESC
                    LIMIT 1
                """, (target,))
                row = cursor.fetchone()
                if not row:
                    return None
                tgt, ts, is_up, ports_json, vulns_json, score, summary = row
                ports_data = json.loads(ports_json) if ports_json else []
                vulns_data = json.loads(vulns_json) if vulns_json else []
                ports = [PortSnapshot.from_dict(p) for p in ports_data]
                return TargetSnapshot(
                    target=tgt,
                    timestamp=ts,
                    is_up=bool(is_up),
                    ports=ports,
                    vulns=vulns_data,
                    risk_score=score,
                    summary=summary,
                )
        except Exception as e:
            logger.warning(f"Error retrieving latest snapshot for {target}: {e}")
            return None

    def record_event(self, target: str, event_type: str, severity: str, title: str, details: Dict[str, Any]):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO monitor_events (target, timestamp, event_type, severity, title, details)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    target,
                    time.time(),
                    event_type,
                    severity,
                    title,
                    json.dumps(details),
                ))
                conn.commit()
        except Exception as e:
            logger.warning(f"Error recording monitor event for {target}: {e}")

    def get_events(self, limit: int = 50, target: Optional[str] = None) -> List[Dict[str, Any]]:
        events = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                if target:
                    cursor.execute("""
                        SELECT id, target, timestamp, event_type, severity, title, details
                        FROM monitor_events
                        WHERE target = ?
                        ORDER BY timestamp DESC
                        LIMIT ?
                    """, (target, limit))
                else:
                    cursor.execute("""
                        SELECT id, target, timestamp, event_type, severity, title, details
                        FROM monitor_events
                        ORDER BY timestamp DESC
                        LIMIT ?
                    """, (limit,))
                for row in cursor.fetchall():
                    eid, tgt, ts, etype, sev, title, det_json = row
                    details = {}
                    try:
                        details = json.loads(det_json) if det_json else {}
                    except Exception:
                        pass
                    events.append({
                        "id": eid,
                        "target": tgt,
                        "timestamp": ts,
                        "iso_time": datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
                        "event_type": etype,
                        "severity": sev,
                        "title": title,
                        "details": details,
                    })
        except Exception as e:
            logger.warning(f"Error reading monitor events: {e}")
        return events

    def clear_history(self, target: Optional[str] = None):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                if target:
                    cursor.execute("DELETE FROM monitor_snapshots WHERE target = ?", (target,))
                    cursor.execute("DELETE FROM monitor_events WHERE target = ?", (target,))
                else:
                    cursor.execute("DELETE FROM monitor_snapshots")
                    cursor.execute("DELETE FROM monitor_events")
                conn.commit()
        except Exception as e:
            logger.warning(f"Error clearing monitor history: {e}")


def compute_diff(previous: Optional[TargetSnapshot], current: TargetSnapshot) -> MonitorDiff:
    """
    Compare current scan state against previous baseline to identify differences.
    """
    diff = MonitorDiff(target=current.target, timestamp=current.timestamp)

    if previous is None:
        # First scan ever: baseline establishment.
        # Report open ports and existing vulnerabilities as initial posture.
        diff.new_ports = list(current.ports)
        diff.new_vulns = list(current.vulns)
        diff.risk_delta = current.risk_score
        diff.severity = "INFO"
        return diff

    # 1. Host status change
    if previous.is_up != current.is_up:
        diff.host_status_change = f"{'ONLINE' if previous.is_up else 'OFFLINE'} ➔ {'ONLINE' if current.is_up else 'OFFLINE'}"

    # 2. Port changes
    prev_ports_map = {p.port: p for p in previous.ports}
    curr_ports_map = {p.port: p for p in current.ports}

    for port_num, p in curr_ports_map.items():
        if port_num not in prev_ports_map:
            diff.new_ports.append(p)
        else:
            old_p = prev_ports_map[port_num]
            if (old_p.service != p.service or old_p.version != p.version or old_p.banner != p.banner):
                diff.service_changes.append({
                    "port": port_num,
                    "old_service": old_p.service,
                    "new_service": p.service,
                    "old_version": old_p.version,
                    "new_version": p.version,
                    "old_banner": old_p.banner,
                    "new_banner": p.banner,
                })

    for port_num, p in prev_ports_map.items():
        if port_num not in curr_ports_map:
            diff.closed_ports.append(p)

    # 3. Vulnerability changes
    def vuln_key(v: Dict[str, Any]) -> str:
        return f"{v.get('cve_id') or v.get('id')}:{v.get('port', 0)}"

    prev_vulns_map = {vuln_key(v): v for v in previous.vulns}
    curr_vulns_map = {vuln_key(v): v for v in current.vulns}

    for v_key, v in curr_vulns_map.items():
        if v_key not in prev_vulns_map:
            diff.new_vulns.append(v)

    for v_key, v in prev_vulns_map.items():
        if v_key not in curr_vulns_map:
            diff.resolved_vulns.append(v)

    # 4. Risk score delta
    diff.risk_delta = round(current.risk_score - previous.risk_score, 2)

    # 5. Severity classification
    # Any new critical vuln or newly opened known critical port -> CRITICAL
    has_crit_vuln = any(v.get("severity") == "CRITICAL" for v in diff.new_vulns)
    has_crit_port = any(p.port in CRITICAL_PORTS for p in diff.new_ports)
    has_high_vuln = any(v.get("severity") == "HIGH" for v in diff.new_vulns)

    if has_crit_vuln or has_crit_port:
        diff.severity = "CRITICAL"
    elif has_high_vuln or diff.new_ports:
        diff.severity = "HIGH"
    elif diff.service_changes or any(v.get("severity") == "MEDIUM" for v in diff.new_vulns):
        diff.severity = "MEDIUM"
    elif diff.resolved_vulns or diff.closed_ports:
        diff.severity = "LOW"
    elif diff.host_status_change:
        diff.severity = "MEDIUM"
    else:
        diff.severity = "INFO"

    return diff


class WebhookDispatcher:
    """
    High-reliability multi-channel webhook dispatcher for:
      • Discord (Rich embed cards with severity colors)
      • Slack (Block kit format)
      • Telegram (HTML formatted messages)
      • Generic HTTP Webhook (Enterprise JSON schema)
    """

    @staticmethod
    def detect_channel_type(url: str) -> str:
        url_lower = url.lower()
        if "discord.com/api/webhooks" in url_lower or "discordapp.com/api/webhooks" in url_lower:
            return "discord"
        elif "hooks.slack.com" in url_lower:
            return "slack"
        elif "api.telegram.org" in url_lower:
            return "telegram"
        return "generic"

    @classmethod
    def _format_discord(cls, diff: MonitorDiff, target_label: str) -> Dict[str, Any]:
        sev = diff.severity.upper()
        # Discord Embed Colors (Decimal)
        color_map = {
            "CRITICAL": 0xDC2626,  # Red
            "HIGH": 0xEA580C,      # Orange
            "MEDIUM": 0xD97706,    # Amber
            "LOW": 0x16A34A,       # Green
            "INFO": 0x2563EB,      # Blue
        }
        color = color_map.get(sev, 0x6B7280)

        fields = []

        if diff.host_status_change:
            fields.append({
                "name": "🌐 Host Status Change",
                "value": diff.host_status_change,
                "inline": False,
            })

        if diff.new_ports:
            port_lines = []
            for p in diff.new_ports:
                crit_tag = f" ⚠️ [b]CRITICAL ({CRITICAL_PORTS[p.port]})[/]" if p.port in CRITICAL_PORTS else ""
                port_lines.append(f"• **Port {p.port}** ({p.service or 'unknown'}){crit_tag}")
            fields.append({
                "name": f"🚨 Newly Opened Ports ({len(diff.new_ports)})",
                "value": "\n".join(port_lines[:10]),
                "inline": False,
            })

        if diff.closed_ports:
            fields.append({
                "name": f"🔒 Closed / Filtered Ports ({len(diff.closed_ports)})",
                "value": ", ".join(f"Port {p.port}" for p in diff.closed_ports[:15]),
                "inline": False,
            })

        if diff.new_vulns:
            vuln_lines = []
            for v in diff.new_vulns:
                vid = v.get("cve_id") or v.get("id") or "VULN"
                sev_tag = v.get("severity", "UNKNOWN")
                title = v.get("title", "")[:60]
                vuln_lines.append(f"• **[{sev_tag}] {vid}** — {title}")
            fields.append({
                "name": f"🔥 New Vulnerabilities Detected ({len(diff.new_vulns)})",
                "value": "\n".join(vuln_lines[:8]),
                "inline": False,
            })

        if diff.resolved_vulns:
            res_lines = []
            for v in diff.resolved_vulns:
                vid = v.get("cve_id") or v.get("id") or "VULN"
                res_lines.append(f"• ✅ **{vid}** fixed/remediated")
            fields.append({
                "name": f"🎉 Remediated Threats ({len(diff.resolved_vulns)})",
                "value": "\n".join(res_lines[:10]),
                "inline": False,
            })

        if diff.service_changes:
            chg_lines = []
            for c in diff.service_changes:
                chg_lines.append(f"• Port {c['port']}: {c['old_service']} ➔ {c['new_service']} ({c.get('new_version') or 'updated'})")
            fields.append({
                "name": f"🔄 Service / Version Changes ({len(diff.service_changes)})",
                "value": "\n".join(chg_lines[:8]),
                "inline": False,
            })

        # Risk delta
        if diff.risk_delta != 0.0:
            sign = "+" if diff.risk_delta > 0 else ""
            fields.append({
                "name": "📊 Security Risk Delta",
                "value": f"{sign}{diff.risk_delta:.2f} points",
                "inline": True,
            })

        embed = {
            "title": f"🛡️ [PVS Monitor] Security State Change: {target_label or diff.target}",
            "description": f"**Severity:** `{sev}` | **Timestamp:** <t:{int(diff.timestamp)}:R>",
            "color": color,
            "fields": fields,
            "footer": {
                "text": f"PVS Continuous Security Monitor v{__version__}",
            },
            "timestamp": datetime.datetime.fromtimestamp(diff.timestamp, datetime.timezone.utc).isoformat(),
        }

        return {"embeds": [embed]}

    @classmethod
    def _format_slack(cls, diff: MonitorDiff, target_label: str) -> Dict[str, Any]:
        sev = diff.severity.upper()
        emoji_map = {
            "CRITICAL": "🚨",
            "HIGH": "⚠️",
            "MEDIUM": "🔔",
            "LOW": "✅",
            "INFO": "ℹ️",
        }
        emoji = emoji_map.get(sev, "ℹ️")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} [PVS Monitor] Alert: {target_label or diff.target}",
                    "emoji": True,
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Severity:* `{sev}` | *Target:* `{diff.target}` | *Time:* <!date^{int(diff.timestamp)}^{{date_num}} {{time_secs}}|{diff.timestamp}>",
                }
            },
            {"type": "divider"}
        ]

        if diff.new_ports:
            ports_text = "\n".join(f"• *Port {p.port}* ({p.service or 'unknown'})" for p in diff.new_ports[:10])
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*🚨 Newly Opened Ports:*\n{ports_text}"}
            })

        if diff.new_vulns:
            vuln_text = "\n".join(f"• *[{v.get('severity')}] {v.get('cve_id') or v.get('id')}* - {v.get('title', '')[:60]}" for v in diff.new_vulns[:8])
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*🔥 New Vulnerabilities Detected:*\n{vuln_text}"}
            })

        if diff.resolved_vulns:
            res_text = "\n".join(f"• ✅ *{v.get('cve_id') or v.get('id')}* remediated" for v in diff.resolved_vulns[:8])
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*🎉 Remediated Threats:*\n{res_text}"}
            })

        return {"blocks": blocks}

    @classmethod
    def _format_generic(cls, diff: MonitorDiff, target_label: str) -> Dict[str, Any]:
        return {
            "source": "PVS",
            "version": __version__,
            "event": "monitor_diff_alert",
            "target": target_label or diff.target,
            "timestamp": diff.timestamp,
            "iso_time": datetime.datetime.fromtimestamp(diff.timestamp, datetime.timezone.utc).isoformat(),
            "severity": diff.severity,
            "diff": diff.to_dict(),
        }

    @classmethod
    def send_webhook_sync(cls, webhook_url: str, diff: MonitorDiff, target_label: str = "") -> bool:
        """Synchronously deliver formatted alert payload to specified webhook URL."""
        channel_type = cls.detect_channel_type(webhook_url)

        if channel_type == "discord":
            payload = cls._format_discord(diff, target_label)
        elif channel_type == "slack":
            payload = cls._format_slack(diff, target_label)
        elif channel_type == "telegram":
            # For Telegram: extract chat_id or send HTML formatted text
            text = (
                f"🛡️ <b>[PVS Security Alert]</b>\n"
                f"<b>Target:</b> {target_label or diff.target}\n"
                f"<b>Severity:</b> {diff.severity}\n"
            )
            if diff.new_ports:
                text += f"🚨 <b>New Ports:</b> {', '.join(str(p.port) for p in diff.new_ports)}\n"
            if diff.new_vulns:
                text += f"🔥 <b>New Vulns:</b> {len(diff.new_vulns)} detected\n"
            if diff.resolved_vulns:
                text += f"✅ <b>Remediated:</b> {len(diff.resolved_vulns)} fixed\n"
            payload = {"text": text, "parse_mode": "HTML"}
        else:
            payload = cls._format_generic(diff, target_label)

        try:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                webhook_url,
                data=req_data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": f"PVS-Monitor/{__version__}",
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                status = getattr(resp, "status", 200)
                try:
                    status_int = int(status)
                except (ValueError, TypeError):
                    status_int = 200
                return 200 <= status_int < 300
        except urllib.error.HTTPError as e:
            logger.error(f"Webhook HTTP error {e.code}: {e.read().decode('utf-8', errors='ignore')}")
            return False
        except Exception as e:
            logger.error(f"Failed to deliver webhook alert: {e}")
            return False

    @classmethod
    async def send_webhook(cls, webhook_url: str, diff: MonitorDiff, target_label: str = "") -> bool:
        """Asynchronously send webhook notification via executor thread."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, cls.send_webhook_sync, webhook_url, diff, target_label)

    @classmethod
    async def send_test_alert(cls, webhook_url: str) -> bool:
        """Send a test verification alert to validate webhook connectivity."""
        test_diff = MonitorDiff(
            target="127.0.0.1 (Self-Test)",
            timestamp=time.time(),
            new_ports=[PortSnapshot(port=8484, state="open", service="http-pvs", version=__version__)],
            new_vulns=[],
            resolved_vulns=[{"id": "TEST-RESOLVED", "cve_id": "CVE-2026-TEST", "title": "Verification Alert"}],
            severity="INFO",
            risk_delta=0.0,
        )
        return await cls.send_webhook(webhook_url, test_diff, target_label="PVS Sentinel Test")


async def perform_monitor_cycle(
    target: str,
    ports_preset: str = "top100",
    timeout: float = 1.5,
    concurrency: int = 100,
    storage: Optional[MonitorStorage] = None,
    webhook_url: Optional[str] = None,
    alert_on: str = "all",
    on_event_cb: Optional[Callable[[MonitorDiff], None]] = None,
) -> MonitorDiff:
    """
    Perform a single scan-and-diff cycle against a target.
    Updates baseline snapshot and dispatches alerts if changes are discovered.
    """
    if storage is None:
        storage = MonitorStorage()

    ports = parse_ports(ports_preset)
    host_res = await scan_host(target, ports, timeout=timeout, concurrency=concurrency)

    # Lookup CVEs / active probes
    vuln_engine = VulnerabilityEngine(offline_mode=False)
    vuln_list = []
    total_risk = 0.0

    if host_res.is_up or host_res.ports:
        for p in host_res.ports:
            cves = await vuln_engine.audit_and_lookup_cves_async(
                ip=target, port=p.port, service=p.service, banner=p.banner, tls_info=p.tls_info
            )
            for cve in cves:
                cve_dict = {
                    "id": cve.id,
                    "cve_id": cve.id,
                    "port": p.port,
                    "service": p.service,
                    "severity": cve.severity,
                    "cvss_score": cve.cvss_score,
                    "title": cve.description[:120] if cve.description else f"{cve.id} on port {p.port}",
                    "epss": getattr(cve, "epss_score", 0.0),
                    "kev": getattr(cve, "in_cisa_kev", False),
                }
                vuln_list.append(cve_dict)
                # Risk calculation weight
                if cve.severity == "CRITICAL":
                    total_risk += 10.0
                elif cve.severity == "HIGH":
                    total_risk += 7.0
                elif cve.severity == "MEDIUM":
                    total_risk += 4.0
                else:
                    total_risk += 1.0

    port_snapshots = [
        PortSnapshot(
            port=p.port,
            state=p.state,
            service=p.service,
            banner=p.banner,
            version=p.version,
        )
        for p in host_res.ports
    ]

    current_snapshot = TargetSnapshot(
        target=target,
        timestamp=time.time(),
        is_up=host_res.is_up or bool(host_res.ports),
        ports=port_snapshots,
        vulns=vuln_list,
        risk_score=round(total_risk, 2),
        summary=f"{len(port_snapshots)} open ports, {len(vuln_list)} vulnerabilities",
    )

    previous_snapshot = storage.get_latest_snapshot(target)
    diff = compute_diff(previous_snapshot, current_snapshot)

    # Persist the latest snapshot
    storage.save_snapshot(current_snapshot)

    # If changes detected, record events in database
    if diff.has_changes:
        if diff.new_ports:
            storage.record_event(
                target=target,
                event_type="NEW_PORTS",
                severity="HIGH" if not any(p.port in CRITICAL_PORTS for p in diff.new_ports) else "CRITICAL",
                title=f"Newly opened ports detected: {', '.join(str(p.port) for p in diff.new_ports)}",
                details={"new_ports": [p.to_dict() for p in diff.new_ports]},
            )
        if diff.closed_ports:
            storage.record_event(
                target=target,
                event_type="CLOSED_PORTS",
                severity="LOW",
                title=f"Ports closed: {', '.join(str(p.port) for p in diff.closed_ports)}",
                details={"closed_ports": [p.to_dict() for p in diff.closed_ports]},
            )
        if diff.service_changes:
            storage.record_event(
                target=target,
                event_type="SERVICE_CHANGE",
                severity="MEDIUM",
                title=f"Service or version modified on {len(diff.service_changes)} port(s)",
                details={"changes": diff.service_changes},
            )
        if diff.new_vulns:
            storage.record_event(
                target=target,
                event_type="NEW_VULNS",
                severity="CRITICAL" if any(v.get("severity") == "CRITICAL" for v in diff.new_vulns) else "HIGH",
                title=f"{len(diff.new_vulns)} new threat(s) or CVE(s) identified",
                details={"vulns": diff.new_vulns},
            )
        if diff.resolved_vulns:
            storage.record_event(
                target=target,
                event_type="RESOLVED_VULNS",
                severity="LOW",
                title=f"{len(diff.resolved_vulns)} threat(s) remediated and eliminated",
                details={"vulns": diff.resolved_vulns},
            )

        # Notify via callback if provided
        if on_event_cb:
            try:
                on_event_cb(diff)
            except Exception as e:
                logger.warning(f"Error in monitor callback: {e}")

        # Check alert_on filter for webhook
        should_alert = False
        if alert_on == "all":
            should_alert = True
        elif alert_on == "ports" and (diff.new_ports or diff.closed_ports):
            should_alert = True
        elif alert_on == "vulns" and (diff.new_vulns or diff.resolved_vulns):
            should_alert = True
        elif alert_on == "critical" and diff.severity == "CRITICAL":
            should_alert = True

        if webhook_url and should_alert:
            await WebhookDispatcher.send_webhook(webhook_url, diff)

    return diff


async def start_monitor_daemon(
    targets: List[str],
    ports_preset: str = "top100",
    interval: int = 300,
    webhook_url: Optional[str] = None,
    alert_on: str = "all",
    once: bool = False,
    max_cycles: Optional[int] = None,
    on_event_cb: Optional[Callable[[MonitorDiff], None]] = None,
) -> int:
    """
    Run continuous monitoring loop across targets with periodic diffing and alerting.
    Returns 0 on success, or 1 if severe changes were found in 'once' mode.
    """
    from .display import console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box

    storage = MonitorStorage()
    cycle = 0
    severe_changes_found = False

    console.print(Panel(
        f"[bold white]Target Scope :[/] [cyan]{', '.join(targets)}[/]\n"
        f"[bold white]Port Preset  :[/] [green]{ports_preset}[/]\n"
        f"[bold white]Poll Interval:[/] [yellow]{interval} seconds[/]\n"
        f"[bold white]Webhook Alert:[/] [magenta]{webhook_url or 'Disabled (Console Only)'}[/]\n"
        f"[bold white]Alert Filter :[/] [bold]{alert_on.upper()}[/]\n"
        f"[bold white]Mode         :[/] [cyan]{'Single Audit Pass (--once)' if once else 'Continuous Daemon'}[/]",
        title="[bold cyan]🛡️ PVS SENTINEL — CONTINUOUS THREAT MONITOR[/]",
        border_style="cyan",
        box=box.ROUNDED,
    ))

    try:
        while True:
            cycle += 1
            now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            console.print(f"\n[dim][{now_str}][/] [bold cyan]Starting Monitor Cycle #{cycle}...[/]")

            for target in targets:
                diff = await perform_monitor_cycle(
                    target=target,
                    ports_preset=ports_preset,
                    storage=storage,
                    webhook_url=webhook_url,
                    alert_on=alert_on,
                    on_event_cb=on_event_cb,
                )

                if not diff.has_changes:
                    console.print(f"  [dim]✔ {target}: Baseline intact. Zero security posture drift.[/]")
                else:
                    # Print Diff Table
                    t = Table(title=f"⚡ State Changes Detected: {target}", box=box.ROUNDED, border_style="yellow")
                    t.add_column("Category", style="bold")
                    t.add_column("Details", style="white")
                    t.add_column("Impact", style="bold")

                    if diff.new_ports:
                        p_str = ", ".join(f"{p.port}/{p.service}" for p in diff.new_ports)
                        t.add_row("[red]New Open Ports[/]", p_str, "[bold red]EXPOSED ATTACK SURFACE[/]")
                    if diff.closed_ports:
                        p_str = ", ".join(f"{p.port}" for p in diff.closed_ports)
                        t.add_row("[green]Closed Ports[/]", p_str, "[dim green]Port Closed[/]")
                    if diff.service_changes:
                        chg_str = "\n".join(f"{c['port']}: {c['old_service']} ➔ {c['new_service']}" for c in diff.service_changes)
                        t.add_row("[yellow]Service Modified[/]", chg_str, "[yellow]Version Drift[/]")
                    if diff.new_vulns:
                        v_str = "\n".join(f"[{v.get('severity')}] {v.get('cve_id') or v.get('id')}: {v.get('title')[:50]}" for v in diff.new_vulns[:5])
                        t.add_row("[red]New Vulnerabilities[/]", v_str, f"[bold red]{len(diff.new_vulns)} CVE(s)[/]")
                    if diff.resolved_vulns:
                        r_str = "\n".join(f"{v.get('cve_id') or v.get('id')}" for v in diff.resolved_vulns[:5])
                        t.add_row("[green]Remediated Threats[/]", r_str, "[bold green]REMEDIATED[/]")

                    console.print(t)
                    if diff.severity in ("CRITICAL", "HIGH"):
                        severe_changes_found = True

            if once:
                break

            if max_cycles and cycle >= max_cycles:
                break

            console.print(f"[dim]Sleeping for {interval}s until next audit cycle (Press Ctrl+C to stop)...[/]")
            await asyncio.sleep(interval)

    except (KeyboardInterrupt, asyncio.CancelledError):
        console.print("\n[yellow]PVS Monitor stopped gracefully.[/]")
        return 0

    return 1 if (once and severe_changes_found) else 0

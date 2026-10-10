# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
Unit tests for pvs/web_ui.py.
"""

import pytest
import json
import io
from pvs.web_ui import PVSWebHandler, _STATE


class MockSocket:
    def __init__(self, request_bytes):
        self.rfile = io.BytesIO(request_bytes)
        self.output = io.BytesIO()

    def makefile(self, mode, *args, **kwargs):
        if "r" in mode:
            return self.rfile
        return self

    def sendall(self, data):
        self.output.write(data)

    def write(self, data):
        self.output.write(data)

    def flush(self):
        pass

    def getresponse(self):
        return self.output.getvalue().decode("utf-8", errors="replace")



def test_web_ui_get_html_page():
    """Test serving the main HTML SPA interface."""
    req = b"GET / HTTP/1.1\r\nHost: localhost:8484\r\n\r\n"
    sock = MockSocket(req)

    # Instantiate handler with mocks
    handler = PVSWebHandler(sock, ("127.0.0.1", 12345), None)
    resp = sock.getresponse()
    assert "200" in resp
    assert "PVS" in resp
    assert "Security Dashboard" in resp
    assert "Interactive Network Topology Visualizer" in resp


def test_web_ui_get_scan_status():
    """Test /api/scan/status endpoint returning JSON state."""
    _STATE["is_scanning"] = False
    _STATE["progress"] = 42
    _STATE["status_message"] = "Scanning in progress"

    req = b"GET /api/scan/status HTTP/1.1\r\nHost: localhost:8484\r\n\r\n"
    sock = MockSocket(req)
    handler = PVSWebHandler(sock, ("127.0.0.1", 12345), None)
    resp = sock.getresponse()
    assert "200" in resp
    assert '"progress": 42' in resp
    assert "Scanning in progress" in resp


def test_web_ui_get_fix_script():
    """Test /api/fix/script endpoint returning remediation script."""
    _STATE["last_scan_data"] = {
        "target": "127.0.0.1",
        "cve_results": {
            "127.0.0.1:22": [{"cve_id": "CVE-2024-6387", "severity": "CRITICAL", "score": 8.1}]
        }
    }
    req = b"GET /api/fix/script HTTP/1.1\r\nHost: localhost:8484\r\n\r\n"
    sock = MockSocket(req)
    handler = PVSWebHandler(sock, ("127.0.0.1", 12345), None)
    resp = sock.getresponse()
    assert "200" in resp
    assert "script" in resp
    assert "rollback_script" in resp


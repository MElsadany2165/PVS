# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

import pytest
from pvs.scanner import get_local_ip, get_local_subnet


def test_get_local_ip():
    ip = get_local_ip()
    assert isinstance(ip, str)
    assert len(ip.split(".")) == 4 or ip == "127.0.0.1"


def test_get_local_subnet():
    subnet = get_local_subnet()
    assert isinstance(subnet, str)
    assert "/" in subnet or subnet == "127.0.0.1"

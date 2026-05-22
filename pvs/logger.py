# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

# logger.py - basic logging setup
# nothing fancy here, just wanted consistent log formatting across modules

import logging
import sys

LOG_FMT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
DATE_FMT = "%H:%M:%S"

_already_setup = False  # prevent duplicate handlers if called twice


def setup_logging(level="INFO", log_file=None):
    """Set up logging once. Calling this multiple times is safe (it no-ops)."""
    global _already_setup
    if _already_setup:
        return

    numeric = getattr(logging, level.upper(), logging.INFO)

    handlers = [logging.StreamHandler(sys.stderr)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=numeric,
        format=LOG_FMT,
        datefmt=DATE_FMT,
        handlers=handlers,
    )
    _already_setup = True


def get_logger(name):
    """Shortcut so I don't have to type logging.getLogger everywhere."""
    return logging.getLogger(name)

# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

import os
import sys

# Add parent directory to sys.path to allow imports from pvs package when run as script
if not __package__:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)

from pvs.cli import main

if __name__ == "__main__":
    sys.exit(main() or 0)


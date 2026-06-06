#!/usr/bin/env python3
"""Compatibility wrapper for running the Opsbook stats agent from a repo checkout."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = ROOT / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from kairix.stats_agent import main


if __name__ == "__main__":
    raise SystemExit(main())

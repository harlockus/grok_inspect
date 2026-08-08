"""OS family and privilege detection."""

from __future__ import annotations

import os
import platform
import sys
from typing import Any


def os_family() -> str:
    s = sys.platform
    if s.startswith("darwin"):
        return "darwin"
    if s.startswith("win"):
        return "windows"
    if s.startswith("linux"):
        return "linux"
    return s


def is_elevated() -> bool:
    family = os_family()
    if family == "windows":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        return False


def probe_host() -> dict[str, Any]:
    return {
        "os_family": os_family(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "hostname": platform.node(),
        "python": platform.python_version(),
        "username": os.environ.get("USER") or os.environ.get("USERNAME") or "",
        "elevated": is_elevated(),
    }

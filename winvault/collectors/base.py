"""Collector base class and small helpers shared by all collectors.

A collector returns a flat mapping of ``stable_key -> attributes``. The key
must identify the same object across two snapshots (e.g. a service name or a
registry value path) so the comparison engine can pair them up.

Attributes whose name starts with ``_`` are *metadata*: they are stored in the
snapshot as evidence (timestamps, last-write times) but ignored when deciding
whether an object was modified, because they change constantly.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


class CollectorError(RuntimeError):
    pass


class Collector:
    name: str = "base"
    description: str = ""

    def collect(self) -> dict[str, dict]:
        raise NotImplementedError


def is_windows() -> bool:
    return sys.platform == "win32"


def is_admin() -> bool:
    if not is_windows():
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def sha256_file(path: str | Path, chunk: int = 1 << 20) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while block := fh.read(chunk):
                h.update(block)
        return h.hexdigest()
    except OSError:
        return None


def iso_from_timestamp(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def filetime_to_iso(filetime: int) -> str | None:
    """Convert a Windows FILETIME (100 ns ticks since 1601-01-01) to ISO-8601 UTC."""
    if not filetime:
        return None
    epoch_diff = 116444736000000000
    try:
        return iso_from_timestamp((filetime - epoch_diff) / 10_000_000)
    except (OverflowError, OSError, ValueError):
        return None


# Windows programs WinVault starts, by their location under %SystemRoot%. Starting them
# by full path means a writable directory earlier on PATH can't substitute a look-alike
# (WinVault runs elevated).
SYSTEM_TOOLS = {
    "powershell.exe": r"System32\WindowsPowerShell\v1.0\powershell.exe",
    "icacls.exe": r"System32\icacls.exe",
    "auditpol.exe": r"System32\auditpol.exe",
    "wevtutil.exe": r"System32\wevtutil.exe",
    "taskkill.exe": r"System32\taskkill.exe",
    "tasklist.exe": r"System32\tasklist.exe",
    "explorer.exe": r"explorer.exe",
}


def system_tool(name: str) -> str:
    """Absolute path of a built-in Windows program (falls back to the bare name off Windows
    or if Windows is installed somewhere unusual, so tests and odd setups still work)."""
    rel = SYSTEM_TOOLS.get(name.lower())
    root = os.environ.get("SystemRoot") or os.environ.get("windir")
    if rel and root:
        path = Path(root, *rel.split("\\"))
        if path.is_file():
            return str(path)
    return name


_DTD_MARKERS = ("<!DOCTYPE", "<!ENTITY")


def safe_fromstring(data):
    """xml.etree.ElementTree.fromstring that refuses any DTD.

    Task definitions and event records never contain a DTD, so one appearing means the
    input was crafted (entity expansion / external entity tricks). Refusing it keeps the
    standard-library parser safe without adding a dependency."""
    import xml.etree.ElementTree as ET
    if isinstance(data, (bytes, bytearray)):
        probes = [m.encode(enc) for m in _DTD_MARKERS for enc in ("utf-8", "utf-16-le", "utf-16-be")]
        if any(p in data for p in probes):
            raise ET.ParseError("XML with a DTD/entity declaration was refused")
    elif any(m in data for m in _DTD_MARKERS):
        raise ET.ParseError("XML with a DTD/entity declaration was refused")
    return ET.fromstring(data)  # nosec B314 - any DTD/entity declaration was refused above


def run_powershell_json(script: str, timeout: int = 120):
    """Run a Windows PowerShell snippet and parse its JSON output."""
    cmd = [
        system_tool("powershell.exe"),
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + script,
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CollectorError(f"PowerShell failed: {exc}") from exc
    out = proc.stdout.decode("utf-8", errors="replace").strip()
    if proc.returncode != 0 or not out:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        raise CollectorError(f"PowerShell exited {proc.returncode}: {err[:500]}")
    return json.loads(out)


def as_list(value) -> list:
    """PowerShell's ConvertTo-Json collapses 1-element arrays; undo that."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]

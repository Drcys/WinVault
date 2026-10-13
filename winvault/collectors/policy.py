"""Security policy collector: password and lockout policy, user rights assignments,
and the advanced audit policy.

`secedit /export` and `auditpol /backup` both write files whose *keys* are
language-independent (policy names, privilege constants, subcategory GUIDs and a
numeric setting value), so the result is the same on Arabic, English or any
other Windows installation. Both need an elevated prompt.
"""

from __future__ import annotations

import csv
import io
import subprocess
import tempfile
from pathlib import Path

from .base import Collector, CollectorError, is_windows, system_tool

SENSITIVE_RIGHTS = {
    "SeDebugPrivilege", "SeTcbPrivilege", "SeBackupPrivilege", "SeRestorePrivilege",
    "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege", "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege", "SeCreateTokenPrivilege", "SeSecurityPrivilege",
    "SeRemoteInteractiveLogonRight", "SeEnableDelegationPrivilege", "SeManageVolumePrivilege",
}


def _decode(raw: bytes) -> str:
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8", errors="replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def parse_secedit(text: str) -> dict[str, dict]:
    """[System Access] and [Privilege Rights] sections of a secedit export."""
    items: dict[str, dict] = {}
    section = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if "=" not in line:
            continue
        key, value = (x.strip() for x in line.split("=", 1))
        if section == "System Access":
            v = value.strip('"')
            items[f"access:{key}"] = {"name": key, "value": int(v) if v.lstrip("-").isdigit() else v}
        elif section == "Privilege Rights":
            members = sorted({m.strip().lstrip("*") for m in value.split(",") if m.strip()})
            items[f"right:{key}"] = {"name": key, "members": members, "sensitive": key in SENSITIVE_RIGHTS}
    return items


def parse_audit_backup(text: str) -> dict[str, dict]:
    """auditpol /backup CSV: one row per subcategory; 'Setting Value' 0-3 (none/success/failure/both)."""
    items: dict[str, dict] = {}
    rows = list(csv.reader(io.StringIO(text.strip())))
    if not rows:
        return items
    header = [h.strip() for h in rows[0]]

    def col(row, name):
        try:
            return row[header.index(name)].strip()
        except (ValueError, IndexError):
            return ""

    for row in rows[1:]:
        guid, sub, value = col(row, "Subcategory GUID"), col(row, "Subcategory"), col(row, "Setting Value")
        if guid:
            items[f"audit:{guid.upper()}"] = {"guid": guid.upper(), "setting": int(value) if value.isdigit() else None,
                                             "_subcategory": sub}
        elif sub.lower().startswith("option:"):
            items[f"auditoption:{sub[7:]}"] = {"name": sub[7:], "value": value}
    return items


def _run(args: list[str]) -> None:
    try:
        proc = subprocess.run([system_tool(args[0]), *args[1:]], capture_output=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CollectorError(f"{args[0]} failed: {exc}") from exc
    if proc.returncode != 0:
        raise CollectorError(f"{args[0]} exited {proc.returncode} - run WinVault from an elevated prompt")


class PolicyCollector(Collector):
    name = "policy"
    description = "Password/lockout policy, user rights assignments, advanced audit policy"

    def collect(self) -> dict[str, dict]:
        if not is_windows():
            raise CollectorError("policy collector requires Windows")
        items: dict[str, dict] = {}
        with tempfile.TemporaryDirectory(prefix="winvault-") as tmp:
            inf, audit = Path(tmp) / "secpol.inf", Path(tmp) / "audit.csv"
            _run(["secedit.exe", "/export", "/cfg", str(inf), "/areas", "SECURITYPOLICY", "USER_RIGHTS", "/quiet"])
            items.update(parse_secedit(_decode(inf.read_bytes())))
            _run(["auditpol.exe", "/backup", f"/file:{audit}"])
            items.update(parse_audit_backup(_decode(audit.read_bytes())))
        return items

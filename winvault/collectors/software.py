"""Installed software collector: the Uninstall entries Windows shows in
"Installed apps", for the machine (64- and 32-bit views) and every loaded user hive."""

from __future__ import annotations

import re

from . import regutil
from .base import Collector, CollectorError, is_windows

UNINSTALL = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
UNINSTALL_32 = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
_USER_SID = re.compile(r"^S-1-5-21-[\d-]+$")


def entry(values: dict, scope: str, subkey: str, last_write: str | None) -> dict | None:
    name = values.get("DisplayName")
    if not name:
        return None                                   # components without a display name aren't "apps"
    return {
        "display_name": str(name),
        "display_version": regutil.plain(values.get("DisplayVersion")),
        "publisher": regutil.plain(values.get("Publisher")),
        "install_location": regutil.plain(values.get("InstallLocation")) or None,
        "uninstall_string": regutil.plain(values.get("UninstallString")),
        "system_component": bool(values.get("SystemComponent")),
        "scope": scope,
        "subkey": subkey,
        "_install_date": regutil.plain(values.get("InstallDate")),
        "_key_last_write": last_write,
    }


class SoftwareCollector(Collector):
    name = "software"
    description = "Installed software (Uninstall entries, machine and per-user)"

    def collect(self) -> dict[str, dict]:
        if not is_windows():
            raise CollectorError("software collector requires Windows")
        roots = [("machine", "HKLM", UNINSTALL), ("machine-x86", "HKLM", UNINSTALL_32)]
        for sid in regutil.subkeys("HKU", ""):
            if _USER_SID.match(sid):
                roots.append((sid, "HKU", sid + "\\" + UNINSTALL))
        items: dict[str, dict] = {}
        for scope, hive, path in roots:
            for sub in regutil.subkeys(hive, path):
                got = regutil.read_values(hive, path + "\\" + sub)
                if got is None:
                    continue
                item = entry(got[0], scope, sub, got[1])
                if item:
                    items[f"{scope}:{sub}"] = item
        return items

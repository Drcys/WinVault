"""Small read-only helpers over winreg shared by the v1.2 collectors.

Everything opens keys with KEY_READ in the native 64-bit view; callers list
WOW6432Node paths explicitly when they want the 32-bit view.
"""

from __future__ import annotations

from .base import filetime_to_iso

HKLM = "HKLM"


def _winreg():
    import winreg
    return winreg


def _root(hive: str):
    winreg = _winreg()
    return {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKU": winreg.HKEY_USERS}[hive]


def open_key(hive: str, path: str):
    winreg = _winreg()
    try:
        return winreg.OpenKey(_root(hive), path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
    except OSError:
        return None


def read_values(hive: str, path: str) -> tuple[dict, str | None] | None:
    """All values of a key as {name: data} plus the key's last-write time, or None if absent."""
    winreg = _winreg()
    key = open_key(hive, path)
    if key is None:
        return None
    with key:
        _, n_values, last_write = winreg.QueryInfoKey(key)
        values = {}
        for i in range(n_values):
            try:
                name, data, _type = winreg.EnumValue(key, i)
            except OSError:
                continue
            values[name] = data
        return values, filetime_to_iso(last_write)


def subkeys(hive: str, path: str) -> list[str]:
    winreg = _winreg()
    key = open_key(hive, path)
    if key is None:
        return []
    names = []
    with key:
        i = 0
        while True:
            try:
                names.append(winreg.EnumKey(key, i))
            except OSError:
                break
            i += 1
    return names


def plain(value):
    """JSON-friendly registry data."""
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    if isinstance(value, list):
        return [str(x) for x in value]
    return value

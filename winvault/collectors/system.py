"""System configuration collector: security-critical OS settings and program-hijack keys.

* A fixed list of registry settings attackers change to weaken a host: UAC, Remote
  Desktop and NLA, LSA protection and NTLM level, WDigest clear-text credentials,
  SMBv1 and signing, Windows Update and PowerShell logging policies, Defender and
  WinRM policies. Absent values are recorded as None, so creating one is a change.
* Image File Execution Options "Debugger" values and SilentProcessExit monitors,
  which make Windows start another program instead of / after the named one
  (T1546.012), including the sticky-keys accessibility backdoor (T1546.008).
"""

from __future__ import annotations

from . import regutil
from .base import Collector, CollectorError, is_windows

POLICIES_SYSTEM = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
TS = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
LSA = r"SYSTEM\CurrentControlSet\Control\Lsa"
LANMAN = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

# (setting name, key under HKLM, value name)
SETTINGS: list[tuple[str, str, str]] = [
    ("UAC_EnableLUA", POLICIES_SYSTEM, "EnableLUA"),
    ("UAC_ConsentPromptBehaviorAdmin", POLICIES_SYSTEM, "ConsentPromptBehaviorAdmin"),
    ("UAC_PromptOnSecureDesktop", POLICIES_SYSTEM, "PromptOnSecureDesktop"),
    ("UAC_LocalAccountTokenFilterPolicy", POLICIES_SYSTEM, "LocalAccountTokenFilterPolicy"),
    ("RDP_fDenyTSConnections", TS, "fDenyTSConnections"),
    ("RDP_Policy_fDenyTSConnections", r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "fDenyTSConnections"),
    ("RDP_UserAuthentication", TS + r"\WinStations\RDP-Tcp", "UserAuthentication"),
    ("RDP_PortNumber", TS + r"\WinStations\RDP-Tcp", "PortNumber"),
    ("LSA_RunAsPPL", LSA, "RunAsPPL"),
    ("LSA_LmCompatibilityLevel", LSA, "LmCompatibilityLevel"),
    ("LSA_NoLMHash", LSA, "NoLMHash"),
    ("LSA_RestrictAnonymous", LSA, "RestrictAnonymous"),
    ("WDigest_UseLogonCredential", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential"),
    ("SMB1_Server", LANMAN, "SMB1"),
    ("SMB_RequireSecuritySignature", LANMAN, "RequireSecuritySignature"),
    ("WU_NoAutoUpdate", r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate"),
    ("PS_ExecutionPolicy", r"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "ExecutionPolicy"),
    ("PS_ScriptBlockLogging", r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging"),
    ("Defender_Policy_DisableAntiSpyware", r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware"),
    ("Defender_Policy_DisableRealtimeMonitoring", r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
     "DisableRealtimeMonitoring"),
    ("WinRM_AllowUnencryptedTraffic", r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service", "AllowUnencryptedTraffic"),
]

IFEO = [("x64", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"),
        ("x86", r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")]
SILENT_EXIT = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"


class SystemCollector(Collector):
    name = "system"
    description = "Security-critical OS settings (UAC, RDP, LSA, WDigest, SMB, PowerShell...) and IFEO hijacks"

    def collect(self) -> dict[str, dict]:
        if not is_windows():
            raise CollectorError("system collector requires Windows")
        items: dict[str, dict] = {}
        cache: dict[str, tuple[dict, str | None] | None] = {}
        for name, path, value in SETTINGS:
            if path not in cache:
                cache[path] = regutil.read_values("HKLM", path)
            got = cache[path]
            items[f"setting:{name}"] = {
                "name": name, "path": f"HKLM\\{path}\\{value}",
                "value": regutil.plain(got[0].get(value)) if got else None,
                "_key_last_write": got[1] if got else None,
            }
        for view, path in IFEO:
            for exe in regutil.subkeys("HKLM", path):
                got = regutil.read_values("HKLM", path + "\\" + exe)
                if got and got[0].get("Debugger"):
                    items[f"ifeo:{view}:{exe.lower()}"] = {"exe": exe, "value": str(got[0]["Debugger"]),
                                                          "_key_last_write": got[1]}
        for exe in regutil.subkeys("HKLM", SILENT_EXIT):
            got = regutil.read_values("HKLM", SILENT_EXIT + "\\" + exe)
            if got and got[0].get("MonitorProcess"):
                items[f"silentexit:{exe.lower()}"] = {"exe": exe, "value": str(got[0]["MonitorProcess"]),
                                                     "_key_last_write": got[1]}
        return items

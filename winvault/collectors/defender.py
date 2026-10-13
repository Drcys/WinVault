"""Microsoft Defender collector: exclusions and protection settings.

Uses Get-MpPreference / Get-MpComputerStatus (the supported interface; the
exclusion registry keys are not readable through the registry API on current
Windows). Signature and engine versions are deliberately *not* collected: they
change daily and are not security changes.
"""

from __future__ import annotations

from .base import Collector, CollectorError, as_list, is_windows, run_powershell_json

PS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$p = Get-MpPreference
$s = Get-MpComputerStatus
[pscustomobject]@{
  ExclusionPath = @($p.ExclusionPath); ExclusionExtension = @($p.ExclusionExtension)
  ExclusionProcess = @($p.ExclusionProcess); ExclusionIpAddress = @($p.ExclusionIpAddress)
  DisableRealtimeMonitoring = $p.DisableRealtimeMonitoring; DisableBehaviorMonitoring = $p.DisableBehaviorMonitoring
  DisableIOAVProtection = $p.DisableIOAVProtection; DisableScriptScanning = $p.DisableScriptScanning
  DisableBlockAtFirstSeen = $p.DisableBlockAtFirstSeen; DisableArchiveScanning = $p.DisableArchiveScanning
  MAPSReporting = [int]$p.MAPSReporting; SubmitSamplesConsent = [int]$p.SubmitSamplesConsent
  PUAProtection = [int]$p.PUAProtection; EnableControlledFolderAccess = [int]$p.EnableControlledFolderAccess
  EnableNetworkProtection = [int]$p.EnableNetworkProtection
  AMServiceEnabled = $s.AMServiceEnabled; AntivirusEnabled = $s.AntivirusEnabled
  RealTimeProtectionEnabled = $s.RealTimeProtectionEnabled; BehaviorMonitorEnabled = $s.BehaviorMonitorEnabled
  IsTamperProtected = $s.IsTamperProtected
} | ConvertTo-Json -Depth 3 -Compress
"""

EXCLUSION_KINDS = {"ExclusionPath": "path", "ExclusionExtension": "extension",
                   "ExclusionProcess": "process", "ExclusionIpAddress": "ip"}
SETTINGS = ["DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection",
            "DisableScriptScanning", "DisableBlockAtFirstSeen", "DisableArchiveScanning", "MAPSReporting",
            "SubmitSamplesConsent", "PUAProtection", "EnableControlledFolderAccess", "EnableNetworkProtection",
            "AMServiceEnabled", "AntivirusEnabled", "RealTimeProtectionEnabled", "BehaviorMonitorEnabled",
            "IsTamperProtected"]


def build_items(data: dict) -> dict[str, dict]:
    items: dict[str, dict] = {}
    for field, kind in EXCLUSION_KINDS.items():
        for value in as_list(data.get(field)):
            if value in (None, "") or str(value).startswith("N/A"):
                continue                     # "N/A: Must be an administrator to view exclusions"
            items[f"exclusion:{kind}:{str(value).lower()}"] = {"kind": kind, "value": str(value)}
    for name in SETTINGS:
        items[f"setting:{name}"] = {"name": name, "value": data.get(name)}
    return items


class DefenderCollector(Collector):
    name = "defender"
    description = "Microsoft Defender exclusions and protection settings"

    def collect(self) -> dict[str, dict]:
        if not is_windows():
            raise CollectorError("defender collector requires Windows")
        try:
            data = run_powershell_json(PS_SCRIPT)
        except CollectorError as exc:
            raise CollectorError(f"Microsoft Defender settings unavailable (another antivirus active?): {exc}") from exc
        return build_items(data)

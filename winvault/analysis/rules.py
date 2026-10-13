"""Rule-based risk scoring.

Each rule inspects one Change and, if it matches, contributes points and a short
human reason. The total decides a level. Every score is therefore explainable:
the reasons list *is* the justification, so the tool never shows a bare
"CRITICAL" without saying why.

Levels:  0-29 low · 30-59 medium · 60-79 high · 80+ critical
"""

from __future__ import annotations

import re
from collections.abc import Callable

from ..models import Change, ChangeStatus

# Directories any standard user can write to — a persistence item living here is
# more suspicious than one under a protected system path.
USER_WRITABLE = re.compile(
    r"(\\Users\\|\\AppData\\|\\Temp\\|\\Tmp\\|\\ProgramData\\|\\Public\\|\\Downloads\\)",
    re.IGNORECASE,
)
LOLBINS = ("powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta",
           "rundll32", "regsvr32", "mshta.exe", "certutil", "bitsadmin")
ADMINS_SID = "S-1-5-32-544"

Rule = Callable[[Change], tuple[int, str] | None]
_RULES: list[tuple[str, Rule]] = []


def rule(name: str):
    def deco(fn: Rule):
        _RULES.append((name, fn))
        return fn
    return deco


# Fields that carry what an object *runs*. A modification touching one of them is
# treated like a new autorun for the interpreter / user-writable qualifiers.
COMMAND_FIELDS = {"image_path", "service_dll", "value", "actions", "command", "app"}

STARTUP_RUNNABLE = (".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
                    ".wsf", ".hta", ".lnk", ".url", ".scr", ".dll", ".pif", ".jar")


def _runs_something_new(change: Change) -> bool:
    """Added object, or a modification of what an existing object executes."""
    if change.status is ChangeStatus.ADDED:
        return True
    return change.status is ChangeStatus.MODIFIED and bool(change.field_names() & COMMAND_FIELDS)


def _text(change: Change) -> str:
    """Command / image / value text to scan for interpreters and paths."""
    it = change.item
    parts = [str(it.get(k, "")) for k in ("image_path", "value", "command", "service_dll", "app")]
    for action in it.get("actions", []) or []:
        if isinstance(action, dict):
            parts += [str(action.get("command", "")), str(action.get("arguments", ""))]
    return " ".join(parts)


# ---- persistence: new autoruns -------------------------------------------------

@rule("new-run-key")
def new_run_key(change: Change):
    if change.category == "registry" and change.status is ChangeStatus.ADDED:
        key = change.item.get("key", "")
        if re.search(r"\\Run(Once)?$", key) or "Policies\\Explorer\\Run" in key:
            return 30, "new autorun registry value"
    return None


@rule("winlogon-shell-change")
def winlogon_shell_change(change: Change):
    if change.category == "registry" and change.status is ChangeStatus.MODIFIED:
        if "Winlogon" in change.item.get("key", "") and change.item.get("value_name") in ("Shell", "Userinit"):
            return 60, "Winlogon Shell/Userinit modified (classic persistence)"
    return None


@rule("new-service")
def new_service(change: Change):
    if change.category == "services" and change.status is ChangeStatus.ADDED:
        return 30, "new service registered"
    return None


@rule("new-task")
def new_task(change: Change):
    if change.category == "tasks" and change.status is ChangeStatus.ADDED:
        return 30, "new scheduled task"
    return None


@rule("new-startup-item")
def new_startup_item(change: Change):
    if change.category == "startup" and change.status is ChangeStatus.ADDED:
        return 25, "new startup-folder item"
    return None


@rule("startup-runnable")
def startup_runnable(change: Change):
    """A startup item that Windows will execute or open at logon (exe, script, shortcut...).
    Every startup folder is under Users or ProgramData, so the path itself says nothing."""
    if change.category == "startup" and change.status is ChangeStatus.ADDED:
        if str(change.item.get("extension") or "").lower() in STARTUP_RUNNABLE:
            return 20, "startup item is an executable, script or shortcut"
    return None


# ---- persistence: changes to existing objects (hijacking) -----------------------

@rule("run-value-changed")
def run_value_changed(change: Change):
    if change.category == "registry" and change.status is ChangeStatus.MODIFIED and "value" in change.field_names():
        key = change.item.get("key", "")
        if re.search(r"\\Run(Once)?$", key) or "Policies\\Explorer\\Run" in key:
            return 30, "existing autorun value now runs something else"
    return None


@rule("service-binary-changed")
def service_binary_changed(change: Change):
    if change.category == "services" and change.status is ChangeStatus.MODIFIED:
        if change.field_names() & {"image_path", "service_dll"}:
            return 40, "existing service now runs a different binary or DLL"
    return None


@rule("task-action-changed")
def task_action_changed(change: Change):
    if change.category == "tasks" and change.status is ChangeStatus.MODIFIED and "actions" in change.field_names():
        return 40, "existing scheduled task now runs a different action"
    return None


@rule("task-privilege-raised")
def task_privilege_raised(change: Change):
    if change.category != "tasks" or change.status is not ChangeStatus.MODIFIED:
        return None
    b, a = _field(change, "run_as_user")
    if a is not None and (str(a) == "S-1-5-18" or str(a).lower().endswith("system")) and a != b:
        return 20, "existing task now runs as SYSTEM"
    b, a = _field(change, "run_level")
    if str(a or "").lower() == "highestavailable" and str(b or "").lower() != "highestavailable":
        return 10, "existing task now runs with highest privileges"
    return None


@rule("task-hidden")
def task_hidden(change: Change):
    if change.category == "tasks" and change.status is ChangeStatus.MODIFIED:
        b, a = _field(change, "hidden")
        if a is True and b is not True:
            return 15, "existing task was made hidden"
    return None


@rule("startup-content-changed")
def startup_content_changed(change: Change):
    if change.category == "startup" and change.status is ChangeStatus.MODIFIED and "sha256" in change.field_names():
        return 25, "startup item content replaced"
    return None


# ---- qualifiers that sharpen the above ----------------------------------------

@rule("runs-as-system")
def runs_as_system(change: Change):
    if change.category == "tasks" and change.status is ChangeStatus.ADDED:
        principal = str(change.item.get("run_as_user") or "")
        if principal in ("S-1-5-18",) or principal.lower().endswith("system"):
            return 20, "runs as SYSTEM"
        if str(change.item.get("run_level", "")).lower() == "highestavailable":
            return 10, "runs with highest privileges"
    return None


def _hijack_key(change: Change) -> bool:
    return change.category == "system" and change.key.startswith(("ifeo:", "silentexit:"))


@rule("uses-interpreter")
def uses_interpreter(change: Change):
    if not _runs_something_new(change):
        return None
    if change.category not in ("registry", "services", "tasks", "startup", "firewall") and not _hijack_key(change):
        return None
    text = _text(change).lower()
    for lol in LOLBINS:
        if lol in text:
            return 20, f"executes {lol}"
    return None


@rule("user-writable-path")
def user_writable_path(change: Change):
    if not _runs_something_new(change):
        return None
    if change.category not in ("registry", "services", "tasks", "firewall") and not _hijack_key(change):
        return None
    if USER_WRITABLE.search(_text(change)):
        return 20, "target binary in a user-writable location"
    return None


@rule("hidden-task")
def hidden_task(change: Change):
    if change.category == "tasks" and change.status is ChangeStatus.ADDED and change.item.get("hidden"):
        return 15, "task is hidden"
    return None


# ---- accounts & privileges -----------------------------------------------------

@rule("new-local-user")
def new_local_user(change: Change):
    if change.category == "users" and change.status is ChangeStatus.ADDED and change.item.get("kind", "user") == "user":
        pts, why = 40, "new local user account"
        if change.item.get("is_admin"):
            return 90, "new local user created directly in Administrators"
        return pts, why
    return None


@rule("added-to-administrators")
def added_to_administrators(change: Change):
    if change.category == "users" and change.status is ChangeStatus.MODIFIED and change.item.get("sid") == ADMINS_SID:
        for f in change.fields:
            if f.name == "members" and isinstance(f.after, list) and isinstance(f.before, list):
                if [m for m in f.after if m not in f.before]:
                    return 50, "account added to Administrators group"
    return None


# ---- defender / security weakening --------------------------------------------

@rule("service-disabled")
def service_disabled(change: Change):
    if change.category == "services" and change.status is ChangeStatus.MODIFIED:
        b, a = _field(change, "start_type")
        if a == "disabled" and b != "disabled":
            name = change.item.get("name", "").lower()
            if any(k in name for k in ("windefend", "wdnissvc", "sense", "wscsvc", "mpssvc")):
                return 60, "security service disabled"
            return 20, "service disabled"
    return None


# ---- file integrity -----------------------------------------------------------

@rule("critical-file-changed")
def critical_file_changed(change: Change):
    if change.category != "files":
        return None
    name = re.split(r"[\\/]", str(change.item.get("path", "")))[-1].lower()
    if change.status is ChangeStatus.MODIFIED and "sha256" in change.field_names():
        if name == "hosts":
            return 50, "hosts file content changed (name resolution can be redirected)"
        return 40, "critical system file content changed"
    if change.status is ChangeStatus.MODIFIED and "exists" in change.field_names():
        return 40, "critical system file created or deleted"
    return None


# ---- firewall (v1.2) ---------------------------------------------------------

ABUSED_PORTS = {"21", "22", "23", "135", "139", "445", "1337", "3389", "4444", "4445", "5555", "5900",
                "5985", "5986", "6666", "6667", "8888", "9999", "31337"}


def _inbound_allow(item: dict) -> bool:
    return str(item.get("direction", "")).lower() == "in" and str(item.get("action", "")).lower() == "allow"


@rule("new-inbound-allow-rule")
def new_inbound_allow_rule(change: Change):
    if change.category == "firewall" and change.status is ChangeStatus.ADDED and change.key.startswith("rule:"):
        if _inbound_allow(change.item):
            if change.item.get("active"):
                return 30, "new inbound allow firewall rule"
            return 10, "new inbound allow firewall rule (disabled)"
    return None


@rule("firewall-port-exposed")
def firewall_port_exposed(change: Change):
    it = change.item
    if change.category != "firewall" or not change.key.startswith("rule:") or not _inbound_allow(it):
        return None
    if change.status is ChangeStatus.MODIFIED and not (change.field_names() & {"local_ports", "app", "active", "action",
                                                                                "direction", "remote_addresses"}):
        return None
    if change.status is ChangeStatus.REMOVED:
        return None
    ports = {p.strip() for p in str(it.get("local_ports") or "").split(",") if p.strip()}
    abused = sorted(ports & ABUSED_PORTS, key=int)
    if abused:
        return 20, f"opens a commonly abused port ({', '.join(abused)})"
    if (not ports or ports & {"*", "Any"}) and not it.get("app") and not it.get("service") and not it.get("package"):
        return 20, "allows any port for any program"
    return None


@rule("firewall-rule-opened")
def firewall_rule_opened(change: Change):
    if change.category != "firewall" or change.status is not ChangeStatus.MODIFIED or not change.key.startswith("rule:"):
        return None
    if not _inbound_allow(change.item):
        return None
    before = change.before or {}
    if not _inbound_allow(before) or (change.item.get("active") and not before.get("active")) \
            or "local_ports" in change.field_names():
        return 30, "existing firewall rule now allows more inbound traffic"
    return None


@rule("firewall-profile-off")
def firewall_profile_off(change: Change):
    if change.category != "firewall" or not change.key.startswith("profile:") or change.status is ChangeStatus.REMOVED:
        return None
    b, a = _field(change, "enabled")
    if change.status is ChangeStatus.ADDED:
        b, a = None, change.item.get("enabled")
    if a is False and b is not False:
        return 60, "Windows Firewall turned off for a profile"
    b, a = _field(change, "default_inbound")
    if change.status is ChangeStatus.ADDED:
        b, a = None, change.item.get("default_inbound")
    if a == "allow" and b != "allow":
        return 40, "firewall now allows unsolicited inbound traffic by default"
    return None


# ---- Microsoft Defender (v1.2) ----------------------------------------------

DEFENDER_WEAK = {
    # setting: (is_weakened(before, after), points)
    "DisableRealtimeMonitoring": (lambda b, a: a is True and b is not True, 60),
    "DisableBehaviorMonitoring": (lambda b, a: a is True and b is not True, 60),
    "DisableIOAVProtection": (lambda b, a: a is True and b is not True, 40),
    "DisableScriptScanning": (lambda b, a: a is True and b is not True, 40),
    "DisableBlockAtFirstSeen": (lambda b, a: a is True and b is not True, 30),
    "DisableArchiveScanning": (lambda b, a: a is True and b is not True, 20),
    "MAPSReporting": (lambda b, a: a == 0 and (b or 0) > 0, 30),
    "SubmitSamplesConsent": (lambda b, a: a == 2 and b != 2, 20),
    "PUAProtection": (lambda b, a: a == 0 and (b or 0) > 0, 20),
    "EnableControlledFolderAccess": (lambda b, a: a == 0 and (b or 0) > 0, 30),
    "EnableNetworkProtection": (lambda b, a: a == 0 and (b or 0) > 0, 30),
    "AMServiceEnabled": (lambda b, a: a is False and b is True, 60),
    "AntivirusEnabled": (lambda b, a: a is False and b is True, 60),
    "RealTimeProtectionEnabled": (lambda b, a: a is False and b is True, 60),
    "BehaviorMonitorEnabled": (lambda b, a: a is False and b is True, 40),
    "IsTamperProtected": (lambda b, a: a is False and b is True, 60),
}
ROOT_PATH = re.compile(r"^[a-z]:\\?$", re.IGNORECASE)


@rule("defender-exclusion-added")
def defender_exclusion_added(change: Change):
    if change.category == "defender" and change.status is ChangeStatus.ADDED and change.key.startswith("exclusion:"):
        return 60, f"new Microsoft Defender {change.item.get('kind', '')} exclusion"
    return None


@rule("defender-exclusion-broad")
def defender_exclusion_broad(change: Change):
    if change.category != "defender" or change.status is not ChangeStatus.ADDED or not change.key.startswith("exclusion:"):
        return None
    value, kind = str(change.item.get("value", "")), change.item.get("kind")
    if kind == "path" and (ROOT_PATH.match(value) or USER_WRITABLE.search(value + "\\")):
        return 20, "exclusion covers a drive root or user-writable folder"
    if kind == "process" and any(lol in value.lower() for lol in LOLBINS):
        return 20, "exclusion covers a script interpreter"
    if kind == "extension" and value.lower().lstrip(".") in ("exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "hta", "scr"):
        return 20, "exclusion covers an executable file type"
    return None


@rule("defender-protection-weakened")
def defender_protection_weakened(change: Change):
    if change.category != "defender" or change.status is not ChangeStatus.MODIFIED or not change.key.startswith("setting:"):
        return None
    name = change.item.get("name")
    test = DEFENDER_WEAK.get(name)
    b, a = _field(change, "value")
    if test and test[0](b, a):
        return test[1], f"Microsoft Defender protection weakened ({name}: {b} -> {a})"
    return None


# ---- security policy (v1.2) -------------------------------------------------

def _num(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


@rule("password-policy-weakened")
def password_policy_weakened(change: Change):
    if change.category != "policy" or change.status is not ChangeStatus.MODIFIED or not change.key.startswith("access:"):
        return None
    name = change.item.get("name")
    b, a = (_num(x) for x in _field(change, "value"))
    if a is None:
        return None
    if name == "ClearTextPassword" and a == 1 and b != 1:
        return 60, "passwords stored with reversible encryption"
    if name == "MinimumPasswordLength" and b is not None and a < b:
        return 30, f"minimum password length lowered ({b} -> {a})"
    if name == "PasswordComplexity" and a == 0 and b == 1:
        return 30, "password complexity requirement turned off"
    if name == "LockoutBadCount" and b and (a == 0 or a > b):
        return 30, f"account lockout weakened ({b} -> {a} attempts)"
    if name == "EnableGuestAccount" and a == 1 and b != 1:
        return 40, "Guest account enabled"
    if name == "EnableAdminAccount" and a == 1 and b != 1:
        return 20, "built-in Administrator account enabled"
    if name == "LSAAnonymousNameLookup" and a == 1 and b != 1:
        return 20, "anonymous SID/name translation allowed"
    return None


@rule("user-right-granted")
def user_right_granted(change: Change):
    if change.category != "policy" or not change.key.startswith("right:") or change.status is ChangeStatus.REMOVED:
        return None
    before = (change.before or {}).get("members") or []
    added = [m for m in change.item.get("members") or [] if m not in before]
    if not added:
        return None
    name = change.item.get("name")
    if change.item.get("sensitive"):
        return 50, f"sensitive right {name} granted to {', '.join(added)}"
    return 20, f"user right {name} granted to {', '.join(added)}"


@rule("audit-policy-weakened")
def audit_policy_weakened(change: Change):
    if change.category != "policy" or change.status is not ChangeStatus.MODIFIED or not change.key.startswith("audit:"):
        return None
    b, a = (_num(x) for x in _field(change, "setting"))
    if b and a is not None and (b & ~a):
        return 40, f"audit policy weakened for {change.item.get('_subcategory') or change.item.get('guid')}"
    return None


# ---- installed software (v1.2) ----------------------------------------------

REMOTE_ACCESS = ("anydesk", "teamviewer", "screenconnect", "connectwise control", "ngrok", "atera", "splashtop",
                 "rustdesk", "simplehelp", "netsupport", "radmin", "meshagent", "mesh agent", "logmein", "ultraviewer",
                 "remote utilities", "tightvnc", "ultravnc", "realvnc", "chrome remote desktop", "zoho assist",
                 "dameware", "level.io", "action1")
SECURITY_PRODUCTS = ("defender", "sysmon", "crowdstrike", "falcon", "sentinelone", "carbon black", "sophos", "eset",
                     "kaspersky", "symantec", "norton", "mcafee", "trellix", "malwarebytes", "bitdefender",
                     "trend micro", "avast", "avg ", "wazuh", "osquery", "velociraptor", "elastic agent", "cylance")


@rule("new-software")
def new_software(change: Change):
    if change.category == "software" and change.status is ChangeStatus.ADDED:
        return 10, "new software installed"
    return None


@rule("remote-access-software")
def remote_access_software(change: Change):
    if change.category != "software" or change.status is ChangeStatus.REMOVED:
        return None

    def tool(entry):
        name = f"{(entry or {}).get('display_name', '')} {(entry or {}).get('publisher', '')}".lower()
        return next((r for r in REMOTE_ACCESS if r in name), None)

    hit = tool(change.after)
    if hit and (change.status is ChangeStatus.ADDED or tool(change.before) != hit):
        # MODIFIED: an existing entry renamed into a remote access tool (not a version update of one)
        return 40, f"remote access software installed ({hit})"
    return None


@rule("security-software-removed")
def security_software_removed(change: Change):
    if change.category == "software" and change.status is ChangeStatus.REMOVED:
        name = f"{change.item.get('display_name', '')} {change.item.get('publisher', '')} ".lower()
        hit = next((s.strip() for s in SECURITY_PRODUCTS if s in name), None)
        if hit:
            return 40, f"security software uninstalled ({hit})"
    return None


# ---- system configuration (v1.2) --------------------------------------------

def _lt(limit):
    return lambda b, a: a is not None and _num(a) is not None and _num(a) < limit and (b is None or _num(b) is None or _num(b) >= limit or _num(a) < _num(b))


SYSTEM_WEAK = {
    # setting: (is_weakened(before, after), points, reason)
    "UAC_EnableLUA": (lambda b, a: a == 0 and b != 0, 60, "User Account Control disabled"),
    "UAC_ConsentPromptBehaviorAdmin": (lambda b, a: a == 0 and b != 0, 30, "UAC elevates administrators without prompting"),
    "UAC_PromptOnSecureDesktop": (lambda b, a: a == 0 and b != 0, 10, "UAC prompt no longer on the secure desktop"),
    "UAC_LocalAccountTokenFilterPolicy": (lambda b, a: a == 1 and b != 1, 40,
                                          "remote UAC token filtering disabled (enables pass-the-hash)"),
    "RDP_fDenyTSConnections": (lambda b, a: a == 0 and b != 0, 30, "Remote Desktop enabled"),
    "RDP_Policy_fDenyTSConnections": (lambda b, a: a == 0 and b != 0, 30, "Remote Desktop enabled by policy"),
    "RDP_UserAuthentication": (lambda b, a: a == 0 and b != 0, 30, "RDP Network Level Authentication disabled"),
    "RDP_PortNumber": (lambda b, a: b is not None and a != b, 20, "Remote Desktop port changed"),
    "LSA_RunAsPPL": (lambda b, a: _num(b) in (1, 2) and _num(a) in (0, None), 40, "LSA protection (RunAsPPL) turned off"),
    "LSA_LmCompatibilityLevel": (_lt(3), 40, "LM/NTLMv1 authentication allowed"),
    "LSA_NoLMHash": (lambda b, a: a == 0 and b != 0, 30, "LM password hashes stored again"),
    "LSA_RestrictAnonymous": (lambda b, a: a == 0 and b not in (0, None), 20, "anonymous access restriction removed"),
    "WDigest_UseLogonCredential": (lambda b, a: a == 1 and b != 1, 60,
                                   "WDigest clear-text credential caching enabled (credential theft)"),
    "SMB1_Server": (lambda b, a: a == 1 and b != 1, 40, "SMBv1 server enabled"),
    "SMB_RequireSecuritySignature": (lambda b, a: a == 0 and b == 1, 20, "SMB signing requirement removed"),
    "WU_NoAutoUpdate": (lambda b, a: a == 1 and b != 1, 30, "automatic Windows Update disabled by policy"),
    "PS_ExecutionPolicy": (lambda b, a: str(a).lower() in ("unrestricted", "bypass") and str(b).lower() not in
                           ("unrestricted", "bypass"), 20, "PowerShell execution policy relaxed"),
    "PS_ScriptBlockLogging": (lambda b, a: b == 1 and a != 1, 40, "PowerShell script block logging turned off"),
    "Defender_Policy_DisableAntiSpyware": (lambda b, a: a == 1 and b != 1, 60, "Microsoft Defender disabled by policy"),
    "Defender_Policy_DisableRealtimeMonitoring": (lambda b, a: a == 1 and b != 1, 60,
                                                  "Defender real-time protection disabled by policy"),
    "WinRM_AllowUnencryptedTraffic": (lambda b, a: a == 1 and b != 1, 30, "WinRM allows unencrypted traffic"),
}
ACCESSIBILITY = {"sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", "magnify.exe", "displayswitch.exe",
                 "atbroker.exe"}


@rule("system-setting-weakened")
def system_setting_weakened(change: Change):
    if change.category != "system" or change.status is not ChangeStatus.MODIFIED or not change.key.startswith("setting:"):
        return None
    test = SYSTEM_WEAK.get(change.item.get("name"))
    b, a = _field(change, "value")
    if test and test[0](b, a):
        return test[1], f"{test[2]} ({b} -> {a})"
    return None


@rule("ifeo-hijack")
def ifeo_hijack(change: Change):
    if change.category != "system" or change.status is ChangeStatus.REMOVED or not _runs_something_new(change):
        return None
    exe = str(change.item.get("exe", "")).lower()
    if change.key.startswith("ifeo:"):
        if exe in ACCESSIBILITY:
            return 90, f"accessibility-feature backdoor: {exe} now launches another program"
        return 60, f"Image File Execution Options debugger set for {exe}"
    if change.key.startswith("silentexit:"):
        return 50, f"SilentProcessExit monitor process set for {exe}"
    return None


def _field(change: Change, name: str):
    for f in change.fields:
        if f.name == name:
            return f.before, f.after
    return None, None


def score_change(change: Change) -> tuple[int, list[str]]:
    total, reasons = 0, []
    for _name, fn in _RULES:
        hit = fn(change)
        if hit:
            pts, why = hit
            total += pts
            reasons.append(f"+{pts} {why}")
    return total, reasons


def level_for(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def rule_names() -> list[str]:
    return [n for n, _ in _RULES]

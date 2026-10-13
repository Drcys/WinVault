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
COMMAND_FIELDS = {"image_path", "service_dll", "value", "actions", "command"}

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
    parts = [str(it.get(k, "")) for k in ("image_path", "value", "command", "service_dll")]
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


@rule("uses-interpreter")
def uses_interpreter(change: Change):
    if not _runs_something_new(change) or change.category not in ("registry", "services", "tasks", "startup"):
        return None
    text = _text(change).lower()
    for lol in LOLBINS:
        if lol in text:
            return 20, f"executes {lol}"
    return None


@rule("user-writable-path")
def user_writable_path(change: Change):
    if not _runs_something_new(change) or change.category not in ("registry", "services", "tasks"):
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

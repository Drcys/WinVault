"""v1.1.0 hardening: scoring of hijacked existing objects, startup items, DTD refusal,
absolute system tool paths, and integrity checks for snapshot files given to `diff`."""

import json
import xml.etree.ElementTree as ET

import pytest

from winvault.analysis.noise import classify_noise
from winvault.analysis.rules import level_for, score_change
from winvault.collectors.base import safe_fromstring, system_tool
from winvault.collectors.tasks import ScheduledTasksCollector, parse_task_xml
from winvault.models import Change, ChangeStatus, FieldChange
from winvault.snapshot import SnapshotStore


def modified(cat, key, before, after):
    fields = [FieldChange(k, before.get(k), after.get(k))
              for k in sorted(set(before) | set(after)) if before.get(k) != after.get(k)]
    return Change(cat, key, ChangeStatus.MODIFIED, before, after, fields)


# ---- scoring of changes to existing objects (finding F-5) -------------------

def test_service_binary_swapped_into_user_writable_path_is_high():
    c = modified("services", "Svc011",
                 {"name": "Svc011", "image_path": "C:\\Windows\\system32\\svchost.exe -k netsvcs"},
                 {"name": "Svc011", "image_path": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.1-0\\evil.exe"})
    assert classify_noise(c) is None                 # not the Defender move: the binary changed
    score, reasons = score_change(c)
    assert score == 60 and level_for(score) == "high"
    assert any("different binary" in r for r in reasons)


def test_microsoft_task_action_hijack_is_critical_not_noise():
    key = "\\Microsoft\\Windows\\Area5\\Task45"
    c = modified("tasks", key,
                 {"name": key, "sha256": "aa", "actions": [{"type": "com", "class_id": "{X}"}]},
                 {"name": key, "sha256": "bb", "actions": [{"type": "exec", "command": "cmd.exe",
                                                            "arguments": "/c C:\\Users\\Public\\x.bat"}]})
    assert classify_noise(c) is None
    score, reasons = score_change(c)
    assert score == 80 and level_for(score) == "critical"     # 40 action + 20 cmd + 20 user-writable


def test_hash_only_microsoft_task_rewrite_is_still_noise():
    key = "\\Microsoft\\Windows\\Area5\\Task46"
    c = modified("tasks", key, {"name": key, "sha256": "aa"}, {"name": key, "sha256": "bb"})
    assert classify_noise(c)


def test_task_made_system_and_hidden():
    c = modified("tasks", "\\Updater",
                 {"name": "\\Updater", "run_as_user": "LAB\\bob", "hidden": False},
                 {"name": "\\Updater", "run_as_user": "S-1-5-18", "hidden": True})
    score, reasons = score_change(c)
    assert score == 35 and any("SYSTEM" in r for r in reasons) and any("hidden" in r for r in reasons)


def test_task_run_level_raised():
    c = modified("tasks", "\\T", {"run_level": "LeastPrivilege"}, {"run_level": "HighestAvailable"})
    assert score_change(c)[0] == 10


def test_existing_run_value_repointed_to_powershell():
    item = {"key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value_name": "Vendor"}
    c = modified("registry", "HKLM\\...\\Run\\Vendor",
                 {**item, "value": "\"C:\\Program Files\\Vendor\\agent.exe\""},
                 {**item, "value": "powershell.exe -w hidden -f C:\\Users\\bob\\AppData\\x.ps1"})
    score, _ = score_change(c)
    assert score == 70 and level_for(score) == "high"          # 30 + 20 interpreter + 20 user-writable


def test_winlogon_userinit_pointing_to_appdata_is_critical():
    item = {"key": "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "value_name": "Userinit"}
    c = modified("registry", "HKLM\\...\\Winlogon\\Userinit",
                 {**item, "value": "C:\\Windows\\system32\\userinit.exe,"},
                 {**item, "value": "C:\\Windows\\system32\\userinit.exe,C:\\Users\\bob\\AppData\\ui.exe,"})
    assert score_change(c)[0] == 80


def test_start_type_change_does_not_pick_up_path_qualifiers():
    c = modified("services", "Spooler",
                 {"name": "Spooler", "start_type": "auto", "image_path": "C:\\Users\\x\\a.exe"},
                 {"name": "Spooler", "start_type": "disabled", "image_path": "C:\\Users\\x\\a.exe"})
    score, reasons = score_change(c)
    assert score == 20 and reasons == ["+20 service disabled"]


# ---- startup items (finding F-6) --------------------------------------------

def test_startup_shortcut_scores_more_than_text_file():
    lnk = Change("startup", "a.lnk", ChangeStatus.ADDED, None,
                 {"path": "C:\\Users\\bob\\AppData\\Roaming\\...\\Startup\\sync.lnk", "extension": ".lnk"})
    txt = Change("startup", "a.txt", ChangeStatus.ADDED, None,
                 {"path": "C:\\ProgramData\\...\\StartUp\\note.txt", "extension": ".txt"})
    assert score_change(lnk)[0] == 45
    assert score_change(txt)[0] == 25


def test_startup_content_replaced():
    c = modified("startup", "a.bat", {"sha256": "aa", "extension": ".bat"}, {"sha256": "bb", "extension": ".bat"})
    assert score_change(c)[0] == 25


# ---- XML hardening (finding F-3) --------------------------------------------

BOMB = """<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">]>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo>
<Description>&lol2;</Description></RegistrationInfo></Task>"""


@pytest.mark.parametrize("data", [BOMB, BOMB.encode("utf-8"), BOMB.encode("utf-16")])
def test_dtd_is_refused(data):
    with pytest.raises(ET.ParseError):
        safe_fromstring(data)


def test_task_with_dtd_is_recorded_as_parse_error(tmp_path):
    (tmp_path / "Evil").write_bytes(BOMB.encode("utf-16"))
    items = ScheduledTasksCollector(tmp_path).collect()
    assert "parse_error" in items["\\Evil"] and items["\\Evil"]["sha256"]
    with pytest.raises(ET.ParseError):
        parse_task_xml(BOMB.encode("utf-8"))


# ---- absolute paths for system tools (finding F-4) --------------------------

def test_system_tool_uses_system32_when_present(tmp_path, monkeypatch):
    (tmp_path / "System32").mkdir()
    (tmp_path / "System32" / "icacls.exe").write_bytes(b"")
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    assert system_tool("icacls.exe") == str(tmp_path / "System32" / "icacls.exe")
    assert system_tool("auditpol.exe") == "auditpol.exe"       # not there: falls back to the name


# ---- `winvault diff` on snapshot files (finding F-2) ------------------------

def _snap(sid, kind, items):
    return {"format": "winvault-snapshot/1", "id": sid, "kind": kind, "label": None,
            "created_utc": "2026-10-05T07:00:00+00:00", "host": {"hostname": "LAB", "elevated": True},
            "collectors": {"services": {"status": "ok", "count": len(items), "items": items}}}


def test_diff_refuses_a_file_that_differs_from_the_store_copy(tmp_path, capsys):
    from winvault.cli import main
    store = SnapshotStore(tmp_path / "store")
    a = _snap("snap-a", "baseline", {"X": {"name": "X"}})
    b = _snap("snap-b", "snapshot", {"X": {"name": "X"}, "Evil": {"name": "Evil"}})
    pa, pb = store.save(a), store.save(b)
    copy = tmp_path / "a.json"
    copy.write_bytes(pa.read_bytes())
    assert main(["--store", str(store.root), "diff", str(copy), str(pb), "--show", "0"]) == 0
    assert "matches the store index" in capsys.readouterr().out

    edited = json.loads(pa.read_text())
    edited["collectors"]["services"]["items"]["Evil"] = {"name": "Evil"}     # hide the new service
    copy.write_text(json.dumps(edited))
    assert main(["--store", str(store.root), "diff", str(copy), str(pb)]) == 1
    assert "was modified" in capsys.readouterr().err


def test_diff_of_unknown_files_prints_their_hashes(tmp_path, capsys):
    from winvault.cli import main
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(_snap("x-a", "baseline", {})))
    b.write_text(json.dumps(_snap("x-b", "snapshot", {"S": {"name": "S"}})))
    assert main(["--store", str(tmp_path / "empty"), "diff", str(a), str(b), "--show", "0"]) == 0
    out = capsys.readouterr().out
    assert "could not be checked against a store index" in out and "SHA-256" in out

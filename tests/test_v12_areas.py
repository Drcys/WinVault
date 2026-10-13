"""v1.2.0: firewall, Defender, security policy, installed software and system configuration
(parsers, scoring, noise with adversarial look-alikes, and event correlation)."""

from winvault.analysis import analyze
from winvault.analysis.noise import classify_noise
from winvault.analysis.rules import level_for, score_change
from winvault.collectors.defender import build_items as defender_items
from winvault.collectors.firewall import build_items as firewall_items
from winvault.collectors.firewall import parse_rule
from winvault.collectors.policy import parse_audit_backup, parse_secedit
from winvault.collectors.software import entry
from winvault.compare import compare_snapshots
from winvault.correlation import correlate
from winvault.events.describe import summarize
from winvault.models import Change, ChangeStatus, FieldChange
from winvault.presentation import display_name

RULE = "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=4444|App=C:\\Users\\bob\\AppData\\x.exe|Name=Updater|"


def added(cat, key, item):
    return Change(cat, key, ChangeStatus.ADDED, None, item)


def modified(cat, key, before, after):
    fields = [FieldChange(k, before.get(k), after.get(k))
              for k in sorted(set(before) | set(after)) if before.get(k) != after.get(k) and not k.startswith("_")]
    return Change(cat, key, ChangeStatus.MODIFIED, before, after, fields)


# ---- firewall ---------------------------------------------------------------

def test_parse_rule_fields_and_repeated_ports():
    r = parse_rule("v2.30|Action=Block|Active=FALSE|Dir=Out|Protocol=17|LPort=53|LPort=5353|RA4=10.0.0.1|Name=X|")
    assert r["action"] == "Block" and r["active"] is False and r["direction"] == "Out"
    assert r["local_ports"] == "53,5353" and r["remote_addresses"] == "10.0.0.1" and r["_version"] == "v2.30"


def test_firewall_items_rules_and_profiles():
    items = firewall_items({"local": {"{ID-1}": RULE}}, {"local": {"Public": {"EnableFirewall": 1, "DefaultInboundAction": 1}}})
    assert items["rule:local:{ID-1}"]["name"] == "Updater"
    assert items["profile:local:Public"] == {"name": "Public profile (local)", "store": "local", "enabled": True,
                                             "default_inbound": "block", "notifications": None}


def test_inbound_rule_on_abused_port_from_user_folder_is_high():
    c = added("firewall", "rule:local:{ID-1}", {**parse_rule(RULE), "rule_id": "{ID-1}", "store": "local"})
    score, reasons = score_change(c)
    assert score == 70 and level_for(score) == "high"          # 30 rule + 20 port 4444 + 20 user-writable app
    assert any("4444" in r for r in reasons)
    assert display_name(c).startswith("rule Updater")


def test_any_port_any_program_rule():
    c = added("firewall", "rule:local:{ID-2}", parse_rule("v2.33|Action=Allow|Active=TRUE|Dir=In|Name=Open|"))
    score, reasons = score_change(c)
    assert score == 50 and any("any port" in r for r in reasons)


def test_firewall_profile_turned_off_is_high():
    c = modified("firewall", "profile:local:Public", {"enabled": True, "default_inbound": "block"},
                 {"enabled": False, "default_inbound": "block"})
    assert score_change(c) == (60, ["+60 Windows Firewall turned off for a profile"])


def test_existing_block_rule_flipped_to_allow():
    before = parse_rule("v2.33|Action=Block|Active=TRUE|Dir=In|LPort=8080|App=C:\\a.exe|Name=R|")
    after = parse_rule("v2.33|Action=Allow|Active=TRUE|Dir=In|LPort=8080|App=C:\\a.exe|Name=R|")
    assert score_change(modified("firewall", "rule:local:R", before, after))[0] == 30


def test_store_app_rule_is_noise_but_look_alike_with_port_is_not():
    pkg = "v2.33|Action=Allow|Active=TRUE|Dir=In|AppPkgId=S-1-15-2-1-2-3|Name=@{Microsoft.Photos}|"
    assert classify_noise(added("firewall", "rule:local:A", parse_rule(pkg)))
    evil = pkg.replace("Dir=In|", "Dir=In|LPort=4444|")
    c = added("firewall", "rule:local:B", parse_rule(evil))
    assert classify_noise(c) is None and score_change(c)[0] >= 50


# ---- Defender ---------------------------------------------------------------

def test_defender_items_skip_non_admin_placeholder():
    items = defender_items({"ExclusionPath": ["C:\\Tools", "N/A: Must be an administrator to view exclusions"],
                            "ExclusionProcess": None, "DisableRealtimeMonitoring": False})
    assert "exclusion:path:c:\\tools" in items and len([k for k in items if k.startswith("exclusion:")]) == 1
    assert items["setting:DisableRealtimeMonitoring"]["value"] is False


def test_defender_exclusion_of_user_folder_is_critical():
    c = added("defender", "exclusion:path:c:\\users\\public", {"kind": "path", "value": "C:\\Users\\Public"})
    score, reasons = score_change(c)
    assert score == 80 and level_for(score) == "critical"
    assert display_name(c) == "path exclusion C:\\Users\\Public"


def test_drive_root_and_interpreter_exclusions():
    assert score_change(added("defender", "exclusion:x:1", {"kind": "path", "value": "C:\\"}))[0] == 80
    assert score_change(added("defender", "exclusion:x:2", {"kind": "process", "value": "powershell.exe"}))[0] == 80
    assert score_change(added("defender", "exclusion:x:3", {"kind": "extension", "value": ".ps1"}))[0] == 80
    assert score_change(added("defender", "exclusion:x:4", {"kind": "path", "value": "D:\\Builds\\cache"}))[0] == 60


def test_realtime_protection_turned_off():
    c = modified("defender", "setting:RealTimeProtectionEnabled",
                 {"name": "RealTimeProtectionEnabled", "value": True}, {"name": "RealTimeProtectionEnabled", "value": False})
    assert score_change(c)[0] == 60
    same = modified("defender", "setting:MAPSReporting", {"name": "MAPSReporting", "value": 2},
                    {"name": "MAPSReporting", "value": 1})
    assert score_change(same)[0] == 0                          # still reporting: not a weakening


# ---- security policy --------------------------------------------------------

SECPOL = """[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 8
PasswordComplexity = 1
LockoutBadCount = 5
NewAdministratorName = "Administrator"
[Privilege Rights]
SeDebugPrivilege = *S-1-5-32-544
SeBatchLogonRight = *S-1-5-32-544,*S-1-5-32-551
"""


def test_parse_secedit():
    items = parse_secedit(SECPOL)
    assert items["access:MinimumPasswordLength"]["value"] == 8
    assert items["access:NewAdministratorName"]["value"] == "Administrator"
    assert items["right:SeDebugPrivilege"] == {"name": "SeDebugPrivilege", "members": ["S-1-5-32-544"], "sensitive": True}


def test_parse_audit_backup_is_language_independent():
    csv = ("Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\n"
           "PC,System,Prozesserstellung,{0cce922b-69ae-11d9-bed3-505054503030},Erfolg,,1\n"
           "PC,System,Option:CrashOnAuditFail,,Disabled,,0\n")
    items = parse_audit_backup(csv)
    assert items["audit:{0CCE922B-69AE-11D9-BED3-505054503030}"]["setting"] == 1
    assert items["auditoption:CrashOnAuditFail"]["value"] == "0"


def test_sensitive_right_granted_is_medium_and_correlated():
    before = {"name": "SeDebugPrivilege", "members": ["S-1-5-32-544"], "sensitive": True}
    after = {**before, "members": ["S-1-5-21-9-1010", "S-1-5-32-544"]}
    c = modified("policy", "right:SeDebugPrivilege", before, after)
    score, reasons = score_change(c)
    assert score == 50 and "S-1-5-21-9-1010" in reasons[0]


def test_password_and_audit_weakening():
    pw = modified("policy", "access:MinimumPasswordLength", {"name": "MinimumPasswordLength", "value": 12},
                  {"name": "MinimumPasswordLength", "value": 0})
    assert score_change(pw)[0] == 30
    au = modified("policy", "audit:{X}", {"guid": "{X}", "setting": 3, "_subcategory": "Process Creation"},
                  {"guid": "{X}", "setting": 0, "_subcategory": "Process Creation"})
    assert score_change(au) == (40, ["+40 audit policy weakened for Process Creation"])
    up = modified("policy", "audit:{X}", {"guid": "{X}", "setting": 1}, {"guid": "{X}", "setting": 3})
    assert score_change(up)[0] == 0                            # more auditing is not a weakening


# ---- installed software -----------------------------------------------------

def test_software_entry_skips_components_without_name():
    assert entry({"DisplayVersion": "1"}, "machine", "{GUID}", None) is None
    e = entry({"DisplayName": "AnyDesk", "Publisher": "AnyDesk Software GmbH"}, "machine", "AnyDesk", None)
    assert e["display_name"] == "AnyDesk" and e["scope"] == "machine"


def test_remote_access_tool_is_medium_plain_app_is_low():
    rat = added("software", "machine:AnyDesk", {"display_name": "AnyDesk", "publisher": "AnyDesk Software GmbH"})
    app = added("software", "machine:7zip", {"display_name": "7-Zip 24.08", "publisher": "Igor Pavlov"})
    assert score_change(rat)[0] == 50 and score_change(app)[0] == 10


def test_security_software_removed():
    c = Change("software", "machine:Sysmon", ChangeStatus.REMOVED, {"display_name": "Sysmon", "publisher": "Sysinternals"}, None)
    assert score_change(c)[0] == 40


def test_version_update_and_upgrade_pair_are_noise_rename_is_not():
    upd = modified("software", "machine:Git", {"display_name": "Git", "display_version": "2.46.0"},
                   {"display_name": "Git", "display_version": "2.47.1"})
    assert classify_noise(upd) == "software version update"
    renamed = modified("software", "machine:Git", {"display_name": "Git", "display_version": "2.46.0"},
                       {"display_name": "AnyDesk", "display_version": "2.46.0"})
    assert classify_noise(renamed) is None

    def snap(sid, items):
        return {"id": sid, "host": {"hostname": "PC", "elevated": True},
                "collectors": {"software": {"status": "ok", "items": items}}}
    base = snap("a", {"machine:{OLD}": {"display_name": "Python 3.12.6 (64-bit)", "publisher": "Python Software Foundation",
                                        "display_version": "3.12.6150.0"}})
    cur = snap("b", {"machine:{NEW}": {"display_name": "Python 3.12.7 (64-bit)", "publisher": "Python Software Foundation",
                                       "display_version": "3.12.7150.0"},
                     "machine:{RAT}": {"display_name": "RustDesk", "publisher": "Purslane"}})
    result = compare_snapshots(base, cur)
    stats = analyze(result)
    assert stats.noise == 2 and stats.signal == 1                  # the upgrade pair; RustDesk stays visible


# ---- system configuration ---------------------------------------------------

def test_uac_disabled_and_wdigest_enabled():
    uac = modified("system", "setting:UAC_EnableLUA", {"name": "UAC_EnableLUA", "value": 1}, {"name": "UAC_EnableLUA", "value": 0})
    wd = modified("system", "setting:WDigest_UseLogonCredential", {"name": "WDigest_UseLogonCredential", "value": None},
                  {"name": "WDigest_UseLogonCredential", "value": 1})
    assert score_change(uac)[0] == 60 and score_change(wd)[0] == 60


def test_ntlm_level_lowered_but_raised_is_fine():
    low = modified("system", "setting:LSA_LmCompatibilityLevel", {"name": "LSA_LmCompatibilityLevel", "value": 5},
                   {"name": "LSA_LmCompatibilityLevel", "value": 1})
    high = modified("system", "setting:LSA_LmCompatibilityLevel", {"name": "LSA_LmCompatibilityLevel", "value": 3},
                    {"name": "LSA_LmCompatibilityLevel", "value": 5})
    assert score_change(low)[0] == 40 and score_change(high)[0] == 0


def test_sticky_keys_backdoor_is_critical():
    c = added("system", "ifeo:x64:sethc.exe", {"exe": "sethc.exe", "value": "C:\\Windows\\System32\\cmd.exe"})
    score, reasons = score_change(c)
    assert score == 110 and level_for(score) == "critical"     # 90 accessibility + 20 cmd
    assert display_name(c) == "ifeo sethc.exe -> C:\\Windows\\System32\\cmd.exe"


def test_plain_ifeo_debugger_from_appdata():
    c = added("system", "ifeo:x64:chrome.exe", {"exe": "chrome.exe", "value": "C:\\Users\\a\\AppData\\l.exe"})
    assert score_change(c)[0] == 80


# ---- correlation and event summaries ----------------------------------------

def _corr_snaps(change_items, events):
    base = {"id": "a", "created_utc": "2026-10-13T10:00:00+00:00", "host": {"hostname": "PC", "elevated": True},
            "collectors": {k: {"status": "ok", "items": {}} for k in change_items}}
    cur = {"id": "b", "created_utc": "2026-10-13T10:05:00+00:00", "host": {"hostname": "PC", "elevated": True},
           "collectors": {k: {"status": "ok", "items": v} for k, v in change_items.items()},
           "events": {"window_start": "2026-10-13T10:00:00.000Z", "window_end": "2026-10-13T10:05:00.000Z",
                      "status": "ok", "errors": {}, "task_log_enabled": True, "events": events}}
    return base, cur


def test_firewall_and_defender_changes_tied_to_their_events():
    fw = {"rule:local:{WV-1}": {**parse_rule(RULE), "rule_id": "{WV-1}", "store": "local"}}
    df = {"exclusion:path:c:\\winvaulttest": {"kind": "path", "value": "C:\\WinVaultTest"}}
    events = [
        {"log": "Security", "event_id": 4946, "record_id": 1, "time": "2026-10-13T10:01:00.0000000Z",
         "data": {"RuleId": "{WV-1}", "RuleName": "Updater", "ProfileChanged": "All"}},
        {"log": "Microsoft-Windows-Windows Defender/Operational", "event_id": 5007, "record_id": 2,
         "time": "2026-10-13T10:02:00.0000000Z", "user_sid": "S-1-5-18",
         "data": {"Old Value": "", "New Value": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\WinVaultTest = 0x0"}},
    ]
    base, cur = _corr_snaps({"firewall": fw, "defender": df}, events)
    result = compare_snapshots(base, cur)
    analyze(result)
    correlate(result, cur, base)
    by = {c.category: c for c in result.changes}
    assert by["firewall"].attribution["when_source"] == "event 4946"
    assert by["defender"].attribution["when_source"] == "event 5007"
    assert "Exclusions" in summarize(events[1]) and "firewall rule added" in summarize(events[0])


def test_user_right_and_audit_events_summaries():
    e = {"event_id": 4704, "data": {"PrivilegeList": "SeDebugPrivilege", "TargetSid": "S-1-5-21-9-1010",
                                    "SubjectUserName": "bob", "SubjectDomainName": "PC"}}
    assert summarize(e, {"S-1-5-21-9-1010": "svc_backup"}) == "user right assigned: SeDebugPrivilege to svc_backup (by PC\\bob)"
    assert summarize({"event_id": 5001, "data": {}}) == "Microsoft Defender real-time protection disabled"


def test_ifeo_entry_seen_through_both_views_is_reported_once(monkeypatch):
    import winvault.collectors.system as system
    monkeypatch.setattr(system, "is_windows", lambda: True)
    base = r"Image File Execution Options"
    monkeypatch.setattr(system.regutil, "subkeys",
                        lambda hive, path: ["WinVaultTest.exe"] if path.endswith(base) else [])

    def values(hive, path):
        if path.endswith("WinVaultTest.exe"):
            return {"Debugger": "notepad.exe"}, None
        return None
    monkeypatch.setattr(system.regutil, "read_values", values)
    items = system.SystemCollector().collect()
    assert [k for k in items if k.startswith("ifeo:")] == ["ifeo:x64:winvaulttest.exe"]


def test_remote_access_detected_when_existing_entry_is_renamed():
    from winvault.analysis.rules import remote_access_software
    from winvault.models import Change, ChangeStatus
    base = {"display_name": "Notepad++ (64-bit x64)", "publisher": "Notepad++ Team", "display_version": "8.6"}
    renamed = Change(category="software", key="machine:Notepad++", status=ChangeStatus.MODIFIED,
                     before=base, after={**base, "display_name": "RustDesk", "publisher": "Purslane"})
    assert remote_access_software(renamed)[0] == 40
    upgrade = Change(category="software", key="machine:AnyDesk", status=ChangeStatus.MODIFIED,
                     before={"display_name": "AnyDesk", "display_version": "9.0.3"},
                     after={"display_name": "AnyDesk", "display_version": "9.0.4"})
    assert remote_access_software(upgrade) is None

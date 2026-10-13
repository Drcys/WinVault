"""Windows Firewall collector: every firewall rule and the on/off state of each profile.

Rules are read straight from the registry, where Windows Defender Firewall
persists them (local store and Group Policy store). Each rule is a value whose
data is a `|`-separated list such as

    v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=4444|App=C:\\x.exe|Name=Example|

Reading the registry keeps the collector fast and language-independent
(netsh / Get-NetFirewallRule output is localized and slow on large rule sets).
"""

from __future__ import annotations

from . import regutil
from .base import Collector, CollectorError, is_windows

RULE_STORES = [
    ("local", r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"),
    ("policy", r"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules"),
]
PROFILE_STORES = [
    ("local", r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"),
    ("policy", r"SOFTWARE\Policies\Microsoft\WindowsFirewall"),
]
PROFILES = {"DomainProfile": "Domain", "StandardProfile": "Private", "PublicProfile": "Public"}


def _joined(values: list[str] | None) -> str | None:
    if not values:
        return None
    return ",".join(sorted(set(values), key=str.lower))


def parse_rule(data: str) -> dict:
    """Turn one rule string into fields. Repeated keys (LPort, RA4, Profile...) are joined."""
    parts = str(data).split("|")
    fields: dict[str, list[str]] = {}
    for part in parts[1:]:
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        fields.setdefault(k, []).append(v)

    def one(k):
        v = fields.get(k)
        return v[0] if v else None

    lports = (fields.get("LPort") or []) + (fields.get("LPort2_10") or [])
    return {
        "name": one("Name"),
        "action": one("Action"),
        "active": (one("Active") or "").upper() == "TRUE",
        "direction": one("Dir"),
        "protocol": one("Protocol"),
        "local_ports": _joined(lports),
        "remote_ports": _joined(fields.get("RPort")),
        "remote_addresses": _joined((fields.get("RA4") or []) + (fields.get("RA6") or [])),
        "app": one("App"),
        "service": one("Svc"),
        "profiles": _joined(fields.get("Profile")),
        "package": one("AppPkgId"),
        "group": one("EmbedCtxt"),
        "_version": parts[0] if parts else None,
    }


def build_items(stores: dict[str, dict], profiles: dict[str, dict]) -> dict[str, dict]:
    """stores: {store: {value_name: rule_string}}; profiles: {store: {profile: values}} (split out for tests)."""
    items: dict[str, dict] = {}
    for store, rules in stores.items():
        for rule_id, data in rules.items():
            item = parse_rule(data)
            item["rule_id"] = rule_id
            item["store"] = store
            items[f"rule:{store}:{rule_id}"] = item
    for store, by_profile in profiles.items():
        for profile, values in by_profile.items():
            enabled = values.get("EnableFirewall")
            inbound = values.get("DefaultInboundAction")
            items[f"profile:{store}:{profile}"] = {
                "name": f"{profile} profile ({store})",
                "store": store,
                "enabled": None if enabled is None else bool(enabled),
                "default_inbound": None if inbound is None else ("block" if inbound else "allow"),
                "notifications": None if values.get("DisableNotifications") is None
                else not bool(values.get("DisableNotifications")),
            }
    return items


class FirewallCollector(Collector):
    name = "firewall"
    description = "Windows Firewall rules (local + Group Policy) and profile state"

    def collect(self) -> dict[str, dict]:
        if not is_windows():
            raise CollectorError("firewall collector requires Windows")
        stores, profiles = {}, {}
        for store, path in RULE_STORES:
            got = regutil.read_values(regutil.HKLM, path)
            if got is not None:
                stores[store] = {k: str(v) for k, v in got[0].items() if isinstance(v, str)}
        for store, base in PROFILE_STORES:
            for reg_name, label in PROFILES.items():
                got = regutil.read_values(regutil.HKLM, base + "\\" + reg_name)
                if got is not None and (store == "local" or got[0]):
                    profiles.setdefault(store, {})[label] = got[0]
        if "local" not in stores:
            raise CollectorError("firewall rule store not found in the registry")
        return build_items(stores, profiles)

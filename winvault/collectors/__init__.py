"""Collector registry. Add new collectors here to include them in snapshots."""

from .base import Collector, CollectorError
from .defender import DefenderCollector
from .files import CriticalFilesCollector
from .firewall import FirewallCollector
from .policy import PolicyCollector
from .registry import RegistryCollector
from .services import ServicesCollector
from .software import SoftwareCollector
from .startup import StartupCollector
from .system import SystemCollector
from .tasks import ScheduledTasksCollector
from .users import UsersCollector

ALL_COLLECTORS: dict[str, type[Collector]] = {
    c.name: c
    for c in (
        RegistryCollector,
        ServicesCollector,
        ScheduledTasksCollector,
        UsersCollector,
        StartupCollector,
        CriticalFilesCollector,
        FirewallCollector,
        DefenderCollector,
        PolicyCollector,
        SoftwareCollector,
        SystemCollector,
    )
}

__all__ = ["ALL_COLLECTORS", "Collector", "CollectorError"]

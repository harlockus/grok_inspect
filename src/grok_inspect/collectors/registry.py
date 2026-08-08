"""Ordered collector registry."""

from __future__ import annotations

from typing import Callable

from grok_inspect.collectors.accounts_access import collect_accounts
from grok_inspect.collectors.base import CollectorContext
from grok_inspect.collectors.env import collect_env
from grok_inspect.collectors.filesystem_hotspots import collect_filesystem
from grok_inspect.collectors.kernel_posture import collect_kernel
from grok_inspect.collectors.logs_sample import collect_logs
from grok_inspect.collectors.network import collect_network
from grok_inspect.collectors.peripheral import collect_peripheral
from grok_inspect.collectors.persistence import collect_persistence
from grok_inspect.collectors.process import collect_process
from grok_inspect.collectors.sniff_surface import collect_sniff_surface
from grok_inspect.collectors.stealer_indicators import collect_stealer

CollectorFn = Callable[[CollectorContext], dict]

COLLECTORS: list[tuple[str, CollectorFn]] = [
    ("env", collect_env),
    ("network", collect_network),
    ("sniff_surface", collect_sniff_surface),
    ("process", collect_process),
    ("persistence", collect_persistence),
    ("stealer_indicators", collect_stealer),
    ("accounts_access", collect_accounts),
    ("filesystem_hotspots", collect_filesystem),
    ("kernel_posture", collect_kernel),
    ("logs_sample", collect_logs),
    ("peripheral", collect_peripheral),
]

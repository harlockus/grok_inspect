"""Collector protocol and timeout runner."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from dataclasses import dataclass, field
from typing import Any, Callable

from grok_inspect.models import CollectorResult, CollectorStatus
from grok_inspect.security.redact import redact_text
from grok_inspect.security.sanitize import deep_sanitize, scrub_control_chars


@dataclass
class CollectorContext:
    host: dict[str, Any]
    timeout_sec: float = 45.0
    project_root: Any = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def elevated(self) -> bool:
        return bool(self.host.get("elevated"))

    @property
    def os_family(self) -> str:
        return str(self.host.get("os_family", ""))


CollectorFn = Callable[[CollectorContext], dict[str, Any] | CollectorResult]


def run_collector(name: str, fn: CollectorFn, ctx: CollectorContext) -> CollectorResult:
    # Hard outer wait = collector timeout (bounded). No grace that defeats short timeouts.
    try:
        outer = float(ctx.timeout_sec)
    except (TypeError, ValueError):
        outer = 45.0
    outer = max(0.05, min(outer, 320.0))


    def _call() -> CollectorResult:
        try:
            out = fn(ctx)
            if isinstance(out, CollectorResult):
                # Sanitize even if collector returned a Result
                return CollectorResult(
                    name=out.name,
                    status=out.status,
                    evidence=deep_sanitize(out.evidence or {}),
                    detail=redact_text(scrub_control_chars(out.detail, max_len=400)),
                    error=(
                        redact_text(scrub_control_chars(out.error, max_len=300))
                        if out.error
                        else None
                    ),
                )
            status = CollectorStatus.FULL
            detail = ""
            evidence: dict[str, Any]
            if isinstance(out, dict):
                evidence = dict(out)
                if evidence.get("_status"):
                    try:
                        status = CollectorStatus(str(evidence.pop("_status")))
                    except ValueError:
                        status = CollectorStatus.ERROR
                        detail = "invalid collector status"
                if "_detail" in evidence:
                    detail = str(evidence.pop("_detail") or "")
            else:
                evidence = {"value": out}
            return CollectorResult(
                name=name,
                status=status,
                evidence=deep_sanitize(evidence or {}),
                detail=redact_text(scrub_control_chars(detail, max_len=400)),
            )
        except Exception as exc:
            # Never include full traceback (path/env leakage)
            return CollectorResult(
                name=name,
                status=CollectorStatus.ERROR,
                evidence={},
                error=redact_text(
                    scrub_control_chars(f"{type(exc).__name__}", max_len=120)
                ),
                detail="",
            )

    with ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(_call)
        try:
            return fut.result(timeout=outer)
        except FuturesTimeout:
            return CollectorResult(
                name=name,
                status=CollectorStatus.ERROR,
                error=f"timeout after {ctx.timeout_sec}s",
            )

"""Core data models for Grok Inspect scans."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class CollectorStatus(str, Enum):
    FULL = "full"
    LIMITED = "limited"
    SKIPPED = "skipped"
    ERROR = "error"


class Finding(BaseModel):
    id: str
    title: str
    summary: str
    severity: Severity
    category: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    confidence: float = 1.0
    remediation_hint: str = ""
    os: str | None = None
    requires_elevated: bool = False
    acknowledged: bool = False


class CoverageEntry(BaseModel):
    collector: str
    status: CollectorStatus
    detail: str = ""
    requires_elevated: bool = False


class CollectorResult(BaseModel):
    name: str
    status: CollectorStatus
    evidence: dict[str, Any] = Field(default_factory=dict)
    detail: str = ""
    error: str | None = None


class ScanBundle(BaseModel):
    """Raw collector outputs before heuristics."""

    started_at: datetime
    host: dict[str, Any] = Field(default_factory=dict)
    elevated: bool = False
    results: list[CollectorResult] = Field(default_factory=list)

    def evidence_for(self, name: str) -> dict[str, Any]:
        for r in self.results:
            if r.name == name:
                return r.evidence or {}
        return {}


class ScanScore(BaseModel):
    max_severity: Severity = Severity.INFO
    counts: dict[str, int] = Field(default_factory=dict)
    open_finding_count: int = 0

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> ScanScore:
        open_f = [f for f in findings if not f.acknowledged]
        counts = {s.value: 0 for s in Severity}
        max_sev = Severity.INFO
        for f in open_f:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
            if f.severity.rank > max_sev.rank:
                max_sev = f.severity
        return cls(
            max_severity=max_sev,
            counts=counts,
            open_finding_count=len(open_f),
        )


class GrokAnalysis(BaseModel):
    available: bool = False
    model_id: str | None = None
    reasoning_effort: str | None = None
    executive_summary: str = ""
    threat_narrative: str = ""
    prioritized_findings: list[dict[str, Any]] = Field(default_factory=list)
    likely_attacker_goals: list[str] = Field(default_factory=list)
    remediation_plan: list[str] = Field(default_factory=list)
    questions_for_operator: list[str] = Field(default_factory=list)
    confidence: float | None = None
    latency_s: float | None = None
    usage_summary: str = ""
    error: str | None = None
    raw_text: str = ""


class ScanResult(BaseModel):
    version: str = "1"
    tool_version: str
    started_at: datetime
    finished_at: datetime
    host: dict[str, Any] = Field(default_factory=dict)
    elevated: bool = False
    coverage: list[CoverageEntry] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    score: ScanScore = Field(default_factory=ScanScore)
    grok: GrokAnalysis = Field(default_factory=GrokAnalysis)
    bundle_summary: dict[str, Any] = Field(default_factory=dict)

    def exit_code(self) -> int:
        if self.score.max_severity == Severity.CRITICAL:
            return 3
        if self.score.max_severity.rank >= Severity.MEDIUM.rank:
            return 1
        return 0


def utcnow() -> datetime:
    return datetime.now(timezone.utc)

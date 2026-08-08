"""Finding allowlist support (safe YAML load)."""

from __future__ import annotations

from pathlib import Path

from grok_inspect.models import Finding
from grok_inspect.security.paths import PathSecurityError
from grok_inspect.security.safe_io import load_yaml_file
from grok_inspect.security.sanitize import scrub_control_chars


class Allowlist:
    def __init__(
        self,
        rule_ids: list[str] | None = None,
        path_substrings: list[str] | None = None,
        process_names: list[str] | None = None,
    ) -> None:
        self.rule_ids = {
            scrub_control_chars(str(r), max_len=120).lower() for r in (rule_ids or [])
        }
        self.path_substrings = [
            scrub_control_chars(str(p), max_len=300).lower()
            for p in (path_substrings or [])
        ][:200]
        self.process_names = {
            scrub_control_chars(str(p), max_len=120).lower()
            for p in (process_names or [])
        }

    @classmethod
    def from_yaml(cls, path: Path | str) -> Allowlist:
        try:
            data = load_yaml_file(path, max_bytes=256_000)
        except PathSecurityError:
            return cls()
        except OSError:
            return cls()
        return cls(
            rule_ids=list(data.get("rule_ids") or [])[:200],
            path_substrings=list(data.get("path_substrings") or [])[:200],
            process_names=list(data.get("process_names") or [])[:200],
        )

    def apply(self, findings: list[Finding]) -> list[Finding]:
        out: list[Finding] = []
        for f in findings:
            if f.id.lower() in self.rule_ids:
                out.append(f.model_copy(update={"acknowledged": True}))
                continue
            blob = (f.summary + " " + str(f.evidence)).lower()
            if any(p and p in blob for p in self.path_substrings):
                out.append(f.model_copy(update={"acknowledged": True}))
                continue
            ev = f.evidence or {}
            names = []
            if isinstance(ev.get("process"), dict):
                names.append(str(ev["process"].get("name", "")))
            if isinstance(ev.get("name"), str):
                names.append(ev["name"])
            if any(n.lower() in self.process_names for n in names if n):
                out.append(f.model_copy(update={"acknowledged": True}))
                continue
            out.append(f)
        return out

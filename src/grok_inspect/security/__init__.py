"""Security helpers: redaction, path confinement, sanitize, safe I/O."""

from grok_inspect.security.paths import PathSecurityError, safe_report_dir
from grok_inspect.security.redact import redact_text
from grok_inspect.security.sanitize import sanitize_scan_result

__all__ = [
    "PathSecurityError",
    "redact_text",
    "safe_report_dir",
    "sanitize_scan_result",
]


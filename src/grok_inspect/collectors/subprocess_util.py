"""Safe subprocess helpers — no shell, scrubbed env, hard timeouts."""

from __future__ import annotations

import os
import subprocess
from typing import Mapping, Sequence

# Never pass secrets into collector child processes
_SCRUB_ENV_KEYS = frozenset(
    {
        "XAI_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "NGROK_AUTHTOKEN",
    }
)


def _sanitized_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in _SCRUB_ENV_KEYS}
    # Ensure PATH exists so system tools still resolve
    if "PATH" not in env:
        env["PATH"] = os.defpath or "/usr/bin:/bin"
    return env


def run_cmd(
    args: Sequence[str],
    *,
    timeout: float = 30.0,
    text: bool = True,
    env: Mapping[str, str] | None = None,
) -> tuple[int, str, str]:
    """
    Run command without shell.

    - ``shell=False`` always (argv list only)
    - timeout hard-capped at 120s
    - secrets stripped from child environment
    - stdout/stderr capped in returned strings
    """
    if not args:
        return 1, "", "empty command"
    argv = [str(a) for a in args]
    # Reject embedded NULs (argv injection weirdness)
    if any("\x00" in a for a in argv):
        return 1, "", "invalid null in argv"
    try:
        t = float(timeout)
    except (TypeError, ValueError):
        t = 30.0
    t = max(1.0, min(t, 120.0))

    child_env = dict(env) if env is not None else _sanitized_env()
    for k in _SCRUB_ENV_KEYS:
        child_env.pop(k, None)

    try:
        p = subprocess.run(
            argv,
            capture_output=True,
            text=text,
            timeout=t,
            check=False,
            shell=False,
            env=child_env,
        )
        out = p.stdout or ""
        err = p.stderr or ""
        if text:
            # Cap collector output size (DoS / log flood)
            if len(out) > 500_000:
                out = out[:500_000] + "\n…[truncated]"
            if len(err) > 50_000:
                err = err[:50_000] + "\n…[truncated]"
        return p.returncode, out, err
    except FileNotFoundError:
        return 127, "", f"not found: {argv[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as exc:
        # Do not leak env or secrets via exception text
        return 1, "", f"{type(exc).__name__}"

"""Path confinement — prevent traversal and unexpected writes."""

from __future__ import annotations

from pathlib import Path


class PathSecurityError(ValueError):
    """Raised when a path is outside an allowed root or otherwise unsafe."""


def resolve_user_path(path: Path | str) -> Path:
    """Resolve symlinks and ``..`` to an absolute path."""
    return Path(path).expanduser().resolve(strict=False)


def ensure_path_inside(path: Path | str, root: Path | str) -> Path:
    """
    Ensure ``path`` resolves inside ``root``.

    Raises PathSecurityError on traversal attempts.
    """
    root_r = resolve_user_path(root)
    path_r = resolve_user_path(path)
    try:
        path_r.relative_to(root_r)
    except ValueError as exc:
        raise PathSecurityError(
            f"Path {path_r} is outside allowed root {root_r}"
        ) from exc
    return path_r


def safe_report_dir(out_dir: Path | str, *, cwd: Path | None = None) -> Path:
    """
    Resolve report output directory.

    Allows absolute paths the operator explicitly chose, or relative paths under cwd.
    Blocks null bytes and empty paths.
    """
    raw = str(out_dir)
    if not raw or "\x00" in raw:
        raise PathSecurityError("Invalid report directory")
    base = cwd or Path.cwd()
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = (base / p).resolve(strict=False)
    else:
        p = p.resolve(strict=False)
    # Disallow writing over sensitive system roots
    forbidden_prefixes = (
        Path("/etc"),
        Path("/bin"),
        Path("/sbin"),
        Path("/usr/bin"),
        Path("/usr/sbin"),
        Path("/System"),
        Path("/dev"),
        Path("/proc"),
        Path("/sys"),
        Path("/Windows/System32"),
        Path("C:/Windows/System32"),
        Path("C:/Windows/system32"),
    )
    for pref in forbidden_prefixes:
        try:
            pref_r = pref.resolve(strict=False)
            p.relative_to(pref_r)
            raise PathSecurityError(f"Refusing to write reports under {pref_r}")
        except ValueError:
            continue
        except OSError:
            continue
    return p


def safe_readable_file(
    path: Path | str,
    *,
    max_bytes: int = 1_000_000,
    must_exist: bool = True,
) -> Path:
    """Validate a file path for reading config/allowlist (not a directory)."""
    p = resolve_user_path(path)
    if must_exist and not p.is_file():
        raise PathSecurityError(f"Not a readable file: {p}")
    if p.is_file():
        try:
            size = p.stat().st_size
        except OSError as exc:
            raise PathSecurityError(f"Cannot stat file: {p}") from exc
        if size > max_bytes:
            raise PathSecurityError(
                f"File too large ({size} bytes > {max_bytes}): {p}"
            )
    return p

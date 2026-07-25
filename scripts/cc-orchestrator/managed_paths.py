"""Path validation and atomic writes for workspace-root managed files."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path
from typing import Callable


class ManagedPathError(RuntimeError):
    """Raised when a managed file path is outside its allowed boundary."""


def _is_link_or_reparse(path: Path) -> bool:
    details = path.lstat()
    if stat.S_ISLNK(details.st_mode):
        return True
    attributes = getattr(details, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _reject_link_chain(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if not current.exists() and not current.is_symlink():
            continue
        if _is_link_or_reparse(current):
            raise ManagedPathError(
                f"Managed path contains a symlink or reparse point: {current}"
            )


def managed_mcp_path(
    workspace_root: str | Path,
    artifact_root: str | Path,
    mcp_path: str | Path | None = None,
) -> Path:
    """Return the only allowed MCP target after validating its managed root."""
    root = Path(os.path.abspath(Path(workspace_root).expanduser()))
    artifacts = Path(os.path.abspath(Path(artifact_root).expanduser()))
    if not root.exists() or not root.is_dir():
        raise ManagedPathError(f"Managed workspace root does not exist: {root}")
    if not artifacts.exists() or not artifacts.is_dir():
        raise ManagedPathError(
            f"Managed workspace is not initialized: {artifacts}"
        )
    _reject_link_chain(root)
    _reject_link_chain(artifacts)

    if mcp_path is not None:
        raw = Path(mcp_path).expanduser()
        if raw.is_absolute():
            raise ManagedPathError("mcp_path must be relative.")
        if ".." in raw.parts:
            raise ManagedPathError("mcp_path must not contain '..'.")
        if raw.parts != (".mcp.json",):
            raise ManagedPathError(
                "mcp_path must name the workspace-root .mcp.json."
            )

    target = root / ".mcp.json"
    _reject_link_chain(target)
    if target.exists():
        details = target.lstat()
        if not stat.S_ISREG(details.st_mode):
            raise ManagedPathError(
                "Managed .mcp.json target must be a regular file."
            )
        if details.st_nlink != 1:
            raise ManagedPathError(
                "Managed .mcp.json target must have exactly one hard link."
            )
    return target


def read_managed_text(path: Path, *, validate: Callable[[], Path]) -> str:
    """Read a single-link regular file and reject identity changes."""
    validated = validate()
    if validated != path:
        raise ManagedPathError("Managed target changed before read.")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ManagedPathError(
                "Managed .mcp.json must be a single-link regular file."
            )
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            text = handle.read()
            after = os.fstat(handle.fileno())
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ManagedPathError("Managed target identity changed during read.")
        if validate() != path:
            raise ManagedPathError("Managed target changed after read.")
        return text
    finally:
        if fd >= 0:
            os.close(fd)


def atomic_replace_text(
    path: Path,
    text: str,
    *,
    validate: Callable[[], Path],
) -> None:
    """Atomically replace a validated file with a same-directory temporary."""
    validate()
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        validated = validate()
        if validated != path:
            raise ManagedPathError("Managed target changed during write.")
        os.replace(temporary, path)
        if os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass

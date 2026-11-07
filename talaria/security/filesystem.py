"""Filesystem reads that stay beneath a repository root and reject symlinks."""

from __future__ import annotations

import os
import stat
from pathlib import Path


class SecureFileError(RuntimeError):
    """Raised when a repository file cannot be safely opened within its budget."""


class SecureFileAccessUnavailable(SecureFileError):
    """Raised when the current platform cannot provide no-follow file access."""


def read_regular_file_beneath(
    root: str | Path,
    relative: str | Path,
    maximum_bytes: int,
) -> bytes:
    """Read a bounded regular file while refusing symlinks in every path segment."""
    root = Path(os.path.abspath(Path(root).expanduser()))
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        raise SecureFileError("Repository root cannot be opened safely") from exc
    if resolved_root != root:
        raise SecureFileError("Repository root must not contain symlinked paths")
    relative = Path(relative)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise SecureFileError("Repository file path is invalid")
    if maximum_bytes <= 0:
        raise SecureFileError("Repository file size limit must be positive")

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory or os.open not in os.supports_dir_fd:
        raise SecureFileAccessUnavailable(
            "Secure repository file access is unsupported on this platform"
        )

    descriptors = []
    try:
        root_fd = _open_absolute_directory(root, directory, nofollow)
        descriptors.append(root_fd)
        parent_fd = root_fd
        for component in relative.parts[:-1]:
            parent_fd = os.open(
                component,
                os.O_RDONLY | directory | nofollow,
                dir_fd=parent_fd,
            )
            descriptors.append(parent_fd)
        file_fd = os.open(
            relative.name,
            os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_fd,
        )
        descriptors.append(file_fd)
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise SecureFileError("Repository source is not a regular file")
        if metadata.st_size > maximum_bytes:
            raise SecureFileError("Repository source exceeds the file size limit")
        contents = bytearray()
        while len(contents) <= maximum_bytes:
            chunk = os.read(file_fd, min(65_536, maximum_bytes + 1 - len(contents)))
            if not chunk:
                break
            contents.extend(chunk)
        if len(contents) > maximum_bytes:
            raise SecureFileError("Repository source exceeds the file size limit")
        return bytes(contents)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _open_absolute_directory(path: Path, directory_flag: int, nofollow_flag: int) -> int:
    """Open an absolute directory one component at a time without symlinks."""
    descriptor = os.open(path.anchor, os.O_RDONLY | directory_flag | nofollow_flag)
    try:
        for component in path.parts[1:]:
            child = os.open(
                component,
                os.O_RDONLY | directory_flag | nofollow_flag,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise

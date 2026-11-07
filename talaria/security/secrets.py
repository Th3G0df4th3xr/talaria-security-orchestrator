"""Read deployment secrets without accepting broadly readable credentials."""

from __future__ import annotations

import stat
from os import O_NOFOLLOW, O_RDONLY, fdopen, fstat
from os import open as os_open
from pathlib import Path


class SecretFileError(ValueError):
    """Raised when a configured secret file cannot be safely read."""


def read_secret_file(
    value: str | Path,
    *,
    label: str,
    strip: bool = True,
    allow_empty: bool = False,
) -> str:
    """Read a secret file and require private permissions for non-empty data."""
    path = Path(value).expanduser()
    try:
        descriptor = os_open(path, O_RDONLY | O_NOFOLLOW)
        with fdopen(descriptor, "r", encoding="utf-8") as stream:
            metadata = fstat(stream.fileno())
            content = stream.read()
        if not stat.S_ISREG(metadata.st_mode):
            raise SecretFileError(f"Configured {label} secret is not a regular file")
    except SecretFileError:
        raise
    except (OSError, UnicodeError) as exc:
        raise SecretFileError(f"Cannot read configured {label} secret file") from exc

    secret = content.strip() if strip else content
    if secret and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise SecretFileError(f"Configured {label} secret file must not be group/world-readable")
    if not secret and not allow_empty:
        raise SecretFileError(f"Configured {label} secret file is empty")
    return secret

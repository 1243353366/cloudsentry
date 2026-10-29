"""Bounded, non-executing reads of explicitly chosen regular files."""
from __future__ import annotations

import os
import stat


def read_regular(path: str, maximum: int) -> bytes:
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("input must be a regular file, not a symlink or device")
    if before.st_size > maximum:
        raise ValueError("input exceeds configured size limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        after = os.fstat(fd)
        if not stat.S_ISREG(after.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError("input changed during safe open")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            content = stream.read(maximum + 1)
        if len(content) > maximum:
            raise ValueError("input exceeds configured size limit")
        return content
    finally:
        if fd >= 0:
            os.close(fd)

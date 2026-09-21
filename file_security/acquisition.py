"""Read one explicitly operator-selected regular file; no traversal or writes."""

import os
from pathlib import Path
import stat

from .text_analysis import MAX_BYTES


class FileInputError(ValueError):
    """Fixed non-sensitive acquisition failure reason."""


def read_selected_file(path: str) -> bytes:
    """Return a bounded snapshot, not ongoing authority over a path.

    Call only for an explicit operator selection, outside the UI thread.
    This is not a defense against hostile same-user path replacement.
    """
    if type(path) is not str or not path or len(path) > 32767 or '\x00' in path or not os.path.isabs(path):
        raise FileInputError('unsupported_path')
    if os.name == 'nt':
        drive, tail = os.path.splitdrive(path)
        if len(drive) != 2 or not drive[0].isalpha() or drive[1] != ':' or ':' in tail:
            raise FileInputError('unsupported_path')
        reserved = getattr(os.path, 'isreserved', None)
        if reserved and reserved(path):
            raise FileInputError('unsupported_path')
    descriptor = None
    try:
        selected = Path(path)
        # Reject existing symlink/reparse components before opening. This is
        # conservative path hygiene under A, not atomic path confinement.
        for component in [*reversed(selected.parents), selected]:
            info = component.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise FileInputError('unsupported_link')
        if not stat.S_ISREG(info.st_mode):
            raise FileInputError('unsupported_file')
        if info.st_size > MAX_BYTES:
            raise FileInputError('input_too_large')
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0)
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino):
            raise FileInputError('file_changed')
        if before.st_size > MAX_BYTES:
            raise FileInputError('input_too_large')
        content = bytearray()
        while len(content) <= MAX_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_BYTES + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) > MAX_BYTES:
            raise FileInputError('input_too_large')
        after = os.fstat(descriptor)
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or len(content) != before.st_size:
            raise FileInputError('file_changed')
        return bytes(content)
    except OSError:
        raise FileInputError('file_unavailable') from None
    finally:
        if descriptor is not None:
            os.close(descriptor)

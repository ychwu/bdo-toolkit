"""Shared filesystem primitives for explicit profile writes."""

import datetime as dt
import os
from pathlib import Path
import tempfile
from typing import Optional


def next_backup_path(path: Path) -> Path:
    backup_dir = path.parent / "opcodes_backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(tz=dt.UTC).strftime("%Y%m%d%H%M%S%f")
    candidate = backup_dir / f"{path.name}.bak.{stamp}"
    suffix = 1
    while candidate.exists():
        candidate = backup_dir / f"{path.name}.bak.{stamp}.{suffix}"
        suffix += 1
    return candidate


def atomic_write_text(path: Path, text: str) -> None:
    """Atomically replace a UTF-8 text file in its destination directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()

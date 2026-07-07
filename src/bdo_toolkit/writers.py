"""Output writers for decoded events."""

from __future__ import annotations

import json
import sys
from typing import TextIO

from .events import BDOEvent


class ConsoleEventWriter:
    """Write human-readable one-line events."""

    def __init__(self, stream: TextIO | None = None) -> None:
        self.stream = stream if stream is not None else sys.stdout

    def write(self, event: BDOEvent) -> None:
        print(event.format_human(), file=self.stream)


class JsonlEventWriter:
    """Write newline-delimited JSON events."""

    def __init__(self, stream: TextIO | None = None) -> None:
        self.stream = stream if stream is not None else sys.stdout

    def write(self, event: BDOEvent) -> None:
        print(json.dumps(event.to_dict(), sort_keys=True), file=self.stream)


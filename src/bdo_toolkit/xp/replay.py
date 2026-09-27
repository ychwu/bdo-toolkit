"""Streaming offline solo XP replay; no implicit profile selection."""
from collections import deque
from collections.abc import Generator, Iterable, Iterator
from dataclasses import replace
from pathlib import Path
from types import TracebackType
from typing import cast

from .._capture_backend import iter_pcap_file
from .._protocol import DEFAULT_SERVER_PORTS
from ..profiles import OpcodeProfile
from ._tracker import XPFlowManager, XPTracker, profile_layout
from .models import XPCaptureHealth, XPReading, XPStatus


class XPReplay(Iterator[XPReading]):
    """Bounded single-consumer replay. Close early exits, preferably with 'with'.

    EOF retains last-observed state, not proof of a live connection. On failure
    discard earlier session totals: status becomes invalid and iteration raises.
    Closing early does not flush or certify an incomplete packet tail.
    """

    def __init__(self, path: str | Path, *, profile: OpcodeProfile,
                 ports: Iterable[int] = DEFAULT_SERVER_PORTS) -> None:
        self._pending: deque[XPReading] = deque()
        self._tracker = XPTracker(profile_layout(profile), self._enqueue)
        self._manager = XPFlowManager(self._tracker, ports)
        self._packets = cast(Generator[None, None, None], iter_pcap_file(Path(path), self._manager))
        self._processed = 0
        self._closed = self._finished = False
        self._error: BaseException | None = None

    def _enqueue(self, reading: XPReading) -> None:
        if len(self._pending) >= 4096:
            self._tracker.invalidate("XP replay event bound exceeded")
        self._pending.append(reading)

    @property
    def status(self) -> XPStatus:
        status = self._tracker.snapshot()
        return replace(status, status="invalid", reading=None, reason=str(self._error)) if self._error else status

    @property
    def health(self) -> XPCaptureHealth:
        return XPCaptureHealth(packets_processed=self._processed, packets_accepted=self._processed,
                               tcp_gap_resets=self._manager.tcp_gap_resets,
                               flow_state_evictions=self._manager.evictions)

    def __iter__(self) -> XPReplay:
        return self

    def __next__(self) -> XPReading:
        if self._closed:
            raise StopIteration
        try:
            while not self._pending:
                if self._finished:
                    self.close()
                    raise StopIteration
                try:
                    next(self._packets)
                except StopIteration:
                    self._finished = True
                else:
                    self._processed += 1
            return self._pending.popleft()
        except StopIteration:
            raise
        except BaseException as exc:
            self._error = exc
            try:
                self.close()
            except BaseException as cleanup:
                exc.add_note(f"XP replay cleanup also failed: {cleanup!r}")
            raise

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._pending.clear()
            try:
                self._packets.close()
            except BaseException as exc:
                self._error = self._error or exc
                raise

    def __enter__(self) -> XPReplay:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None,
                 traceback: TracebackType | None) -> None:
        try:
            self.close()
        except BaseException as exc:
            if exc_value is None:
                raise
            exc_value.add_note(f"XP replay cleanup also failed: {exc!r}")


def replay_xp(path: str | Path, *, profile: OpcodeProfile,
              ports: Iterable[int] = DEFAULT_SERVER_PORTS) -> XPReplay:
    """Replay only with the recording's explicit matching XP profile."""
    return XPReplay(path, profile=profile, ports=ports)

"""Bounded, streaming offline Agris replay with observable discovery status."""
from __future__ import annotations

from collections import deque
from collections.abc import Generator, Iterable, Iterator
from dataclasses import replace
from pathlib import Path
from types import TracebackType
from typing import cast

from .._capture_backend import iter_pcap_file
from .._protocol import DEFAULT_SERVER_PORTS
from ..profiles import OpcodeProfile
from ._profile import profile_layout
from ._capture import AgrisCaptureHealth, AgrisFlowManager
from ._discovery import AgrisTracker
from .models import AgrisBalance, AgrisDiscoveryOptions, AgrisStatus


class AgrisReplay(Iterator[AgrisBalance]):
    """Single-consumer iterator. Close early-stopped replays or use a with block.

    An explicit profile bypasses discovery. Otherwise discovery is local to this object. Initial learning observations are not
    replayed as historical events: the first event is the newest balance at
    selection time. No entire-file list of balances or packets is retained.
    """

    def __init__(self, path: str | Path, *, expected_maximum_points: int,
                 ports: Iterable[int] = DEFAULT_SERVER_PORTS,
                 discovery_options: AgrisDiscoveryOptions | None = None,
                 profile: OpcodeProfile | None = None) -> None:
        self._pending: deque[AgrisBalance] = deque()
        self._tracker = AgrisTracker(expected_maximum_points=expected_maximum_points,
                                    options=discovery_options, on_balance=self._enqueue,
                                    profile_layout=profile_layout(profile))
        self._manager = AgrisFlowManager(self._tracker, ports)
        self._packets = cast(Generator[None, None, None], iter_pcap_file(Path(path), self._manager))
        self._processed = 0
        self._closed = False
        self._finished = False
        self._error: BaseException | None = None

    def _enqueue(self, balance: AgrisBalance) -> None:
        if len(self._pending) >= 4096:
            self._tracker.invalidate("Agris replay event bound exceeded")
        self._pending.append(balance)

    @property
    def status(self) -> AgrisStatus:
        status = self._tracker.snapshot()
        if self._error is not None:
            return replace(status, status="invalid", balance=None, reason=str(self._error))
        return status

    @property
    def health(self) -> AgrisCaptureHealth:
        return AgrisCaptureHealth(packets_processed=self._processed, packets_accepted=self._processed,
                                  tcp_gap_resets=self._manager.tcp_gap_resets,
                                  flow_state_evictions=self._manager.evictions)

    def __iter__(self) -> AgrisReplay:
        return self

    def __next__(self) -> AgrisBalance:
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
                    self._manager.refresh()
            return self._pending.popleft()
        except StopIteration:
            raise
        except BaseException as exc:
            self._error = exc
            try:
                self.close()
            except BaseException as cleanup:
                exc.add_note(f"Agris replay cleanup also failed: {cleanup!r}")
            raise

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._pending.clear()
        # Closing a partial iterator must NOT flush/qualify its incomplete tail.
        self._packets.close()

    def __enter__(self) -> AgrisReplay:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None,
                 traceback: TracebackType | None) -> None:
        try:
            self.close()
        except BaseException as cleanup:
            if exc_value is None:
                raise
            exc_value.add_note(f"Agris replay cleanup also failed: {cleanup!r}")


def replay_agris(path: str | Path, *, expected_maximum_points: int,
                 ports: Iterable[int] = DEFAULT_SERVER_PORTS,
                 discovery_options: AgrisDiscoveryOptions | None = None,
                 profile: OpcodeProfile | None = None) -> AgrisReplay:
    """Discover and stream balance observations; the caller must supply the cap."""
    return AgrisReplay(path, expected_maximum_points=expected_maximum_points,
                       ports=ports, discovery_options=discovery_options, profile=profile)

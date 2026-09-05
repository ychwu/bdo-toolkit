"""Private calibration capture implementation."""

from __future__ import annotations

import math
from collections import deque
from dataclasses import replace
from pathlib import Path
from threading import Lock, RLock
from typing import Optional
from .._capture_backend import (
    make_packet_handler,
    replay_pcap_file,
    validate_server_ports,
)
from .._capture_options import PacketCaptureOptions
from .._capture_runtime import (
    DEFAULT_STARTUP_TIMEOUT_SECONDS,
    LivePacketCapture,
    _attach_cleanup_owner,
)
from .._framing import FrameCollectorScanner
from .._protocol import BDOFrame, DEFAULT_SERVER_PORTS
from .._reassembly import FlowManager
from ._constants import (
    DEFAULT_CALIBRATION_MAX_RETAINED_BYTES,
    DEFAULT_CALIBRATION_MAX_RETAINED_FRAMES,
    _CALIBRATION_MAX_ACTIVE_FLOWS,
)
from .analysis import calibrate_frames
from .models import CalibrationResult, CalibrationRetention
from .validation import (
    _validate_calibration_options,
    _validate_calibration_retention_limits,
)


def collect_frames_pcap(
    path: str | Path,
    *,
    ports: tuple[int, ...] = DEFAULT_SERVER_PORTS,
) -> list[BDOFrame]:
    """Reassemble a pcap and return every generic BDO frame."""
    validated_ports = validate_server_ports(ports)
    frames: list[BDOFrame] = []
    manager = FlowManager(
        server_ports=validated_ports,
        scanner_factory=lambda: FrameCollectorScanner(frames.append),
        track_flow_generations=True,
    )
    replay_pcap_file(Path(path), manager)
    return frames


def calibrate_pcap(
    path: str | Path,
    *,
    item_id: int,
    quantity: Optional[int] = None,
    action: str = "auto",
    ports: tuple[int, ...] = DEFAULT_SERVER_PORTS,
    context_frames: int = 5,
    min_confidence: float = 0.80,
) -> CalibrationResult:
    """Calibrate message specs from a pcap of a known in-game action."""
    _validate_calibration_options(
        item_id=item_id,
        quantity=quantity,
        action=action,
        context_frames=context_frames,
        min_confidence=min_confidence,
    )
    frames = collect_frames_pcap(path, ports=ports)
    return calibrate_frames(
        frames,
        item_id=item_id,
        quantity=quantity,
        action=action,
        context_frames=context_frames,
        min_confidence=min_confidence,
    )


class CalibrationSession:
    """Live calibration with programmatic start/stop, for embedding in apps.

    The session captures passively in the background between ``start()`` and
    ``stop()``. ``start()`` returns after the capture adapter reports ready,
    or raises after a finite startup deadline. Typical app flow::

        # quantity=1 matches each serialized unstackable record; it is not
        # the number of items moved by each user-performed action.
        session = CalibrationSession(item_id=15156, quantity=1)
        session.start()
        # ... deposit 1; deposit the remaining 4; withdraw all 5;
        #     then have the user click "Done" ...
        result = session.stop()
        if result.specs:
            update_profile(result, my_profile_path)

    Auto calibration (the default) classifies each transfer direction from
    packet structure, so no ``action`` need be declared. Storage authority
    requires at least two distinct deposit counts plus one withdrawal. The
    guided five-unstackable sequence is deposit one, deposit four, withdraw
    all five. The user performs those actions; the session passively observes
    them, and ``quantity=1`` continues to describe every repeated item record.
    The values 1, 4, and 5 are a recommended operator workflow rather than
    constructor arguments; the session learns batch cardinality from traffic.
    Loot preview is a separate explicit action and may use ``quantity=None``
    when only the watched item ID is stable.

    Live evidence is bounded by both ``max_retained_frames`` and
    ``max_retained_bytes``. The newest contiguous frame tail is retained so a
    transfer performed shortly before ``stop()`` keeps its preceding context.
    ``frames_collected`` remains the total-observed progress count; use
    ``frames_retained``, ``frames_discarded``, or ``retention`` to surface
    eviction. A truncated result calibrates only the retained tail.

    TCP reassembly is also bounded to 64 active flows. Admitting another flow
    finalizes the least-recently active state. FIN/RST or session finalization
    releases remaining flow state; live calibration does not configure
    time-based idle eviction.

    Used as a context manager, the capture is stopped on exit even if the
    block raises; call ``stop()`` inside the block to get the result.
    """

    _STARTUP_TIMEOUT_SECONDS = DEFAULT_STARTUP_TIMEOUT_SECONDS

    def __init__(
        self,
        *,
        item_id: int,
        quantity: Optional[int] = None,
        action: str = "auto",
        capture_options: Optional[PacketCaptureOptions] = None,
        context_frames: int = 5,
        min_confidence: float = 0.80,
        max_retained_frames: int = DEFAULT_CALIBRATION_MAX_RETAINED_FRAMES,
        max_retained_bytes: int = DEFAULT_CALIBRATION_MAX_RETAINED_BYTES,
    ) -> None:
        _validate_calibration_options(
            item_id=item_id,
            quantity=quantity,
            action=action,
            context_frames=context_frames,
            min_confidence=min_confidence,
        )
        _validate_calibration_retention_limits(
            max_retained_frames=max_retained_frames,
            max_retained_bytes=max_retained_bytes,
            context_frames=context_frames,
        )
        if capture_options is not None and not isinstance(
            capture_options, PacketCaptureOptions
        ):
            raise TypeError(
                "capture_options must be a PacketCaptureOptions or None"
            )
        self._item_id = item_id
        self._quantity = quantity
        self._action = action
        self._capture_options = capture_options or PacketCaptureOptions()
        self._context_frames = context_frames
        self._min_confidence = min_confidence
        self._max_retained_frames = max_retained_frames
        self._max_retained_bytes = max_retained_bytes
        self._frames: deque[BDOFrame] = deque()
        self._frames_observed = 0
        self._frames_discarded = 0
        self._bytes_observed = 0
        self._bytes_retained = 0
        self._bytes_discarded = 0
        self._manager: Optional[FlowManager] = None
        self._capture: Optional[LivePacketCapture] = None
        self._error: Optional[BaseException] = None
        self._lifecycle_lock = RLock()
        # Scanner callbacks run on the capture thread. Keep their short data
        # lock independent from lifecycle operations that may join that thread.
        self._retention_lock = Lock()

    @property
    def running(self) -> bool:
        with self._lifecycle_lock:
            capture = self._capture
            return capture is not None and capture.running

    @property
    def cleanup_incomplete(self) -> bool:
        """Whether capture shutdown retained resources for a stop retry."""

        with self._lifecycle_lock:
            capture = self._capture
            return capture is not None and capture.cleanup_incomplete

    @property
    def error(self) -> Optional[BaseException]:
        """First startup, callback, or shutdown failure for the current run."""

        with self._lifecycle_lock:
            if self._error is not None:
                return self._error
            capture = self._capture
            return capture.error if capture is not None else None

    @property
    def frames_collected(self) -> int:
        """Total frames observed, including frames later evicted."""

        return self.frames_observed

    @property
    def frames_observed(self) -> int:
        with self._retention_lock:
            return self._frames_observed

    @property
    def frames_retained(self) -> int:
        with self._retention_lock:
            return len(self._frames)

    @property
    def frames_discarded(self) -> int:
        with self._retention_lock:
            return self._frames_discarded

    @property
    def bytes_observed(self) -> int:
        """Total generic-frame payload bytes observed."""

        with self._retention_lock:
            return self._bytes_observed

    @property
    def bytes_retained(self) -> int:
        """Generic-frame payload bytes currently retained."""

        with self._retention_lock:
            return self._bytes_retained

    @property
    def bytes_discarded(self) -> int:
        with self._retention_lock:
            return self._bytes_discarded

    @property
    def retention_truncated(self) -> bool:
        return self.retention.truncated

    @property
    def retention(self) -> CalibrationRetention:
        """Atomic snapshot of observed, retained, and discarded evidence."""

        with self._retention_lock:
            return self._retention_unlocked()

    def start(self) -> None:
        """Begin passive capture and return once the adapter is ready."""

        with self._lifecycle_lock:
            if self._capture is not None or self._manager is not None:
                raise RuntimeError("calibration session is already running")

            self._reset_retention()
            self._error = None
            manager = FlowManager(
                server_ports=self._capture_options.ports,
                scanner_factory=lambda: FrameCollectorScanner(
                    self._retain_frame
                ),
                max_flows=_CALIBRATION_MAX_ACTIVE_FLOWS,
                track_flow_generations=True,
            )
            capture = LivePacketCapture(
                capture_options=self._capture_options,
                on_packet=make_packet_handler(manager),
                startup_timeout=self._STARTUP_TIMEOUT_SECONDS,
            )
            self._manager = manager
            self._capture = capture
            try:
                capture.start()
            except BaseException as exc:
                self._record_error(exc)
                if capture.cleanup_incomplete:
                    # The capture thread may still call into this manager. Keep
                    # both objects alive so stop() can retry verified shutdown
                    # before finalizing stream state.
                    _attach_cleanup_owner(
                        exc,
                        self,
                        context="live calibration startup",
                    )
                    raise
                try:
                    manager.finish()
                except BaseException as cleanup_error:
                    exc.add_note(
                        "calibration flow cleanup also failed: "
                        f"{cleanup_error!r}"
                    )
                self._manager = None
                self._capture = None
                raise

    def stop(self) -> CalibrationResult:
        """End the capture and calibrate the collected frames."""
        with self._lifecycle_lock:
            self._finish_capture()
            with self._retention_lock:
                frames = list(self._frames)
                retention = self._retention_unlocked()
            result = calibrate_frames(
                frames,
                item_id=self._item_id,
                quantity=self._quantity,
                action=self._action,
                context_frames=self._context_frames,
                min_confidence=self._min_confidence,
            )
            return replace(result, retention=retention)

    def raise_if_failed(self) -> None:
        """Re-raise a background capture failure in the calling thread."""

        with self._lifecycle_lock:
            if self._error is not None:
                raise self._error
            capture = self._capture
            if capture is None:
                return
            try:
                capture.raise_if_failed()
            except BaseException as exc:
                self._record_error(exc)
                raise
            if not capture.running:
                error = RuntimeError(
                    "live calibration capture ended unexpectedly"
                )
                self._record_error(error)
                raise error

    def _finish_capture(self) -> None:
        capture = self._capture
        manager = self._manager
        if capture is None or manager is None:
            raise RuntimeError("calibration session was not started")

        failures: list[BaseException] = []

        def retain(error: BaseException) -> None:
            if not any(error is previous for previous in failures):
                failures.append(error)

        if self._error is not None:
            retain(self._error)
        stop_failure: Optional[BaseException] = None
        try:
            capture.stop()
        except BaseException as exc:
            stop_failure = exc
            retain(exc)
        capture_stopped = bool(
            getattr(capture, "stopped", not capture.running)
        )
        if not capture_stopped:
            if stop_failure is None:
                stop_failure = capture.cleanup_error or RuntimeError(
                    "live calibration capture cleanup is incomplete"
                )
                retain(stop_failure)
            self._record_error(failures[0])
            # Reassembly state is still reachable from the capture callback.
            # Do not finish or discard it until a later stop() verifies that
            # the capture thread has terminated.
            raise stop_failure
        try:
            capture.raise_if_failed()
        except BaseException as exc:
            retain(exc)
        try:
            manager.finish()
        except BaseException as exc:
            retain(exc)
        finally:
            self._capture = None
            self._manager = None

        if failures:
            self._record_error(failures[0])
            raise failures[0]

    def _record_error(self, error: BaseException) -> None:
        with self._lifecycle_lock:
            if self._error is None:
                self._error = error

    def _reset_retention(self) -> None:
        with self._retention_lock:
            self._frames.clear()
            self._frames_observed = 0
            self._frames_discarded = 0
            self._bytes_observed = 0
            self._bytes_retained = 0
            self._bytes_discarded = 0

    def _retain_frame(self, frame: BDOFrame) -> None:
        """Retain one frame, evicting the oldest tail prefix as needed."""

        payload_bytes = len(frame.message)
        with self._retention_lock:
            self._frames_observed += 1
            self._bytes_observed += payload_bytes
            self._frames.append(frame)
            self._bytes_retained += payload_bytes

            while self._frames and (
                len(self._frames) > self._max_retained_frames
                or self._bytes_retained > self._max_retained_bytes
            ):
                discarded = self._frames.popleft()
                discarded_bytes = len(discarded.message)
                self._frames_discarded += 1
                self._bytes_discarded += discarded_bytes
                self._bytes_retained -= discarded_bytes

    def _retention_unlocked(self) -> CalibrationRetention:
        return CalibrationRetention(
            frames_observed=self._frames_observed,
            frames_retained=len(self._frames),
            frames_discarded=self._frames_discarded,
            bytes_observed=self._bytes_observed,
            bytes_retained=self._bytes_retained,
            bytes_discarded=self._bytes_discarded,
            max_retained_frames=self._max_retained_frames,
            max_retained_bytes=self._max_retained_bytes,
        )

    def __enter__(self) -> "CalibrationSession":
        with self._lifecycle_lock:
            if self._capture is None:
                self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        # Safety net only: discard the capture if the block exited without
        # calling stop() (for example on an exception).
        with self._lifecycle_lock:
            if self._capture is None:
                return
            try:
                self._finish_capture()
            except BaseException as cleanup_error:
                if exc_value is None:
                    raise
                if self.cleanup_incomplete:
                    _attach_cleanup_owner(
                        exc_value,
                        self,
                        context="live calibration context",
                    )
                exc_value.add_note(
                    "calibration context cleanup also failed: "
                    f"{cleanup_error!r}"
                )


def calibrate_live(
    *,
    item_id: int,
    capture_seconds: Optional[float] = None,
    quantity: Optional[int] = None,
    action: str = "auto",
    capture_options: Optional[PacketCaptureOptions] = None,
    context_frames: int = 5,
    min_confidence: float = 0.80,
    max_retained_frames: int = DEFAULT_CALIBRATION_MAX_RETAINED_FRAMES,
    max_retained_bytes: int = DEFAULT_CALIBRATION_MAX_RETAINED_BYTES,
) -> CalibrationResult:
    """Blocking convenience wrapper around :class:`CalibrationSession`.

    Suited to console scripts: perform the required in-game sequence while the
    capture runs. For automatic transfer calibration, the guided sequence is
    deposit one matching unstackable, deposit four, then withdraw all five.
    The toolkit does not perform those actions; ``quantity=1`` matches every
    serialized item record rather than the batch totals 1, 4, or 5.
    These counts are observed from traffic and are not hard-coded. Loot preview
    is a separate explicit action; omit ``quantity`` when its displayed amount
    is random.
    With ``capture_seconds`` the capture stops automatically; without it, the
    capture runs until the user interrupts (Ctrl+C), which is treated as
    "actions performed, calibrate now" rather than as an abort. Apps with
    their own UI should use :class:`CalibrationSession` directly.
    """
    import time

    if capture_seconds is not None and (
        isinstance(capture_seconds, bool)
        or not isinstance(capture_seconds, (int, float))
        or not math.isfinite(capture_seconds)
        or capture_seconds < 0
    ):
        raise ValueError("capture_seconds must be finite and non-negative")

    session = CalibrationSession(
        item_id=item_id,
        quantity=quantity,
        action=action,
        capture_options=capture_options,
        context_frames=context_frames,
        min_confidence=min_confidence,
        max_retained_frames=max_retained_frames,
        max_retained_bytes=max_retained_bytes,
    )
    with session:
        deadline = (
            None
            if capture_seconds is None
            else time.monotonic() + capture_seconds
        )
        try:
            while True:
                session.raise_if_failed()
                if deadline is None:
                    wait_seconds = 0.2
                else:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    wait_seconds = min(0.2, remaining)
                time.sleep(wait_seconds)
        except KeyboardInterrupt:
            # Ctrl+C ends the listening window; the collected frames still get
            # calibrated, matching the legacy stop-to-finish workflow.
            pass
        return session.stop()

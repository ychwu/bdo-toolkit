"""Private live packet-acquisition lifecycle shared by toolkit features.

This module deliberately stops below protocol decoding.  It owns interface
selection, capture filters, Scapy's background sniffer, and the enlarged
Windows/Npcap capture socket, while callers retain control of packet queues,
decoder finalization, and app-facing result delivery.
"""

from __future__ import annotations

import inspect
import math
import os
import time
from dataclasses import dataclass
from threading import Event, Lock, current_thread
from typing import Any, Callable, Optional

from ._capture_backend import (
    build_bpf_filter,
    detect_default_capture_target,
    import_scapy,
)
from ._capture_options import PacketCaptureOptions


DEFAULT_CAPTURE_BUFFER_BYTES = 64 * 1024 * 1024
DEFAULT_STARTUP_TIMEOUT_SECONDS = 10.0
_CAPTURE_JOIN_TIMEOUT_SECONDS = 2.0


def _capture_is_clean(
    *,
    tcp_gap_resets: int,
    pcap_dropped: Optional[int],
    pcap_interface_dropped: Optional[int],
    packet_queue_overflows: int,
    flow_state_evictions: int,
) -> bool:
    """Apply the shared acquisition-loss predicate used by public health types."""

    return (
        tcp_gap_resets == 0
        and pcap_dropped in (None, 0)
        and pcap_interface_dropped in (None, 0)
        and packet_queue_overflows == 0
        and flow_state_evictions == 0
    )


def _attach_cleanup_owner(
    error: BaseException,
    owner: object,
    *,
    context: str,
) -> None:
    """Keep retry ownership reachable when startup/context entry cannot return."""

    attached = False
    try:
        setattr(error, "cleanup_owner", owner)
        attached = True
    except BaseException:
        # Built-in and ordinary application exceptions expose __dict__. Keep
        # the original failure identity even for an exotic immutable subtype.
        pass
    if attached:
        error.add_note(
            f"{context} cleanup is incomplete; retry stop() on "
            "exception.cleanup_owner"
        )
    else:
        error.add_note(
            f"{context} cleanup is incomplete; this exception subtype "
            "cannot expose cleanup_owner, so retain and stop the original "
            "session object"
        )


@dataclass(frozen=True)
class CaptureEndpoint:
    """Resolved interface and filters used by one live capture."""

    interface: Optional[str]
    local_ip: Optional[str]
    bpf_filter: Optional[str]

    def to_dict(self) -> dict[str, Optional[str]]:
        """Return the resolved endpoint as a JSON-ready mapping."""

        return {
            "interface": self.interface,
            "local_ip": self.local_ip,
            "bpf_filter": self.bpf_filter,
        }


@dataclass(frozen=True)
class CaptureStats:
    """Best-effort kernel capture statistics collected during shutdown."""

    received: Optional[int] = None
    dropped: Optional[int] = None
    interface_dropped: Optional[int] = None
    capture_buffer_bytes: Optional[int] = None


def _is_windows() -> bool:
    return os.name == "nt"


def _new_async_sniffer(**options: Any) -> Any:
    from scapy.sendrecv import AsyncSniffer  # type: ignore

    return AsyncSniffer(**options)


def _open_enlarged_windows_socket(
    *,
    interface: Optional[str],
    bpf_filter: Optional[str],
    buffer_bytes: int,
) -> Any:
    """Open one libpcap socket and enlarge its Npcap kernel buffer."""

    from scapy.arch.libpcap import L2pcapListenSocket  # type: ignore
    from scapy.libs.winpcapy import pcap_setbuff  # type: ignore

    capture_socket = L2pcapListenSocket(
        iface=interface,
        filter=bpf_filter,
    )
    try:
        capture_handle = capture_socket.pcap_fd.pcap
        if pcap_setbuff(capture_handle, buffer_bytes) != 0:
            raise RuntimeError(
                f"Npcap rejected the requested {buffer_bytes}-byte capture buffer"
            )
    except BaseException:
        capture_socket.close()
        raise
    return capture_socket


def _read_windows_capture_stats(
    capture_socket: Any,
) -> tuple[int, int, int] | None:
    """Read Npcap counters while the caller-owned handle is still open."""

    try:
        from ctypes import byref

        from scapy.libs.winpcapy import pcap_stat, pcap_stats  # type: ignore

        capture_stats = pcap_stat()
        if pcap_stats(
            capture_socket.pcap_fd.pcap,
            byref(capture_stats),
        ) != 0:
            return None
        return (
            int(capture_stats.ps_recv),
            int(capture_stats.ps_drop),
            int(capture_stats.ps_ifdrop),
        )
    except BaseException:
        # Statistics are diagnostic evidence. Their absence must not turn an
        # otherwise valid capture into a decoder failure.
        return None


class LivePacketCapture:
    """Single-use private owner of one passive Scapy capture handle.

    ``on_packet`` runs in Scapy's capture thread.  Callers that need a tiny
    capture callback (notably Solare's multi-megabyte leaderboard burst) should
    pass a queue's non-blocking ``put`` method and process packets elsewhere.
    Existing synchronous decoders can keep their present callback semantics.

    The enlarged Npcap buffer is best-effort by default so existing toolkit
    features do not acquire a dependency on Scapy's private Windows bindings.
    Integrity-sensitive classifiers can set ``require_capture_buffer=True``.
    That requirement applies only on Windows, where the Npcap buffer exists.
    """

    def __init__(
        self,
        *,
        capture_options: PacketCaptureOptions,
        on_packet: Callable[[object], None],
        capture_buffer_bytes: int = DEFAULT_CAPTURE_BUFFER_BYTES,
        require_capture_buffer: bool = False,
        startup_timeout: float = DEFAULT_STARTUP_TIMEOUT_SECONDS,
    ) -> None:
        if not isinstance(capture_options, PacketCaptureOptions):
            raise TypeError("capture_options must be a PacketCaptureOptions")
        if not callable(on_packet):
            raise TypeError("on_packet must be callable")
        if (
            isinstance(capture_buffer_bytes, bool)
            or not isinstance(capture_buffer_bytes, int)
            or capture_buffer_bytes <= 0
        ):
            raise ValueError("capture_buffer_bytes must be a positive integer")
        if not isinstance(require_capture_buffer, bool):
            raise ValueError("require_capture_buffer must be a boolean")
        if (
            isinstance(startup_timeout, bool)
            or not isinstance(startup_timeout, (int, float))
            or not math.isfinite(startup_timeout)
            or startup_timeout <= 0
        ):
            raise ValueError("startup_timeout must be finite and greater than zero")

        self._capture_options = capture_options
        self._on_packet = on_packet
        self._capture_buffer_bytes = capture_buffer_bytes
        self._require_capture_buffer = require_capture_buffer
        self._startup_timeout = float(startup_timeout)

        self._capture_ready = Event()
        self._state_lock = Lock()
        self._cleanup_lock = Lock()
        self._start_attempted = False
        self._started = False
        self._stopped = False
        self._capture: Any = None
        self._capture_socket: Any = None
        self._endpoint: Optional[CaptureEndpoint] = None
        self._stats = CaptureStats()
        self._error: Optional[BaseException] = None
        self._buffer_error: Optional[BaseException] = None
        self._cleanup_incomplete = False
        self._cleanup_error: Optional[BaseException] = None

    @property
    def endpoint(self) -> Optional[CaptureEndpoint]:
        """Resolved endpoint after capture startup has been attempted."""

        return self._endpoint

    @property
    def stats(self) -> CaptureStats:
        """Latest capture counters; kernel values appear after ``stop()``."""

        return self._stats

    def snapshot_stats(self) -> CaptureStats:
        """Read best-effort counters without stopping the capture.

        This is used to bind acquisition health to a decoder's first latched
        result even when the caller intentionally keeps recording afterward.
        Backends without a caller-owned statistics handle return the counters
        that are currently available.
        """

        with self._cleanup_lock:
            if not self._started:
                raise RuntimeError("live packet capture was not started")
            if self._stopped:
                return self._stats
            received = dropped = interface_dropped = None
            if self._capture_socket is not None:
                raw_stats = _read_windows_capture_stats(self._capture_socket)
                if raw_stats is not None:
                    received, dropped, interface_dropped = raw_stats
            return CaptureStats(
                received=received,
                dropped=dropped,
                interface_dropped=interface_dropped,
                capture_buffer_bytes=self._stats.capture_buffer_bytes,
            )

    @property
    def buffer_error(self) -> Optional[BaseException]:
        """Why best-effort enlarged-buffer setup fell back, if it did."""

        return self._buffer_error

    @property
    def error(self) -> Optional[BaseException]:
        """First callback, sniffer, or shutdown failure."""

        with self._state_lock:
            error = self._error
        if error is not None:
            return error
        capture_error = getattr(self._capture, "exception", None)
        return capture_error if isinstance(capture_error, BaseException) else None

    @property
    def cleanup_incomplete(self) -> bool:
        """Whether shutdown still owns resources that require another attempt."""

        return self._cleanup_incomplete

    @property
    def cleanup_error(self) -> Optional[BaseException]:
        """Explicit failure explaining why the last shutdown was incomplete."""

        return self._cleanup_error

    @property
    def running(self) -> bool:
        capture = self._capture
        capture_thread = getattr(capture, "thread", None)
        thread_finished = (
            capture_thread is not None
            and capture_thread.ident is not None
            and not capture_thread.is_alive()
        )
        return (
            (self._started or self._cleanup_incomplete)
            and not self._stopped
            and capture is not None
            and not thread_finished
            and (not self._capture_ready.is_set() or bool(capture.running))
        )

    @property
    def stopped(self) -> bool:
        return self._stopped

    def start(self) -> None:
        """Resolve the endpoint, open the adapter, and wait until it is ready."""

        with self._cleanup_lock:
            if self._start_attempted:
                raise RuntimeError("live packet capture is single-use")
            self._start_attempted = True
            self._capture_ready.clear()

            # Scapy lazily initializes its Windows interface table. Import it
            # before route detection so the selected interface is reliable.
            IP, TCP, _, _, _ = import_scapy()

            detected_target = None
            if self._capture_options.interface is None:
                detected_target = detect_default_capture_target()
                capture_interface = detected_target.interface
            else:
                capture_interface = self._capture_options.interface

            capture_local_ip = self._capture_options.local_ip
            if (
                capture_local_ip is None
                and self._capture_options.interface is None
                and self._capture_options.auto_local_ip
            ):
                assert detected_target is not None
                capture_local_ip = detected_target.local_ip

            bpf_filter = (
                build_bpf_filter(self._capture_options.ports, capture_local_ip)
                if self._capture_options.use_bpf
                else None
            )
            lfilter = None
            if not self._capture_options.use_bpf:
                ports = frozenset(self._capture_options.ports)

                def lfilter(packet: object) -> bool:
                    return bool(
                        IP in packet  # type: ignore[operator]
                        and TCP in packet  # type: ignore[operator]
                        and int(packet[TCP].sport) in ports  # type: ignore[index]
                        and (
                            capture_local_ip is None
                            or str(packet[IP].dst) == capture_local_ip  # type: ignore[index]
                        )
                    )

            self._endpoint = CaptureEndpoint(
                interface=capture_interface,
                local_ip=capture_local_ip,
                bpf_filter=bpf_filter,
            )

            capture_socket = None
            configured_buffer_bytes = None
            if _is_windows():
                try:
                    capture_socket = _open_enlarged_windows_socket(
                        interface=capture_interface,
                        bpf_filter=bpf_filter,
                        buffer_bytes=self._capture_buffer_bytes,
                    )
                    configured_buffer_bytes = self._capture_buffer_bytes
                except BaseException as exc:
                    self._buffer_error = exc
                    if self._require_capture_buffer:
                        self._record_error(exc)
                        raise RuntimeError(
                            "failed to configure the enlarged Npcap capture buffer"
                        ) from exc

            self._stats = CaptureStats(
                capture_buffer_bytes=configured_buffer_bytes,
            )

            def handle_packet(packet: object) -> None:
                try:
                    self._on_packet(packet)
                except BaseException as exc:
                    self._record_error(exc)
                    # Scapy intentionally ends a capture whose callback raises.
                    # Retaining the error here lets the owning session surface
                    # the original decoder or queue failure.
                    raise

            sniffer_options: dict[str, Any] = {
                "lfilter": lfilter,
                "prn": handle_packet,
                "store": False,
                "started_callback": self._capture_ready.set,
            }
            if capture_socket is not None:
                # AsyncSniffer must use exactly this enlarged socket. Supplying
                # iface/filter too would make Scapy open another default-sized
                # handle and silently bypass it.
                sniffer_options["opened_socket"] = capture_socket
            else:
                sniffer_options["iface"] = capture_interface
                sniffer_options["filter"] = bpf_filter

            capture = None
            self._capture_socket = capture_socket
            try:
                capture = _new_async_sniffer(**sniffer_options)
                self._capture = capture
                capture.start()
                deadline = time.monotonic() + self._startup_timeout
                while not self._capture_ready.wait(timeout=0.05):
                    capture_error = getattr(capture, "exception", None)
                    if isinstance(capture_error, BaseException):
                        raise capture_error
                    capture_thread = getattr(capture, "thread", None)
                    if (
                        capture_thread is not None
                        and capture_thread.ident is not None
                        and not capture_thread.is_alive()
                    ):
                        raise RuntimeError(
                            "live capture thread ended during startup"
                        )
                    if time.monotonic() >= deadline:
                        raise RuntimeError(
                            "timed out while opening the live capture interface"
                        )
            except BaseException as exc:
                self._record_error(exc)
                try:
                    self._shutdown_backend()
                except BaseException as cleanup_error:
                    # Startup remains the primary failure, but incomplete
                    # cleanup must be explicit in its traceback and remains
                    # retryable through stop().
                    exc.add_note(
                        "live capture startup cleanup also failed: "
                        f"{cleanup_error!r}"
                    )
                if not self._cleanup_incomplete:
                    self._capture = None
                    self._capture_socket = None
                else:
                    _attach_cleanup_owner(
                        exc,
                        self,
                        context="live packet capture startup",
                    )
                raise

            self._started = True

    def stop(self) -> CaptureStats:
        """Stop and join capture, read counters, then close the owned socket."""

        with self._cleanup_lock:
            if not self._started and not self._cleanup_incomplete:
                raise RuntimeError("live packet capture was not started")
            if self._stopped:
                return self._stats
            self._shutdown_backend()
            return self._stats

    def _shutdown_backend(self) -> None:
        """Attempt every safe shutdown step and verify resource ownership.

        Scapy's ordinary ``AsyncSniffer.stop()`` joins without a timeout. Ask
        it only to signal the backend, then perform our own bounded join. A
        caller-owned Npcap socket is closed before that join so a blocking read
        has an independent way to wake even when the stop request raises.
        """

        capture = self._capture
        capture_socket = self._capture_socket
        failures: list[BaseException] = []

        def retain(error: BaseException) -> None:
            self._record_error(error)
            if not any(error is previous for previous in failures):
                failures.append(error)

        capture_error = getattr(capture, "exception", None)
        if isinstance(capture_error, BaseException):
            self._record_error(capture_error)

        capture_thread = getattr(capture, "thread", None)
        thread_alive = False
        if capture_thread is not None:
            thread_alive = bool(capture_thread.is_alive())

        if capture is not None and (
            bool(getattr(capture, "running", False)) or thread_alive
        ):
            try:
                stop_method = capture.stop
                try:
                    parameters = inspect.signature(stop_method).parameters.values()
                except (TypeError, ValueError):
                    # The real supported Scapy backend accepts ``join``. This
                    # fallback is for non-introspectable compatible wrappers.
                    stop_method(join=False)
                else:
                    supports_join = any(
                        parameter.name == "join"
                        or parameter.kind is inspect.Parameter.VAR_KEYWORD
                        for parameter in parameters
                    )
                    if supports_join:
                        stop_method(join=False)
                    else:
                        # Lightweight test/application fakes may expose only a
                        # synchronous no-argument stop method.
                        stop_method()
            except BaseException as exc:
                retain(exc)

        received = self._stats.received
        dropped = self._stats.dropped
        interface_dropped = self._stats.interface_dropped
        if capture_socket is not None:
            raw_stats = _read_windows_capture_stats(capture_socket)
            if raw_stats is not None:
                received, dropped, interface_dropped = raw_stats
            try:
                capture_socket.close()
            except BaseException as exc:
                # Keep the socket reference so a later stop() can retry it.
                retain(exc)
            else:
                self._capture_socket = None

        self._stats = CaptureStats(
            received=received,
            dropped=dropped,
            interface_dropped=interface_dropped,
            capture_buffer_bytes=self._stats.capture_buffer_bytes,
        )

        if capture_thread is not None:
            thread_alive = bool(capture_thread.is_alive())
            if thread_alive:
                if capture_thread is current_thread():
                    retain(
                        RuntimeError(
                            "live capture cannot join its own capture thread"
                        )
                    )
                else:
                    try:
                        capture_thread.join(
                            timeout=_CAPTURE_JOIN_TIMEOUT_SECONDS
                        )
                    except BaseException as exc:
                        retain(exc)
                    thread_alive = bool(capture_thread.is_alive())

        backend_running_without_thread = (
            capture is not None
            and capture_thread is None
            and bool(getattr(capture, "running", False))
        )
        incomplete = (
            thread_alive
            or backend_running_without_thread
            or self._capture_socket is not None
        )
        self._cleanup_incomplete = incomplete
        self._stopped = not incomplete

        if incomplete:
            reasons: list[str] = []
            if thread_alive or backend_running_without_thread:
                reasons.append(
                    "the capture thread/backend is still running after the "
                    f"{_CAPTURE_JOIN_TIMEOUT_SECONDS:g}-second join deadline"
                )
            if self._capture_socket is not None:
                reasons.append("the caller-owned capture socket did not close")
            cleanup_error = RuntimeError(
                "live packet capture cleanup is incomplete: " + "; ".join(reasons)
            )
            self._cleanup_error = cleanup_error
            self._record_error(cleanup_error)
            if failures:
                raise cleanup_error from failures[0]
            raise cleanup_error

        self._cleanup_error = None
        if failures:
            raise failures[0]

    def raise_if_failed(self) -> None:
        """Raise the first retained capture failure, if one occurred."""

        error = self.error
        if error is not None:
            raise error

    def _record_error(self, error: BaseException) -> None:
        with self._state_lock:
            if self._error is None:
                self._error = error

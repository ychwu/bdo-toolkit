"""Passive character-load replay and live-session lifecycle."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Optional

from .._capture_backend import (
    iter_pcap_file,
    make_packet_handler,
    open_packet_writer,
)
from .._capture_options import PacketCaptureOptions
from .._capture_runtime import (
    DEFAULT_STARTUP_TIMEOUT_SECONDS,
    LivePacketCapture,
    _attach_cleanup_owner,
)
from .._engine import PacketEngine
from .._protocol import DEFAULT_SERVER_PORTS, EventSpec
from ..capture import (
    _EventCollector,
    _ProfileAuthority,
    _load_profile_authority,
)
from ..diagnostics import DecoderHealth
from ..filters import EventFilter
from ..profiles import OpcodeProfile, ProfileError

from .assembly import _CharacterStateAccumulator
from .models import CharacterStateSnapshot, ItemStateCaptureLimits


_CHARACTER_LOAD_STARTUP_TIMEOUT_SECONDS = DEFAULT_STARTUP_TIMEOUT_SECONDS
# Lossless character-load bursts can arrive heavily out of TCP order.
# This larger reorder budget is local to finite item-state capture.
_CHARACTER_LOAD_MAX_PENDING_SEGMENTS = 2048
_CHARACTER_LOAD_MAX_PENDING_BYTES = 8 * 1024 * 1024


def _validate_item_state_identity_specs(specs: Iterable[EventSpec]) -> None:
    """Reject layouts that cannot prove complete character-state semantics."""
    missing: list[tuple[EventSpec, tuple[str, ...]]] = []
    for spec in specs:
        fields: list[str] = []
        if spec.label == "INVENTORY_TRANSFER":
            if spec.item_instance_offset is None:
                fields.append("item instance")
            if spec.source_context_offset is None:
                fields.append("snapshot context")
        elif spec.label == "INVENTORY_TO_STORAGE":
            if spec.storage_instance_offset is None:
                fields.append("storage instance")
            if spec.source_context_offset is None:
                fields.append("storage destination")
            if spec.record_count_offset is None:
                fields.append("record count")
        if fields:
            missing.append((spec, tuple(fields)))
    if not missing:
        return
    descriptions = ", ".join(
        f"{spec.label}(0x{spec.opcode:04X}: {', '.join(fields)})"
        for spec, fields in missing
    )
    raise ProfileError(
        "item-state snapshots require calibrated identity and wrapper authority; "
        f"missing geometry: {descriptions}. Recalibrate the active profile."
    )


def _active_profile_authority(
    opcode_profile: str | Path | OpcodeProfile,
) -> _ProfileAuthority:
    authority = _load_profile_authority(opcode_profile)
    _validate_item_state_identity_specs(authority.loaded_specs.specs)
    return authority


def analyze_character_load_pcap(
    path: str | Path,
    *,
    opcode_profile: str | Path | OpcodeProfile,
    ports: tuple[int, ...] = DEFAULT_SERVER_PORTS,
    capture_limits: Optional[ItemStateCaptureLimits] = None,
) -> CharacterStateSnapshot:
    """Replay a capture and summarize framed inventory/storage hydration."""
    options = PacketCaptureOptions(ports=ports)
    authority = _active_profile_authority(opcode_profile)
    profile_source = str(authority.profile.path)
    specs = authority.loaded_specs.specs
    accumulator = _CharacterStateAccumulator(
        profile_source=profile_source,
        specs=specs,
        capture_mode="pcap_replay",
        input_path=path,
        capture_limits=capture_limits,
    )
    collector = _EventCollector(
        server_ports=options.ports,
        event_filter=EventFilter(
            event_types={
                "inventory_snapshot",
                "storage_snapshot",
                "storage_record",
                "storage_delta",
            }
        ),
        on_event=accumulator.observe_event,
        frame_observer=accumulator.observe_frame,
        _profile_authority=authority,
        _max_pending_segments=_CHARACTER_LOAD_MAX_PENDING_SEGMENTS,
        _max_pending_bytes=_CHARACTER_LOAD_MAX_PENDING_BYTES,
    )
    for _ in iter_pcap_file(Path(path), collector.engine):
        pass
    collector.finalize()
    return accumulator.snapshot(decoder_health=collector.decoder_health)


def _validate_save_pcap_path(path: str | Path) -> Path:
    if not isinstance(path, (str, Path)):
        raise TypeError("save_pcap must be a path string, Path, or None")
    capture_path = Path(path)
    if capture_path.suffix.casefold() not in {".pcap", ".pcapng"}:
        raise ValueError("save_pcap must end in .pcap or .pcapng")
    return capture_path


def _open_packet_writer(path: Path) -> Any:
    """Open a Scapy writer matching the requested capture container."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing capture: {path}")
    return open_packet_writer(path)


class CharacterLoadSession:
    """Experimental live capture session returning a character-state summary."""

    def __init__(
        self,
        *,
        opcode_profile: str | Path | OpcodeProfile,
        capture_options: Optional[PacketCaptureOptions] = None,
        save_pcap: str | Path | None = None,
        capture_limits: Optional[ItemStateCaptureLimits] = None,
    ) -> None:
        if capture_options is not None and not isinstance(
            capture_options, PacketCaptureOptions
        ):
            raise TypeError("capture_options must be a PacketCaptureOptions or None")
        if capture_limits is not None and not isinstance(
            capture_limits, ItemStateCaptureLimits
        ):
            raise TypeError("capture_limits must be an ItemStateCaptureLimits or None")
        self._capture_options = capture_options or PacketCaptureOptions()
        self._capture_limits = capture_limits or ItemStateCaptureLimits()
        self._save_pcap_path = (
            _validate_save_pcap_path(save_pcap) if save_pcap is not None else None
        )
        self._profile_authority = _active_profile_authority(opcode_profile)
        self._profile_source = str(self._profile_authority.profile.path)
        self._specs = self._profile_authority.loaded_specs.specs
        self._start_attempted = False
        self._accumulator: Optional[_CharacterStateAccumulator] = None
        self._collector: Optional[_EventCollector] = None
        self._engine: Optional[PacketEngine] = None
        self._capture: Optional[LivePacketCapture] = None
        self._capture_writer: Any = None
        self._result: Optional[CharacterStateSnapshot] = None
        self._error: Optional[BaseException] = None

    @property
    def running(self) -> bool:
        capture = self._capture
        return capture is not None and capture.running

    @property
    def cleanup_incomplete(self) -> bool:
        """Whether capture shutdown retained resources for a stop retry."""

        capture = self._capture
        return capture is not None and capture.cleanup_incomplete

    @property
    def frames_seen(self) -> int:
        return self._accumulator.frames_seen if self._accumulator is not None else 0

    @property
    def decoder_health(self) -> DecoderHealth:
        """Current storage-decoder compatibility for this capture."""

        if self._collector is not None:
            return self._collector.decoder_health
        if self._result is not None:
            return self._result.decoder_health
        return DecoderHealth()

    @property
    def error(self) -> Optional[BaseException]:
        """First background capture or decoder failure, if any."""
        if self._error is not None:
            return self._error
        capture = self._capture
        return capture.error if capture is not None else None

    @property
    def save_pcap_path(self) -> Optional[Path]:
        """Destination for opt-in raw live packets, if configured."""
        return self._save_pcap_path

    def start(self) -> None:
        """Begin passive capture and return once the adapter is ready.

        A session is single-use, including after a failed startup. Construct a
        new session to retry with a fresh writer, decoder, and capture handle.
        If startup reports incomplete cleanup, first call ``stop()`` on this
        session until the retained capture backend is verified stopped.
        """
        if self._start_attempted:
            raise RuntimeError(
                "character-load session is single-use and already started"
            )
        self._start_attempted = True
        self._error = None

        accumulator = _CharacterStateAccumulator(
            profile_source=self._profile_source,
            specs=self._specs,
            capture_mode="live_capture",
            saved_capture_path=self._save_pcap_path,
            capture_limits=self._capture_limits,
        )
        collector = _EventCollector(
            server_ports=self._capture_options.ports,
            event_filter=EventFilter(
                event_types={
                    "inventory_snapshot",
                    "storage_snapshot",
                    "storage_record",
                    "storage_delta",
                }
            ),
            on_event=accumulator.observe_event,
            frame_observer=accumulator.observe_frame,
            _profile_authority=self._profile_authority,
            _max_pending_segments=_CHARACTER_LOAD_MAX_PENDING_SEGMENTS,
            _max_pending_bytes=_CHARACTER_LOAD_MAX_PENDING_BYTES,
        )
        engine = collector.engine
        packet_handler = make_packet_handler(engine)
        capture_writer = None
        capture: Optional[LivePacketCapture] = None
        try:
            capture_writer = (
                _open_packet_writer(self._save_pcap_path)
                if self._save_pcap_path is not None
                else None
            )

            def handle_packet(packet: object) -> None:
                try:
                    # Persist the untouched packet before decoding so parser
                    # failures still retain the packet that exposed them.
                    if capture_writer is not None:
                        capture_writer.write(packet)
                    packet_handler(packet)
                except BaseException as exc:
                    self._record_error(exc)
                    raise

            capture = LivePacketCapture(
                capture_options=self._capture_options,
                on_packet=handle_packet,
                startup_timeout=_CHARACTER_LOAD_STARTUP_TIMEOUT_SECONDS,
            )
            self._accumulator = accumulator
            self._collector = collector
            self._engine = engine
            self._capture_writer = capture_writer
            self._capture = capture
            capture.start()
        except BaseException as exc:
            self._record_error(exc)
            if capture is not None and capture.cleanup_incomplete:
                # The backend may still invoke handle_packet(). Keep its
                # writer, engine, accumulator, and capture owner reachable so
                # stop() can safely retry before any dependent resource closes.
                _attach_cleanup_owner(
                    exc,
                    self,
                    context="character-load capture startup",
                )
                raise
            if capture_writer is not None:
                try:
                    capture_writer.close()
                except BaseException:
                    # Preserve the original startup failure.
                    pass
            self._capture = None
            self._capture_writer = None
            self._accumulator = None
            self._collector = None
            self._engine = None
            raise

    def stop(self) -> CharacterStateSnapshot:
        """Stop capture, finish reassembly, and return the queryable summary."""
        if self._result is not None:
            if self._error is not None:
                # A cached diagnostic snapshot must never turn a previously
                # failed run into an apparent success on a repeated stop().
                raise self._error
            return self._result
        if (
            self._capture is None
            or self._collector is None
            or self._engine is None
            or self._accumulator is None
        ):
            raise RuntimeError("character-load session was not started")
        capture = self._capture
        collector = self._collector
        engine = self._engine
        accumulator = self._accumulator
        capture_writer = self._capture_writer
        stop_failure: Optional[BaseException] = None
        try:
            capture.stop()
        except BaseException as exc:
            stop_failure = exc
            self._record_error(exc)
        if not capture.stopped:
            if stop_failure is None:
                stop_failure = capture.cleanup_error or RuntimeError(
                    "character-load capture cleanup is incomplete"
                )
                self._record_error(stop_failure)
            # The capture callback still owns the writer and decoder. Leave
            # every dependency intact for a later, verified stop attempt.
            raise stop_failure
        capture_error = capture.error
        if capture_error is not None:
            self._record_error(capture_error)
        try:
            engine.finish()
        except BaseException as exc:
            self._record_error(exc)
        try:
            collector.finalize()
        except BaseException as exc:
            self._record_error(exc)
        if capture_writer is not None:
            try:
                capture_writer.close()
            except BaseException as exc:
                self._record_error(exc)
        result: Optional[CharacterStateSnapshot] = None
        try:
            result = accumulator.snapshot(decoder_health=collector.decoder_health)
        except BaseException as exc:
            self._record_error(exc)
        self._capture = None
        self._capture_writer = None
        self._collector = None
        self._engine = None
        if result is not None:
            self._result = result
        if self._error is not None:
            raise self._error
        assert result is not None
        return result

    def _record_error(self, error: BaseException) -> None:
        if self._error is None:
            self._error = error

    def __enter__(self) -> "CharacterLoadSession":
        if not self._start_attempted:
            self.start()
        elif self._capture is None and self._result is None:
            raise RuntimeError(
                "character-load session is single-use and cannot be restarted"
            )
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self._capture is not None:
            try:
                self.stop()
            except BaseException as cleanup_error:
                if exc_value is None:
                    raise
                if self.cleanup_incomplete:
                    _attach_cleanup_owner(
                        exc_value,
                        self,
                        context="character-load capture context",
                    )
                exc_value.add_note(
                    "character-load context cleanup also failed: "
                    f"{cleanup_error!r}"
                )

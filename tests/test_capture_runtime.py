from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from bdo_toolkit import _capture_runtime as runtime
from bdo_toolkit._capture_backend import CaptureTarget
from bdo_toolkit._capture_options import PacketCaptureOptions


IP = object()
TCP = object()


@dataclass
class _IPLayer:
    dst: str


@dataclass
class _TCPLayer:
    sport: int


class _Packet:
    def __init__(self, *, sport: int, dst: str, tcp: bool = True) -> None:
        self._layers: dict[object, object] = {IP: _IPLayer(dst)}
        if tcp:
            self._layers[TCP] = _TCPLayer(sport)

    def __contains__(self, layer: object) -> bool:
        return layer in self._layers

    def __getitem__(self, layer: object) -> object:
        return self._layers[layer]


class _FakeSniffer:
    instances: list["_FakeSniffer"] = []

    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs
        self.running = False
        self.exception = None
        self.thread: Any = None
        self.stop_calls = 0
        self.__class__.instances.append(self)

    def start(self) -> None:
        self.running = True
        callback = self.kwargs.get("started_callback")
        if callable(callback):
            callback()

    def stop(self) -> None:
        self.stop_calls += 1
        self.running = False

    def emit(self, packet: object) -> None:
        callback = self.kwargs["prn"]
        assert callable(callback)
        callback(packet)


class _ControlledThread:
    def __init__(self, *, alive: bool = True) -> None:
        self.ident = 1234
        self.alive = alive
        self.join_calls: list[float | None] = []

    def is_alive(self) -> bool:
        return self.alive

    def join(self, timeout: float | None = None) -> None:
        self.join_calls.append(timeout)


class _UncooperativeSniffer(_FakeSniffer):
    failure = OSError("backend stop request failed")

    def start(self) -> None:
        self.running = True
        self.thread = _ControlledThread()
        callback = self.kwargs.get("started_callback")
        if callable(callback):
            callback()

    def stop(self, join: bool = True) -> None:
        self.stop_calls += 1
        assert join is False
        raise self.failure


@pytest.fixture(autouse=True)
def capture_fakes(monkeypatch):
    _FakeSniffer.instances.clear()
    monkeypatch.setattr(
        runtime,
        "import_scapy",
        lambda: (IP, TCP, None, None, None),
    )
    monkeypatch.setattr(runtime, "_new_async_sniffer", _FakeSniffer)
    monkeypatch.setattr(runtime, "_is_windows", lambda: False)


def test_runtime_resolves_default_endpoint_and_positive_bpf(monkeypatch):
    monkeypatch.setattr(
        runtime,
        "detect_default_capture_target",
        lambda: CaptureTarget(
            interface="default-interface",
            local_ip="192.0.2.25",
            gateway="192.0.2.1",
        ),
    )
    packets: list[object] = []
    capture = runtime.LivePacketCapture(
        capture_options=PacketCaptureOptions(ports=(8889, 8884, 8889)),
        on_packet=packets.append,
    )

    capture.start()

    assert capture.running
    assert capture.endpoint == runtime.CaptureEndpoint(
        interface="default-interface",
        local_ip="192.0.2.25",
        bpf_filter=(
            "tcp and (src port 8889 or src port 8884) and dst host 192.0.2.25"
        ),
    )
    sniffer = _FakeSniffer.instances[-1]
    assert sniffer.kwargs["iface"] == "default-interface"
    assert sniffer.kwargs["filter"] == capture.endpoint.bpf_filter
    assert sniffer.kwargs["lfilter"] is None

    packet = object()
    sniffer.emit(packet)
    assert packets == [packet]

    stats = capture.stop()
    assert stats == runtime.CaptureStats()
    assert capture.stopped
    assert not capture.running


def test_capture_endpoint_is_a_public_serializable_value() -> None:
    endpoint = runtime.CaptureEndpoint(
        interface="capture-adapter",
        local_ip="192.0.2.50",
        bpf_filter="tcp",
    )

    assert endpoint.to_dict() == {
        "interface": "capture-adapter",
        "local_ip": "192.0.2.50",
        "bpf_filter": "tcp",
    }


def test_runtime_python_filter_restricts_source_port_and_destination():
    capture = runtime.LivePacketCapture(
        capture_options=PacketCaptureOptions(
            interface="test-interface",
            local_ip="198.51.100.10",
            ports=(8889,),
            use_bpf=False,
        ),
        on_packet=lambda packet: None,
    )
    capture.start()

    sniffer = _FakeSniffer.instances[-1]
    packet_filter = sniffer.kwargs["lfilter"]
    assert callable(packet_filter)
    assert packet_filter(_Packet(sport=8889, dst="198.51.100.10"))
    assert not packet_filter(_Packet(sport=8884, dst="198.51.100.10"))
    assert not packet_filter(_Packet(sport=8889, dst="198.51.100.11"))
    assert not packet_filter(
        _Packet(sport=8889, dst="198.51.100.10", tcp=False)
    )
    assert capture.endpoint is not None
    assert capture.endpoint.bpf_filter is None
    capture.stop()


def test_runtime_can_disable_automatic_local_ip(monkeypatch):
    monkeypatch.setattr(
        runtime,
        "detect_default_capture_target",
        lambda: CaptureTarget(
            interface="default-interface",
            local_ip="192.0.2.25",
            gateway="192.0.2.1",
        ),
    )
    capture = runtime.LivePacketCapture(
        capture_options=PacketCaptureOptions(auto_local_ip=False),
        on_packet=lambda packet: None,
    )

    capture.start()

    assert capture.endpoint is not None
    assert capture.endpoint.local_ip is None
    assert "dst host" not in (capture.endpoint.bpf_filter or "")
    capture.stop()


def test_windows_runtime_uses_only_enlarged_socket_and_reads_stats_before_close(
    monkeypatch,
):
    order: list[str] = []

    class FakeSocket:
        closed = False

        def close(self) -> None:
            assert not self.closed
            self.closed = True
            order.append("close")

    capture_socket = FakeSocket()
    opened_with: dict[str, object] = {}

    def open_socket(**kwargs):
        opened_with.update(kwargs)
        return capture_socket

    def read_stats(socket):
        assert socket is capture_socket
        assert not capture_socket.closed
        order.append("stats")
        return (1154, 0, 0)

    monkeypatch.setattr(runtime, "_is_windows", lambda: True)
    monkeypatch.setattr(runtime, "_open_enlarged_windows_socket", open_socket)
    monkeypatch.setattr(runtime, "_read_windows_capture_stats", read_stats)

    capture = runtime.LivePacketCapture(
        capture_options=PacketCaptureOptions(interface="npcap-interface"),
        on_packet=lambda packet: None,
        require_capture_buffer=True,
    )
    capture.start()

    assert opened_with == {
        "interface": "npcap-interface",
        "bpf_filter": (
            "tcp and (src port 8884 or src port 8885 or src port 8889)"
        ),
        "buffer_bytes": runtime.DEFAULT_CAPTURE_BUFFER_BYTES,
    }
    sniffer = _FakeSniffer.instances[-1]
    assert sniffer.kwargs["opened_socket"] is capture_socket
    assert "iface" not in sniffer.kwargs
    assert "filter" not in sniffer.kwargs
    assert capture.stats.capture_buffer_bytes == 64 * 1024 * 1024

    live_stats = capture.snapshot_stats()
    assert live_stats == runtime.CaptureStats(
        received=1154,
        dropped=0,
        interface_dropped=0,
        capture_buffer_bytes=64 * 1024 * 1024,
    )

    first_stats = capture.stop()
    second_stats = capture.stop()

    assert order == ["stats", "stats", "close"]
    assert first_stats == second_stats == runtime.CaptureStats(
        received=1154,
        dropped=0,
        interface_dropped=0,
        capture_buffer_bytes=64 * 1024 * 1024,
    )
    assert sniffer.stop_calls == 1


def test_best_effort_windows_buffer_failure_falls_back_to_normal_sniffer(
    monkeypatch,
):
    failure = OSError("Scapy has no libpcap binding")
    monkeypatch.setattr(runtime, "_is_windows", lambda: True)
    monkeypatch.setattr(
        runtime,
        "_open_enlarged_windows_socket",
        lambda **kwargs: (_ for _ in ()).throw(failure),
    )
    capture = runtime.LivePacketCapture(
        capture_options=PacketCaptureOptions(interface="fallback-interface"),
        on_packet=lambda packet: None,
    )

    capture.start()

    sniffer = _FakeSniffer.instances[-1]
    assert sniffer.kwargs["iface"] == "fallback-interface"
    assert "opened_socket" not in sniffer.kwargs
    assert capture.stats.capture_buffer_bytes is None
    assert capture.buffer_error is failure
    assert capture.error is None
    capture.stop()


def test_required_windows_buffer_failure_refuses_to_start(monkeypatch):
    failure = OSError("Npcap buffer unavailable")
    monkeypatch.setattr(runtime, "_is_windows", lambda: True)
    monkeypatch.setattr(
        runtime,
        "_open_enlarged_windows_socket",
        lambda **kwargs: (_ for _ in ()).throw(failure),
    )
    capture = runtime.LivePacketCapture(
        capture_options=PacketCaptureOptions(interface="test-interface"),
        on_packet=lambda packet: None,
        require_capture_buffer=True,
    )

    with pytest.raises(RuntimeError, match="enlarged Npcap") as caught:
        capture.start()

    assert caught.value.__cause__ is failure
    assert capture.error is failure
    assert capture.buffer_error is failure
    assert not _FakeSniffer.instances
    with pytest.raises(RuntimeError, match="not started"):
        capture.stop()


def test_startup_thread_failure_closes_caller_owned_socket(monkeypatch):
    class FakeSocket:
        closed = False

        def close(self) -> None:
            self.closed = True

    class DeadThread:
        ident = 123

        @staticmethod
        def is_alive() -> bool:
            return False

    class DeadSniffer(_FakeSniffer):
        def start(self) -> None:
            self.thread = DeadThread()
            self.running = False

    capture_socket = FakeSocket()
    monkeypatch.setattr(runtime, "_is_windows", lambda: True)
    monkeypatch.setattr(
        runtime,
        "_open_enlarged_windows_socket",
        lambda **kwargs: capture_socket,
    )
    monkeypatch.setattr(runtime, "_new_async_sniffer", DeadSniffer)
    capture = runtime.LivePacketCapture(
        capture_options=PacketCaptureOptions(interface="test-interface"),
        on_packet=lambda packet: None,
        require_capture_buffer=True,
    )

    with pytest.raises(RuntimeError, match="ended during startup"):
        capture.start()

    assert capture_socket.closed
    assert isinstance(capture.error, RuntimeError)


def test_callback_failure_is_retained_as_the_first_error():
    callback_failure = ValueError("decoder rejected packet")

    def fail(packet: object) -> None:
        raise callback_failure

    capture = runtime.LivePacketCapture(
        capture_options=PacketCaptureOptions(interface="test-interface"),
        on_packet=fail,
    )
    capture.start()

    with pytest.raises(ValueError, match="decoder rejected"):
        _FakeSniffer.instances[-1].emit(object())

    capture.stop()
    assert capture.error is callback_failure
    with pytest.raises(ValueError, match="decoder rejected"):
        capture.raise_if_failed()


def test_raising_stop_still_closes_socket_joins_and_retains_retry_owner(
    monkeypatch,
):
    class FakeSocket:
        def __init__(self) -> None:
            self.close_calls = 0

        def close(self) -> None:
            self.close_calls += 1

    capture_socket = FakeSocket()
    monkeypatch.setattr(runtime, "_is_windows", lambda: True)
    monkeypatch.setattr(
        runtime,
        "_open_enlarged_windows_socket",
        lambda **kwargs: capture_socket,
    )
    monkeypatch.setattr(runtime, "_new_async_sniffer", _UncooperativeSniffer)
    capture = runtime.LivePacketCapture(
        capture_options=PacketCaptureOptions(interface="test-interface"),
        on_packet=lambda packet: None,
    )
    capture.start()
    sniffer = _UncooperativeSniffer.instances[-1]
    thread = sniffer.thread
    assert isinstance(thread, _ControlledThread)

    with pytest.raises(RuntimeError, match="cleanup is incomplete") as caught:
        capture.stop()

    assert caught.value.__cause__ is _UncooperativeSniffer.failure
    assert sniffer.stop_calls == 1
    assert thread.join_calls == [runtime._CAPTURE_JOIN_TIMEOUT_SECONDS]
    assert capture_socket.close_calls == 1
    assert not capture.stopped
    assert capture.cleanup_incomplete
    assert capture.cleanup_error is caught.value
    assert capture.error is _UncooperativeSniffer.failure
    assert capture._capture is sniffer

    # A later control-plane attempt can complete once the non-cooperative
    # native backend actually exits. The original failure remains observable.
    thread.alive = False
    sniffer.running = False
    capture.stop()
    assert capture.stopped
    assert not capture.cleanup_incomplete
    assert capture.cleanup_error is None
    with pytest.raises(OSError) as retained:
        capture.raise_if_failed()
    assert retained.value is _UncooperativeSniffer.failure


def test_socket_close_failure_keeps_handle_for_a_cleanup_retry(monkeypatch):
    failure = OSError("capture socket close failed")

    class RetrySocket:
        def __init__(self) -> None:
            self.close_calls = 0

        def close(self) -> None:
            self.close_calls += 1
            if self.close_calls == 1:
                raise failure

    capture_socket = RetrySocket()
    monkeypatch.setattr(runtime, "_is_windows", lambda: True)
    monkeypatch.setattr(
        runtime,
        "_open_enlarged_windows_socket",
        lambda **kwargs: capture_socket,
    )
    capture = runtime.LivePacketCapture(
        capture_options=PacketCaptureOptions(interface="test-interface"),
        on_packet=lambda packet: None,
    )
    capture.start()

    with pytest.raises(RuntimeError, match="capture socket did not close") as caught:
        capture.stop()

    assert caught.value.__cause__ is failure
    assert capture._capture_socket is capture_socket
    assert capture.cleanup_incomplete
    assert not capture.stopped

    capture.stop()
    assert capture_socket.close_calls == 2
    assert capture._capture_socket is None
    assert capture.stopped


def test_startup_failure_retains_an_unstopped_backend_for_cleanup_retry(
    monkeypatch,
):
    class NeverReadyUncooperativeSniffer(_UncooperativeSniffer):
        def start(self) -> None:
            self.running = True
            self.thread = _ControlledThread()

    monkeypatch.setattr(
        runtime,
        "_new_async_sniffer",
        NeverReadyUncooperativeSniffer,
    )
    capture = runtime.LivePacketCapture(
        capture_options=PacketCaptureOptions(interface="test-interface"),
        on_packet=lambda packet: None,
        startup_timeout=0.01,
    )

    with pytest.raises(RuntimeError, match="timed out") as startup:
        capture.start()

    sniffer = NeverReadyUncooperativeSniffer.instances[-1]
    thread = sniffer.thread
    assert isinstance(thread, _ControlledThread)
    assert capture.cleanup_incomplete
    assert capture.running
    assert capture._capture is sniffer
    assert thread.join_calls == [runtime._CAPTURE_JOIN_TIMEOUT_SECONDS]
    if hasattr(BaseException, "add_note"):
        assert any(
            "startup cleanup also failed" in note
            for note in startup.value.__notes__
        )

    thread.alive = False
    sniffer.running = False
    capture.stop()
    assert capture.stopped
    assert not capture.cleanup_incomplete


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"capture_options": object(), "on_packet": lambda packet: None}, TypeError),
        (
            {
                "capture_options": PacketCaptureOptions(),
                "on_packet": object(),
            },
            TypeError,
        ),
        (
            {
                "capture_options": PacketCaptureOptions(),
                "on_packet": lambda packet: None,
                "capture_buffer_bytes": 0,
            },
            ValueError,
        ),
        (
            {
                "capture_options": PacketCaptureOptions(),
                "on_packet": lambda packet: None,
                "startup_timeout": float("inf"),
            },
            ValueError,
        ),
    ],
)
def test_runtime_validates_private_configuration(kwargs, error):
    with pytest.raises(error):
        runtime.LivePacketCapture(**kwargs)


def test_runtime_is_single_use_and_stop_before_start_is_an_error():
    capture = runtime.LivePacketCapture(
        capture_options=PacketCaptureOptions(interface="test-interface"),
        on_packet=lambda packet: None,
    )

    with pytest.raises(RuntimeError, match="not started"):
        capture.stop()
    capture.start()
    capture.stop()
    with pytest.raises(RuntimeError, match="single-use"):
        capture.start()

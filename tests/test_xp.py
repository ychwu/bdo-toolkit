"""Public solo XP API: profile authority, accounting, replay and live ownership."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import time

import pytest

from bdo_toolkit import CaptureIntegrityError, LiveCaptureOptions, load_opcode_profile, fetch_opcode_profile
from bdo_toolkit._capture_runtime import CaptureStats
from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
from bdo_toolkit.profiles import ProfileError, XPProfileLayout
from bdo_toolkit.xp import LiveXPSession, XPTrackingError, replay_xp, update_xp_profile
from bdo_toolkit.xp._tracker import XPTracker, XPFlowManager
from bdo_toolkit.xp import session as module
from tests.test_remote_profiles import _serve, _envelope
from tests.test_agris_session import FakeCapture, wait_stopped


LAYOUT = XPProfileLayout(0xBEEF, 60, 18, 5, 47)
FLOW = FlowKey("192.0.2.1", 8889, "192.0.2.2", 40000)


def frame(current=100, required=1000, level=19, *, at=1., epoch=1, flow=FLOW, layout=LAYOUT):
    b = bytearray([0xED] * layout.message_length)
    b[:2] = len(b).to_bytes(2, "little")
    b[2] = 0
    b[3:5] = layout.opcode.to_bytes(2, "little")
    b[layout.level_offset] = level
    b[layout.current_offset:layout.current_offset + 8] = current.to_bytes(8, "little")
    b[layout.required_offset:layout.required_offset + 8] = required.to_bytes(8, "little")
    return BDOFrame(1, bytes(b), PacketContext(at, flow, flow_generation=epoch), 1000)


def profile_file(tmp_path, layout=LAYOUT):
    path = tmp_path / "profile.json"
    path.write_text(json.dumps({"version": 1, "profile_active": True, "specs": {},
        "updated_at": "preserve", "extension": [1, 2], **({"xp": layout.to_dict()} if layout else {})}))
    return path


def test_accounting_duplicates_losses_and_rollover():
    updates = []
    tracker = XPTracker(LAYOUT, updates.append)
    assert tracker.snapshot().status == "waiting"
    for f in [frame(900), frame(950), frame(950, at=2), frame(30, required=2000, level=20), frame(20, required=2000, level=20)]:
        tracker.observe(f)
    assert [r.delta_xp for r in updates] == [None, 50, 80, -10]
    assert [r.net_xp for r in updates] == [0, 50, 130, 120]
    assert updates[-1].percentage == 1.0
    assert updates[0].to_dict()["scope"] == "solo-unverified"
    with pytest.raises(AttributeError):
        updates[0].current_xp = 0


@pytest.mark.parametrize("changes", [dict(level=0), dict(level=76), dict(current=1000), dict(required=0),
    dict(at=float("nan")), dict(level=21), dict(level=18), dict(required=2000), dict(epoch=2),
    dict(flow=FlowKey("192.0.2.3", 8889, "192.0.2.2", 40001))])
def test_corruption_and_discontinuities_withdraw_authority(changes):
    tracker = XPTracker(LAYOUT, lambda reading: None)
    tracker.observe(frame())
    with pytest.raises(XPTrackingError):
        tracker.observe(frame(**changes))
    assert tracker.snapshot().status == "invalid" and tracker.snapshot().reading is None
    with pytest.raises(XPTrackingError):
        tracker.observe(frame())


def test_shape_mismatch_and_no_implicit_opcode_fallback():
    tracker = XPTracker(LAYOUT, lambda reading: None)
    tracker.observe(frame(layout=replace(LAYOUT, opcode=0x1234)))
    assert tracker.reading is None
    with pytest.raises(XPTrackingError, match="shape"):
        tracker.observe(frame(layout=replace(LAYOUT, message_length=61)))


def test_uint64_and_logical_level_byte():
    tracker = XPTracker(LAYOUT, lambda reading: None)
    tracker.observe(frame(6234811493094, 403611950304000, 66))
    assert tracker.reading.current_xp == 6234811493094
    assert tracker.reading.level == 66  # Nonzero adjacent opaque bytes ignored.


def test_profile_merge_preserves_unrelated_data_and_uses_backup(tmp_path):
    path = profile_file(tmp_path, None)
    before = path.read_bytes()
    digest = hashlib.sha256(before).hexdigest()
    result = update_xp_profile(LAYOUT, path, expected_profile_sha256=digest)
    assert result.written and result.backup_path.read_bytes() == before
    after = json.loads(path.read_text())
    assert {k: v for k, v in after.items() if k != "xp"} == json.loads(before)
    assert not update_xp_profile(LAYOUT, path).written
    with pytest.raises(ProfileError, match="changed"):
        update_xp_profile(LAYOUT, path, expected_profile_sha256=digest)


@pytest.fixture
def fake(monkeypatch):
    captures = []
    class Capture(FakeCapture):
        frames = [frame(100), frame(200)]
        def start(self):
            self.running = True
            for f in self.frames:
                try:
                    self.callback(f)
                except BaseException as exc:
                    self.error = exc
                    break
    def factory(**kwargs):
        capture = Capture(**kwargs)
        captures.append(capture)
        return capture
    monkeypatch.setattr(module, "LivePacketCapture", factory)
    monkeypatch.setattr(module, "make_packet_handler", lambda manager: manager.tracker.observe)
    return Capture, captures


def test_fetch_then_live_api_without_calibration(tmp_path, monkeypatch, fake):
    data = json.loads(profile_file(tmp_path).read_text())
    _serve(monkeypatch, _envelope(data))
    fetched = fetch_opcode_profile("https://profiles.example.test/current.json", tmp_path / "fetched.json")
    owner = LiveXPSession(profile=fetched.profile, capture_seconds=.02)
    assert owner.status.reading is None
    with owner:
        wait_stopped(owner)  # Owner deadline works while app does not poll.
        events = list(owner.events())
    assert [r.delta_xp for r in events] == [None, 100]
    assert owner.status.reading.net_xp == 100
    assert owner.health.packets_processed == 2
    assert owner.stop_reason == "duration"
    with pytest.raises(RuntimeError, match="single-use"):
        owner.start()


def test_missing_inactive_profiles_rejected_before_acquisition(tmp_path, fake):
    with pytest.raises(TypeError):
        LiveXPSession()
    with pytest.raises(ProfileError):
        LiveXPSession(profile=load_opcode_profile(profile_file(tmp_path, None)))
    with pytest.raises(ProfileError):
        LiveXPSession(profile=replace(load_opcode_profile(profile_file(tmp_path)), active=False))
    assert not fake[1]


@pytest.mark.parametrize("queue_kind", ["event_queue_size", "packet_queue_size"])
def test_queue_overflow_fails_closed(tmp_path, fake, queue_kind):
    owner = LiveXPSession(profile=load_opcode_profile(profile_file(tmp_path)),
                          live_options=LiveCaptureOptions(**{queue_kind: 1}), capture_seconds=.02)
    try:
        owner.start()
    except CaptureIntegrityError:
        pass
    wait_stopped(owner)
    with pytest.raises(CaptureIntegrityError):
        owner.poll(0)
    assert owner.status.status == "invalid" and owner.status.reading is None
    assert not owner.health.capture_is_clean


def test_native_loss_hides_reading_and_buffered_updates(tmp_path, fake, monkeypatch):
    monkeypatch.setattr(fake[0], "snapshot_stats", lambda self: CaptureStats(dropped=1))
    owner = LiveXPSession(profile=load_opcode_profile(profile_file(tmp_path)), capture_seconds=.02)
    try:
        owner.start()
    except CaptureIntegrityError:
        pass
    wait_stopped(owner)
    with pytest.raises(CaptureIntegrityError):
        owner.poll(0)
    assert owner.status.reading is None


def test_disconnect_vs_eof():
    tracker = XPTracker(LAYOUT, lambda reading: None)
    manager = XPFlowManager(tracker, (8889,))
    tracker.observe(frame())
    manager.finish()
    assert tracker.reading is not None
    with pytest.raises(XPTrackingError, match="closed"):
        tracker.close_flow(FLOW)


def write_capture(path, packets):
    from scapy.all import Ether, IP, TCP, Raw, wrpcap
    seq = 1000
    output = []
    for f in packets:
        p = Ether() / IP(src=FLOW.source_ip, dst=FLOW.destination_ip) / TCP(
            sport=FLOW.source_port, dport=FLOW.destination_port, seq=seq, flags="PA") / Raw(f.message)
        p.time = f.context.timestamp
        output.append(p)
        seq += len(f.message)
    wrpcap(str(path), output)


def test_offline_stream_and_same_decoding(tmp_path):
    path = tmp_path / "capture.pcap"
    write_capture(path, [frame(100), frame(200, at=2), frame(200, at=3), frame(250, at=4)])
    with replay_xp(path, profile=load_opcode_profile(profile_file(tmp_path))) as replay:
        assert [r.net_xp for r in replay] == [0, 100, 150]
        assert replay.status.reading.current_xp == 250
        assert replay.health.pcap_dropped is None


def test_replay_error_hides_partial_state(tmp_path):
    path = tmp_path / "capture.pcap"
    write_capture(path, [frame(100), frame(1200, at=2)])
    with replay_xp(path, profile=load_opcode_profile(profile_file(tmp_path))) as replay:
        with pytest.raises(XPTrackingError):
            list(replay)
        assert replay.status.reading is None


def test_private_high_level_and_rollover_with_public_replay(tmp_path):
    from tests.fixture_paths import capture_catalog
    catalog = capture_catalog()
    if not catalog.installed:
        pytest.skip("Private capture catalog not installed")
    layout = XPProfileLayout(0x0D18, 56, 18, 5, 47)
    profile = load_opcode_profile(profile_file(tmp_path, layout))
    for cid, level, current, net in [
        ("combat--self-levelup18-to19--e5369e6d8e", 19, 5311, 17157),
        ("combat--level63-xp--76cbe42996", 63, 685930220615, 297631633),
    ]:
        with replay_xp(catalog.capture_path(cid), profile=profile) as replay:
            rows = list(replay)
            assert (rows[-1].level, rows[-1].current_xp, rows[-1].net_xp) == (level, current, net)

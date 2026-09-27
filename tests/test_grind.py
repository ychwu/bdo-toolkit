"""Shared grind capture: parity, opt-out, independent failures and lifecycle."""
from dataclasses import replace
import json
import time

import pytest

from bdo_toolkit import BDOEvent, CaptureIntegrityError, EventFilter, LiveCaptureOptions, load_opcode_profile, replay_pcap
from bdo_toolkit._capture_backend import iter_pcap_file, make_packet_handler
from bdo_toolkit._capture_runtime import CaptureStats
from bdo_toolkit.agris import AgrisBalance, replay_agris
from bdo_toolkit.grind import GrindFeatureError, GrindSession
from bdo_toolkit.grind import session as module
from bdo_toolkit.grind import _pipeline as pipeline_module
from bdo_toolkit.grind._pipeline import GrindPipeline
from bdo_toolkit.profiles import ProfileError
from bdo_toolkit.xp import XPReading, replay_xp
from tests.test_agris_profiles import LAYOUT as AGRIS
from tests.test_agris_session import FakeCapture, frames as agris_frames, wait_stopped
from tests.test_xp import LAYOUT as XP, FLOW, frame as xp_frame
from tests.test_inventory_snapshots import _inventory_snapshot


@pytest.fixture
def profile(tmp_path):
    path = tmp_path / "profile.json"
    path.write_text(json.dumps({"version": 1, "profile_active": True,
        "specs": {"INVENTORY_TRANSFER": [{"opcode": "0x194A", "length": 254,
            "item_id_offset": 31, "quantity_offset": 35, "context_offset": 27}]},
        "xp": XP.to_dict(), "agris": AGRIS.to_dict()}))
    return load_opcode_profile(path)


def drop(item=7003, quantity=3, context="85fa5745"):
    b = _inventory_snapshot(count=1, quantities=(quantity,))
    b[27:31] = bytes.fromhex(context)
    b[31:35] = item.to_bytes(4, "little")
    return bytes(b)


def traffic():
    a, b = list(agris_frames((99960, 99920)))
    return [xp_frame(900).message, a.message, drop(),
            drop(context="00000000"), drop(context="01020304"),
            xp_frame(950).message, b.message, drop(7004, 2),
            xp_frame(30, required=2000, level=20).message]


def packets(messages, *, fragmented=False):
    from scapy.all import Ether, IP, TCP, Raw
    seq = 1000
    chunks = messages
    if fragmented:
        combined = b"".join(messages)
        chunks = [combined[i:i + 29] for i in range(0, len(combined), 29)]
    result = []
    now = time.time()
    # SYN anchors the exact origin before testing arbitrary fragmentation.
    syn = Ether() / IP(src=FLOW.source_ip, dst=FLOW.destination_ip) / TCP(
        sport=FLOW.source_port, dport=FLOW.destination_port, seq=seq - 1, flags="S")
    syn.time = now
    result.append(syn)
    for index, message in enumerate(chunks):
        p = Ether() / IP(src=FLOW.source_ip, dst=FLOW.destination_ip) / TCP(
            sport=FLOW.source_port, dport=FLOW.destination_port, seq=seq, flags="PA") / Raw(message)
        p.time = now + index * .001
        result.append(p)
        seq += len(message)
    decoded = []
    for p in result:
        wire = Ether(bytes(p))
        wire.time = p.time
        decoded.append(wire)
    return decoded


def pipeline(profile, output, *, xp=True, agris=True, live=False):
    return GrindPipeline(profile=profile, track_xp=xp, track_agris=agris,
        expected_maximum_points=100000 if agris else None, ports=(8889,), publish=output.append, live=live)


@pytest.mark.parametrize("xp,agris", [(False, False), (True, False), (False, True), (True, True)])
@pytest.mark.parametrize("fragmented", [False, True])
def test_replay_parity_all_feature_combinations(profile, tmp_path, xp, agris, fragmented):
    from scapy.all import wrpcap
    path = tmp_path / "combined.pcap"
    pkts = packets(traffic(), fragmented=fragmented)
    # Retransmitted old packets must not duplicate any domain's output.
    pkts.insert(3, pkts[2].copy())
    wrpcap(str(path), pkts)
    rows = []
    owner = pipeline(profile, rows, xp=xp, agris=agris)
    list(iter_pcap_file(path, owner))
    expected_items = list(replay_pcap(path, opcode_profile=profile,
        event_filter=EventFilter(event_types={"item_received"}, sources={"Mob Drop"})))
    assert [r for r in rows if isinstance(r, BDOEvent)] == expected_items
    assert [(r.item_id, r.quantity) for r in expected_items] == [(7003, 3), (7004, 2)]
    expected_xp = list(replay_xp(path, profile=profile)) if xp else []
    expected_agris = list(replay_agris(path, profile=profile, expected_maximum_points=100000)) if agris else []
    assert [r for r in rows if isinstance(r, XPReading)] == expected_xp
    assert [r for r in rows if isinstance(r, AgrisBalance)] == expected_agris
    if xp:
        assert [r.delta_xp for r in expected_xp] == [None, 50, 80]
    assert owner.snapshot().status == "ready"
    assert (owner.snapshot().xp is None) == (not xp)
    assert (owner.snapshot().agris is None) == (not agris)


def test_disabled_readers_never_construct_or_discover(profile, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("disabled reader was constructed")
    monkeypatch.setattr(pipeline_module, "XPTracker", forbidden)
    monkeypatch.setattr(pipeline_module, "AgrisTracker", forbidden)
    owner = pipeline(replace(profile, xp=None, agris=None), [], xp=False, agris=False)
    handler = make_packet_handler(owner)
    for p in packets(traffic()):
        handler(p)
    owner.finish()
    assert owner.xp is None and owner.agris is None
    assert owner.collector._tracker is None  # No storage-origin discovery graph.


def test_enabled_readers_never_search_or_refresh_discovery(profile, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("profile recording entered discovery")
    for name in ("_add_family", "_update_family", "_find_candidates", "refresh"):
        monkeypatch.setattr(pipeline_module.AgrisTracker, name, forbidden)
    rows = []
    owner = pipeline(profile, rows)
    handler = make_packet_handler(owner)
    for p in packets(traffic()):
        handler(p)
    owner.finish()
    assert len(rows) == 7


@pytest.mark.parametrize("feature", ["xp", "agris"])
def test_feature_failure_is_latched_and_other_readers_continue(profile, feature):
    bad = xp_frame(current=1000).message if feature == "xp" else list(agris_frames((100001,)))[0].message
    rows = []
    owner = pipeline(profile, rows)
    handler = make_packet_handler(owner)
    for p in packets([*traffic(), bad, drop(), list(agris_frames((99900,)))[0].message,
                      xp_frame(40, required=2000, level=20).message, drop(7004)]):
        handler(p)
    owner.finish()
    errors = [r for r in rows if isinstance(r, GrindFeatureError)]
    assert len(errors) == 1 and errors[0].feature == feature
    assert errors[0].to_dict()["event_type"] == "grind_feature_error"
    status = owner.snapshot()
    assert status.status == "degraded"
    failed = status.xp if feature == "xp" else status.agris
    assert failed.status == "invalid"
    assert (failed.reading if feature == "xp" else failed.balance) is None
    assert len([r for r in rows if isinstance(r, BDOEvent)]) == 4
    assert (status.agris if feature == "xp" else status.xp).status == "tracking"


@pytest.fixture
def fake(monkeypatch):
    captures = []
    class Capture(FakeCapture):
        input_packets = None
        def start(self):
            self.running = True
            for p in self.input_packets if self.input_packets is not None else packets(traffic()):
                try:
                    self.callback(p)
                except BaseException as exc:
                    self.error = exc
                    break
    def factory(**kwargs):
        capture = Capture(**kwargs)
        captures.append(capture)
        return capture
    monkeypatch.setattr(module, "LivePacketCapture", factory)
    return Capture, captures


def session(profile, **kwargs):
    return GrindSession(profile=profile, track_xp=True, track_agris=True,
                        expected_maximum_points=100000, **kwargs)


def test_live_one_capture_and_reassembly_deadline_and_clean_stop(profile, fake, monkeypatch):
    from bdo_toolkit import _engine
    managers = []
    original = _engine.FlowManager
    def factory(**kwargs):
        result = original(**kwargs)
        managers.append(result)
        return result
    monkeypatch.setattr(_engine, "FlowManager", factory)
    owner = session(profile, capture_seconds=.02)
    assert owner.status.xp.reading is None
    with owner:
        wait_stopped(owner)
        rows = list(owner.events())
    assert len(fake[1]) == len(managers) == 1
    assert len(rows) == 7
    assert owner.status.xp.reading.net_xp == 130
    assert owner.status.agris.balance.remaining_points == 99920
    assert owner.health.capture_is_clean
    assert owner.health.packets_processed == len(traffic()) + 1
    assert fake[1][0].stop_calls == 1
    assert owner.stop_reason == "duration"
    with pytest.raises(RuntimeError, match="single-use"):
        owner.start()


def test_preflight_missing_layouts_and_bad_options(profile, fake):
    for kwargs, error in [
        ({"profile": replace(profile, xp=None), "track_xp": True}, ProfileError),
        ({"profile": replace(profile, agris=None), "track_agris": True, "expected_maximum_points": 100000}, ProfileError),
        ({"profile": replace(profile, specs={})}, ProfileError),
        ({"profile": replace(profile, active=False)}, ProfileError),
        ({"profile": profile, "track_agris": True}, ValueError),
        ({"profile": profile, "expected_maximum_points": 100000}, ValueError),
        ({"profile": profile, "track_xp": 1}, TypeError),
        ({"profile": profile, "live_options": {}}, TypeError),
    ]:
        with pytest.raises(error):
            GrindSession(**kwargs)
    assert not fake[1]


@pytest.mark.parametrize("queue", ["event_queue_size", "packet_queue_size"])
def test_queue_loss_invalidates_every_enabled_feature(profile, fake, queue):
    owner = session(profile, capture_seconds=.02, live_options=LiveCaptureOptions(**{queue: 1}))
    try:
        owner.start()
    except CaptureIntegrityError:
        pass
    wait_stopped(owner)
    with pytest.raises(CaptureIntegrityError):
        owner.poll(0)
    assert owner.status.status == "invalid"
    assert owner.status.xp.reading is owner.status.agris.balance is None
    assert not owner.health.capture_is_clean


def test_native_loss_and_no_buffered_delivery(profile, fake, monkeypatch):
    def stats(self):
        self.stats = CaptureStats(dropped=1)
        return self.stats
    monkeypatch.setattr(fake[0], "snapshot_stats", stats)
    owner = session(profile, capture_seconds=.02)
    try:
        owner.start()
    except CaptureIntegrityError:
        pass
    wait_stopped(owner)
    with pytest.raises(CaptureIntegrityError):
        owner.poll(0)
    assert owner.status.xp.reading is owner.status.agris.balance is None
    assert not owner.health.capture_is_clean


def test_disconnect_is_not_clean_stop(profile, fake):
    from scapy.layers.inet import IP, TCP
    pkts = packets(traffic())
    last = pkts[-1].copy()
    last[TCP].seq += len(bytes(last[TCP].payload))
    last[TCP].remove_payload()
    last[TCP].flags = "F"
    last[IP].len = 40
    fake[0].input_packets = [*pkts, last]
    owner = session(profile, capture_seconds=.02)
    with owner:
        wait_stopped(owner)
        errors = [r for r in owner.events() if isinstance(r, GrindFeatureError)]
    assert {r.feature for r in errors} == {"xp", "agris"}
    assert owner.status.status == "degraded"
    assert owner.status.xp.reading is owner.status.agris.balance is None


def test_gap_and_flow_eviction_are_shared_failures(profile):
    owner = pipeline(profile, [])
    handler = make_packet_handler(owner)
    pkts = packets(traffic())
    handler(pkts[0])
    handler(pkts[1])
    handler(pkts[3])  # Missing packet 2, gap exposed on finish.
    with pytest.raises(CaptureIntegrityError, match="TCP gap"):
        owner.finish()
    assert owner.tcp_gap_resets == 1

    owner = pipeline(profile, [])
    for i in range(64):
        owner.process_tcp_segment(source_ip=FLOW.source_ip, source_port=8889,
            destination_ip=FLOW.destination_ip, destination_port=40000 + i,
            sequence=999, payload=b"", timestamp=1., syn=True)
    with pytest.raises(CaptureIntegrityError, match="flow limit"):
        owner.process_tcp_segment(source_ip=FLOW.source_ip, source_port=8889,
            destination_ip=FLOW.destination_ip, destination_port=41000,
            sequence=999, payload=b"", timestamp=1., syn=True)
    assert owner.evictions == 1


@pytest.mark.parametrize("ordering", ["reordered", "no-syn", "coalesced"])
def test_transport_boundaries_keep_domain_results(profile, tmp_path, ordering):
    from scapy.all import wrpcap
    pkts = packets([b"".join(traffic())] if ordering == "coalesced" else traffic())
    if ordering == "reordered":
        pkts[2], pkts[3] = pkts[3], pkts[2]
    elif ordering == "no-syn":
        pkts = pkts[1:]
    path = tmp_path / "transport.pcap"
    wrpcap(str(path), pkts)
    rows = []
    owner = pipeline(profile, rows)
    list(iter_pcap_file(path, owner))
    assert [(r.item_id, r.quantity) for r in rows if isinstance(r, BDOEvent)] == [(7003, 3), (7004, 2)]
    assert [r for r in rows if isinstance(r, XPReading)] == list(replay_xp(path, profile=profile))
    assert [r for r in rows if isinstance(r, AgrisBalance)] == list(
        replay_agris(path, profile=profile, expected_maximum_points=100000))


def test_no_nested_frame_promotion(profile):
    embedded = xp_frame(200).message + list(agris_frames((99960,)))[0].message + drop()
    outer = (len(embedded) + 5).to_bytes(2, "little") + b"\x00\x31\x12" + embedded
    rows = []
    owner = pipeline(profile, rows)
    handler = make_packet_handler(owner)
    for p in packets([outer, *traffic()]):
        handler(p)
    owner.finish()
    assert len(rows) == 7
    assert owner.snapshot().status == "ready"


def test_live_drain_and_preserve_existing_raw_file(profile, fake, tmp_path):
    owner = session(profile)
    owner.start()
    owner.stop()
    assert len(list(owner.events())) == 7
    assert owner.health.packets_accepted == owner.health.packets_processed
    path = tmp_path / "existing.pcap"
    path.write_bytes(b"private evidence")
    second = session(profile, save_pcap=path)
    with pytest.raises(FileExistsError):
        second.start()
    assert path.read_bytes() == b"private evidence"
    assert len(fake[1]) == 1


def test_raw_capture_then_replay_matches_and_closes(profile, fake, tmp_path):
    path = tmp_path / "new.pcap"
    owner = session(profile, save_pcap=path, capture_seconds=.02)
    with owner:
        wait_stopped(owner)
        expected = list(owner.events())
    rows = []
    replay = pipeline(profile, rows)
    list(iter_pcap_file(path, replay))
    # PCAP timestamp rounding is allowed; compare all other fields exactly.
    def values(event):
        return {k: v for k, v in event.to_dict().items() if k not in {"timestamp", "observed_at"}}
    assert [values(r) for r in rows] == [values(r) for r in expected]
    with path.open("ab"):
        pass  # Recording owner released its handle.


def test_feature_error_event_overflow_is_shared_loss(profile, fake):
    fake[0].input_packets = packets([xp_frame().message, xp_frame(current=1000).message])
    owner = session(profile, capture_seconds=.02, live_options=LiveCaptureOptions(event_queue_size=1))
    try:
        owner.start()
    except CaptureIntegrityError:
        pass
    wait_stopped(owner)
    with pytest.raises(CaptureIntegrityError):
        owner.poll(0)
    assert owner.status.status == "invalid"


def test_failure_arriving_during_dequeue_wins(profile, fake, monkeypatch):
    owner = session(profile, capture_seconds=.02)
    with owner:
        wait_stopped(owner)
    original = owner._events.get_nowait
    error = CaptureIntegrityError("late native failure")
    def raced_get():
        result = original()
        owner._record_error(error)
        return result
    monkeypatch.setattr(owner._events, "get_nowait", raced_get)
    with pytest.raises(CaptureIntegrityError) as caught:
        owner.poll(0)
    assert caught.value is error
    assert owner.status.status == "invalid"


def test_optional_error_is_delivered_live_without_stopping_items(profile, fake):
    fake[0].input_packets = packets([xp_frame().message, xp_frame(current=1000).message, drop()])
    owner = session(profile, capture_seconds=.02)
    with owner:
        wait_stopped(owner)
        rows = list(owner.events())
    assert [type(r) for r in rows] == [XPReading, GrindFeatureError, BDOEvent]
    assert owner.status.status == "degraded" and owner.error is None
    assert owner.status.xp.reading is None
    assert owner.health.capture_is_clean  # Decoder compatibility is separate.


def test_incomplete_cleanup_retry_preserves_failure(profile, fake, monkeypatch):
    original = fake[0].stop
    def incomplete_once(self):
        if not getattr(self, "retried", False):
            self.retried = True
            self.cleanup_incomplete = True
            raise OSError("stop failed")
        return original(self)
    monkeypatch.setattr(fake[0], "stop", incomplete_once)
    owner = session(profile, capture_seconds=.02)
    owner.start()
    wait_stopped(owner)
    assert owner.cleanup_incomplete and not owner.health.capture_is_clean
    with pytest.raises(OSError, match="stop failed"):
        owner.stop()
    assert owner.stopped and not owner.cleanup_incomplete
    assert owner.status.status == "invalid"


def test_unexpected_decoder_exception_is_not_swallowed(profile, fake, monkeypatch):
    failure = ValueError("unexpected bug")
    def broken(*args):
        raise failure
    monkeypatch.setattr(pipeline_module.XPTracker, "observe", broken)
    owner = session(profile, capture_seconds=.02)
    try:
        owner.start()
    except ValueError as exc:
        assert exc is failure
    wait_stopped(owner)
    with pytest.raises(ValueError) as caught:
        owner.poll(0)
    assert caught.value is failure
    assert owner.status.status == "invalid"


@pytest.mark.parametrize("xp,agris", [(False, False), (True, False), (False, True), (True, True)])
def test_immediate_stop_detects_missing_fin_tail(profile, fake, xp, agris):
    from scapy.layers.inet import IP, TCP
    pkts = packets(traffic())
    fin = pkts[-1].copy()
    fin[TCP].seq += len(bytes(fin[TCP].payload)) + 100
    fin[TCP].remove_payload()
    fin[TCP].flags = "F"
    fin[IP].len = 40
    fake[0].input_packets = [*pkts, fin]
    owner = GrindSession(profile=profile, track_xp=xp, track_agris=agris,
        expected_maximum_points=100000 if agris else None, capture_seconds=.02)
    try:
        owner.start()
    except CaptureIntegrityError:
        pass
    wait_stopped(owner)
    with pytest.raises(CaptureIntegrityError, match="TCP gap"):
        owner.stop()
    with pytest.raises(CaptureIntegrityError):
        owner.poll(0)
    assert owner.status.status == "invalid"
    assert owner.health.tcp_gap_resets == 1
    assert not owner.health.capture_is_clean
    if xp:
        assert owner.status.xp.reading is None
    if agris:
        assert owner.status.agris.balance is None


@pytest.mark.parametrize("syn", [False, True])
@pytest.mark.parametrize("xp,agris", [(True, False), (False, True), (True, True)])
def test_partial_prefix_item_hint_cannot_change_optional_framing(profile, tmp_path, syn, xp, agris):
    from scapy.all import wrpcap
    payload = (b"\xff" * 7 + (100).to_bytes(2, "little") + b"\x00\x4a\x19"
               + b"\xff" * 10 + xp_frame(900).message + next(agris_frames((99960,))).message)
    pkts = packets([payload])
    path = tmp_path / "midstream.pcap"
    wrpcap(str(path), pkts if syn else pkts[1:])
    rows = []
    owner = pipeline(profile, rows, xp=xp, agris=agris)
    list(iter_pcap_file(path, owner))
    standalone_xp = list(replay_xp(path, profile=profile))
    standalone_agris = list(replay_agris(path, profile=profile, expected_maximum_points=100000))
    assert [r.current_xp for r in standalone_xp] == [900]
    assert [r.remaining_points for r in standalone_agris] == [99960]
    assert [r for r in rows if isinstance(r, XPReading)] == (standalone_xp if xp else [])
    assert [r for r in rows if isinstance(r, AgrisBalance)] == (standalone_agris if agris else [])
    assert [r for r in rows if isinstance(r, BDOEvent)] == list(replay_pcap(
        path, opcode_profile=profile,
        event_filter=EventFilter(event_types={"item_received"}, sources={"Mob Drop"})))


@pytest.mark.parametrize("xp,agris", [(False, False), (True, False), (False, True), (True, True)])
def test_optional_readers_share_one_unhinted_scanner_only_when_enabled(profile, monkeypatch, xp, agris):
    from bdo_toolkit import _engine
    original = _engine.FrameCollectorScanner
    hints = []
    def factory(*args, **kwargs):
        hints.append("known_opcodes" in kwargs)
        return original(*args, **kwargs)
    monkeypatch.setattr(_engine, "FrameCollectorScanner", factory)
    owner = pipeline(profile, [], xp=xp, agris=agris)
    handler = make_packet_handler(owner)
    for packet in packets(traffic()):
        handler(packet)
    owner.finish()
    assert hints == ([True, False] if xp or agris else [True])


def test_standalone_optional_replays_also_reject_missing_fin_tail(profile, tmp_path):
    from scapy.all import wrpcap
    from scapy.layers.inet import IP, TCP
    from bdo_toolkit.agris import AgrisDetectionError
    from bdo_toolkit.xp import XPTrackingError
    pkts = packets(traffic())
    fin = pkts[-1].copy()
    fin[TCP].seq += len(bytes(fin[TCP].payload)) + 100
    fin[TCP].remove_payload()
    fin[TCP].flags = "F"
    fin[IP].len = 40
    path = tmp_path / "missing-fin-tail.pcap"
    wrpcap(str(path), [*pkts, fin])
    with replay_xp(path, profile=profile) as xp:
        with pytest.raises(XPTrackingError, match="TCP gap"):
            list(xp)
        assert xp.status.reading is None
        assert xp.health.tcp_gap_resets == 1
    with replay_agris(path, profile=profile, expected_maximum_points=100000) as agris:
        with pytest.raises(AgrisDetectionError, match="TCP gap"):
            list(agris)
        assert agris.status.balance is None
        assert agris.health.tcp_gap_resets == 1

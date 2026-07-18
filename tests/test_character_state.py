from __future__ import annotations

from pathlib import Path

import pytest

from bdo_toolkit import PacketCaptureOptions
from bdo_toolkit import character_state as character_state_module
from bdo_toolkit.character_state import (
    CharacterLoadSession,
    _CharacterStateAccumulator,
    analyze_character_load_pcap,
    format_character_state,
)
from bdo_toolkit._protocol import (
    BDOFrame,
    CHARACTER_LOAD_CONTEXT,
    EventSpec,
    FlowKey,
    LootEvent,
    PacketContext,
)
from bdo_toolkit.events import BDOEvent, Flow
from fixture_paths import fixture_path, has_fixture_pcaps

requires_fixtures = pytest.mark.skipif(
    not has_fixture_pcaps(), reason="private packet fixtures are not available"
)


@requires_fixtures
def test_july17_character_state_report_recovers_inventory_and_storage():
    try:
        capture = fixture_path("fullcapture.pcapng")
    except FileNotFoundError:
        pytest.skip("July 17 private initial-load fixture not present")
    profile = Path(__file__).resolve().parents[1] / "opcodes.local"

    state = analyze_character_load_pcap(capture, opcode_profile=profile)

    assert state.hydration_detected
    assert state.provenance.capture_mode == "pcap_replay"
    assert state.provenance.input_path == str(capture)
    assert state.provenance.saved_capture_path is None
    assert state.load_reason is None
    assert state.hydration_generations_seen == 1
    assert state.inventory.raw_records == 247
    assert state.inventory.serialized_records == 247
    assert state.inventory.occupied_stacks == 243
    assert state.inventory.currency_balance_records == 4
    assert state.inventory.unclassified_records == 0
    assert state.inventory.group_counts == (72, 2, 72, 70, 2, 0, 29, 0)
    assert state.inventory.populated_groups == 6
    assert state.inventory.empty_groups == 2
    assert state.inventory.inferred_strides == (223,)

    main = state.inventory.container(0x00)
    pearl = state.inventory.container_named("pearl inventory")
    currencies = state.inventory.container(0x18)
    enhancement = state.inventory.container(0x0B)
    assert main is not None and main.occupied_stacks == 74
    assert pearl is not None and pearl.occupied_stacks == 140
    assert pearl.serialized_records == 142
    assert currencies is not None and currencies.occupied_stacks == 0
    assert currencies.serialized_records == 2
    assert enhancement is not None and enhancement.occupied_stacks == 29
    assert all(
        container.confidence == "provisional"
        for container in state.inventory.containers
    )
    assert state.inventory.currency("Silver").quantity == 1_832_291_219
    assert state.inventory.currency(6).quantity == 363
    assert state.inventory.currency("Loyalties").quantity == 17_600
    assert state.inventory.currency(10).quantity == 105_742

    # Two repeated storage sweeps produce 2,480 decoded records but describe
    # one 1,240-stack state. Four explicit empty envelopes complete all 33
    # registered destinations in the second sweep.
    assert state.storage_snapshot_records == 2480
    assert state.storage_occupied_stacks == 1240
    assert state.known_storage_destinations_detected == 33
    assert state.nonempty_storage_destinations == 29
    assert state.empty_storage_destinations == 4

    heidel = state.storage(0x0020)
    assert heidel is not None
    assert heidel.name == "Heidel"
    assert heidel.occupied_stacks == 184
    assert heidel.raw_records == 368
    assert heidel.duplicate_records == 184
    assert heidel.capacity is None
    assert state.storage_named("heidel") == heidel


@requires_fixtures
def test_character_state_formatter_separates_items_currencies_and_capacity():
    try:
        capture = fixture_path("fullcapture.pcapng")
    except FileNotFoundError:
        pytest.skip("July 17 private initial-load fixture not present")
    profile = Path(__file__).resolve().parents[1] / "opcodes.local"
    state = analyze_character_load_pcap(capture, opcode_profile=profile)

    output = format_character_state(state)

    assert (
        "247 serialized records: 243 occupied item stacks + 4 currency balances"
        in output
    )
    assert "6 populated, 2 empty" in output
    assert "33/33 known destinations observed" in output
    assert "29 non-empty, 4 explicitly empty, 0 not observed" in output
    assert "known destinations not observed" not in output
    assert "Heidel: 184 occupied item stacks detected" in output
    assert "capacity: unavailable" in output
    assert "Main Inventory [0x00, provisional]: 74 item stacks" in output
    assert "Pearl Inventory [0x10, provisional]: 140 item stacks" in output
    assert "Global Currencies [0x18, provisional]: 0 item stacks" in output
    assert "Enhancement Inventory [0x0B, provisional]: 29 item stacks" in output
    assert "2 empty wrappers: unclassified" in output
    assert "Silver: 1,832,291,219" in output
    assert "/192" not in output
    assert "initial login vs character switch" in output


@requires_fixtures
def test_july17_character_switch_classifies_exact_inventory_state():
    try:
        capture = fixture_path("character-switch-2026-07-17-01.pcapng")
    except FileNotFoundError:
        pytest.skip("July 17 private character-switch fixture not present")
    profile = Path(__file__).resolve().parents[1] / "opcodes.local"

    state = analyze_character_load_pcap(capture, opcode_profile=profile)
    inventory = state.inventory

    assert inventory.raw_records == 246
    assert inventory.serialized_records == 246
    assert inventory.occupied_stacks == 242
    assert inventory.currency_balance_records == 4
    assert inventory.group_counts == (72, 1, 72, 70, 2, 0, 29, 0)
    assert inventory.inferred_strides == (223,)
    assert inventory.unclassified_records == 0

    assert state.hydration_detected
    assert state.load_reason is None
    assert state.hydration_generations_seen == 1
    assert state.storage_snapshot_records == 2_484
    assert state.storage_occupied_stacks == 1_242
    assert state.known_storage_destinations_detected == 33
    assert state.nonempty_storage_destinations == 29
    assert state.empty_storage_destinations == 4

    heidel = state.storage_named("Heidel")
    assert heidel is not None
    assert (
        heidel.raw_records,
        heidel.occupied_stacks,
        heidel.duplicate_records,
        heidel.groups,
    ) == (366, 183, 183, 6)

    # One retransmitted Old Wisdom Tree frame must not create a third group.
    old_wisdom = state.storage_named("Old Wisdom Tree")
    assert old_wisdom is not None
    assert (
        old_wisdom.raw_records,
        old_wisdom.occupied_stacks,
        old_wisdom.duplicate_records,
        old_wisdom.groups,
    ) == (26, 13, 13, 2)

    bukpo = state.storage_named("Bukpo")
    assert bukpo is not None
    assert bukpo.raw_records == 0
    assert bukpo.occupied_stacks == 0
    assert bukpo.groups == 1
    assert bukpo.empty_envelope_seen

    assert [
        (
            container.raw_code,
            container.name,
            container.confidence,
            container.occupied_stacks,
            len(container.currency_balances),
        )
        for container in inventory.containers
    ] == [
        (0x00, "Main Inventory", "provisional", 73, 0),
        (0x10, "Pearl Inventory", "provisional", 140, 2),
        (0x18, "Global Currencies", "provisional", 0, 2),
        (0x0B, "Enhancement Inventory", "provisional", 29, 0),
    ]
    assert {
        balance.item_id: (
            balance.currency_name,
            balance.quantity,
            balance.inventory_slot,
            balance.container_code,
        )
        for balance in inventory.currency_balances
    } == {
        1: ("Silver", 1_832_291_219, 3, 0x18),
        6: ("Pearl", 363, 0, 0x10),
        7: ("Loyalties", 17_900, 1, 0x10),
        10: ("Crow Coin", 105_742, 0, 0x18),
    }

    # The one-record second main-inventory wrapper uses a stride learned from
    # its multi-record siblings and still receives validated metadata.
    singleton_item = inventory.records_for(44_391)
    assert len(singleton_item) == 1
    assert singleton_item[0].inventory_slot == 122
    assert singleton_item[0].container_code == 0x00
    assert singleton_item[0].container_name == "Main Inventory"

    payload = state.to_dict()["inventory"]
    assert isinstance(payload, dict)
    assert payload["serialized_records"] == 246
    assert payload["currency_balance_records"] == 4
    assert payload["unclassified_records"] == 0
    container_payloads = payload["containers"]
    assert isinstance(container_payloads, list)
    assert container_payloads[0]["raw_code"] == 0x00
    assert container_payloads[0]["raw_code_hex"] == "0x00"


def _synthetic_inventory_tail_group(
    *,
    sequence: int,
    stride: int,
    slot_relative: int,
    container_relative: int,
    container_code: int,
    decoy_slot_relative: int | None = None,
) -> tuple[BDOFrame, list[BDOEvent], EventSpec, int]:
    item_offset = 31
    count = 3
    base_length = item_offset + stride
    message_length = base_length + (count - 1) * stride
    message = bytearray(message_length)
    message[:2] = message_length.to_bytes(2, "little")
    message[3:5] = (0x194A).to_bytes(2, "little")
    message[27:31] = CHARACTER_LOAD_CONTEXT
    flow_key = FlowKey("10.0.0.1", 8889, "10.0.0.2", 50000)
    flow = Flow("10.0.0.1", 8889, "10.0.0.2", 50000)
    records: list[BDOEvent] = []
    for index in range(count):
        record_offset = item_offset + index * stride
        message[record_offset + slot_relative] = 2 + index
        message[record_offset + container_relative] = container_code
        if decoy_slot_relative is not None:
            message[record_offset + decoy_slot_relative] = 20 + index
        records.append(
            BDOEvent(
                event_type="inventory_snapshot",
                timestamp=float(sequence),
                flow=flow,
                item_id=7003 + index,
                quantity=1,
                opcode=0x194A,
                message_length=message_length,
                item_instance=f"instance-{sequence}-{index}",
                record_index=index + 1,
                record_count=count,
                record_offset=record_offset,
                extra={"stream_sequence": sequence},
            )
        )
    frame = BDOFrame(
        index=sequence,
        message=bytes(message),
        context=PacketContext(
            timestamp=float(sequence),
            flow=flow_key,
            stream_start=sequence,
        ),
        stream_sequence=sequence,
    )
    spec = EventSpec(
        label="INVENTORY_TRANSFER",
        opcode=0x194A,
        item_offset=item_offset,
        quantity_offset=item_offset + 4,
        min_message_length=base_length,
        source_context_offset=27,
        item_instance_offset=66,
        single_record_message_length=base_length,
    )
    return frame, records, spec, stride


def test_inventory_tail_layout_is_discovered_for_legacy_geometry():
    groups = [
        _synthetic_inventory_tail_group(
            sequence=100 + code,
            stride=228,
            slot_relative=221,
            container_relative=224,
            container_code=code,
        )
        for code in (0x00, 0x0B)
    ]

    layout = character_state_module._discover_inventory_tail_layout(groups)

    assert layout == (221, 224)
    frame, records, spec, stride = groups[1]
    metadata = character_state_module._inventory_record_metadata(
        frame,
        records,
        spec,
        stride,
        layout,
    )
    assert metadata is not None
    assert [metadata[event.record_offset].slot for event in records] == [2, 3, 4]
    assert {metadata[event.record_offset].container_code for event in records} == {0x0B}


def test_inventory_tail_layout_fails_closed_when_slot_column_is_ambiguous():
    groups = [
        _synthetic_inventory_tail_group(
            sequence=200 + code,
            stride=223,
            slot_relative=221,
            container_relative=222,
            container_code=code,
            decoy_slot_relative=220,
        )
        for code in (0x00, 0x10)
    ]

    assert character_state_module._discover_inventory_tail_layout(groups) is None


def test_inventory_tail_layout_fails_closed_for_an_unknown_container_code():
    groups = [
        _synthetic_inventory_tail_group(
            sequence=300 + code,
            stride=223,
            slot_relative=221,
            container_relative=222,
            container_code=code,
        )
        for code in (0x00, 0x42)
    ]

    assert character_state_module._discover_inventory_tail_layout(groups) is None


def test_known_currency_id_requires_its_observed_container_pairing():
    event = BDOEvent(
        event_type="inventory_snapshot",
        timestamp=1.0,
        flow=Flow("10.0.0.1", 8889, "10.0.0.2", 50000),
        item_id=6,
        quantity=1,
    )
    metadata = character_state_module._InventoryRecordMetadata(
        slot=5,
        container_code=0x00,
    )

    item = character_state_module._snapshot_item(event, "instance", metadata)

    assert item.currency_name is None
    assert not item.is_currency_balance
    assert item.container_name == "Main Inventory"


def _snapshot_record(
    *,
    timestamp: float,
    sequence: int,
    storage: bool,
    instance_byte: int,
) -> LootEvent:
    return LootEvent(
        label="INVENTORY_TO_STORAGE" if storage else "INVENTORY_TRANSFER",
        opcode=0x126D if storage else 0x194A,
        item_id=7003 + instance_byte,
        quantity=instance_byte,
        inventory_slot=None,
        source_context_candidate=(
            bytes.fromhex("20000000") if storage else CHARACTER_LOAD_CONTEXT
        ),
        item_instance=None if storage else bytes([instance_byte]) * 8,
        storage_instance=bytes([instance_byte]) * 8 if storage else None,
        message_length=257 if storage else 254,
        default_context="Storage" if storage else None,
        context=PacketContext(
            timestamp=timestamp,
            flow=FlowKey("10.0.0.1", 8889, "10.0.0.2", 50000),
            stream_start=sequence,
        ),
        stream_sequence=sequence,
        record_offset=36 if storage else 31,
        storage_id=0x0020 if storage else None,
        storage_operation="snapshot" if storage else None,
    )


def test_repeated_inventory_observation_keeps_raw_and_state_counts_distinct():
    accumulator = _CharacterStateAccumulator(profile_source="test", specs=())
    for timestamp, sequence in ((1.0, 100), (1.1, 200)):
        accumulator.observe_record(
            _snapshot_record(
                timestamp=timestamp,
                sequence=sequence,
                storage=False,
                instance_byte=1,
            ),
            b"",
        )

    state = accumulator.snapshot()

    assert state.inventory.raw_records == 2
    assert state.inventory.duplicate_records == 1
    assert state.inventory.serialized_records == 1
    assert state.inventory.occupied_stacks == 1
    assert state.inventory.currency_balance_records == 0
    output = format_character_state(state)
    assert (
        "1 serialized records: 1 occupied item stacks + 0 currency balances" in output
    )
    assert "2 serialized records:" not in output


def test_multiple_character_loads_report_only_the_latest_generation():
    accumulator = _CharacterStateAccumulator(profile_source="test", specs=())
    for record in (
        _snapshot_record(timestamp=1.0, sequence=100, storage=False, instance_byte=1),
        _snapshot_record(timestamp=2.0, sequence=200, storage=True, instance_byte=2),
        _snapshot_record(timestamp=10.0, sequence=300, storage=False, instance_byte=3),
        _snapshot_record(timestamp=11.0, sequence=400, storage=True, instance_byte=4),
    ):
        accumulator.observe_record(record, b"")

    state = accumulator.snapshot()

    assert state.hydration_generations_seen == 2
    assert [item.item_id for item in state.inventory.items] == [7006]
    assert state.storage_snapshot_records == 1
    heidel = state.storage(0x0020)
    assert heidel is not None
    assert [item.item_id for item in heidel.items] == [7007]
    assert any("only the latest generation" in warning for warning in state.warnings)

    output = format_character_state(state)
    assert "1/33 known destinations observed" in output
    assert "1 non-empty, 0 explicitly empty, 32 not observed" in output
    assert "known destinations not observed:" in output
    missing_line = next(
        line
        for line in output.splitlines()
        if "known destinations not observed:" in line
    )
    assert "Heidel" not in missing_line


def test_storage_only_capture_discloses_that_no_generation_boundary_exists():
    accumulator = _CharacterStateAccumulator(profile_source="test", specs=())
    for record in (
        _snapshot_record(timestamp=2.0, sequence=200, storage=True, instance_byte=2),
        _snapshot_record(timestamp=11.0, sequence=400, storage=True, instance_byte=4),
    ):
        accumulator.observe_record(record, b"")

    state = accumulator.snapshot()

    assert state.hydration_generations_seen == 0
    assert state.storage_snapshot_records == 2
    assert (
        state.provenance.generation_selection
        == "all_observed_storage_no_inventory_boundary"
    )
    assert any("may span multiple loads" in warning for warning in state.warnings)


@pytest.fixture
def character_load_live_fakes(monkeypatch):
    parser_packets = []

    class FakeSniffer:
        instances = []

        def __init__(self, *, prn, started_callback=None, **kwargs):
            self.prn = prn
            self.started_callback = started_callback
            self.kwargs = kwargs
            self.running = False
            self.exception = None
            self.stop_calls = 0
            self.__class__.instances.append(self)

        def start(self):
            self.running = True
            if self.started_callback is not None:
                self.started_callback()

        def stop(self):
            self.stop_calls += 1
            self.running = False

        def emit(self, packet):
            self.prn(packet)

    monkeypatch.setattr(
        character_state_module, "_active_specs", lambda path: ("test", ())
    )
    monkeypatch.setattr(
        character_state_module,
        "import_scapy",
        lambda: (object(), object(), None, None, None),
    )
    monkeypatch.setattr(
        character_state_module,
        "make_packet_handler",
        lambda engine: parser_packets.append,
    )
    monkeypatch.setattr("scapy.sendrecv.AsyncSniffer", FakeSniffer)
    return FakeSniffer, parser_packets


@pytest.mark.parametrize("suffix", [".pcap", ".pcapng"])
def test_live_character_load_can_save_every_filtered_raw_packet(
    tmp_path,
    character_load_live_fakes,
    suffix,
):
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw
    from scapy.utils import PcapReader

    FakeSniffer, parser_packets = character_load_live_fakes
    output = tmp_path / "new" / "capture" / f"character-load{suffix}"
    packet = (
        IP(src="203.0.113.1", dst="198.51.100.2")
        / TCP(
            sport=8889,
            dport=50000,
        )
        / Raw(b"raw-packet-evidence")
    )

    session = CharacterLoadSession(
        capture_options=PacketCaptureOptions(interface="test-interface"),
        save_pcap=output,
    )
    session.start()
    FakeSniffer.instances[-1].emit(packet)
    state = session.stop()

    assert parser_packets == [packet]
    assert session.save_pcap_path == output
    assert state.provenance.capture_mode == "live_capture"
    assert state.provenance.input_path is None
    assert state.provenance.saved_capture_path == str(output)
    with PcapReader(str(output)) as reader:
        saved_packets = list(reader)
    assert len(saved_packets) == 1
    assert bytes(saved_packets[0]) == bytes(packet)


def test_live_character_load_refuses_to_overwrite_an_existing_capture(
    tmp_path,
    character_load_live_fakes,
):
    output = tmp_path / "existing.pcapng"
    original = b"keep this capture"
    output.write_bytes(original)
    session = CharacterLoadSession(
        capture_options=PacketCaptureOptions(interface="test-interface"),
        save_pcap=output,
    )

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        session.start()

    assert output.read_bytes() == original


def test_live_character_load_saves_packet_before_parser_failure(
    monkeypatch,
    character_load_live_fakes,
):
    FakeSniffer, _ = character_load_live_fakes

    class FakeWriter:
        def __init__(self):
            self.packets = []
            self.closed = False

        def write(self, packet):
            self.packets.append(packet)

        def close(self):
            self.closed = True

    writer = FakeWriter()
    monkeypatch.setattr(
        character_state_module, "_open_packet_writer", lambda path: writer
    )

    def failing_handler(engine):
        def fail(packet):
            raise RuntimeError("snapshot parser failed")

        return fail

    monkeypatch.setattr(character_state_module, "make_packet_handler", failing_handler)
    session = CharacterLoadSession(
        capture_options=PacketCaptureOptions(interface="test-interface"),
        save_pcap="failure.pcapng",
    )
    session.start()
    packet = object()

    with pytest.raises(RuntimeError, match="snapshot parser failed"):
        FakeSniffer.instances[-1].emit(packet)
    with pytest.raises(RuntimeError, match="snapshot parser failed"):
        session.stop()

    assert writer.packets == [packet]
    assert writer.closed


def test_live_character_load_closes_writer_when_sniffer_start_fails(
    monkeypatch,
    character_load_live_fakes,
):
    class FakeWriter:
        closed = False

        def close(self):
            self.closed = True

    class FailingSniffer:
        def __init__(self, **kwargs):
            self.running = False

        def start(self):
            raise OSError("adapter unavailable")

    writer = FakeWriter()
    monkeypatch.setattr(
        character_state_module, "_open_packet_writer", lambda path: writer
    )
    monkeypatch.setattr("scapy.sendrecv.AsyncSniffer", FailingSniffer)
    session = CharacterLoadSession(
        capture_options=PacketCaptureOptions(interface="test-interface"),
        save_pcap="startup.pcap",
    )

    with pytest.raises(OSError, match="adapter unavailable"):
        session.start()

    assert writer.closed


def test_character_load_tool_rejects_save_path_during_offline_replay():
    import importlib.util

    tool_path = (
        Path(__file__).resolve().parents[1]
        / "tools"
        / "character_load"
        / "inspect_character_load.py"
    )
    spec = importlib.util.spec_from_file_location("inspect_character_load", tool_path)
    assert spec is not None and spec.loader is not None
    inspect_character_load = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inspect_character_load)

    parser = inspect_character_load._parser()
    args = parser.parse_args(["--pcap", "input.pcapng", "--save-pcap", "output.pcapng"])

    with pytest.raises(SystemExit):
        inspect_character_load._validate_args(parser, args)

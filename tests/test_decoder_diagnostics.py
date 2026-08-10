"""Public contract and collector integration for decoder diagnostics."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
import json

import pytest

from bdo_toolkit import DecoderDiagnostic, DecoderHealth, EventFilter
from bdo_toolkit.capture import _EventCollector
from bdo_toolkit._protocol import (
    CHARACTER_LOAD_CONTEXT,
    FlowKey,
    LootEvent,
    PacketContext,
    STORAGE_LOCATIONS,
)


def _write_storage_profile(
    tmp_path,
    *,
    context_offset: int | None = 8,
    record_count_offset: int | None = 6,
    include_inventory: bool = False,
):
    entry = {
        "event": "STORAGE_ITEM_DELTA",
        "opcode": "0x2222",
        "length": 261,
        "item_id_offset": 37,
        "quantity_added_offset": 41,
        "destination_instance_offset": 72,
    }
    if context_offset is not None:
        entry["context_offset"] = context_offset
    if record_count_offset is not None:
        entry["record_count_offset"] = record_count_offset

    specs = {"STORAGE_ITEM_DELTA": [entry]}
    if include_inventory:
        specs["INVENTORY_TRANSFER"] = [
            {
                "event": "INVENTORY_TRANSFER",
                "opcode": "0x3333",
                "length": 261,
                "item_id_offset": 37,
                "quantity_offset": 41,
                "item_instance_offset": 72,
                "context_offset": 8,
            }
        ]

    profile = tmp_path / "storage-diagnostics.json"
    profile.write_text(
        json.dumps(
            {
                "version": 1,
                "profile_active": True,
                "specs": specs,
            }
        ),
        encoding="utf-8",
    )
    return profile


def _storage_message(
    *,
    declared_count: int = 1,
    storage_id: int = 0x0020,
) -> bytes:
    message = bytearray(261)
    message[0:2] = len(message).to_bytes(2, "little")
    message[3:5] = (0x2222).to_bytes(2, "little")
    message[6:8] = declared_count.to_bytes(2, "little")
    message[8:12] = storage_id.to_bytes(4, "little")
    message[37:41] = (7307).to_bytes(4, "little")
    message[41:45] = (8).to_bytes(4, "little")
    message[72:80] = bytes.fromhex("1122334455667788")
    return bytes(message)


def _inventory_snapshot_message() -> bytes:
    message = bytearray(261)
    message[0:2] = len(message).to_bytes(2, "little")
    message[3:5] = (0x3333).to_bytes(2, "little")
    message[6:8] = (1).to_bytes(2, "little")
    message[8:12] = b"\x00" * 4
    message[37:41] = (7003).to_bytes(4, "little")
    message[41:45] = (1).to_bytes(4, "little")
    message[72:80] = bytes.fromhex("8877665544332211")
    return bytes(message)


def _inventory_snapshot_record(
    sequence: int,
    *,
    flow_generation: int = 1,
    destination_port: int = 51000,
) -> LootEvent:
    return LootEvent(
        label="INVENTORY_TRANSFER",
        opcode=0x3333,
        item_id=7003,
        quantity=1,
        inventory_slot=None,
        source_context_candidate=CHARACTER_LOAD_CONTEXT,
        item_instance=bytes.fromhex("8877665544332211"),
        storage_instance=None,
        message_length=261,
        default_context=None,
        context=PacketContext(
            timestamp=float(sequence),
            flow=FlowKey(
                "203.0.113.10",
                8889,
                "198.51.100.20",
                destination_port,
            ),
            stream_start=sequence,
            flow_generation=flow_generation,
        ),
        stream_sequence=sequence,
        record_offset=37,
    )


def _feed(collector: _EventCollector, payload: bytes) -> None:
    collector.engine.process_tcp_segment(
        source_ip="203.0.113.10",
        source_port=8889,
        destination_ip="198.51.100.20",
        destination_port=51000,
        sequence=1000,
        payload=payload,
        timestamp=1000.0,
    )
    collector.engine.finish()
    collector.finalize()


def test_diagnostic_models_are_frozen_exported_and_serializable() -> None:
    diagnostic = DecoderDiagnostic(
        code="storage_decoder_incompatible",
        message="recalibrate",
        opcode=0x2222,
        requested_sources=("Heidel",),
    )
    assert diagnostic.to_dict() == {
        "code": "storage_decoder_incompatible",
        "message": "recalibrate",
        "severity": "warning",
        "subsystem": "storage",
        "opcode": 0x2222,
        "requested_sources": ("Heidel",),
    }
    with pytest.raises(FrozenInstanceError):
        diagnostic.code = "changed"

    health = DecoderHealth(
        storage_status="compatible",
        storage_messages_observed=1,
        storage_messages_decoded=1,
        storage_records_decoded=1,
    )
    assert health.storage_is_compatible is True
    assert health.to_dict()["storage_is_compatible"] is True
    with pytest.raises(FrozenInstanceError):
        health.storage_status = "incompatible"


def test_incomplete_profile_emits_one_out_of_band_town_filter_diagnostic(
    tmp_path,
) -> None:
    diagnostics: list[DecoderDiagnostic] = []
    collector = _EventCollector(
        server_ports=(8889,),
        event_filter=EventFilter(sources={"Heidel"}),
        opcode_profile=_write_storage_profile(
            tmp_path,
            context_offset=None,
            record_count_offset=None,
        ),
        on_diagnostic=diagnostics.append,
    )

    assert list(collector.drain_events()) == []
    assert len(diagnostics) == 1
    assert diagnostics[0].code == "storage_decoder_incompatible"
    assert diagnostics[0].opcode == 0x2222
    assert diagnostics[0].requested_sources == ("Heidel",)
    assert collector.decoder_health.storage_status == "incompatible"
    assert collector.decoder_health.diagnostics_emitted == 1


def test_valid_profile_moves_health_from_not_observed_to_compatible(tmp_path) -> None:
    diagnostics: list[DecoderDiagnostic] = []
    collector = _EventCollector(
        server_ports=(8889,),
        event_filter=EventFilter.all(),
        opcode_profile=_write_storage_profile(tmp_path),
        on_diagnostic=diagnostics.append,
    )

    initial = collector.decoder_health
    assert initial.storage_status == "not_observed"
    assert initial.storage_is_compatible is None

    _feed(collector, _storage_message())

    health = collector.decoder_health
    assert health.storage_status == "compatible"
    assert health.storage_is_compatible is True
    assert health.storage_messages_observed == 1
    assert health.storage_messages_decoded == 1
    assert health.storage_records_decoded == 1
    assert health.storage_geometry_failures == 0
    assert diagnostics == []
    events = list(collector.drain_events())
    assert len(events) == 1
    assert events[0].event_type == "storage_record"
    assert events[0].source == "Heidel"


def test_malformed_declared_count_is_incompatible_and_emits_no_event(tmp_path) -> None:
    diagnostics: list[DecoderDiagnostic] = []
    collector = _EventCollector(
        server_ports=(8889,),
        event_filter=EventFilter.all(),
        opcode_profile=_write_storage_profile(tmp_path),
        on_diagnostic=diagnostics.append,
    )

    # A two-record declaration cannot fit a calibrated one-record base frame.
    malformed = _storage_message(declared_count=2)
    _feed(collector, malformed + malformed)

    assert list(collector.drain_events()) == []
    health = collector.decoder_health
    assert health.storage_status == "incompatible"
    assert health.storage_is_compatible is False
    assert health.storage_messages_observed == 2
    assert health.storage_messages_decoded == 0
    assert health.storage_records_decoded == 0
    assert health.storage_geometry_failures == 2
    assert health.diagnostics_emitted == 1
    assert len(diagnostics) == 1
    assert diagnostics[0].code == "storage_decoder_incompatible"
    assert diagnostics[0].opcode == 0x2222


def test_first_top_level_storage_rejection_warns_immediately(tmp_path) -> None:
    diagnostics: list[DecoderDiagnostic] = []
    collector = _EventCollector(
        server_ports=(8889,),
        event_filter=EventFilter.all(),
        opcode_profile=_write_storage_profile(tmp_path),
        on_diagnostic=diagnostics.append,
    )

    _feed(collector, _storage_message(declared_count=2))

    assert list(collector.drain_events()) == []
    assert collector.decoder_health.storage_status == "incompatible"
    assert collector.decoder_health.storage_messages_observed == 1
    assert collector.decoder_health.storage_geometry_failures == 1
    assert [diagnostic.code for diagnostic in diagnostics] == [
        "storage_decoder_incompatible"
    ]


def test_nested_storage_signature_does_not_poison_decoder_health(tmp_path) -> None:
    diagnostics: list[DecoderDiagnostic] = []
    collector = _EventCollector(
        server_ports=(8889,),
        event_filter=EventFilter.all(),
        opcode_profile=_write_storage_profile(tmp_path),
        on_diagnostic=diagnostics.append,
    )

    outer = bytearray(400)
    outer[0:2] = len(outer).to_bytes(2, "little")
    outer[3:5] = (0x7777).to_bytes(2, "little")
    nested = _storage_message(declared_count=2)
    outer[50 : 50 + len(nested)] = nested
    _feed(collector, bytes(outer))

    assert list(collector.drain_events()) == []
    assert collector.decoder_health.storage_status == "not_observed"
    assert collector.decoder_health.storage_messages_observed == 0
    assert diagnostics == []


def test_valid_nested_storage_wrapper_is_not_delivered_as_a_top_level_event(
    tmp_path,
) -> None:
    diagnostics: list[DecoderDiagnostic] = []
    collector = _EventCollector(
        server_ports=(8889,),
        event_filter=EventFilter.all(),
        opcode_profile=_write_storage_profile(tmp_path),
        on_diagnostic=diagnostics.append,
    )

    outer = bytearray(400)
    outer[0:2] = len(outer).to_bytes(2, "little")
    outer[3:5] = (0x7777).to_bytes(2, "little")
    nested = _storage_message(declared_count=1)
    outer[50 : 50 + len(nested)] = nested
    _feed(collector, bytes(outer))

    assert list(collector.drain_events()) == []
    health = collector.decoder_health
    assert health.storage_status == "not_observed"
    assert health.storage_messages_observed == 0
    assert health.storage_messages_decoded == 0
    assert health.storage_records_decoded == 0
    assert diagnostics == []


def test_nested_inventory_cannot_anchor_eight_top_level_storage_towns(
    tmp_path,
) -> None:
    collector = _EventCollector(
        server_ports=(8889,),
        event_filter=EventFilter.all(),
        opcode_profile=_write_storage_profile(tmp_path, include_inventory=True),
    )

    outer = bytearray(400)
    outer[0:2] = len(outer).to_bytes(2, "little")
    outer[3:5] = (0x7777).to_bytes(2, "little")
    nested = _inventory_snapshot_message()
    outer[50 : 50 + len(nested)] = nested
    storage_ids = tuple(STORAGE_LOCATIONS)[:8]
    payload = bytes(outer) + b"".join(
        _storage_message(storage_id=storage_id) for storage_id in storage_ids
    )

    _feed(collector, payload)

    events = list(collector.drain_events())
    assert not any(event.event_type == "inventory_snapshot" for event in events)
    assert not any(event.event_type == "storage_snapshot" for event in events)
    storage_records = [
        event for event in events if event.event_type == "storage_record"
    ]
    assert len(storage_records) == 8
    assert {event.storage_id for event in storage_records} == set(storage_ids)
    assert collector.decoder_health.storage_status == "compatible"


def test_exact_adjacent_inventory_pair_recovers_without_generic_boundary(
    tmp_path,
) -> None:
    collector = _EventCollector(
        server_ports=(8889,),
        event_filter=EventFilter.all(),
        opcode_profile=_write_storage_profile(tmp_path, include_inventory=True),
    )
    message = _inventory_snapshot_message()

    collector._handle_record(_inventory_snapshot_record(1000), message)
    assert list(collector.drain_events()) == []

    collector._handle_record(_inventory_snapshot_record(1261), message)
    events = list(collector.drain_events())
    assert [event.event_type for event in events] == [
        "inventory_snapshot",
        "inventory_snapshot",
    ]


def test_inventory_pair_recovery_does_not_cross_flow_generation_or_close(
    tmp_path,
) -> None:
    collector = _EventCollector(
        server_ports=(8889,),
        event_filter=EventFilter.all(),
        opcode_profile=_write_storage_profile(tmp_path, include_inventory=True),
    )
    message = _inventory_snapshot_message()
    first = _inventory_snapshot_record(1000, flow_generation=1)

    collector._handle_record(first, message)
    collector._handle_record(
        _inventory_snapshot_record(1261, flow_generation=2),
        message,
    )
    collector._close_flow(first.context.flow)
    collector._handle_record(
        _inventory_snapshot_record(1261, flow_generation=1),
        message,
    )

    assert list(collector.drain_events()) == []
    collector.finalize()
    assert not collector._inventory_boundary_states


def test_pending_inventory_boundary_state_is_bounded(tmp_path) -> None:
    collector = _EventCollector(
        server_ports=(8889,),
        event_filter=EventFilter.all(),
        opcode_profile=_write_storage_profile(tmp_path, include_inventory=True),
    )
    message = _inventory_snapshot_message()

    for index in range(80):
        collector._handle_record(
            _inventory_snapshot_record(1000, destination_port=51000 + index),
            message,
        )

    assert len(collector._inventory_boundary_states) == 64
    assert list(collector.drain_events()) == []


@pytest.mark.parametrize(
    "prefix",
    (b"", b"\xFE" * 17),
    ids=("top-level", "midstream-after-junk"),
)
def test_real_inventory_boundary_still_anchors_eight_storage_towns(
    tmp_path,
    prefix: bytes,
) -> None:
    collector = _EventCollector(
        server_ports=(8889,),
        event_filter=EventFilter.all(),
        opcode_profile=_write_storage_profile(tmp_path, include_inventory=True),
    )
    storage_ids = tuple(STORAGE_LOCATIONS)[:8]
    payload = prefix + _inventory_snapshot_message() + b"".join(
        _storage_message(storage_id=storage_id) for storage_id in storage_ids
    )

    _feed(collector, payload)

    events = list(collector.drain_events())
    inventory = [event for event in events if event.event_type == "inventory_snapshot"]
    snapshots = [event for event in events if event.event_type == "storage_snapshot"]
    assert len(inventory) == 1
    assert len(snapshots) == 8
    assert {event.storage_id for event in snapshots} == set(storage_ids)


def test_same_opcode_nonstorage_layout_is_not_a_storage_rejection(tmp_path) -> None:
    profile = tmp_path / "same-opcode.json"
    profile.write_text(
        json.dumps(
            {
                "version": 1,
                "profile_active": True,
                "specs": {
                    "INVENTORY_TRANSFER": [
                        {
                            "event": "INVENTORY_TRANSFER",
                            "opcode": "0x2222",
                            "length": 261,
                            "item_id_offset": 37,
                            "quantity_offset": 41,
                            "item_instance_offset": 72,
                            "context_offset": 20,
                        }
                    ],
                    "STORAGE_ITEM_DELTA": [
                        {
                            "event": "STORAGE_ITEM_DELTA",
                            "opcode": "0x2222",
                            "length": 261,
                            "item_id_offset": 37,
                            "quantity_added_offset": 41,
                            "destination_instance_offset": 72,
                            "context_offset": 8,
                            "record_count_offset": 6,
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    diagnostics: list[DecoderDiagnostic] = []
    collector = _EventCollector(
        server_ports=(8889,),
        event_filter=EventFilter.all(),
        opcode_profile=profile,
        on_diagnostic=diagnostics.append,
    )

    message = bytearray(_storage_message(declared_count=2))
    message[20:24] = bytes.fromhex("d0f205a3")
    _feed(collector, bytes(message))

    events = list(collector.drain_events())
    assert len(events) == 1
    assert events[0].event_type == "item_received"
    assert collector.decoder_health.storage_status == "not_observed"
    assert diagnostics == []


def test_configured_unknown_destination_cannot_be_replaced_by_known_decoy(
    tmp_path,
) -> None:
    diagnostics: list[DecoderDiagnostic] = []
    collector = _EventCollector(
        server_ports=(8889,),
        event_filter=EventFilter.all(),
        opcode_profile=_write_storage_profile(tmp_path),
        on_diagnostic=diagnostics.append,
    )

    message = bytearray(_storage_message())
    message[8:12] = bytes.fromhex("78563412")
    message[20:24] = (0x0005).to_bytes(4, "little")
    _feed(collector, bytes(message))

    events = list(collector.drain_events())
    assert len(events) == 1
    assert events[0].storage_id == 0x12345678
    assert events[0].storage_name is None
    assert events[0].source == "UNKNOWN_STORAGE(0x12345678)"
    assert collector.decoder_health.storage_status == "incompatible"
    assert len(diagnostics) == 1
    assert diagnostics[0].code == "storage_destination_unrecognized"

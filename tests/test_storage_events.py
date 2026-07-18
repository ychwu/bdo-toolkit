from dataclasses import replace

from bdo_toolkit import EventFilter, storage_location
from bdo_toolkit._engine import toolkit_event_from_record
from bdo_toolkit._protocol import FlowKey, LootEvent, PacketContext


def _storage_record(
    *,
    context: bytes,
    operation: str | None,
    storage_id: int | None = None,
) -> LootEvent:
    return LootEvent(
        label="INVENTORY_TO_STORAGE",
        opcode=0x126D,
        item_id=8508,
        quantity=1,
        inventory_slot=None,
        source_context_candidate=context,
        item_instance=None,
        storage_instance=bytes.fromhex("6fecd08ccc1b8e00"),
        message_length=257,
        default_context="Storage",
        context=PacketContext(
            timestamp=1000.0,
            flow=FlowKey("10.0.0.1", 8889, "10.0.0.2", 50000),
            stream_start=1234,
        ),
        stream_sequence=1234,
        record_offset=35,
        record_index=1,
        record_count=1,
        storage_id=storage_id,
        storage_operation=operation,
    )


def test_storage_location_metadata_preserves_mapping_confidence():
    assert storage_location(0x0058).name == "Olvia"
    assert storage_location(0x0058).confidence == "observed"
    assert storage_location(0x0034).name == "Glish"
    assert storage_location(0x0034).confidence == "observed"
    assert storage_location(0x0590).name == "Godu Village"
    assert storage_location(0x0590).confidence == "observed"
    assert storage_location(0x05A4).name == "Bukpo"
    assert storage_location(0x05A4).confidence == "observed"
    assert storage_location(0x02B6).name == "Muiquun"
    assert storage_location(0x02B6).confidence == "probable"
    assert storage_location(0xDEADBEEF) is None


def test_live_storage_delta_exposes_destination_fields_and_legacy_context():
    event = toolkit_event_from_record(
        _storage_record(context=bytes.fromhex("20000000"), operation="live")
    )

    assert event.event_type == "storage_delta"
    assert event.source == "Heidel"
    assert event.raw_context == "0x20000000"
    assert event.storage_id == 0x0020
    assert event.storage_name == "Heidel"
    assert event.storage_name_confidence == "observed"
    assert event.storage_operation == "live"
    assert event.deposit_origin is None
    assert event.to_dict()["extra"]["storage_delta"] == 1


def test_initial_load_snapshot_is_not_a_deposit_event():
    event = toolkit_event_from_record(
        _storage_record(context=bytes.fromhex("58000000"), operation="snapshot")
    )

    assert event.event_type == "storage_snapshot"
    assert event.source == "Olvia"
    assert event.storage_id == 0x0058
    assert event.storage_name == "Olvia"
    assert event.storage_operation == "snapshot"
    assert event.deposit_origin is None
    assert "storage_delta" not in event.extra
    assert event.extra["storage_quantity"] == 1
    assert "STORAGE_SNAPSHOT" in event.format_human()
    assert "storage_id=0x00000058" in event.format_human()
    assert "storage_name='Olvia'" in event.format_human()
    assert "storage_name_confidence=observed" in event.format_human()
    assert "storage_operation=snapshot" in event.format_human()


def test_unknown_storage_key_remains_visible_without_inventing_a_name():
    event = toolkit_event_from_record(
        _storage_record(context=bytes.fromhex("efbeadde"), operation="live")
    )

    assert event.storage_id == 0xDEADBEEF
    assert event.storage_name is None
    assert event.storage_name_confidence is None
    assert event.source == "UNKNOWN_STORAGE(0xdeadbeef)"
    assert event.raw_context == "0xefbeadde"


def test_unrecognized_current_wrapper_operation_fails_closed():
    event = toolkit_event_from_record(
        _storage_record(context=bytes.fromhex("20000000"), operation="unknown")
    )

    assert event.event_type == "storage_record"
    assert event.storage_operation == "unknown"
    assert event.deposit_origin is None
    assert "storage_delta" not in event.extra
    assert "storage_quantity" not in event.extra
    assert not EventFilter(
        event_types={"item_received", "storage_delta"}
    ).allows(event)


def test_event_filter_presets_separate_activity_snapshot_and_all_events():
    storage_delta = toolkit_event_from_record(
        _storage_record(context=bytes.fromhex("20000000"), operation="live")
    )
    storage_snapshot = toolkit_event_from_record(
        _storage_record(context=bytes.fromhex("58000000"), operation="snapshot")
    )
    storage_record = toolkit_event_from_record(
        _storage_record(context=bytes.fromhex("20000000"), operation="unknown")
    )
    item_received = replace(storage_delta, event_type="item_received")
    inventory_snapshot = replace(storage_delta, event_type="inventory_snapshot")
    loot_preview = replace(storage_delta, event_type="loot_preview")

    activity = EventFilter.activity()
    assert activity.event_types == frozenset(
        {"loot_preview", "item_received", "storage_delta"}
    )
    assert activity.allows(loot_preview)
    assert activity.allows(item_received)
    assert activity.allows(storage_delta)
    assert not activity.allows(inventory_snapshot)
    assert not activity.allows(storage_snapshot)
    assert not activity.allows(storage_record)

    snapshots = EventFilter.snapshot_records()
    assert snapshots.event_types == frozenset(
        {"inventory_snapshot", "storage_snapshot"}
    )
    assert snapshots.allows(inventory_snapshot)
    assert snapshots.allows(storage_snapshot)
    assert not snapshots.allows(item_received)
    assert not snapshots.allows(storage_delta)
    assert not snapshots.allows(storage_record)

    all_events = EventFilter.all()
    assert all_events == EventFilter()
    assert all(
        all_events.allows(event)
        for event in (
            item_received,
            inventory_snapshot,
            storage_delta,
            storage_snapshot,
            storage_record,
            loot_preview,
        )
    )


def test_zero_storage_context_is_not_promoted_to_a_location_key():
    event = toolkit_event_from_record(
        _storage_record(
            context=b"\x00" * 4,
            operation=None,
            storage_id=0,
        )
    )

    assert event.event_type == "storage_delta"
    assert event.storage_id is None
    assert event.storage_name is None
    assert event.source == "Character Load"

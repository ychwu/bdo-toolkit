from __future__ import annotations

from dataclasses import asdict, fields

from bdo_toolkit import __all__ as package_exports
from bdo_toolkit.character_state import (
    CharacterStateSnapshot,
    InventorySnapshotSummary,
    SnapshotItem,
    StorageContents,
    StorageSnapshotSummary,
    analyze_character_load_pcap,
    format_character_state,
)
from bdo_toolkit.diagnostics import DecoderHealth
from bdo_toolkit.item_state import (
    CharacterLoadSession,
    ItemStateCaptureLimitError,
    ItemStateCaptureLimits,
    ItemStateSnapshot,
    analyze_item_state_pcap,
    format_item_state,
)


def _item(item_id: int, quantity: int, instance: str) -> SnapshotItem:
    return SnapshotItem(
        item_id=item_id,
        quantity=quantity,
        instance=instance,
        timestamp=1.0,
        opcode=None,
        message_length=None,
    )


def _storage(
    storage_id: int,
    name: str | None,
    *items: SnapshotItem,
    empty_envelope_seen: bool = False,
) -> StorageSnapshotSummary:
    return StorageSnapshotSummary(
        storage_id=storage_id,
        name=name,
        name_confidence="observed" if name is not None else None,
        items=tuple(items),
        raw_records=len(items),
        duplicate_records=0,
        groups=1,
        empty_envelope_seen=empty_envelope_seen,
    )


def _inventory() -> InventorySnapshotSummary:
    return InventorySnapshotSummary(
        items=(_item(5000, 2, "inventory-1"),),
        raw_records=1,
        duplicate_records=0,
        group_counts=(1,),
        inferred_strides=(),
        currency_balances=(),
        containers=(),
        unclassified_records=1,
    )


def test_storage_contents_preserves_tuple_use_and_adds_queries():
    heidel = _storage(
        0x0020,
        "Heidel",
        _item(7003, 5, "heidel-potato"),
        _item(7004, 3, "heidel-corn"),
    )
    velia = _storage(0x0005, "Velia", _item(7003, 7, "velia-potato"))
    contents = StorageContents((heidel, velia))

    assert len(contents) == 2
    assert tuple(contents) == (heidel, velia)
    assert contents == (heidel, velia)
    assert isinstance(contents, tuple)
    assert contents[0] is heidel
    assert contents[-1] is velia
    assert contents[:1] == (heidel,)
    assert contents + (heidel,) == (heidel, velia, heidel)
    assert contents * 2 == (heidel, velia, heidel, velia)

    assert contents.by_id(0x0020) is heidel
    assert contents.by_id(0xFFFF) is None
    assert contents.named("hEiDeL") is heidel
    assert contents.named("missing") is None
    assert [item.quantity for item in contents.find_item(7003)] == [5, 7]
    assert contents.find_item(9999) == ()
    assert contents.total_quantity(7003) == 12
    assert contents.total_quantity(9999) == 0
    assert contents.locations_for(7003) == (heidel, velia)
    assert contents.locations_for(7004) == (heidel,)
    assert contents.locations_for(9999) == ()


def test_item_state_serialization_exposes_honest_coverage_and_provenance():
    heidel = _storage(0x0020, "Heidel", _item(7003, 5, "heidel-potato"))
    unknown_empty = _storage(
        0xDEAD,
        None,
        empty_envelope_seen=True,
    )
    # Passing the historical tuple shape remains accepted and is normalized to
    # the first-class collection.
    state = CharacterStateSnapshot(
        profile_source="opcodes.local",
        frames_seen=12,
        inventory=_inventory(),
        storages=(heidel, unknown_empty),
        storage_snapshot_records=1,
        hydration_generations_seen=1,
        warnings=("capture may be partial",),
        capture_mode="pcap_replay",
        input_path="capture.pcapng",
    )

    assert isinstance(state.storages, StorageContents)
    assert isinstance(state.storages, tuple)
    assert state.storage(0x0020) is state.storages.by_id(0x0020)
    assert state.storage_named("heidel") is state.storages.named("Heidel")

    coverage = state.coverage
    assert coverage.completion_status == "unknown"
    assert coverage.completion_basis == "no_proven_protocol_end_marker"
    assert coverage.capture_may_be_partial
    assert coverage.inventory_records_decoded == 1
    assert coverage.inventory_unique_records == 1
    assert coverage.inventory_groups_observed == 1
    assert coverage.inventory_unclassified_records == 1
    assert coverage.storage_records_decoded == 1
    assert coverage.storage_locations_observed == 2
    assert coverage.registered_storage_locations_observed == 1
    assert coverage.registered_storage_locations_total > 1
    assert 0x0005 in coverage.registered_storage_ids_not_observed
    assert coverage.unregistered_storage_ids_observed == (0xDEAD,)
    assert coverage.explicitly_empty_storage_locations_observed == 1
    assert coverage.identity_complete
    assert coverage.identity_status == "complete"
    assert coverage.inventory_records_missing_instance == 0
    assert coverage.storage_records_missing_instance == 0
    assert coverage.accumulation_status == "not_reported"

    provenance = state.provenance
    assert provenance.capture_mode == "pcap_replay"
    assert provenance.profile_source == "opcodes.local"
    assert provenance.input_path == "capture.pcapng"
    assert provenance.saved_capture_path is None
    assert provenance.generation_selection == "latest_observed_inventory_hydration"
    assert provenance.load_reason is None
    assert provenance.load_reason_basis == "not_decoded_from_protocol"
    assert provenance.instance_identity_policy == "observed_instance_only"
    assert provenance.identity_status == "complete"
    assert provenance.accumulation_policy == "not_reported"

    payload = state.to_dict()
    assert payload["schema_version"] == 4
    assert payload["decoder_health"]["storage_status"] == "not_observed"
    assert payload["coverage"] == coverage.to_dict()
    assert payload["provenance"] == provenance.to_dict()
    assert payload["storage"]["destinations"][0]["storage_id"] == 0x0020
    generic_payload = asdict(state)
    assert isinstance(generic_payload["storages"], tuple)
    assert generic_payload["storages"][0]["storage_id"] == 0x0020


def test_decoder_health_is_a_first_class_snapshot_dataclass_field():
    common = {
        "profile_source": "opcodes.local",
        "frames_seen": 1,
        "inventory": _inventory(),
        "storages": (),
        "storage_snapshot_records": 0,
        "hydration_generations_seen": 1,
        "warnings": (),
    }
    compatible = CharacterStateSnapshot(
        **common,
        decoder_health=DecoderHealth(storage_status="compatible"),
    )
    incompatible = CharacterStateSnapshot(
        **common,
        decoder_health=DecoderHealth(storage_status="incompatible"),
    )

    assert "decoder_health" in {field.name for field in fields(compatible)}
    assert asdict(compatible)["decoder_health"]["storage_status"] == "compatible"
    assert "decoder_health=DecoderHealth" in repr(compatible)
    assert compatible != incompatible


def test_storage_only_provenance_discloses_missing_generation_boundary():
    state = CharacterStateSnapshot(
        profile_source="opcodes.local",
        frames_seen=3,
        inventory=InventorySnapshotSummary(
            items=(),
            raw_records=0,
            duplicate_records=0,
            group_counts=(),
            inferred_strides=(),
            currency_balances=(),
            containers=(),
            unclassified_records=0,
        ),
        storages=(_storage(0x0020, "Heidel", _item(7003, 5, "stack")),),
        storage_snapshot_records=1,
        hydration_generations_seen=0,
        warnings=(),
    )

    assert (
        state.provenance.generation_selection
        == "all_observed_storage_no_inventory_boundary"
    )


def test_item_state_facade_is_additive_and_not_package_root_exported():
    assert ItemStateSnapshot is CharacterStateSnapshot
    assert analyze_item_state_pcap is analyze_character_load_pcap
    assert format_item_state is format_character_state
    assert CharacterLoadSession.__module__ == "bdo_toolkit.character_state"
    assert ItemStateCaptureLimits.__module__ == "bdo_toolkit.character_state"
    assert issubclass(ItemStateCaptureLimitError, RuntimeError)
    assert "ItemStateSnapshot" not in package_exports
    assert "analyze_item_state_pcap" not in package_exports

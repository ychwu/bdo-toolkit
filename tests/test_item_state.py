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
    ItemStateCoverage,
    ItemStateDiagnostics,
    ItemStateProvenance,
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
    assert contents.registered_count == 2
    assert contents.selected_count == 2
    assert contents.nonempty_count == 2
    assert contents.empty_count == 0
    assert contents.occupied_stacks == 3
    assert contents.to_dict()["occupied_stacks"] == 3


def test_item_state_serialization_is_compact_and_diagnostics_are_opt_in():
    heidel = _storage(0x0020, "Heidel", _item(7003, 5, "heidel-potato"))
    unknown_empty = _storage(
        0xDEAD,
        None,
        empty_envelope_seen=True,
    )
    state = CharacterStateSnapshot(
        inventory=_inventory(),
        storages=(heidel, unknown_empty),
        provenance=ItemStateProvenance(
            capture_mode="pcap_replay",
            profile_source="opcodes.local",
            generation_selection="latest_observed_inventory_hydration",
            capture_path="capture.pcapng",
        ),
        coverage=ItemStateCoverage(
            inventory_records_missing_instance=0,
            storage_records_missing_instance=0,
            selected_storage_records_missing_instance=0,
            registered_storage_ids_not_observed=(0x0005,),
            unregistered_storage_ids_observed=(0xDEAD,),
            storage_locations_not_selected=0,
            storage_locations_with_incomplete_current_identity=0,
        ),
        warnings=("capture may be partial",),
        diagnostics=ItemStateDiagnostics(
            frames_seen=12,
            storage_records_decoded=1,
            inventory_generations_observed=1,
            storage_sweeps_observed=1,
            selected_storage_sweep=1,
            relevant_frames_retained=2,
            relevant_bytes_retained=512,
            snapshot_records_retained=2,
            capture_limits=ItemStateCaptureLimits(),
        ),
    )

    assert isinstance(state.storages, StorageContents)
    assert isinstance(state.storages, tuple)
    assert state.storages.by_id(0x0020) is heidel
    assert state.storages.named("heidel") is heidel
    assert state.storages.registered_count == 1
    assert state.storages.empty_count == 1

    coverage = state.coverage
    assert 0x0005 in coverage.registered_storage_ids_not_observed
    assert coverage.unregistered_storage_ids_observed == (0xDEAD,)
    assert coverage.inventory_records_missing_instance == 0
    assert coverage.storage_records_missing_instance == 0
    assert coverage.storage_locations_not_selected == 0
    assert state.identity_complete
    assert state.hydration_detected

    provenance = state.provenance
    assert provenance.capture_mode == "pcap_replay"
    assert provenance.profile_source == "opcodes.local"
    assert provenance.capture_path == "capture.pcapng"
    assert provenance.generation_selection == "latest_observed_inventory_hydration"

    payload = state.to_dict()
    assert payload["schema_version"] == 5
    assert payload["decoder_health"]["storage_status"] == "not_observed"
    assert payload["coverage"] == coverage.to_dict()
    assert payload["provenance"] == provenance.to_dict()
    assert payload["storages"]["destinations"][0]["storage_id"] == 0x0020
    assert "diagnostics" not in payload
    diagnostic_payload = state.to_dict(include_diagnostics=True)
    assert diagnostic_payload["diagnostics"] == state.diagnostics.to_dict()
    assert diagnostic_payload["provenance"]["capture_path"] == "capture.pcapng"
    assert "capture_path" not in payload["provenance"]
    assert "profile_source" not in payload
    assert "accumulation" not in payload
    assert "load_reason" not in payload
    generic_payload = asdict(state)
    assert isinstance(generic_payload["storages"], tuple)
    assert generic_payload["storages"][0]["storage_id"] == 0x0020


def test_decoder_health_is_a_first_class_snapshot_dataclass_field():
    common = {
        "inventory": _inventory(),
        "storages": (),
        "provenance": ItemStateProvenance(
            capture_mode="pcap_replay",
            profile_source="opcodes.local",
            generation_selection="latest_observed_inventory_hydration",
        ),
        "coverage": ItemStateCoverage(
            inventory_records_missing_instance=0,
            storage_records_missing_instance=0,
            selected_storage_records_missing_instance=0,
            registered_storage_ids_not_observed=(),
            unregistered_storage_ids_observed=(),
            storage_locations_not_selected=0,
            storage_locations_with_incomplete_current_identity=0,
        ),
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
    assert {field.name for field in fields(compatible)} == {
        "inventory",
        "storages",
        "provenance",
        "coverage",
        "decoder_health",
        "warnings",
        "diagnostics",
    }


def test_storage_only_provenance_discloses_missing_generation_boundary():
    state = CharacterStateSnapshot(
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
        provenance=ItemStateProvenance(
            capture_mode="unknown",
            profile_source="opcodes.local",
            generation_selection="all_observed_storage_no_inventory_boundary",
        ),
        coverage=ItemStateCoverage(
            inventory_records_missing_instance=0,
            storage_records_missing_instance=0,
            selected_storage_records_missing_instance=0,
            registered_storage_ids_not_observed=(),
            unregistered_storage_ids_observed=(),
            storage_locations_not_selected=0,
            storage_locations_with_incomplete_current_identity=0,
        ),
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
    assert ItemStateDiagnostics.__module__ == "bdo_toolkit.character_state"
    assert issubclass(ItemStateCaptureLimitError, RuntimeError)
    assert "ItemStateSnapshot" not in package_exports
    assert "analyze_item_state_pcap" not in package_exports

from __future__ import annotations

import json
import pickle
from typing import get_type_hints

from bdo_toolkit import character_state

from bdo_toolkit.character_state import (
    CharacterStateSnapshot,
    InventorySnapshotSummary,
    SnapshotItem,
    StorageContents,
    StorageSnapshotSummary,
    analyze_character_load_pcap,
    format_character_state,
)
from bdo_toolkit.item_state import (
    InventoryHydrationDiagnostics,
    ItemStateCaptureLimitError,
    ItemStateCaptureLimits,
    ItemStateCoverage,
    ItemStateDiagnostics,
    ItemStateProvenance,
    ItemStateSnapshot,
    StorageDestinationDiagnostics,
    StorageHydrationDiagnostics,
    analyze_item_state_pcap,
    format_item_state,
)


def _item(item_id: int, quantity: int, instance: str) -> SnapshotItem:
    return SnapshotItem(
        item_id=item_id,
        quantity=quantity,
        instance=instance,
        observed_at=1.0,
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
        current_state_observed=True,
        current_empty=empty_envelope_seen,
        current_identity_complete=True,
    )


def _inventory() -> InventorySnapshotSummary:
    return InventorySnapshotSummary(
        hydration_observed=True,
        items=(_item(5000, 2, "inventory-1"),),
        currency_balances=(),
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

    assert isinstance(contents, tuple)
    assert tuple(contents) == (heidel, velia)

    assert contents.by_id(0x0020) is heidel
    assert contents.by_id(0xFFFF) is None
    assert contents.named("hEiDeL") is heidel
    assert [item.quantity for item in contents.find_item(7003)] == [5, 7]
    assert contents.total_quantity(7003) == 12
    assert contents.locations_for(7003) == (heidel, velia)
    assert contents.locations_for(7004) == (heidel,)
    assert (
        contents.registered_count,
        contents.selected_count,
        contents.nonempty_count,
        contents.empty_count,
        contents.occupied_stacks,
    ) == (2, 2, 2, 0, 3)
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
            relevant_frames_retained=2,
            relevant_bytes_retained=512,
            snapshot_records_retained=2,
            capture_limits=ItemStateCaptureLimits(),
            inventory=InventoryHydrationDiagnostics(
                raw_records=1,
                duplicate_records=0,
                group_counts=(1,),
                inferred_strides=(),
                generations_observed=1,
                source_opcodes=(0x194A,),
                message_lengths=(254,),
            ),
            storage=StorageHydrationDiagnostics(
                records_decoded=1,
                records_without_destination=0,
                sweeps_observed=1,
                selected_sweep=1,
                destinations=(
                    StorageDestinationDiagnostics(
                        storage_id=0x0020,
                        raw_records=1,
                        duplicate_records=0,
                        groups=1,
                        empty_envelope_seen=False,
                        selected_records=1,
                        selected_groups=1,
                        sweeps_observed=1,
                        selected_sweep=1,
                        missing_instance_records=0,
                        selected_missing_instance_records=0,
                        source_opcodes=(0x126D,),
                        message_lengths=(257,),
                    ),
                    StorageDestinationDiagnostics(
                        storage_id=0xDEAD,
                        raw_records=0,
                        duplicate_records=0,
                        groups=1,
                        empty_envelope_seen=True,
                        selected_records=0,
                        selected_groups=1,
                        sweeps_observed=1,
                        selected_sweep=1,
                        missing_instance_records=0,
                        selected_missing_instance_records=0,
                        source_opcodes=(0x126D,),
                        message_lengths=(34,),
                    ),
                ),
            ),
        ),
    )

    coverage = state.coverage
    assert state.identity_complete
    assert state.hydration_detected
    provenance = state.provenance

    payload = state.to_dict()
    destination = payload["storages"]["destinations"][0]
    assert payload["schema_version"] == 5
    assert payload["decoder_health"]["storage_status"] == "not_observed"
    assert payload["coverage"] == coverage.to_dict()
    assert payload["provenance"] == provenance.to_dict()
    assert payload["inventory"]["hydration_observed"] is True
    assert destination["storage_id"] == 0x0020
    assert destination["name"] == "Heidel"
    serialized_item = destination["items"][0]
    assert serialized_item["item_id"] == 7003
    assert serialized_item["quantity"] == 5
    assert serialized_item["instance"] == "heidel-potato"
    assert serialized_item["observed_at"] == 1.0
    json_payload = json.dumps(payload)
    assert json_payload.count("heidel-potato") == 1
    assert json_payload.count("inventory-1") == 1

    diagnostic_payload = state.to_dict(include_diagnostics=True)
    assert diagnostic_payload["diagnostics"] == state.diagnostics.to_dict()
    assert diagnostic_payload["diagnostics"]["frames_seen"] == 12
    assert diagnostic_payload["diagnostics"]["storage"]["records_decoded"] == 1
    assert state.diagnostics.storage.destination(0x0020) is not None
    assert diagnostic_payload["provenance"]["capture_path"] == "capture.pcapng"


def test_storage_only_provenance_discloses_missing_generation_boundary():
    state = CharacterStateSnapshot(
        inventory=InventorySnapshotSummary(
            hydration_observed=False,
            items=(),
            currency_balances=(),
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
    output = format_item_state(state)
    assert "Generic BDO frames observed: unavailable" in output
    assert "Heidel: 1 occupied item stacks detected" in output


def test_item_state_facade_exposes_canonical_aliases():
    assert ItemStateSnapshot is CharacterStateSnapshot
    assert analyze_item_state_pcap is analyze_character_load_pcap
    assert format_item_state is format_character_state
    assert issubclass(ItemStateCaptureLimitError, RuntimeError)


def test_item_state_public_objects_keep_import_and_pickle_locations():
    for name in character_state.__all__:
        public_object = getattr(character_state, name)
        assert public_object.__module__ == "bdo_toolkit.character_state"
        assert pickle.loads(pickle.dumps(public_object)) is public_object
        # Postponed annotations on moved public classes must still resolve
        # through their preserved module identity.
        get_type_hints(public_object)
    item = _item(7003, 5, "synthetic-instance")
    assert pickle.loads(pickle.dumps(item)) == item

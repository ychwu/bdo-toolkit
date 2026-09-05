"""Console rendering for item-state snapshots."""

from __future__ import annotations

from .._protocol import STORAGE_LOCATIONS

from .models import CharacterStateSnapshot


def format_character_state(
    snapshot: CharacterStateSnapshot,
    *,
    show_items: bool = False,
) -> str:
    """Render a stable, honest diagnostic summary for console tools."""
    diagnostics = snapshot.diagnostics
    frames_seen = diagnostics.frames_seen if diagnostics is not None else "unavailable"
    lines = [
        "CHARACTER LOAD SNAPSHOT DIAGNOSTIC",
        f"Profile: {snapshot.provenance.profile_source}",
        f"Generic BDO frames observed: {frames_seen}",
        (
            "Storage decoder: "
            f"{snapshot.decoder_health.storage_status} "
            f"({snapshot.decoder_health.storage_messages_decoded}/"
            f"{snapshot.decoder_health.storage_messages_observed} "
            "observed wrappers decoded)"
        ),
        (
            "Hydration packets detected; trigger is unclassified "
            "(initial login vs character switch)."
            if snapshot.hydration_detected
            else "No hydration packets were detected."
        ),
        "",
        "INVENTORY SNAPSHOT",
    ]
    inventory = snapshot.inventory
    inventory_diagnostics = diagnostics.inventory if diagnostics is not None else None
    if inventory.hydration_observed:
        lines.append(
            f"  {inventory.serialized_records} serialized records: "
            f"{inventory.occupied_stacks} occupied item stacks + "
            f"{inventory.currency_balance_records} currency balances"
        )
        if inventory_diagnostics is not None:
            lines.extend(
                [
                    (
                        f"  {inventory_diagnostics.groups} groups: "
                        f"{inventory_diagnostics.populated_groups} populated, "
                        f"{inventory_diagnostics.empty_groups} empty"
                    ),
                    "  group record counts: "
                    + ", ".join(
                        str(count) for count in inventory_diagnostics.group_counts
                    ),
                    "  inferred record strides: "
                    + (
                        ", ".join(
                            str(stride)
                            for stride in inventory_diagnostics.inferred_strides
                        )
                        if inventory_diagnostics.inferred_strides
                        else "unavailable"
                    ),
                ]
            )
        if inventory.containers:
            lines.append("  provisional containers (raw code is authoritative):")
            for container in inventory.containers:
                lines.append(
                    f"    {container.name} [0x{container.raw_code:02X}, "
                    f"{container.confidence}]: {container.occupied_stacks} item stacks, "
                    f"{len(container.currency_balances)} currency balances"
                )
        else:
            lines.append("  container/tab labels: unclassified")
        if inventory_diagnostics is not None and inventory_diagnostics.empty_groups:
            lines.append(
                f"  {inventory_diagnostics.empty_groups} empty wrappers: unclassified "
                "(no record-level container field)"
            )
        if inventory.unclassified_records:
            lines.append(
                f"  records without a validated container: "
                f"{inventory.unclassified_records}"
            )
        if inventory.currency_balances:
            lines.append("  currency balances:")
            for balance in sorted(
                inventory.currency_balances,
                key=lambda item: item.item_id,
            ):
                lines.append(
                    f"    {balance.currency_name}: {balance.quantity:,} "
                    f"(item_id={balance.item_id}, "
                    f"container={balance.container_name}, "
                    f"slot={balance.inventory_slot})"
                )
        if (
            inventory_diagnostics is not None
            and inventory_diagnostics.duplicate_records
        ):
            lines.append(
                "  repeated records merged by item instance: "
                f"{inventory_diagnostics.duplicate_records}"
            )
        if snapshot.coverage.inventory_records_missing_instance:
            lines.append(
                f"  identity-unresolved records excluded: "
                f"{snapshot.coverage.inventory_records_missing_instance}"
            )
        if show_items:
            for item in inventory.items:
                lines.append(
                    f"    item_id={item.item_id} quantity={item.quantity} "
                    f"instance={item.instance} container={item.container_name or 'unknown'} "
                    f"container_code="
                    f"{f'0x{item.container_code:02X}' if item.container_code is not None else 'unknown'} "
                    f"slot={item.inventory_slot}"
                )
    else:
        lines.append("  NOT DETECTED")

    lines.extend(["", "STORAGE SNAPSHOT"])
    storage_records_decoded = (
        diagnostics.storage.records_decoded
        if diagnostics is not None
        else None
    )
    if storage_records_decoded or snapshot.storages:
        missing_known_ids = snapshot.coverage.registered_storage_ids_not_observed
        earlier_only = tuple(
            storage
            for storage in snapshot.storages
            if not storage.current_state_observed
        )
        identity_incomplete = tuple(
            storage
            for storage in snapshot.storages
            if storage.current_state_observed
            and storage.current_identity_complete is False
        )
        if earlier_only or identity_incomplete:
            current_state_parts = [
                f"  {snapshot.storages.nonempty_count} non-empty",
                f"{snapshot.storages.empty_count} explicitly empty",
            ]
            if identity_incomplete:
                current_state_parts.append(
                    f"{len(identity_incomplete)} identity-incomplete"
                )
            if earlier_only:
                current_state_parts.append(
                    f"{len(earlier_only)} earlier-only (current state unavailable)"
                )
            current_state_parts.append(f"{len(missing_known_ids)} not observed")
            current_state_line = ", ".join(current_state_parts)
        else:
            current_state_line = (
                f"  {snapshot.storages.nonempty_count} non-empty, "
                f"{snapshot.storages.empty_count} explicitly empty, "
                f"{len(missing_known_ids)} not observed"
            )
        storage_item_line = (
            f"  {snapshot.storages.occupied_stacks} unique occupied item stacks"
        )
        if storage_records_decoded is not None:
            storage_item_line += (
                f" from {storage_records_decoded} decoded snapshot records"
            )
        lines.extend(
            [
                (
                    f"  {snapshot.storages.registered_count}/"
                    f"{len(STORAGE_LOCATIONS)} known destinations observed"
                ),
                current_state_line,
                storage_item_line,
                "  capacity: unavailable (not present in the decoded item wrappers)",
                "",
            ]
        )
        if diagnostics is not None and diagnostics.storage.sweeps_observed:
            lines.insert(
                len(lines) - 1,
                f"  selected inferred storage sweep "
                f"{diagnostics.storage.selected_sweep}/"
                f"{diagnostics.storage.sweeps_observed}",
            )
        if snapshot.coverage.storage_records_missing_instance:
            lines.insert(
                len(lines) - 1,
                f"  identity-unresolved records excluded: "
                f"{snapshot.coverage.storage_records_missing_instance}",
            )
        if missing_known_ids:
            missing_names = sorted(
                STORAGE_LOCATIONS[storage_id].name for storage_id in missing_known_ids
            )
            lines.append(
                "  known destinations not observed: " + ", ".join(missing_names)
            )
            lines.append("")
        for storage in snapshot.storages:
            label = storage.name or f"UNKNOWN_STORAGE(0x{storage.storage_id:08x})"
            if not storage.current_state_observed:
                lines.append(
                    f"  {label}: current state unavailable "
                    f"(observed only in an earlier inferred sweep)"
                )
                continue
            lines.append(
                f"  {label}: {storage.occupied_stacks} occupied item stacks detected"
            )
            storage_diagnostics = (
                diagnostics.storage.destination(storage.storage_id)
                if diagnostics is not None
                else None
            )
            if (
                storage_diagnostics is not None
                and storage_diagnostics.selected_missing_instance_records
            ):
                lines.append(
                    f"    identity-unresolved current records excluded: "
                    f"{storage_diagnostics.selected_missing_instance_records}"
                )
            if show_items:
                for item in storage.items:
                    lines.append(
                        f"    item_id={item.item_id} quantity={item.quantity} "
                        f"instance={item.instance}"
                    )
    else:
        lines.append("  NOT DETECTED")

    lines.extend(["", "LIMITATIONS"])
    lines.extend(f"  - {warning}" for warning in snapshot.warnings)
    return "\n".join(lines)

# Character-load snapshot diagnostic

This experimental tool passively summarizes the inventory and storage state
sent by the server during initial login or a character switch.

For the smallest live example built only from the public item-state API, run:

```powershell
py examples/live_character_load_snapshot.py
```

It loads the repository `opcodes.local`, starts capture, waits for initial login
or a character switch to finish, and prints the same default human report via
`format_item_state()`. Use the tool below when replay, raw-PCAP saving, JSON,
timed capture, adapter controls, or complete per-item output are needed.

Run it from the repository root, switch characters, wait until loading has
finished, and press Enter:

```powershell
py tools/character_load/inspect_character_load.py
```

Save the packets admitted by the live diagnostic's capture filter while also
parsing them:

```powershell
py tools/character_load/inspect_character_load.py --save-pcap tests\fixtures\inventory_snapshot\character_switch\character-switch.pcapng
```

Both `.pcap` and `.pcapng` are supported. Saving is opt-in, packets are written
before decoding, and the writer is closed when capture stops or fails. The file
contains the untouched Scapy packets delivered to the diagnostic after its BPF
or Python capture filter; it is not a synthetic export of decoded events. Any
missing parent directories are created. An existing capture is never
overwritten; choose a new filename for each run. The example uses the
git-ignored fixture tree so a sensitive raw capture is less likely to be
committed accidentally.

> **Privacy:** Filtered raw BDO packets can still expose IP addresses, session
> data, account-related data, and complete inventory/storage contents. Treat
> captures as sensitive and inspect or redact them before sharing. Do not
> publish them blindly.

Replay a saved capture without opening a live capture adapter:

```powershell
py tools/character_load/inspect_character_load.py --pcap path\to\capture.pcapng
```

Add `--show-items` for every decoded item record or `--json` for a structured
report. Use `--help` for interface, port, timed-capture, and filter options.
`--save-pcap` is live-only and cannot be combined with the replay-only
`--pcap` option. The JSON report is the aggregate model's `to_dict()` output:
top-level `schema_version` is currently `4`. `coverage`, `provenance`, and
`decoder_health` separately make observation limits, capture source, and final
storage-schema compatibility machine-readable.

## What the report means

- Inventory output distinguishes serialized records from ordinary occupied
  item stacks and the four known currency-wallet balances. Storage counts are
  occupied item stacks. Both are deduplicated by opaque instance identifiers.
- Large storages can span several protocol wrappers; the tool merges those
  chunks instead of treating each wrapper as a complete storage.
- Repeated hydration sweeps are ordered conservatively and the latest inferred
  sweep is selected as current state. Older observations remain diagnostic but
  do not inflate current item totals.
- If one capture contains more than one inventory hydration generation, only
  the latest character load is reported; older inventory and storage state is
  discarded.
- Empty storage envelopes are reported only when calibrated count/destination
  fields, sibling prefix/stride geometry, a nonzero numeric destination, and
  the hydration window all validate. An unregistered numeric ID is preserved
  without inventing a town name and makes decoder health incompatible.
- The profile supplies the patch-specific opcodes, calibrated item offsets,
  instance offsets, single-record lengths, storage destination
  `context_offset`, and storage `record_count_offset`. Multi-record stride is
  derived from each wrapper's declared count and validated record geometry.

## After a game patch

Run the normal guided transfer calibration first. For storage authority, use a
controlled unstackable sequence containing at least two distinct validated
record counts: one single plus one multi, or two different multi counts. Pass
the quantity in each record (normally `1`), not the batch size. Calibration
relearns the shared `INVENTORY_TRANSFER` and `STORAGE_ITEM_DELTA` families,
their patch-specific opcodes, first-item positions, normalized base lengths,
storage destination `context_offset`, and declared `record_count_offset`.

The recommended one-session sequence is three actions with five matching
unstackables: deposit one, deposit the remaining four, then withdraw all five.
Pass `quantity=1` throughout. Counts `1` and `4` provide the required distinct
storage evidence; the final withdrawal provides the reverse transfer family.

If a storage wrapper is observed but either destination or count column remains
ambiguous—including a run with only one validated record count—calibration
raises `bdo_toolkit.calibration.CalibrationAuthorityError`, returns no result,
and writes no profile. An older profile missing either new storage field is
reported incompatible and needs this one migration calibration; no July/August
mode/token/layout branch is merged behind it.

Inventory hydration should resume from that profile when the patch retains the
shared transfer record and all-zero character-load context: its count is
searched in the prefix, stride is derived per frame, and container metadata is
learned from either a validated record tail or a common wrapper-header byte.

Storage hydration uses the calibrated destination and declared-count fields;
runtime derives stride and validates every record without a patch-generation
layout table. Every decoded storage record begins neutral. Manual/worker origin
evidence gets first claim, a bounded multi-destination cohort can then prove
hydration, and filtering happens last. The finite character-state assembler can
also use its stronger inventory-load boundary to validate sparse/count-zero
state while the continuous activity stream remains fail-neutral. If one
otherwise coherent hydration sweep is split by the live tracker's timing
window, finite assembly can reconcile the pieces only within the same flow
generation, opcode, inferred sweep, and inventory-anchored epoch; a proven live
storage mutation prevents reconciliation across it.

Offline analysis loads one immutable profile revision for both decoding and
aggregation. `CharacterLoadSession` pins the same combined profile/spec
authority when constructed, so replacing the file before `start()` cannot mix
revisions. Construct a new session after recalibration to use the new file.

This survives ordinary opcode, absolute-offset, base-length, and stride rotation
after fresh calibration. It still fails closed if the shared item record,
quantity/instance relationships (`item+4` / `item+35`), count encoding,
destination-ID meaning, or origin/hydration relationships themselves change.
In every case, replay the new capture and require
`state.decoder_health.storage_status == "compatible"` before treating missing
towns as meaningful.

## Deliberate limitations

- Storage capacity is not decoded. `Heidel: 184 occupied item stacks` does not
  imply a maximum capacity of 184, and the tool will not invent a `/192` value.
- Storage output distinguishes explicit empty envelopes from known destinations
  that were not transmitted. A missing destination is not silently called empty.
- Inventory container fields are discovered from validated multi-record
  geometry rather than frozen at one patch's offsets. July layouts expose a
  record-tail slot/container pair; the August 7 layout exposes a wrapper-level
  container byte and no validated per-record slot, so `inventory_slot` is
  `None` there.
  Raw codes `0x00`, `0x10`, `0x18`, and `0x0B` have provisional Main, Pearl,
  Global Currencies, and Enhancement labels respectively. These labels agree
  across the July 17 captures and the August 7 character-switch pcap but remain
  experimental; use the numeric code as identity. Count-zero groups remain
  unclassified. If a future patch introduces an unknown container code, the
  current layout check leaves all records
  for that opcode unclassified instead of guessing an offset or silently
  assigning the new code to an existing label; decoded items are still kept.
- The hydration packets do not currently distinguish initial login from a
  character switch. The operator knows which action was performed; the API
  leaves `load_reason` unset.
- The assembled state model is experimental. Per-item `inventory_snapshot` and
  `storage_snapshot` events are the lower-level toolkit evidence.
- Registered-storage coverage is not a protocol completion signal. Even if the
  report observed every registered storage ID, there is no proven end marker;
  `coverage.completion_status` remains `"unknown"` and
  `coverage.capture_may_be_partial` remains true.
- Decoder compatibility is a different signal. `"not_observed"` is
  inconclusive; `"incompatible"` means calibrated authority failed or a numeric
  destination is missing from the name registry. The latter ID and its items
  are preserved with `name=None`, and the report includes a registry warning.

Developers should use the canonical experimental `bdo_toolkit.item_state`
facade:

```python
from bdo_toolkit.item_state import (
    CharacterLoadSession,
    analyze_item_state_pcap,
)

state = analyze_item_state_pcap(
    "capture.pcapng",
    opcode_profile="opcodes.local",
)

heidel = state.storages.named("Heidel")
same_storage = state.storages.by_id(0x0020)
if heidel is not None:
    print(heidel.occupied_stacks)
    print(heidel.quantity_for(7003))

print(len(state.storages))
print(state.storages[0] if state.storages else None)
print(state.storages.find_item(7003))
print(state.storages.total_quantity(7003))
print(state.storages.locations_for(7003))

print(state.inventory.records_for(1000306))

main = state.inventory.container(0x00)
pearl = state.inventory.container_named("Pearl Inventory")
silver = state.inventory.currency("Silver")
if silver is not None:
    print(silver.quantity, silver.inventory_slot, silver.container_code)

payload = state.to_dict()
print(payload["schema_version"])        # 4
print(payload["decoder_health"]["storage_status"])
print(state.decoder_health.storage_status)
print(state.coverage.completion_status)  # "unknown"
print(state.coverage.capture_may_be_partial)  # True
print(state.provenance.capture_mode)     # "pcap_replay"
```

`state.storages` remains an immutable tuple: it supports tuple type checks and
operators, iteration, integer indexing, and slicing in addition to the storage
and cross-storage item queries shown above. The older `state.storage(id)` and
`state.storage_named(name)` helpers remain available.

`state.coverage` reports decoded inventory/storage counts, registered IDs seen
or not seen, unregistered IDs, and explicit empty envelopes without claiming a
complete capture. `state.provenance` records `capture_mode`, `profile_source`,
input or saved-capture path, the generation-selection rule, and
`load_reason=None` with a basis explaining that it is not decoded from the
protocol. When no inventory boundary decodes, provenance reports
`all_observed_storage_no_inventory_boundary` and the summary warns that retained
storage records may span multiple loads.

`state.decoder_health` is also available as `session.decoder_health` during a
live `CharacterLoadSession`. The stopped snapshot freezes its final value. A
validated sparse/count-zero cohort can upgrade aggregate health from
`not_observed` to `compatible`; an unregistered authoritative destination makes
it `incompatible` without discarding the numeric ID or item state. Schema 4
adds this health object at top level, so persisted schema-3-or-earlier consumers
must update their version gate.

For an embedded live workflow, use the imported
`CharacterLoadSession.start()` and `CharacterLoadSession.stop()`. Pass
`save_pcap="capture.pcapng"` to preserve the filtered live packets alongside the
returned state summary. Existing `bdo_toolkit.character_state` imports and the
older `CharacterStateSnapshot`, `analyze_character_load_pcap()`, and
`format_character_state()` names remain supported for compatibility. The
experimental aggregate is intentionally not exported from the package root.

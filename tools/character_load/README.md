# Character-load snapshot diagnostic

This experimental tool passively summarizes the inventory and storage state
sent by the server during initial login or a character switch.

For the smallest live example built only from the public item-state API, run:

```powershell
py examples/live_item_state_snapshot.py
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
top-level `schema_version` is currently `1`, and `coverage` plus `provenance`
make the observation limits and capture source machine-readable.

## What the report means

- Inventory output distinguishes serialized records from ordinary occupied
  item stacks and the four known currency-wallet balances. Storage counts are
  occupied item stacks. Both are deduplicated by opaque instance identifiers.
- Large storages can span several protocol wrappers; the tool merges those
  chunks instead of treating each wrapper as a complete storage.
- Repeated hydration sweeps are merged by instance, so two identical sweeps do
  not double the reported state.
- If one capture contains more than one inventory hydration generation, only
  the latest character load is reported; older inventory and storage state is
  discarded.
- Empty storage envelopes are reported when the current wrapper exposes a
  known numeric destination with zero records.
- The profile supplies the patch-specific opcodes, calibrated item offsets,
  instance offsets, and single-record lengths. Multi-record stride is derived
  from each wrapper's declared count and validated record geometry.

## After a game patch

Run the normal guided transfer calibration first. It relearns the two shared
record families (`INVENTORY_TRANSFER` and `STORAGE_ITEM_DELTA`) and their
patch-specific opcodes, first-item positions, and normalized base lengths.
There is currently no separate mandatory character-load calibration, but
ordinary calibration is not a generic schema learner: quantity and instance
still assume `item+4` / `item+35`, and receipt context discovery searches for
known values. Storage destination/mode/token positions remain decoder-owned;
the current decoder recognizes both the July 17 and August 7 layouts.

Inventory hydration should resume from that profile when the patch retains the
shared transfer record and all-zero character-load context: its count is
searched in the prefix, stride is derived per frame, and container metadata is
learned from either a validated record tail or a common wrapper-header byte.

Storage hydration has a narrower guarantee. Record count is searched in the
prefix and stride is derived structurally, but snapshot/live/empty and town
metadata use observed destination/mode/token wrapper layouts that ordinary
calibration does not discover or persist. The July 17 and August 7 layouts are
recognized. An opcode/base change should recover after calibration while the
shared record assumptions and one recognized wrapper layout survive; a new
wrapper-metadata layout requires a decoder update or a future snapshot-specific
detection/calibration enhancement. In every case, replay the new capture and
confirm the diagnostic summary before relying on it in an application.

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
print(payload["schema_version"])        # 1
print(state.coverage.completion_status)  # "unknown"
print(state.coverage.capture_may_be_partial)  # True
print(state.provenance.capture_mode)     # "pcap_replay"
```

`state.storages` remains an immutable tuple: it supports tuple type checks and
operators, iteration, integer indexing, and slicing in addition to the storage
and cross-storage item queries shown above. The older `state.storage(id)` and `state.storage_named(name)`
helpers remain available.

`state.coverage` reports decoded inventory/storage counts, registered IDs seen
or not seen, unregistered IDs, and explicit empty envelopes without claiming a
complete capture. `state.provenance` records `capture_mode`, `profile_source`,
input or saved-capture path, the generation-selection rule, and
`load_reason=None` with a basis explaining that it is not decoded from the
protocol. When no inventory boundary decodes, provenance reports
`all_observed_storage_no_inventory_boundary` and the summary warns that retained
storage records may span multiple loads.

For an embedded live workflow, use the imported
`CharacterLoadSession.start()` and `CharacterLoadSession.stop()`. Pass
`save_pcap="capture.pcapng"` to preserve the filtered live packets alongside the
returned state summary. Existing `bdo_toolkit.character_state` imports and the
older `CharacterStateSnapshot`, `analyze_character_load_pcap()`, and
`format_character_state()` names remain supported for compatibility. The
experimental aggregate is intentionally not exported from the package root.

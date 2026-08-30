"""Smoke the maintained examples and the two public event writers."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
from types import ModuleType

from bdo_toolkit import BDOEvent, Flow
from bdo_toolkit.writers import ConsoleEventWriter, JsonlEventWriter


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
GUARDED_EXAMPLES = frozenset(
    {
        "async_calibrate_profile.py",
        "async_live_capture.py",
        "live_calibrate_loot_preview.py",
        "live_calibrate_profile.py",
        "live_character_load_snapshot.py",
        "live_inventory_contents.py",
        "live_item_state_search.py",
        "live_mob_drops.py",
        "live_town_storage_contents.py",
        "live_transfer_log.py",
        "live_worker_productions.py",
    }
)


def _load_example(filename: str) -> ModuleType:
    path = EXAMPLES / filename
    spec = importlib.util.spec_from_file_location(f"example_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _storage_event(
    *, storage_id: int | None, storage_name: str | None
) -> BDOEvent:
    return BDOEvent(
        event_type="storage_delta",
        timestamp=1_700_000_000.0,
        flow=Flow("10.0.0.1", 8889, "10.0.0.2", 50_000),
        item_id=15156,
        quantity=1,
        source="Worker Production",
        storage_id=storage_id,
        storage_name=storage_name,
    )


def test_examples_compile_and_guarded_examples_import() -> None:
    paths = sorted(EXAMPLES.glob("*.py"))
    assert paths
    assert GUARDED_EXAMPLES <= {path.name for path in paths}

    for path in paths:
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
        if path.name in GUARDED_EXAMPLES:
            _load_example(path.name)


def test_transfer_examples_render_known_unknown_and_unavailable_destinations(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    known = _storage_event(storage_id=0x0020, storage_name="Heidel")
    unknown = _storage_event(storage_id=0x06C6, storage_name=None)
    unavailable = _storage_event(storage_id=None, storage_name=None)

    transfer_log = _load_example("live_transfer_log.py")
    for event in (known, unknown, unavailable):
        transfer_log.print_event(event)
    transfer_lines = capsys.readouterr().out.splitlines()
    assert "destination='Heidel'" in transfer_lines[0]
    assert "storage_id=0x00000020" in transfer_lines[0]
    assert "destination='0x000006c6'" in transfer_lines[1]
    assert "storage_id=0x000006c6" in transfer_lines[1]
    assert "destination=" not in transfer_lines[2]
    assert "storage_id=" not in transfer_lines[2]

    worker_log = _load_example("live_worker_productions.py")
    profile = tmp_path / "opcodes.local"
    profile.write_text("{}", encoding="utf-8")
    observed: dict[str, object] = {}

    def fake_capture_live(**kwargs):
        observed.update(kwargs)
        return iter((known, unknown, unavailable))

    monkeypatch.setattr(worker_log, "PROFILE", profile)
    monkeypatch.setattr(worker_log, "capture_live", fake_capture_live)
    worker_log.main()
    worker_output = capsys.readouterr().out
    assert "destination='Heidel' storage_id=0x00000020" in worker_output
    assert "destination='0x000006c6' storage_id=0x000006c6" in worker_output
    assert "destination='unknown' storage_id=unavailable" in worker_output
    assert observed["event_filter"] is worker_log.WORKER_PRODUCTIONS
    assert worker_log.WORKER_PRODUCTIONS.event_types == frozenset({"storage_delta"})
    assert worker_log.WORKER_PRODUCTIONS.sources == frozenset({"Worker Production"})


def test_console_and_jsonl_writers_emit_one_canonical_event() -> None:
    event = _storage_event(storage_id=0x0020, storage_name="Heidel")
    console = io.StringIO()
    jsonl = io.StringIO()

    ConsoleEventWriter(console).write(event)
    JsonlEventWriter(jsonl).write(event)

    assert "destination='Heidel'" in console.getvalue()
    assert "source='Worker Production'" in console.getvalue()
    payload = json.loads(jsonl.getvalue())
    assert payload["event_type"] == "storage_delta"
    assert payload["quantity"] == 1
    assert payload["source"] == "Worker Production"
    assert payload["storage_id"] == 0x0020
    assert payload["storage_name"] == "Heidel"

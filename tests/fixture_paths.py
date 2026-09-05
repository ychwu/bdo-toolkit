"""Explicit private capture catalog routes; no profile or filename guessing."""

from functools import lru_cache
import json
from pathlib import Path


TEST_DIR = Path(__file__).resolve().parent
ARCHIVE_DIR = TEST_DIR.parent / "private-captures"
CATALOG_PATH = ARCHIVE_DIR / "catalog.json"
HISTORICAL_PROFILE_DIR = TEST_DIR / "profiles"
# Synthetic tests use tracked profiles even when the private archive is absent.
JULY6_OPCODE_PROFILE = HISTORICAL_PROFILE_DIR / "opcodes-2026-07-06.json"
JULY17_OPCODE_PROFILE = HISTORICAL_PROFILE_DIR / "opcodes-2026-07-17.json"


class CaptureCatalog:
    """Resolve immutable capture IDs and recorded legacy aliases within one archive."""

    def __init__(self, path: Path):
        self.root = path.resolve().parent
        self.installed = path.is_file()
        data = json.loads(path.read_text(encoding="utf-8")) if self.installed else {
            "schema_version": 1, "profiles": {}, "captures": []
        }
        if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
            raise ValueError("unsupported private capture catalog schema")
        self.profiles = data["profiles"]
        self.entries = data["captures"]
        self._ids = {}
        self._paths = {}
        self._aliases = {}
        for entry in self.entries:
            capture_id = entry["id"]
            capture_path = self.path(entry["path"])
            if capture_id in self._ids or capture_path in self._paths:
                raise ValueError(f"duplicate capture ID or path: {capture_id}")
            self._ids[capture_id] = entry
            self._paths[capture_path] = entry
            for alias in set(entry.get("legacy_names", []) + entry.get("source_paths", [])):
                self._aliases.setdefault(alias, []).append(entry)
            profile_id = entry["profile_id"]
            if profile_id is not None and profile_id not in self.profiles:
                raise ValueError(f"unknown profile {profile_id!r} for {capture_id}")
            for attachment in [entry.get("baseline"), *entry.get("attachments", [])]:
                if attachment:
                    self.path(attachment["path"])
            if entry.get("observations_path"):
                self.path(entry["observations_path"])
        for profile in self.profiles.values():
            self.path(profile["path"])

    def path(self, relative: str) -> Path:
        candidate = Path(relative)
        resolved = (self.root / candidate).resolve()
        if candidate.is_absolute() or not resolved.is_relative_to(self.root):
            raise ValueError(f"catalog path escapes archive: {relative}")
        return resolved

    def entry(self, name: str) -> dict:
        if name in self._ids:
            return self._ids[name]
        matches = self._aliases.get(name, [])
        if len(matches) != 1:
            raise ValueError(f"unknown or ambiguous capture ID/alias: {name!r}")
        return matches[0]

    def capture_path(self, name: str, *, required: bool = True) -> Path:
        if not self.installed:
            if required:
                raise FileNotFoundError("private capture catalog is not installed")
            return self.root / "unavailable" / "capture.pcapng"
        path = self.path(self.entry(name)["path"])
        if required and not path.is_file():
            raise FileNotFoundError(f"private capture is not installed: {name}")
        return path

    def for_path(self, path: Path) -> dict:
        try:
            return self._paths[path.resolve()]
        except KeyError:
            raise ValueError(f"capture is not registered: {path}") from None

    def profile_path(self, entry: dict) -> Path:
        profile_id = entry["profile_id"]
        if profile_id is None:
            raise ValueError(f"capture {entry['id']} has no item profile ({entry['profile_status']})")
        path = self.path(self.profiles[profile_id]["path"])
        if not path.is_file():
            raise FileNotFoundError(f"recorded profile is missing: {profile_id}")
        return path


@lru_cache(maxsize=1)
def capture_catalog() -> CaptureCatalog:
    return CaptureCatalog(CATALOG_PATH)


def all_fixture_pcaps() -> list[Path]:
    catalog = capture_catalog()
    return sorted(catalog.path(e["path"]) for e in catalog.entries if e["generic_fixture"])


def all_baseline_jsonl() -> list[Path]:
    catalog = capture_catalog()
    return sorted(catalog.path(e["baseline"]["path"]) for e in catalog.entries if e["baseline"])


def has_fixture_pcaps() -> bool:
    return any(path.is_file() for path in all_fixture_pcaps())


def fixture_path(capture_id: str) -> Path:
    return capture_catalog().capture_path(capture_id)


def optional_fixture_path(capture_id: str) -> Path:
    """Keep private test cases collectible in a public clone without captures."""
    return capture_catalog().capture_path(capture_id, required=False)


def baseline_path_for_fixture(pcap: Path) -> Path:
    catalog = capture_catalog()
    baseline = catalog.for_path(pcap)["baseline"]
    if baseline is None:
        raise ValueError(f"capture has no recorded baseline: {pcap}")
    return catalog.path(baseline["path"])


def opcode_profile_for_fixture(pcap: Path) -> Path:
    catalog = capture_catalog()
    return catalog.profile_path(catalog.for_path(pcap))

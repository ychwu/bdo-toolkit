from pathlib import Path


TEST_DIR = Path(__file__).resolve().parent
FIXTURE_DIR = TEST_DIR / "fixtures"
BASELINE_DIR = TEST_DIR / "baselines"
HISTORICAL_PROFILE_DIR = TEST_DIR / "profiles"
JULY6_OPCODE_PROFILE = HISTORICAL_PROFILE_DIR / "opcodes-2026-07-06.json"
JULY17_OPCODE_PROFILE = HISTORICAL_PROFILE_DIR / "opcodes-2026-07-17.json"
GENERIC_FIXTURE_EXCLUDED_DIRECTORIES = frozenset({"combat"})


def all_fixture_pcaps() -> list[Path]:
    return sorted(
        path
        for path in FIXTURE_DIR.rglob("*.pcapng")
        if not (
            GENERIC_FIXTURE_EXCLUDED_DIRECTORIES
            & {part.casefold() for part in path.relative_to(FIXTURE_DIR).parts[:-1]}
        )
    )


def all_baseline_jsonl() -> list[Path]:
    return sorted(BASELINE_DIR.rglob("*.jsonl"))


def has_fixture_pcaps() -> bool:
    return FIXTURE_DIR.exists() and any(FIXTURE_DIR.rglob("*.pcapng"))


def fixture_path(name: str) -> Path:
    matches = sorted(FIXTURE_DIR.rglob(name))
    if not matches:
        raise FileNotFoundError(f"missing fixture {name!r} under {FIXTURE_DIR}")
    if len(matches) > 1:
        paths = ", ".join(str(path.relative_to(FIXTURE_DIR)) for path in matches)
        raise RuntimeError(f"fixture name {name!r} is ambiguous: {paths}")
    return matches[0]


def baseline_path_for_fixture(pcap: Path) -> Path:
    return (BASELINE_DIR / pcap.relative_to(FIXTURE_DIR)).with_suffix(".jsonl")


def opcode_profile_for_fixture(pcap: Path) -> Path:
    """Use a fixture-local patch profile when present, else the July baseline."""
    sidecar = pcap.with_suffix(".profile.json")
    return sidecar if sidecar.is_file() else JULY6_OPCODE_PROFILE

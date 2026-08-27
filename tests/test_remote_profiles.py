"""Remote opcode-profile retrieval is explicit, verified, and atomic."""

from __future__ import annotations

import hashlib
import json
from http.client import HTTPException, IncompleteRead, InvalidURL
from pathlib import Path
from typing import Any

import pytest

import bdo_toolkit
from bdo_toolkit import RemoteProfileError, fetch_opcode_profile
from bdo_toolkit import remote_profiles as remote_profiles_module
from fixture_paths import JULY17_OPCODE_PROFILE


class _Response:
    def __init__(
        self,
        payload: bytes,
        *,
        final_url: str = "https://profiles.example.test/v1/current.json",
        headers: dict[str, str] | None = None,
    ) -> None:
        self._payload = payload
        self._final_url = final_url
        self.headers = headers or {}

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        del args

    def geturl(self) -> str:
        return self._final_url

    def read(self, size: int = -1) -> bytes:
        return self._payload if size < 0 else self._payload[:size]


class _Opener:
    def __init__(self, response: _Response, observed: dict[str, Any]) -> None:
        self._response = response
        self._observed = observed

    def open(self, request: Any, *, timeout: float) -> _Response:
        self._observed["url"] = request.full_url
        self._observed["accept"] = request.get_header("Accept")
        self._observed["user_agent"] = request.get_header("User-agent")
        self._observed["timeout"] = timeout
        return self._response


class _FailingOpener:
    def __init__(self, failure: BaseException) -> None:
        self._failure = failure

    def open(self, request: Any, *, timeout: float) -> _Response:
        del request, timeout
        raise self._failure


def _profile_data() -> dict[str, Any]:
    return json.loads(JULY17_OPCODE_PROFILE.read_text(encoding="utf-8"))


def _canonical_profile(profile: dict[str, Any]) -> bytes:
    return json.dumps(
        profile,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _envelope(
    profile: dict[str, Any],
    *,
    revision: str = "naeu-2026-07-17-r1",
    digest: str | None = None,
) -> bytes:
    profile_digest = digest or hashlib.sha256(_canonical_profile(profile)).hexdigest()
    return json.dumps(
        {
            "schema_version": 1,
            "manifest": {
                "revision": revision,
                "profile_sha256": profile_digest,
            },
            "profile": profile,
        },
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _serve(
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
    *,
    final_url: str = "https://profiles.example.test/v1/current.json",
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    observed: dict[str, Any] = {}
    response = _Response(payload, final_url=final_url, headers=headers)
    monkeypatch.setattr(
        remote_profiles_module,
        "build_opener",
        lambda *_handlers: _Opener(response, observed),
    )
    return observed


def test_fetch_profile_verifies_and_installs_one_get_envelope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile_data()
    payload = _envelope(profile)
    observed = _serve(
        monkeypatch,
        payload,
        final_url="https://cdn.example.test/profiles/naeu-2026-07-17-r1.json",
        headers={"ETag": '"profile-r1"'},
    )
    destination = tmp_path / "managed" / "opcodes.json"

    result = fetch_opcode_profile(
        "https://profiles.example.test/v1/current.json",
        destination,
        timeout=2.5,
    )

    assert result.path == destination
    assert result.profile.path == destination
    assert result.profile.active
    assert result.source_url == (
        "https://cdn.example.test/profiles/naeu-2026-07-17-r1.json"
    )
    assert result.revision == "naeu-2026-07-17-r1"
    assert result.profile_sha256 == hashlib.sha256(
        _canonical_profile(profile)
    ).hexdigest()
    assert result.etag == '"profile-r1"'
    assert result.backup_path is None
    assert json.loads(destination.read_text(encoding="utf-8")) == profile
    assert observed == {
        "url": "https://profiles.example.test/v1/current.json",
        "accept": "application/json",
        "user_agent": "bdo-toolkit-profile-fetch/1",
        "timeout": 2.5,
    }
    assert bdo_toolkit.fetch_opcode_profile is fetch_opcode_profile


def test_fetch_profile_rejects_malformed_envelope_without_touching_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "opcodes.json"
    destination.write_bytes(b"existing-profile")
    _serve(monkeypatch, b"{not valid json")

    with pytest.raises(RemoteProfileError, match="valid UTF-8 JSON"):
        fetch_opcode_profile(
            "https://profiles.example.test/current.json", destination
        )

    assert destination.read_bytes() == b"existing-profile"


def test_fetch_profile_rejects_oversize_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _envelope(_profile_data())
    _serve(monkeypatch, payload)

    with pytest.raises(RemoteProfileError, match="exceeds"):
        fetch_opcode_profile(
            "https://profiles.example.test/current.json",
            tmp_path / "opcodes.json",
            max_bytes=len(payload) - 1,
        )


def test_fetch_profile_rejects_hash_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _serve(monkeypatch, _envelope(_profile_data(), digest="0" * 64))

    with pytest.raises(RemoteProfileError, match="hash mismatch"):
        fetch_opcode_profile(
            "https://profiles.example.test/current.json",
            tmp_path / "opcodes.json",
        )


def test_fetch_profile_rejects_inactive_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile_data()
    profile["profile_active"] = False
    _serve(monkeypatch, _envelope(profile))

    with pytest.raises(RemoteProfileError, match="inactive"):
        fetch_opcode_profile(
            "https://profiles.example.test/current.json",
            tmp_path / "opcodes.json",
        )


def test_fetch_profile_rejects_runtime_invalid_layout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile_data()
    profile["specs"]["INVENTORY_TRANSFER"][0].pop("item_id_offset")
    _serve(monkeypatch, _envelope(profile))

    with pytest.raises(RemoteProfileError, match="runtime validation"):
        fetch_opcode_profile(
            "https://profiles.example.test/current.json",
            tmp_path / "opcodes.json",
        )

    assert not list(tmp_path.glob(".opcodes.json.*.tmp"))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("quantity_removed_offset", 47),
        ("source_instance_offset", 40),
        ("repeat_stride", 60),
    ],
    ids=("quantity-outside-length", "instance-outside-length", "invalid-stride"),
)
def test_fetch_profile_rejects_malformed_runtime_decrement_geometry(
    field: str,
    value: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile_data()
    profile["specs"]["SOURCE_STACK_DECREMENT"][0][field] = value
    _serve(monkeypatch, _envelope(profile))
    destination = tmp_path / "opcodes.json"
    destination.write_bytes(b"existing-profile")

    with pytest.raises(
        RemoteProfileError,
        match=r"runtime validation.*SOURCE_STACK_DECREMENT",
    ):
        fetch_opcode_profile(
            "https://profiles.example.test/current.json",
            destination,
        )

    assert destination.read_bytes() == b"existing-profile"


@pytest.mark.parametrize(
    "version",
    [None, 2],
    ids=("missing", "unsupported"),
)
def test_fetch_profile_requires_exact_inner_profile_version(
    version: int | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile_data()
    if version is None:
        profile.pop("version")
    else:
        profile["version"] = version
    _serve(monkeypatch, _envelope(profile))

    with pytest.raises(RemoteProfileError, match=r"version.*must be 1"):
        fetch_opcode_profile(
            "https://profiles.example.test/current.json",
            tmp_path / "opcodes.json",
        )


@pytest.mark.parametrize(
    "revision",
    [
        "",
        "Uppercase",
        "-leading-hyphen",
        "contains space",
        "line\nbreak",
        "a" * 129,
        "non-ascii-\N{LATIN SMALL LETTER E WITH ACUTE}",
    ],
)
def test_fetch_profile_rejects_unsafe_revision_slugs(
    revision: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _serve(monkeypatch, _envelope(_profile_data(), revision=revision))

    with pytest.raises(RemoteProfileError, match="lowercase slug"):
        fetch_opcode_profile(
            "https://profiles.example.test/current.json",
            tmp_path / "opcodes.json",
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://profiles.example.test/current.json",
        "https://user:secret@profiles.example.test/current.json",
        "profiles.example.test/current.json",
    ],
)
def test_fetch_profile_requires_credential_free_https(url: str, tmp_path: Path) -> None:
    with pytest.raises(RemoteProfileError, match="HTTPS|credentials"):
        fetch_opcode_profile(url, tmp_path / "opcodes.json")


def test_fetch_profile_normalizes_url_parser_failures(tmp_path: Path) -> None:
    with pytest.raises(RemoteProfileError, match="invalid remote opcode profile URL"):
        fetch_opcode_profile("https://[invalid", tmp_path / "opcodes.json")


@pytest.mark.parametrize(
    "failure",
    [
        HTTPException("malformed response"),
        IncompleteRead(b"partial", 100),
        InvalidURL("invalid request target"),
    ],
    ids=("http-exception", "incomplete-read", "invalid-url"),
)
def test_fetch_profile_normalizes_http_protocol_failures(
    failure: BaseException,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        remote_profiles_module,
        "build_opener",
        lambda *_handlers: _FailingOpener(failure),
    )

    with pytest.raises(RemoteProfileError, match="could not fetch"):
        fetch_opcode_profile(
            "https://profiles.example.test/current.json",
            tmp_path / "opcodes.json",
        )


def test_fetch_profile_normalizes_recursive_json_decode_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _serve(monkeypatch, b"{}")

    def fail_loads(*_args: object, **_kwargs: object) -> object:
        raise RecursionError("nested JSON sentinel")

    monkeypatch.setattr(remote_profiles_module.json, "loads", fail_loads)

    with pytest.raises(RemoteProfileError, match="valid UTF-8 JSON"):
        fetch_opcode_profile(
            "https://profiles.example.test/current.json",
            tmp_path / "opcodes.json",
        )


@pytest.mark.parametrize(
    "renderer_name",
    ["_canonical_profile_bytes", "_render_profile"],
)
def test_profile_renderers_normalize_recursive_json_failure(
    renderer_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_dumps(*_args: object, **_kwargs: object) -> str:
        raise RecursionError("nested profile sentinel")

    monkeypatch.setattr(remote_profiles_module.json, "dumps", fail_dumps)

    with pytest.raises(RemoteProfileError, match="encoded"):
        getattr(remote_profiles_module, renderer_name)({"profile_active": True})


@pytest.mark.parametrize(
    "renderer_name",
    ["_canonical_profile_bytes", "_render_profile"],
)
def test_profile_renderers_normalize_unicode_encoding_failure(
    renderer_name: str,
) -> None:
    with pytest.raises(RemoteProfileError, match="encoded"):
        getattr(remote_profiles_module, renderer_name)({"invalid": "\ud800"})


@pytest.mark.parametrize(
    ("final_url", "message"),
    [
        ("http://profiles.example.test/current.json", "HTTPS"),
        (
            "https://user:secret@profiles.example.test/current.json",
            "credentials",
        ),
    ],
    ids=("downgrade", "credentials"),
)
def test_fetch_profile_rejects_unsafe_redirect_target(
    final_url: str,
    message: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _serve(
        monkeypatch,
        _envelope(_profile_data()),
        final_url=final_url,
    )

    with pytest.raises(RemoteProfileError, match=message):
        fetch_opcode_profile(
            "https://profiles.example.test/current.json",
            tmp_path / "opcodes.json",
        )


def test_atomic_install_failure_preserves_existing_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "opcodes.json"
    destination.write_bytes(b"existing-profile")
    _serve(monkeypatch, _envelope(_profile_data()))

    def fail_replace(_source: object, _destination: object) -> None:
        raise OSError("replace sentinel")

    monkeypatch.setattr(remote_profiles_module.os, "replace", fail_replace)

    with pytest.raises(OSError, match="replace sentinel"):
        fetch_opcode_profile(
            "https://profiles.example.test/current.json",
            destination,
            backup=False,
        )

    assert destination.read_bytes() == b"existing-profile"
    assert not list(tmp_path.glob(".opcodes.json.*.tmp"))


def test_fetch_profile_backs_up_existing_destination_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "opcodes.json"
    destination.write_bytes(b"previous-profile")
    _serve(monkeypatch, _envelope(_profile_data()))

    result = fetch_opcode_profile(
        "https://profiles.example.test/current.json", destination
    )

    assert result.backup_path is not None
    assert result.backup_path.parent == tmp_path / "opcodes_backups"
    assert result.backup_path.read_bytes() == b"previous-profile"
    assert json.loads(destination.read_text(encoding="utf-8"))["profile_active"]

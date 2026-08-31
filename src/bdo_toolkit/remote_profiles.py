"""Explicit retrieval and atomic installation of verified opcode profiles."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import math
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, replace
from http.client import HTTPException
from pathlib import Path
from typing import Any, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ._profile_runtime import validate_runtime_profile
from .profiles import OpcodeProfile, ProfileError, load_opcode_profile


DEFAULT_REMOTE_PROFILE_TIMEOUT_SECONDS = 10.0
DEFAULT_REMOTE_PROFILE_MAX_BYTES = 1024 * 1024
REMOTE_PROFILE_ENVELOPE_VERSION = 1
_REVISION_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")


class RemoteProfileError(ProfileError):
    """Raised when a remote profile cannot be securely fetched or installed."""


@dataclass(frozen=True)
class ProfileFetchResult:
    """Result of installing one verified remote opcode-profile envelope."""

    profile: OpcodeProfile
    source_url: str
    revision: str
    etag: Optional[str]
    backup_path: Optional[Path]

    @property
    def path(self) -> Path:
        """Installed destination, canonically owned by the loaded profile."""

        return self.profile.path


class _HttpsOnlyRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> Optional[Request]:
        _validate_https_url(new_url)
        return super().redirect_request(
            request,
            file_pointer,
            code,
            message,
            headers,
            new_url,
        )


def fetch_opcode_profile(
    url: str,
    destination: str | Path,
    *,
    timeout: float = DEFAULT_REMOTE_PROFILE_TIMEOUT_SECONDS,
    max_bytes: int = DEFAULT_REMOTE_PROFILE_MAX_BYTES,
    backup: bool = True,
) -> ProfileFetchResult:
    """Fetch, verify, and atomically install one remote opcode profile.

    The endpoint must return a version-1 envelope containing a manifest and an
    embedded profile. The manifest's SHA-256 covers the canonical JSON encoding
    of the embedded profile, so manifest metadata and profile bytes arrive in
    one envelope response. HTTPS redirects are permitted only to credential-free
    HTTPS URLs. Capture and replay APIs never call this function implicitly.

    Installation uses atomic replacement but no inter-process lock. The caller
    must enforce one writer per destination path; concurrent fetches targeting
    the same file are unsupported.
    """

    _validate_https_url(url)
    validated_timeout = _validate_timeout(timeout)
    validated_max_bytes = _validate_max_bytes(max_bytes)
    if not isinstance(backup, bool):
        raise TypeError("backup must be a boolean")
    try:
        destination_path = Path(destination)
    except TypeError as exc:
        raise TypeError("destination must be a path string or Path") from exc
    if destination_path.exists() and not destination_path.is_file():
        raise IsADirectoryError(
            f"Opcode profile destination is not a file: {destination_path}"
        )

    payload, source_url, etag = _fetch_envelope_bytes(
        url,
        timeout=validated_timeout,
        max_bytes=validated_max_bytes,
    )
    profile_data, revision, expected_digest = _decode_envelope(payload)
    actual_digest = hashlib.sha256(_canonical_profile_bytes(profile_data)).hexdigest()
    if not hmac.compare_digest(actual_digest, expected_digest):
        raise RemoteProfileError(
            "remote profile hash mismatch: manifest declared "
            f"{expected_digest}, decoded profile was {actual_digest}"
        )

    rendered_profile = _render_profile(profile_data)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Optional[Path] = None
    backup_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=destination_path.parent,
            prefix=f".{destination_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(rendered_profile)
            handle.flush()
            os.fsync(handle.fileno())

        try:
            installed_profile = load_opcode_profile(temporary_path)
            if not installed_profile.active:
                raise RemoteProfileError(
                    "remote opcode profile is inactive and was not installed"
                )
            validate_runtime_profile(installed_profile)
        except RemoteProfileError:
            raise
        except (
            ProfileError,
            RecursionError,
            TypeError,
            UnicodeError,
            ValueError,
        ) as exc:
            raise RemoteProfileError(
                f"remote opcode profile failed runtime validation: {exc}"
            ) from exc

        if backup and destination_path.exists():
            backup_path = _next_backup_path(destination_path)
            shutil.copy2(destination_path, backup_path)
        os.replace(temporary_path, destination_path)
        temporary_path = None
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()

    installed_profile = replace(installed_profile, path=destination_path)
    return ProfileFetchResult(
        profile=installed_profile,
        source_url=source_url,
        revision=revision,
        etag=etag,
        backup_path=backup_path,
    )


def _fetch_envelope_bytes(
    url: str,
    *,
    timeout: float,
    max_bytes: int,
) -> tuple[bytes, str, Optional[str]]:
    try:
        request = Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "bdo-toolkit-profile-fetch/1",
            },
            method="GET",
        )
        opener = build_opener(_HttpsOnlyRedirectHandler())
        with opener.open(request, timeout=timeout) as response:
            final_url = response.geturl()
            _validate_https_url(final_url)
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                except ValueError:
                    declared_length = -1
                if declared_length > max_bytes:
                    raise RemoteProfileError(
                        "remote profile envelope exceeds the configured "
                        f"{max_bytes}-byte limit"
                    )
            payload = response.read(max_bytes + 1)
            if len(payload) > max_bytes:
                raise RemoteProfileError(
                    "remote profile envelope exceeds the configured "
                    f"{max_bytes}-byte limit"
                )
            etag_value = response.headers.get("ETag")
            etag = etag_value if isinstance(etag_value, str) else None
            return payload, final_url, etag
    except RemoteProfileError:
        raise
    except (
        HTTPError,
        URLError,
        HTTPException,
        TimeoutError,
        OSError,
        ValueError,
    ) as exc:
        raise RemoteProfileError(f"could not fetch remote opcode profile: {exc}") from exc


def _decode_envelope(payload: bytes) -> tuple[dict[str, Any], str, str]:
    try:
        envelope = json.loads(payload.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise RemoteProfileError(
            f"remote profile envelope is not valid UTF-8 JSON: {exc}"
        ) from exc
    if not isinstance(envelope, dict):
        raise RemoteProfileError("remote profile envelope must be a JSON object")
    schema_version = envelope.get("schema_version")
    if (
        isinstance(schema_version, bool)
        or schema_version != REMOTE_PROFILE_ENVELOPE_VERSION
    ):
        raise RemoteProfileError(
            "unsupported remote profile envelope schema_version; expected "
            f"{REMOTE_PROFILE_ENVELOPE_VERSION}"
        )

    manifest = envelope.get("manifest")
    if not isinstance(manifest, dict):
        raise RemoteProfileError("remote profile envelope manifest must be an object")
    revision_value = manifest.get("revision")
    if (
        not isinstance(revision_value, str)
        or _REVISION_PATTERN.fullmatch(revision_value) is None
    ):
        raise RemoteProfileError(
            "remote profile envelope manifest.revision must be a lowercase "
            "slug of 1 to 128 ASCII letters, digits, dots, underscores, or hyphens"
        )
    digest_value = manifest.get("profile_sha256")
    if not isinstance(digest_value, str) or not _is_sha256(digest_value):
        raise RemoteProfileError(
            "remote profile envelope manifest.profile_sha256 must be 64 hex characters"
        )
    profile = envelope.get("profile")
    if not isinstance(profile, dict):
        raise RemoteProfileError("remote profile envelope profile must be an object")
    return profile, revision_value, digest_value.casefold()


def _canonical_profile_bytes(profile: dict[str, Any]) -> bytes:
    try:
        rendered = json.dumps(
            profile,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return rendered.encode("utf-8")
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise RemoteProfileError(
            f"remote profile cannot be canonically encoded: {exc}"
        ) from exc


def _render_profile(profile: dict[str, Any]) -> bytes:
    try:
        rendered = json.dumps(
            profile,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        return (rendered + "\n").encode("utf-8")
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise RemoteProfileError(f"remote profile cannot be encoded: {exc}") from exc


def _validate_https_url(url: str) -> None:
    if not isinstance(url, str):
        raise TypeError("url must be a string")
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
    except ValueError as exc:
        raise RemoteProfileError(f"invalid remote opcode profile URL: {exc}") from exc
    if parsed.scheme.casefold() != "https" or not hostname:
        raise RemoteProfileError("remote opcode profile URL must use HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise RemoteProfileError("remote opcode profile URL must not contain credentials")


def _validate_timeout(timeout: float) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError("timeout must be a finite positive number")
    result = float(timeout)
    if not math.isfinite(result) or result <= 0:
        raise ValueError("timeout must be a finite positive number")
    return result


def _validate_max_bytes(max_bytes: int) -> int:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
        raise TypeError("max_bytes must be a positive integer")
    if max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    return max_bytes


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdefABCDEF" for character in value
    )


def _next_backup_path(path: Path) -> Path:
    backup_dir = path.parent / "opcodes_backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(tz=dt.UTC).strftime("%Y%m%d%H%M%S%f")
    candidate = backup_dir / f"{path.name}.bak.{stamp}"
    suffix = 1
    while candidate.exists():
        candidate = backup_dir / f"{path.name}.bak.{stamp}.{suffix}"
        suffix += 1
    return candidate


__all__ = [
    "DEFAULT_REMOTE_PROFILE_MAX_BYTES",
    "DEFAULT_REMOTE_PROFILE_TIMEOUT_SECONDS",
    "ProfileFetchResult",
    "REMOTE_PROFILE_ENVELOPE_VERSION",
    "RemoteProfileError",
    "fetch_opcode_profile",
]

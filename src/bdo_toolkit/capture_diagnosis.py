"""Read-only Windows connection discovery; candidates are not capture validation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import ipaddress
import json
import math
import subprocess
import sys
from typing import Any, Literal

from ._capture_options import LiveCaptureOptions
from ._protocol import DEFAULT_SERVER_PORTS


@dataclass(frozen=True)
class CaptureCandidate:
    """One observed game connection mapped to a capture adapter, if available."""

    process_id: int
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    interface: str | None
    peer_process: str | None
    kind: Literal["local_proxy", "game_port", "other_tcp"]
    explanation: str

    def to_live_options(self) -> LiveCaptureOptions:
        """Build explicit options; reject candidates without a matching adapter."""
        if self.interface is None:
            raise ValueError("No matching capture adapter; manual investigation required")
        return LiveCaptureOptions(
            interface=self.interface, local_ip=self.local_ip,
            ports=(self.remote_port,),
        )


@dataclass(frozen=True)
class CaptureSettingsProposal:
    """Compatible connections grouped for one explicit capture configuration."""

    process_id: int
    interface: str | None
    local_ip: str
    kind: Literal["local_proxy", "game_port", "other_tcp"]
    ports: tuple[int, ...]
    candidates: tuple[CaptureCandidate, ...]

    def to_live_options(self) -> LiveCaptureOptions:
        """Build settings with every observed port; never starts capture."""
        if self.interface is None:
            raise ValueError("No matching capture adapter; manual investigation required")
        return LiveCaptureOptions(
            interface=self.interface, local_ip=self.local_ip, ports=self.ports,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible settings and underlying connection evidence."""
        return {
            "process_id": self.process_id, "interface": self.interface,
            "local_ip": self.local_ip, "kind": self.kind,
            "ports": list(self.ports),
            "candidates": [asdict(candidate) for candidate in self.candidates],
        }


@dataclass(frozen=True)
class CaptureDiagnosis:
    """Snapshot of candidates and limitations; never automatically applied."""

    status: Literal["candidates", "no_game", "no_connections", "unavailable"]
    candidates: tuple[CaptureCandidate, ...] = ()
    messages: tuple[str, ...] = ()

    @property
    def proposals(self) -> tuple[CaptureSettingsProposal, ...]:
        """Group by process, adapter, local address, and kind in evidence order.

        Local proxies additionally match peer address and process name. When
        ownership is unknown, different peer ports remain separate. Candidates
        without matching adapters remain visible but cannot produce options.
        """
        groups: dict[tuple[object, ...], list[CaptureCandidate]] = {}
        for candidate in self.candidates:
            key: tuple[object, ...] = (
                candidate.process_id, candidate.interface,
                candidate.local_ip, candidate.kind,
            )
            if candidate.kind == "local_proxy":
                key += (candidate.remote_ip, candidate.peer_process)
                if candidate.peer_process is None:
                    key += (candidate.remote_port,)
            groups.setdefault(key, []).append(candidate)
        return tuple(
            CaptureSettingsProposal(
                process_id=group[0].process_id, interface=group[0].interface,
                local_ip=group[0].local_ip, kind=group[0].kind,
                ports=tuple(sorted({candidate.remote_port for candidate in group})),
                candidates=tuple(group),
            )
            for group in groups.values()
        )

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible diagnostic data, including local endpoints."""
        return {
            "status": self.status,
            "candidates": [asdict(candidate) for candidate in self.candidates],
            "messages": list(self.messages),
            "proposals": [proposal.to_dict() for proposal in self.proposals],
        }


# Fixed script: no user text is interpolated into PowerShell. Read the connection
# table once, and correlate local proxies by the exact reversed TCP four-tuple.
_WINDOWS_SNAPSHOT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$processes = @(Get-Process)
$games = @($processes | Where-Object { $_.ProcessName -in @('BlackDesert64', 'BlackDesert') })
$connections = @(Get-NetTCPConnection)
$rows = @($connections | Where-Object { $_.State -eq 'Established' -and $_.OwningProcess -in $games.Id } | ForEach-Object {
    $connection = $_
    $peer = $connections | Where-Object {
        $_.LocalAddress -eq $connection.RemoteAddress -and $_.LocalPort -eq $connection.RemotePort -and
        $_.RemoteAddress -eq $connection.LocalAddress -and $_.RemotePort -eq $connection.LocalPort
    } | Select-Object -First 1
    $peerName = $null
    if ($null -ne $peer) { $peerName = ($processes | Where-Object { $_.Id -eq $peer.OwningProcess } | Select-Object -First 1).ProcessName }
    @{ process_id = [int]$connection.OwningProcess; local_ip = $connection.LocalAddress;
       local_port = [int]$connection.LocalPort; remote_ip = $connection.RemoteAddress;
       remote_port = [int]$connection.RemotePort; peer_process = $peerName }
})
@{ game_count = $games.Count; connections = $rows } | ConvertTo-Json -Depth 4 -Compress
"""


def _windows_snapshot(timeout: float) -> dict[str, Any]:
    result = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", _WINDOWS_SNAPSHOT],
        capture_output=True, encoding="utf-8", errors="replace", timeout=timeout,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if result.returncode:
        raise RuntimeError("Windows connection inspection failed; check permissions and NetTCPIP availability")
    value = json.loads(result.stdout.lstrip("\ufeff"))
    if not isinstance(value, dict) or not isinstance(value.get("connections"), list):
        raise ValueError("Unexpected Windows connection snapshot")
    if type(value.get("game_count")) is not int or value["game_count"] < 0:
        raise ValueError("Unexpected Windows process count")
    for row in value["connections"]:
        if not isinstance(row, dict):
            raise ValueError("Unexpected Windows connection row")
        for name in ("local_ip", "remote_ip"):
            if not isinstance(row.get(name), str):
                raise ValueError("Missing Windows connection address")
            ipaddress.ip_address(row[name])
        for name, maximum in (("process_id", 0xFFFFFFFF), ("local_port", 65535), ("remote_port", 65535)):
            if type(row.get(name)) is not int or not 1 <= row[name] <= maximum:
                raise ValueError("Invalid Windows connection identifier or port")
        if "peer_process" not in row or not isinstance(row["peer_process"], (str, type(None))):
            raise ValueError("Invalid Windows peer process name")
    return value


def _capture_adapters() -> list[tuple[str, tuple[str, ...]]]:
    from scapy.all import conf  # type: ignore

    conf.ifaces.reload()
    return [
        (str(adapter.network_name), tuple(str(ip) for ip in adapter.ips.get(4, [])))
        for adapter in conf.ifaces.values()
    ]


def diagnose_capture(*, timeout: float = 15.0) -> CaptureDiagnosis:
    """Inspect Windows BDO TCP connections and capture interfaces.

    ``timeout`` bounds the Windows subprocess, not Scapy adapter enumeration.
    Call from a worker in GUI applications. No packets are captured, no profile
    is needed, and no settings are applied. IPv6 connections are reported as a
    limitation. Other platforms return ``unavailable``. Operational inspection
    failures are returned in messages; invalid timeout values raise ValueError.
    Proxy ports and process IDs are valid only for the observed session.
    """
    if isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be finite and greater than zero")
    if sys.platform != "win32":
        return CaptureDiagnosis("unavailable", messages=("Connection discovery currently supports Windows only.",))
    try:
        snapshot = _windows_snapshot(timeout)
    except subprocess.TimeoutExpired:
        return CaptureDiagnosis("unavailable", messages=(
            f"Windows connection inspection timed out after {timeout:g} seconds; retry or increase timeout.",
        ))
    except (OSError, RuntimeError, ValueError) as exc:
        return CaptureDiagnosis("unavailable", messages=(f"Could not inspect BDO connections: {exc}",))
    if not snapshot["game_count"]:
        return CaptureDiagnosis("no_game", messages=("Start Black Desert, enter the game, and retry.",))
    messages = ["Candidates are unverified: test with known in-game activity. No settings were changed."]
    try:
        adapters = _capture_adapters()
    except Exception as exc:
        adapters = []
        messages.append(f"Could not enumerate capture adapters: {exc}")
    candidates: list[CaptureCandidate] = []
    for row in snapshot["connections"]:
        local = ipaddress.ip_address(row["local_ip"])
        remote = ipaddress.ip_address(row["remote_ip"])
        if local.version != 4 or remote.version != 4:
            messages.append("An established BDO IPv6 connection was skipped: capture decoding supports IPv4 only.")
            continue
        interfaces = sorted({
            name for name, ips in adapters
            if str(local) in ips or (local.is_loopback and name == r"\Device\NPF_Loopback")
        })
        kind: Literal["local_proxy", "game_port", "other_tcp"]
        if local.is_loopback and remote.is_loopback:
            kind = "local_proxy"
            explanation = "BDO connects through a local TCP peer; capture loopback using the peer port. Recheck after reconnecting."
        elif row["remote_port"] in DEFAULT_SERVER_PORTS:
            kind = "game_port"
            explanation = "Connection uses a default BDO game port; verify traffic is visible on this adapter."
        else:
            kind = "other_tcp"
            explanation = "Nonstandard TCP peer; may be web, authentication, or other traffic rather than gameplay."
        if not interfaces:
            explanation += " No capture adapter matches the local IPv4 address."
        if len(interfaces) > 1:
            explanation += " Multiple adapters match; test each candidate explicitly."
        matches: list[str | None] = list(interfaces) if interfaces else [None]
        for interface in matches:
            candidates.append(CaptureCandidate(
                process_id=row["process_id"], local_ip=str(local), local_port=row["local_port"],
                remote_ip=str(remote), remote_port=row["remote_port"], interface=interface,
                peer_process=row["peer_process"], kind=kind, explanation=explanation,
            ))
    candidates.sort(key=lambda c: ({"local_proxy": 0, "game_port": 1, "other_tcp": 2}[c.kind], c.process_id, c.local_port, c.interface or ""))
    if not candidates:
        messages.append("No established IPv4 TCP candidates found. Enter a game server and retry.")
    return CaptureDiagnosis("candidates" if candidates else "no_connections", tuple(candidates), tuple(dict.fromkeys(messages)))

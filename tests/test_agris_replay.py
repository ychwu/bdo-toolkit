"""Agris replay has the same inference clock and no startup arithmetic."""
from __future__ import annotations

import pytest

from bdo_toolkit.agris import AgrisDiscoveryOptions, replay_agris


def write_capture(path, *, count=7, cap=100000, tail=True):
    from scapy.all import Ether, IP, TCP, PcapWriter
    sequence = 100
    with PcapWriter(str(path), sync=True) as writer:
        for index in range(count):
            data = bytearray([0xAB] * 37)
            data[:2] = (37).to_bytes(2, 'little')
            data[2] = 0
            data[3:5] = (0x1746).to_bytes(2, 'little')
            data[12:16] = cap.to_bytes(4, 'little')
            data[33:37] = (cap - 40 * (index + 1)).to_bytes(4, 'little')
            packet = Ether()/IP(src='192.0.2.1', dst='192.0.2.2')/TCP(sport=8889, dport=40000, seq=sequence, flags='PA')/bytes(data)
            packet.time = float(index)
            writer.write(packet)
            sequence += len(data)
        if tail:
            packet = Ether()/IP(src='192.0.2.1', dst='192.0.2.2')/TCP(sport=8889, dport=40000, seq=sequence, flags='A')
            packet.time = float(count + 5)
            writer.write(packet)


def test_streaming_replay_reads_new_geometry_and_no_consumption_schema(tmp_path):
    path = tmp_path / 'shifted.pcap'
    write_capture(path)
    with replay_agris(path, expected_maximum_points=100000,
                      discovery_options=AgrisDiscoveryOptions(settle_seconds=0)) as replay:
        updates = list(replay)
        assert [balance.remaining_points for balance in updates] == [99800, 99760, 99720]
        assert replay.status.status == 'tracking'
        assert replay.status.balance.remaining_points == 99720
        assert replay.health.packets_processed == 8
        for row in updates:
            assert not {'starting_points', 'consumed', 'delta'} & row.to_dict().keys()


def test_ack_only_tail_advances_replay_settling_without_wall_clock(tmp_path):
    path = tmp_path / 'tail.pcap'
    write_capture(path, count=5)
    replay = replay_agris(path, expected_maximum_points=100000)
    updates = list(replay)
    assert len(updates) == 1
    assert updates[0].remaining_points == 99800
    assert updates[0].observed_at == 4.0


def test_missing_cap_and_invalid_cap_fail_before_opening_file(tmp_path):
    path = tmp_path / 'missing.pcap'
    with pytest.raises(TypeError):
        replay_agris(path)
    for value in (True, 0, -1, 1.0, 0x100000000):
        with pytest.raises((ValueError, TypeError)):
            replay_agris(path, expected_maximum_points=value)


def test_wrong_cap_stays_unresolved_without_fallback(tmp_path):
    path = tmp_path / 'wrong-cap.pcap'
    write_capture(path)
    replay = replay_agris(path, expected_maximum_points=50000)
    assert list(replay) == []
    assert replay.status.status == 'searching'
    assert replay.status.balance is None


def test_close_partial_replay_releases_file_without_finalizing_history(tmp_path):
    path = tmp_path / 'partial.pcap'
    write_capture(path)
    replay = replay_agris(path, expected_maximum_points=100000,
                          discovery_options=AgrisDiscoveryOptions(settle_seconds=0))
    assert next(replay).remaining_points == 99800
    replay.close()
    assert list(replay) == []
    # Windows rename provides an independent open-handle release check.
    path.rename(tmp_path / 'released.pcap')

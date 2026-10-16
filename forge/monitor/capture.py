"""Passive Modbus traffic monitor and OT asset discovery.

Sits on the traffic callback from the PLC server, parses every Modbus
frame, maintains an asset inventory, and feeds transactions to the
detection engine.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from forge.protocol.modbus import FC, Frame


@dataclass
class OTAsset:
    """A device discovered on the OT network."""

    ip: str
    first_seen: float
    last_seen: float
    role: str  # "plc", "hmi", "unknown", "attacker"
    unit_ids: set[int] = field(default_factory=set)
    read_count: int = 0
    write_count: int = 0
    function_codes_seen: set[int] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "role": self.role,
            "unit_ids": sorted(self.unit_ids),
            "read_count": self.read_count,
            "write_count": self.write_count,
            "function_codes_seen": sorted(self.function_codes_seen),
        }


@dataclass
class Transaction:
    """A parsed Modbus transaction for the detection engine."""

    src_ip: str
    src_port: int
    unit_id: int
    function_code: int
    is_write: bool
    is_read: bool
    address: int | None = None
    value: int | None = None
    time: float = field(default_factory=time.time)


class TrafficMonitor:
    """Collects Modbus traffic and maintains the asset inventory."""

    def __init__(self, hmi_ip: str = "127.0.0.1") -> None:
        self.hmi_ip = hmi_ip
        self.assets: dict[str, OTAsset] = {}
        self.transactions: list[Transaction] = []
        self._rate: dict[str, list[float]] = defaultdict(list)

    def on_frame(self, src_ip: str, src_port: int, frame: Frame) -> Transaction:
        """Process an incoming Modbus frame. Returns a Transaction for the detector."""
        now = time.time()

        # Update asset inventory
        if src_ip not in self.assets:
            role = "hmi" if src_ip == self.hmi_ip else "unknown"
            self.assets[src_ip] = OTAsset(
                ip=src_ip, first_seen=now, last_seen=now, role=role,
            )
        asset = self.assets[src_ip]
        asset.last_seen = now
        asset.unit_ids.add(frame.unit_id)
        asset.function_codes_seen.add(frame.function_code)

        if frame.is_write:
            asset.write_count += 1
        if frame.is_read:
            asset.read_count += 1

        # Parse address from data if present
        address = None
        value = None
        if len(frame.data) >= 2:
            address = int.from_bytes(frame.data[0:2], "big")
        if len(frame.data) >= 4:
            value = int.from_bytes(frame.data[2:4], "big")

        tx = Transaction(
            src_ip=src_ip,
            src_port=src_port,
            unit_id=frame.unit_id,
            function_code=frame.function_code,
            is_write=frame.is_write,
            is_read=frame.is_read,
            address=address,
            value=value,
            time=now,
        )
        self.transactions.append(tx)

        # Track request rate per IP
        self._rate[src_ip].append(now)

        return tx

    def request_rate(self, ip: str, window: float = 10.0) -> float:
        """Requests per second from this IP over the last `window` seconds."""
        now = time.time()
        times = self._rate.get(ip, [])
        recent = [t for t in times if now - t < window]
        self._rate[ip] = recent
        return len(recent) / window if window > 0 else 0

    def asset_list(self) -> list[dict]:
        return [a.to_dict() for a in self.assets.values()]

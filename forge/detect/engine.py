"""ICS threat detection engine with MITRE ATT&CK for ICS mapping.

Each rule inspects Modbus transactions and/or process state and yields
alerts when it matches.  Rules are plain functions registered in a list
so they are easy to extend.

MITRE ATT&CK for ICS techniques referenced:
    T0846  Remote System Discovery
    T0855  Unauthorized Command Message
    T0836  Modify Parameter
    T0816  Device Restart/Shutdown
    T0831  Manipulation of Control
    T0814  Denial of Service
    T0806  Brute Force I/O
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import TYPE_CHECKING

from forge.events import Alert

if TYPE_CHECKING:
    from forge.monitor.capture import TrafficMonitor, Transaction


# Safe operating limits
SAFE_TANK_HIGH = 95
SAFE_TANK_LOW = 5
SAFE_CHLORINE_HIGH = 800  # register value, 8.00 mg/L

SAFE_CHLORINE_LOW = 20   # register value, 0.20 mg/L minimum residual
SAFE_PUMP_SPEED_MAX = 1750  # RPM, above this indicates runaway condition
SAFE_PRESSURE_MAX = 120     # PSI, maximum safe line pressure
RATE_THRESHOLD = 5.0  # requests/sec considered flooding
SCAN_THRESHOLD = 5    # unique unit IDs in 10 seconds = recon
COIL_BRUTE_THRESHOLD = 8  # coil writes in 5 seconds = brute force (T0806)


class DetectionEngine:
    """Evaluates traffic against ICS-specific detection rules."""

    def __init__(self, monitor: TrafficMonitor, hmi_ip: str = "127.0.0.1") -> None:
        self.monitor = monitor
        self.hmi_ip = hmi_ip
        self._seen_scans: dict[str, set[int]] = defaultdict(set)
        self._scan_window: dict[str, float] = {}
        self._coil_toggles: dict[str, list[float]] = defaultdict(list)

    def evaluate(self, tx: Transaction) -> list[Alert]:
        """Run all rules against a transaction. Returns any alerts raised."""
        alerts: list[Alert] = []

        alerts.extend(self._rule_unauthorized_write(tx))
        alerts.extend(self._rule_recon_scan(tx))
        alerts.extend(self._rule_dangerous_setpoint(tx))
        alerts.extend(self._rule_estop_manipulation(tx))
        alerts.extend(self._rule_flooding(tx))
        alerts.extend(self._rule_coil_brute_force(tx))

        return alerts

    def _rule_unauthorized_write(self, tx: Transaction) -> list[Alert]:
        """Write from an IP that is not the HMI."""
        if not tx.is_write:
            return []
        if tx.src_ip == self.hmi_ip:
            return []
        return [Alert(
            rule_id="ICS-001",
            title="Unauthorized Modbus write",
            severity="critical",
            src_ip=tx.src_ip,
            detail=f"Write FC={tx.function_code} to address {tx.address} from non-HMI source",
            mitre_id="T0855",
            mitre_tactic="Impair Process Control",
        )]

    def _rule_recon_scan(self, tx: Transaction) -> list[Alert]:
        """Rapid scanning of multiple unit IDs from one source."""
        now = tx.time
        ip = tx.src_ip
        if ip == self.hmi_ip:
            return []

        last = self._scan_window.get(ip, 0)
        if now - last > 10:
            self._seen_scans[ip] = set()
            self._scan_window[ip] = now

        self._seen_scans[ip].add(tx.unit_id)

        if len(self._seen_scans[ip]) >= SCAN_THRESHOLD:
            self._seen_scans[ip] = set()
            return [Alert(
                rule_id="ICS-002",
                title="Modbus reconnaissance scan",
                severity="high",
                src_ip=ip,
                detail=f"Scanned {SCAN_THRESHOLD}+ unit IDs within 10 seconds",
                mitre_id="T0846",
                mitre_tactic="Discovery",
            )]
        return []

    def _rule_dangerous_setpoint(self, tx: Transaction) -> list[Alert]:
        """Write that pushes a setpoint outside safe operating range."""
        if not tx.is_write or tx.address is None or tx.value is None:
            return []
        if tx.function_code == 0x06:  # write single register
            if tx.address == 2 and tx.value > SAFE_TANK_HIGH:
                return [Alert(
                    rule_id="ICS-003",
                    title="Dangerous setpoint: tank high threshold",
                    severity="critical",
                    src_ip=tx.src_ip,
                    detail=f"Tank high threshold set to {tx.value}% (safe max {SAFE_TANK_HIGH}%)",
                    mitre_id="T0836",
                    mitre_tactic="Impair Process Control",
                )]
            if tx.address == 3 and tx.value < SAFE_TANK_LOW:
                return [Alert(
                    rule_id="ICS-003",
                    title="Dangerous setpoint: tank low threshold",
                    severity="critical",
                    src_ip=tx.src_ip,
                    detail=f"Tank low threshold set to {tx.value}% (safe min {SAFE_TANK_LOW}%)",
                    mitre_id="T0836",
                    mitre_tactic="Impair Process Control",
                )]
            if tx.address == 4 and tx.value > SAFE_PUMP_SPEED_MAX:
                return [Alert(
                    rule_id="ICS-003",
                    title="Dangerous setpoint: pump speed runaway",
                    severity="high",
                    src_ip=tx.src_ip,
                    detail=f"Pump speed setpoint {tx.value} RPM exceeds safe max {SAFE_PUMP_SPEED_MAX} RPM",
                    mitre_id="T0836",
                    mitre_tactic="Impair Process Control",
                )]
            if tx.address == 5 and tx.value > SAFE_PRESSURE_MAX:
                return [Alert(
                    rule_id="ICS-003",
                    title="Dangerous setpoint: line pressure exceeded",
                    severity="high",
                    src_ip=tx.src_ip,
                    detail=f"Pressure setpoint {tx.value} PSI exceeds safe max {SAFE_PRESSURE_MAX} PSI",
                    mitre_id="T0836",
                    mitre_tactic="Impair Process Control",
                )]
        return []

    def _rule_estop_manipulation(self, tx: Transaction) -> list[Alert]:
        """Emergency stop coil toggled by non-HMI source."""
        if not tx.is_write:
            return []
        if tx.function_code == 0x05 and tx.address == 3:
            if tx.src_ip != self.hmi_ip:
                return [Alert(
                    rule_id="ICS-004",
                    title="Emergency stop manipulation",
                    severity="critical",
                    src_ip=tx.src_ip,
                    detail="E-stop coil written by unauthorized source",
                    mitre_id="T0816",
                    mitre_tactic="Inhibit Response Function",
                )]
        return []

    def _rule_flooding(self, tx: Transaction) -> list[Alert]:
        """Excessive Modbus request rate from a single IP."""
        rate = self.monitor.request_rate(tx.src_ip)
        if rate > RATE_THRESHOLD and tx.src_ip != self.hmi_ip:
            return [Alert(
                rule_id="ICS-005",
                title="Modbus flooding",
                severity="high",
                src_ip=tx.src_ip,
                detail=f"{rate:.1f} req/s exceeds threshold of {RATE_THRESHOLD} req/s",
                mitre_id="T0814",
                mitre_tactic="Inhibit Response Function",
            )]
        return []

    def _rule_coil_brute_force(self, tx: Transaction) -> list[Alert]:
        """Rapid toggling of coils (brute forcing actuator states)."""
        if tx.function_code != 0x05:
            return []
        ip = tx.src_ip
        if ip == self.hmi_ip:
            return []

        now = tx.time
        self._coil_toggles[ip].append(now)
        recent = [t for t in self._coil_toggles[ip] if now - t < 5]
        self._coil_toggles[ip] = recent

        if len(recent) >= COIL_BRUTE_THRESHOLD:
            self._coil_toggles[ip] = []
            return [Alert(
                rule_id="ICS-006",
                title="Coil brute force",
                severity="high",
                src_ip=tx.src_ip,
                detail=f"{len(recent)} coil writes in 5 seconds",
                mitre_id="T0806",
                mitre_tactic="Impair Process Control",
            )]
        return []

"""Process value baseline and anomaly detection.

Learns the normal operating range of each process value over a sliding
window.  When values deviate beyond a threshold, flags it for the
detection engine.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import math


@dataclass
class Baseline:
    """Tracks mean and standard deviation of a process value."""

    window: int = 120
    _values: deque[float] = field(default_factory=lambda: deque(maxlen=120))

    def add(self, value: float) -> None:
        self._values.append(value)

    @property
    def ready(self) -> bool:
        return len(self._values) >= 30

    @property
    def mean(self) -> float:
        if not self._values:
            return 0.0
        return sum(self._values) / len(self._values)

    @property
    def std(self) -> float:
        if len(self._values) < 2:
            return 0.0
        m = self.mean
        variance = sum((v - m) ** 2 for v in self._values) / (len(self._values) - 1)
        return math.sqrt(variance)

    def is_anomaly(self, value: float, sigma: float = 3.0) -> bool:
        if not self.ready:
            return False
        return abs(value - self.mean) > sigma * max(self.std, 0.01)


class ProcessBaseline:
    """Baselines for all process values in the plant."""

    def __init__(self) -> None:
        self.tank_level = Baseline()
        self.chlorine = Baseline()
        self.inlet_pressure = Baseline()
        self.flow_rate = Baseline()

    def update(self, snapshot: dict) -> list[str]:
        """Feed in a plant snapshot. Returns list of anomaly descriptions."""
        anomalies = []

        self.tank_level.add(snapshot["tank_level"])
        if self.tank_level.is_anomaly(snapshot["tank_level"]):
            anomalies.append(
                f"Tank level {snapshot['tank_level']:.1f}% deviates from "
                f"baseline {self.tank_level.mean:.1f}% +/- {self.tank_level.std:.1f}"
            )

        self.chlorine.add(snapshot["chlorine_mg_l"])
        if self.chlorine.is_anomaly(snapshot["chlorine_mg_l"]):
            anomalies.append(
                f"Chlorine {snapshot['chlorine_mg_l']:.2f} mg/L deviates from "
                f"baseline {self.chlorine.mean:.2f} +/- {self.chlorine.std:.2f}"
            )

        self.inlet_pressure.add(snapshot["inlet_pressure"])
        if self.inlet_pressure.is_anomaly(snapshot["inlet_pressure"]):
            anomalies.append(
                f"Inlet pressure {snapshot['inlet_pressure']:.1f} PSI deviates from "
                f"baseline {self.inlet_pressure.mean:.1f} +/- {self.inlet_pressure.std:.1f}"
            )

        self.flow_rate.add(snapshot["flow_rate"])
        if self.flow_rate.is_anomaly(snapshot["flow_rate"]):
            anomalies.append(
                f"Flow rate {snapshot['flow_rate']:.1f} L/min deviates from "
                f"baseline {self.flow_rate.mean:.1f} +/- {self.flow_rate.std:.1f}"
            )

        return anomalies

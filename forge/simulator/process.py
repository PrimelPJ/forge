"""Water treatment plant physics simulation.

Models a simplified plant with an intake pump, chemical dosing, a holding
tank, and an outlet valve.  The simulation ticks once per second and updates
all process values according to basic fluid and chemistry rules.

Register map
============

Coils (read/write, 0-indexed):
    0  intake_pump       on/off
    1  dosing_pump       on/off
    2  outlet_valve      on/off
    3  emergency_stop    on/off  (kills all actuators)

Holding registers (read/write, uint16):
    0  intake_rate       0-100 %
    1  dose_rate         0-100 %
    2  tank_high_thresh  0-100 %   (default 90)
    3  tank_low_thresh   0-100 %   (default 10)
    4  chlorine_target   0-100     (maps to 0-10 mg/L)

Input registers (read-only, uint16, value * 100 for two decimals):
    0  tank_level        0-10000   (0.00-100.00 %)
    1  chlorine_level    0-10000   (0.00-10.00 mg/L)
    2  inlet_pressure    0-10000   (0.00-100.00 PSI)
    3  outlet_pressure   0-10000   (0.00-100.00 PSI)
    4  flow_rate         0-10000   (0.00-100.00 GPM)

Discrete inputs (read-only, bool):
    0  tank_high_alarm
    1  tank_low_alarm
    2  chlorine_high_alarm
    3  chlorine_low_alarm
    4  system_fault
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field


@dataclass
class PlantState:
    # Actuator coils
    intake_pump: bool = False
    dosing_pump: bool = False
    outlet_valve: bool = False
    emergency_stop: bool = False

    # Setpoints (holding registers)
    intake_rate: int = 50
    dose_rate: int = 40
    tank_high_thresh: int = 90
    tank_low_thresh: int = 10
    chlorine_target: int = 30  # 3.0 mg/L

    # Process values
    tank_level: float = 45.0
    chlorine_mg_l: float = 2.5
    inlet_pressure: float = 52.0
    outlet_pressure: float = 22.0
    flow_rate: float = 0.0

    # Alarms
    tank_high_alarm: bool = False
    tank_low_alarm: bool = False
    chlorine_high_alarm: bool = False
    chlorine_low_alarm: bool = False
    system_fault: bool = False

    # Internal
    _rng: random.Random = field(default_factory=random.Random, repr=False)

    def tick(self) -> None:
        """Advance the simulation by one second."""
        if self.emergency_stop:
            self.flow_rate = 0.0
            self._update_alarms()
            return

        # Intake pump fills the tank
        if self.intake_pump:
            inflow = (self.intake_rate / 100.0) * 0.8
            self.tank_level += inflow
            self.flow_rate = (self.intake_rate / 100.0) * 65.0
        else:
            self.flow_rate = 0.0

        # Outlet valve drains proportional to level
        if self.outlet_valve and self.tank_level > 0:
            drain = 0.6 * (self.tank_level / 100.0)
            self.tank_level -= drain

        # Chemical dosing
        if self.dosing_pump:
            self.chlorine_mg_l += (self.dose_rate / 100.0) * 0.04

        # Chlorine decay
        self.chlorine_mg_l *= 0.997

        # Clamp values
        self.tank_level = max(0.0, min(100.0, self.tank_level))
        self.chlorine_mg_l = max(0.0, min(10.0, self.chlorine_mg_l))

        # Pressure with noise
        self.inlet_pressure = 48.0 + self._rng.gauss(0, 1.5)
        self.outlet_pressure = self.tank_level * 0.45 + self._rng.gauss(0, 0.5)

        self._update_alarms()

    def _update_alarms(self) -> None:
        self.tank_high_alarm = self.tank_level > self.tank_high_thresh
        self.tank_low_alarm = self.tank_level < self.tank_low_thresh
        self.chlorine_high_alarm = self.chlorine_mg_l > 8.0
        self.chlorine_low_alarm = self.chlorine_mg_l < 0.5

    # --- Register interface ---

    def get_coils(self, start: int, count: int) -> list[bool]:
        coils = [self.intake_pump, self.dosing_pump, self.outlet_valve, self.emergency_stop]
        return coils[start : start + count]

    def set_coil(self, address: int, value: bool) -> None:
        if address == 0:
            self.intake_pump = value
        elif address == 1:
            self.dosing_pump = value
        elif address == 2:
            self.outlet_valve = value
        elif address == 3:
            self.emergency_stop = value

    def get_holding_registers(self, start: int, count: int) -> list[int]:
        regs = [
            self.intake_rate,
            self.dose_rate,
            self.tank_high_thresh,
            self.tank_low_thresh,
            self.chlorine_target,
        ]
        return regs[start : start + count]

    def set_holding_register(self, address: int, value: int) -> None:
        value = max(0, min(100, value))
        if address == 0:
            self.intake_rate = value
        elif address == 1:
            self.dose_rate = value
        elif address == 2:
            self.tank_high_thresh = value
        elif address == 3:
            self.tank_low_thresh = value
        elif address == 4:
            self.chlorine_target = value

    def get_input_registers(self, start: int, count: int) -> list[int]:
        regs = [
            int(self.tank_level * 100),
            int(self.chlorine_mg_l * 100),
            int(max(0, self.inlet_pressure) * 100),
            int(max(0, self.outlet_pressure) * 100),
            int(self.flow_rate * 100),
        ]
        return regs[start : start + count]

    def get_discrete_inputs(self, start: int, count: int) -> list[bool]:
        inputs = [
            self.tank_high_alarm,
            self.tank_low_alarm,
            self.chlorine_high_alarm,
            self.chlorine_low_alarm,
            self.system_fault,
        ]
        return inputs[start : start + count]

    def snapshot(self) -> dict:
        return {
            "tank_level": round(self.tank_level, 2),
            "chlorine_mg_l": round(self.chlorine_mg_l, 2),
            "inlet_pressure": round(self.inlet_pressure, 2),
            "outlet_pressure": round(self.outlet_pressure, 2),
            "flow_rate": round(self.flow_rate, 2),
            "intake_pump": self.intake_pump,
            "dosing_pump": self.dosing_pump,
            "outlet_valve": self.outlet_valve,
            "emergency_stop": self.emergency_stop,
            "intake_rate": self.intake_rate,
            "dose_rate": self.dose_rate,
            "tank_high_alarm": self.tank_high_alarm,
            "tank_low_alarm": self.tank_low_alarm,
            "chlorine_high_alarm": self.chlorine_high_alarm,
            "chlorine_low_alarm": self.chlorine_low_alarm,
        }

"""Tests for the water treatment plant simulation."""

from forge.simulator.process import PlantState


def test_intake_fills_tank(plant):
    plant.intake_pump = True
    plant.intake_rate = 100
    initial = plant.tank_level
    for _ in range(10):
        plant.tick()
    assert plant.tank_level > initial


def test_outlet_drains_tank(plant):
    plant.tank_level = 80.0
    plant.outlet_valve = True
    initial = plant.tank_level
    for _ in range(10):
        plant.tick()
    assert plant.tank_level < initial


def test_dosing_increases_chlorine(plant):
    plant.dosing_pump = True
    plant.dose_rate = 100
    initial = plant.chlorine_mg_l
    for _ in range(20):
        plant.tick()
    assert plant.chlorine_mg_l > initial


def test_emergency_stop_freezes_flow(plant):
    plant.intake_pump = True
    plant.emergency_stop = True
    plant.tick()
    assert plant.flow_rate == 0.0


def test_tank_clamped(plant):
    plant.tank_level = 99.5
    plant.intake_pump = True
    plant.intake_rate = 100
    for _ in range(100):
        plant.tick()
    assert plant.tank_level <= 100.0


def test_alarms_fire(plant):
    plant.tank_level = 95.0
    plant.tick()
    assert plant.tank_high_alarm is True
    assert plant.tank_low_alarm is False

    plant.tank_level = 5.0
    plant.tick()
    assert plant.tank_low_alarm is True


def test_coil_interface(plant):
    plant.set_coil(0, True)
    assert plant.intake_pump is True
    assert plant.get_coils(0, 1) == [True]


def test_register_interface(plant):
    plant.set_holding_register(0, 75)
    assert plant.intake_rate == 75
    regs = plant.get_holding_registers(0, 2)
    assert regs[0] == 75


def test_input_registers_scaled(plant):
    plant.tank_level = 45.67
    regs = plant.get_input_registers(0, 1)
    assert regs[0] == 4567

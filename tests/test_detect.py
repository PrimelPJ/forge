"""Tests for the ICS detection engine."""

import time

from forge.detect.engine import DetectionEngine
from forge.monitor.capture import TrafficMonitor, Transaction


def make_tx(**kwargs) -> Transaction:
    defaults = {
        "src_ip": "10.0.10.99",
        "src_port": 45000,
        "unit_id": 1,
        "function_code": 0x03,
        "is_write": False,
        "is_read": True,
        "address": 0,
        "value": None,
        "time": time.time(),
    }
    defaults.update(kwargs)
    return Transaction(**defaults)


def test_unauthorized_write():
    monitor = TrafficMonitor(hmi_ip="10.0.10.50")
    engine = DetectionEngine(monitor, hmi_ip="10.0.10.50")

    tx = make_tx(is_write=True, is_read=False, function_code=0x05)
    alerts = engine.evaluate(tx)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "ICS-001"
    assert alerts[0].mitre_id == "T0855"


def test_hmi_write_not_flagged():
    monitor = TrafficMonitor(hmi_ip="10.0.10.50")
    engine = DetectionEngine(monitor, hmi_ip="10.0.10.50")

    tx = make_tx(src_ip="10.0.10.50", is_write=True, is_read=False, function_code=0x05)
    alerts = engine.evaluate(tx)
    assert len(alerts) == 0


def test_dangerous_setpoint():
    monitor = TrafficMonitor(hmi_ip="10.0.10.50")
    engine = DetectionEngine(monitor, hmi_ip="10.0.10.50")

    tx = make_tx(is_write=True, function_code=0x06, address=2, value=100)
    alerts = engine.evaluate(tx)
    rule_ids = [a.rule_id for a in alerts]
    assert "ICS-003" in rule_ids


def test_estop_manipulation():
    monitor = TrafficMonitor(hmi_ip="10.0.10.50")
    engine = DetectionEngine(monitor, hmi_ip="10.0.10.50")

    tx = make_tx(is_write=True, function_code=0x05, address=3)
    alerts = engine.evaluate(tx)
    rule_ids = [a.rule_id for a in alerts]
    assert "ICS-004" in rule_ids
    assert any(a.mitre_id == "T0816" for a in alerts)


def test_flooding():
    monitor = TrafficMonitor(hmi_ip="10.0.10.50")
    engine = DetectionEngine(monitor, hmi_ip="10.0.10.50")

    # Simulate high rate
    now = time.time()
    for i in range(60):
        monitor._rate["10.0.10.99"].append(now - i * 0.1)

    tx = make_tx(time=now)
    alerts = engine.evaluate(tx)
    rule_ids = [a.rule_id for a in alerts]
    assert "ICS-005" in rule_ids

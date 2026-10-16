"""CLI entry point for the Forge ICS lab.

Usage:
    python -m forge run           # Start PLC + HMI + monitor + dashboard
    python -m forge run --no-hmi  # Start without the automated HMI
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from forge.dashboard.server import Dashboard
from forge.detect.engine import DetectionEngine
from forge.events import EventBus
from forge.monitor.baseline import ProcessBaseline
from forge.monitor.capture import TrafficMonitor
from forge.simulator.hmi import HMI
from forge.simulator.plc import PLCServer
from forge.simulator.process import PlantState

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("forge")


async def run_lab(args: argparse.Namespace) -> None:
    plant = PlantState()
    bus = EventBus()
    monitor = TrafficMonitor(hmi_ip="127.0.0.1")
    detector = DetectionEngine(monitor, hmi_ip="127.0.0.1")
    baseline = ProcessBaseline()

    def on_traffic(src_ip: str, src_port: int, frame) -> None:
        tx = monitor.on_frame(src_ip, src_port, frame)
        alerts = detector.evaluate(tx)
        for alert in alerts:
            bus.publish(alert)

    plc = PLCServer(
        plant,
        host=args.host,
        port=args.plc_port,
        unit_id=1,
        on_traffic=on_traffic,
    )
    dashboard = Dashboard(plant, bus, monitor, host=args.host, port=args.dash_port)

    await plc.start()
    await dashboard.start()

    tasks: list[asyncio.Task] = [asyncio.create_task(bus.run())]

    if not args.no_hmi:
        hmi = HMI(plc_host="127.0.0.1", plc_port=args.plc_port)
        tasks.append(asyncio.create_task(hmi.run()))

    # Baseline check loop
    async def baseline_loop() -> None:
        while True:
            anomalies = baseline.update(plant.snapshot())
            for desc in anomalies:
                from forge.events import Alert

                bus.publish(Alert(
                    rule_id="ICS-007",
                    title="Process baseline deviation",
                    severity="medium",
                    src_ip="process",
                    detail=desc,
                    mitre_id="T0831",
                    mitre_tactic="Impair Process Control",
                ))
            await asyncio.sleep(2)

    tasks.append(asyncio.create_task(baseline_loop()))

    log.info("Forge ICS lab running")
    log.info("  PLC (Modbus TCP) on port %d", args.plc_port)
    log.info("  Dashboard at http://%s:%d", args.host, args.dash_port)
    log.info("  HMI %s", "connected" if not args.no_hmi else "disabled")

    await asyncio.gather(*tasks)


def main() -> None:
    parser = argparse.ArgumentParser(prog="forge", description="Forge ICS/SCADA security lab")
    sub = parser.add_subparsers(dest="command")

    run_p = sub.add_parser("run", help="Start the full lab")
    run_p.add_argument("--host", default="0.0.0.0")
    run_p.add_argument("--plc-port", type=int, default=5020)
    run_p.add_argument("--dash-port", type=int, default=8080)
    run_p.add_argument("--no-hmi", action="store_true", help="Skip the automated HMI")

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "run":
        asyncio.run(run_lab(args))


if __name__ == "__main__":
    main()

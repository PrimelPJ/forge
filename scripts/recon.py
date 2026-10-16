"""Modbus reconnaissance: enumerate unit IDs and function codes.

Scans the PLC for responsive unit IDs and probes each supported function
code.  This is the ICS equivalent of a port scan - a common first step
in OT network reconnaissance (MITRE ATT&CK for ICS: T0846).

Usage:
    python scripts/recon.py [--host 127.0.0.1] [--port 5020]
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time

sys.path.insert(0, ".")
from forge.protocol.modbus import (
    FC,
    MBAP_HEADER_SIZE,
    frame_length,
    parse_frame,
    read_coils,
    read_holding_registers,
    read_input_registers,
)


def probe(sock: socket.socket, request: bytes, timeout: float = 1.0) -> bytes | None:
    try:
        sock.sendall(request)
        sock.settimeout(timeout)
        data = sock.recv(256)
        return data if data else None
    except (socket.timeout, OSError):
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Modbus reconnaissance scanner")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5020)
    parser.add_argument("--unit-start", type=int, default=1)
    parser.add_argument("--unit-end", type=int, default=10)
    args = parser.parse_args()

    print(f"[*] Scanning {args.host}:{args.port} for Modbus devices")
    print(f"[*] Unit ID range: {args.unit_start}-{args.unit_end}\n")

    tid = 0
    found = []

    for uid in range(args.unit_start, args.unit_end + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            sock.connect((args.host, args.port))
        except OSError:
            print(f"[-] Cannot connect to {args.host}:{args.port}")
            return

        tid += 1
        resp = probe(sock, read_input_registers(tid, uid, 0, 1))
        if resp:
            frame = parse_frame(resp)
            if frame and not frame.is_error:
                print(f"[+] Unit ID {uid}: ALIVE - responds to input register reads")
                found.append(uid)

                # Probe function codes
                for fc_name, builder in [
                    ("Read Coils (0x01)", read_coils),
                    ("Read Holding Registers (0x03)", read_holding_registers),
                    ("Read Input Registers (0x04)", read_input_registers),
                ]:
                    tid += 1
                    r = probe(sock, builder(tid, uid, 0, 1))
                    if r:
                        f = parse_frame(r)
                        if f and not f.is_error:
                            print(f"    [+] {fc_name}: supported")
                        else:
                            print(f"    [-] {fc_name}: error response")
            else:
                print(f"[-] Unit ID {uid}: no response or error")
        else:
            print(f"[-] Unit ID {uid}: no response")

        sock.close()
        time.sleep(0.1)

    print(f"\n[*] Scan complete. Found {len(found)} device(s): {found}")


if __name__ == "__main__":
    main()

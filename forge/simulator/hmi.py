"""HMI client that polls the PLC and maintains a normal operating cycle.

The HMI reads process values every second and adjusts actuators to keep the
plant in a safe operating range.  It represents the legitimate traffic
baseline that the monitor uses to distinguish normal from malicious.
"""

from __future__ import annotations

import asyncio
import logging
import struct

from forge.protocol.modbus import (
    FC,
    frame_length,
    parse_frame,
    read_coils,
    read_input_registers,
    write_single_coil,
    write_single_register,
)

log = logging.getLogger(__name__)


class HMI:
    def __init__(self, plc_host: str = "127.0.0.1", plc_port: int = 5020, unit_id: int = 1) -> None:
        self.plc_host = plc_host
        self.plc_port = plc_port
        self.unit_id = unit_id
        self._tid = 0
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    def _next_tid(self) -> int:
        self._tid = (self._tid + 1) & 0xFFFF
        return self._tid

    async def connect(self) -> None:
        self._reader, self._writer = await asyncio.open_connection(self.plc_host, self.plc_port)
        log.info("HMI connected to PLC at %s:%d", self.plc_host, self.plc_port)

    async def _transact(self, request: bytes) -> bytes:
        assert self._writer and self._reader
        self._writer.write(request)
        await self._writer.drain()
        buf = b""
        while True:
            chunk = await self._reader.read(4096)
            if not chunk:
                raise ConnectionError("PLC closed connection")
            buf += chunk
            flen = frame_length(buf)
            if flen and len(buf) >= flen:
                return buf[:flen]

    async def read_input_regs(self, start: int, count: int) -> list[int]:
        resp_raw = await self._transact(
            read_input_registers(self._next_tid(), self.unit_id, start, count)
        )
        frame = parse_frame(resp_raw)
        if frame is None or frame.is_error:
            return []
        byte_count = frame.data[0]
        values = struct.unpack(f">{byte_count // 2}H", frame.data[1 : 1 + byte_count])
        return list(values)

    async def read_coil_values(self, start: int, count: int) -> list[bool]:
        resp_raw = await self._transact(
            read_coils(self._next_tid(), self.unit_id, start, count)
        )
        frame = parse_frame(resp_raw)
        if frame is None or frame.is_error:
            return []
        coil_byte = frame.data[1]
        return [bool(coil_byte & (1 << i)) for i in range(count)]

    async def write_coil(self, address: int, value: bool) -> None:
        await self._transact(
            write_single_coil(self._next_tid(), self.unit_id, address, value)
        )

    async def write_register(self, address: int, value: int) -> None:
        await self._transact(
            write_single_register(self._next_tid(), self.unit_id, address, value)
        )

    async def run(self) -> None:
        """Control loop: keep tank level between 30-70% and chlorine around 3 mg/L."""
        await self.connect()

        while True:
            try:
                regs = await self.read_input_regs(0, 5)
                if not regs:
                    await asyncio.sleep(1)
                    continue

                tank = regs[0] / 100.0
                chlorine = regs[1] / 100.0

                # Tank level control
                if tank < 30:
                    await self.write_coil(0, True)   # intake on
                    await self.write_coil(2, False)  # outlet off
                elif tank > 70:
                    await self.write_coil(0, False)  # intake off
                    await self.write_coil(2, True)   # outlet on
                elif tank > 50:
                    await self.write_coil(2, True)

                # Chlorine control
                if chlorine < 2.0:
                    await self.write_coil(1, True)
                elif chlorine > 4.0:
                    await self.write_coil(1, False)

                await asyncio.sleep(2)

            except ConnectionError:
                log.warning("Lost connection to PLC, reconnecting...")
                await asyncio.sleep(3)
                try:
                    await self.connect()
                except OSError:
                    pass

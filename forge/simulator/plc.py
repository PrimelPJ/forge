"""Modbus TCP PLC simulator.

Runs a TCP server that speaks Modbus, backed by the water treatment plant
simulation.  Every second the process physics tick forward and register
values update.  Clients (the HMI, or an attacker) read and write over
standard Modbus function codes.
"""

from __future__ import annotations

import asyncio
import logging
import struct
import time
from typing import Any, Callable

from forge.protocol.modbus import (
    FC,
    ILLEGAL_DATA_ADDRESS,
    ILLEGAL_FUNCTION,
    Frame,
    error_response,
    frame_length,
    parse_frame,
    read_coils_response,
    read_registers_response,
    write_single_coil_response,
    write_single_register_response,
)
from forge.simulator.process import PlantState

log = logging.getLogger(__name__)

TrafficCallback = Callable[[str, int, Frame], Any]


class PLCServer:
    """Asyncio Modbus TCP server wrapping a PlantState."""

    def __init__(
        self,
        state: PlantState,
        host: str = "0.0.0.0",
        port: int = 5020,
        unit_id: int = 1,
        on_traffic: TrafficCallback | None = None,
    ) -> None:
        self.state = state
        self.host = host
        self.port = port
        self.unit_id = unit_id
        self._on_traffic = on_traffic
        self._server: asyncio.Server | None = None
        self._tick_task: asyncio.Task | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        self._tick_task = asyncio.create_task(self._tick_loop())
        log.info("PLC (unit %d) listening on %s:%d", self.unit_id, self.host, self.port)

    async def stop(self) -> None:
        if self._tick_task:
            self._tick_task.cancel()
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _tick_loop(self) -> None:
        while True:
            self.state.tick()
            await asyncio.sleep(1.0)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        src_ip, src_port = str(peer[0]), int(peer[1])
        buf = b""
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                buf += data
                while True:
                    flen = frame_length(buf)
                    if flen is None:
                        break
                    raw, buf = buf[:flen], buf[flen:]
                    frame = parse_frame(raw)
                    if frame is None:
                        continue
                    if self._on_traffic:
                        self._on_traffic(src_ip, src_port, frame)
                    resp = self._process(frame)
                    if resp:
                        writer.write(resp)
                        await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()

    def _process(self, frame: Frame) -> bytes | None:
        tid = frame.transaction_id
        uid = frame.unit_id
        fc = frame.function_code
        data = frame.data

        if uid != self.unit_id and uid != 0:
            return None

        try:
            if fc == FC.READ_COILS:
                start, count = struct.unpack(">HH", data[:4])
                values = self.state.get_coils(start, count)
                return read_coils_response(tid, uid, values)

            elif fc == FC.READ_DISCRETE_INPUTS:
                start, count = struct.unpack(">HH", data[:4])
                values = self.state.get_discrete_inputs(start, count)
                return read_coils_response(tid, uid, values)

            elif fc == FC.READ_HOLDING_REGISTERS:
                start, count = struct.unpack(">HH", data[:4])
                values = self.state.get_holding_registers(start, count)
                return read_registers_response(tid, uid, FC.READ_HOLDING_REGISTERS, values)

            elif fc == FC.READ_INPUT_REGISTERS:
                start, count = struct.unpack(">HH", data[:4])
                values = self.state.get_input_registers(start, count)
                return read_registers_response(tid, uid, FC.READ_INPUT_REGISTERS, values)

            elif fc == FC.WRITE_SINGLE_COIL:
                addr, val = struct.unpack(">HH", data[:4])
                self.state.set_coil(addr, val == 0xFF00)
                return write_single_coil_response(tid, uid, addr, val == 0xFF00)

            elif fc == FC.WRITE_SINGLE_REGISTER:
                addr, val = struct.unpack(">HH", data[:4])
                self.state.set_holding_register(addr, val)
                return write_single_register_response(tid, uid, addr, val)

            else:
                return error_response(tid, uid, fc, ILLEGAL_FUNCTION)

        except (struct.error, IndexError):
            return error_response(tid, uid, fc, ILLEGAL_DATA_ADDRESS)

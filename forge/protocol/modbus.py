"""Modbus TCP protocol: frame parsing and building.

Implements enough of the Modbus TCP specification (MBAP header + the function
codes used in water treatment SCADA) to simulate PLCs, parse captured traffic,
and craft attack packets.

Reference: Modbus Application Protocol Specification V1.1b3
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

MBAP_HEADER_SIZE = 7
PROTOCOL_ID = 0x0000


class FC(IntEnum):
    """Modbus function codes used in the lab."""

    READ_COILS = 0x01
    READ_DISCRETE_INPUTS = 0x02
    READ_HOLDING_REGISTERS = 0x03
    READ_INPUT_REGISTERS = 0x04
    WRITE_SINGLE_COIL = 0x05
    WRITE_SINGLE_REGISTER = 0x06
    WRITE_MULTIPLE_COILS = 0x0F
    WRITE_MULTIPLE_REGISTERS = 0x10


ERROR_FLAG = 0x80

WRITE_CODES = {
    FC.WRITE_SINGLE_COIL,
    FC.WRITE_SINGLE_REGISTER,
    FC.WRITE_MULTIPLE_COILS,
    FC.WRITE_MULTIPLE_REGISTERS,
}

READ_CODES = {
    FC.READ_COILS,
    FC.READ_DISCRETE_INPUTS,
    FC.READ_HOLDING_REGISTERS,
    FC.READ_INPUT_REGISTERS,
}


@dataclass
class MBAPHeader:
    transaction_id: int
    protocol_id: int
    length: int
    unit_id: int

    def pack(self) -> bytes:
        return struct.pack(
            ">HHHB",
            self.transaction_id,
            self.protocol_id,
            self.length,
            self.unit_id,
        )

    @classmethod
    def unpack(cls, data: bytes) -> MBAPHeader:
        if len(data) < MBAP_HEADER_SIZE:
            raise ValueError(f"need {MBAP_HEADER_SIZE} bytes, got {len(data)}")
        tid, pid, length, uid = struct.unpack(">HHHB", data[:MBAP_HEADER_SIZE])
        return cls(tid, pid, length, uid)


@dataclass
class Frame:
    """A parsed Modbus TCP frame (MBAP header + PDU)."""

    header: MBAPHeader
    function_code: int
    data: bytes

    @property
    def is_error(self) -> bool:
        return bool(self.function_code & ERROR_FLAG)

    @property
    def is_write(self) -> bool:
        return (self.function_code & ~ERROR_FLAG) in WRITE_CODES

    @property
    def is_read(self) -> bool:
        return (self.function_code & ~ERROR_FLAG) in READ_CODES

    @property
    def unit_id(self) -> int:
        return self.header.unit_id

    @property
    def transaction_id(self) -> int:
        return self.header.transaction_id

    def pack(self) -> bytes:
        pdu = bytes([self.function_code]) + self.data
        hdr = MBAPHeader(
            self.header.transaction_id,
            PROTOCOL_ID,
            len(pdu) + 1,
            self.header.unit_id,
        )
        return hdr.pack() + pdu

    @classmethod
    def unpack(cls, data: bytes) -> Frame:
        hdr = MBAPHeader.unpack(data)
        fc = data[MBAP_HEADER_SIZE]
        end = 6 + hdr.length
        payload = data[MBAP_HEADER_SIZE + 1 : end]
        return cls(hdr, fc, payload)


def parse_frame(data: bytes) -> Frame | None:
    """Try to parse a single Modbus TCP frame. Returns None on failure."""
    if len(data) < MBAP_HEADER_SIZE + 1:
        return None
    try:
        return Frame.unpack(data)
    except (struct.error, ValueError, IndexError):
        return None


def frame_length(data: bytes) -> int | None:
    """Return the total byte length of the first frame in the buffer, or None if incomplete."""
    if len(data) < MBAP_HEADER_SIZE:
        return None
    length = struct.unpack(">H", data[4:6])[0]
    total = 6 + length
    return total if len(data) >= total else None


# --- Request builders ---


def _request(tid: int, uid: int, fc: int, data: bytes) -> bytes:
    pdu = bytes([fc]) + data
    hdr = MBAPHeader(tid, PROTOCOL_ID, len(pdu) + 1, uid)
    return hdr.pack() + pdu


def read_coils(tid: int, uid: int, start: int, count: int) -> bytes:
    return _request(tid, uid, FC.READ_COILS, struct.pack(">HH", start, count))


def read_discrete_inputs(tid: int, uid: int, start: int, count: int) -> bytes:
    return _request(tid, uid, FC.READ_DISCRETE_INPUTS, struct.pack(">HH", start, count))


def read_holding_registers(tid: int, uid: int, start: int, count: int) -> bytes:
    return _request(tid, uid, FC.READ_HOLDING_REGISTERS, struct.pack(">HH", start, count))


def read_input_registers(tid: int, uid: int, start: int, count: int) -> bytes:
    return _request(tid, uid, FC.READ_INPUT_REGISTERS, struct.pack(">HH", start, count))


def write_single_coil(tid: int, uid: int, address: int, value: bool) -> bytes:
    val = 0xFF00 if value else 0x0000
    return _request(tid, uid, FC.WRITE_SINGLE_COIL, struct.pack(">HH", address, val))


def write_single_register(tid: int, uid: int, address: int, value: int) -> bytes:
    return _request(tid, uid, FC.WRITE_SINGLE_REGISTER, struct.pack(">HH", address, value))


# --- Response builders ---


def read_coils_response(tid: int, uid: int, values: list[bool]) -> bytes:
    byte_count = (len(values) + 7) // 8
    result = bytearray(byte_count)
    for i, v in enumerate(values):
        if v:
            result[i // 8] |= 1 << (i % 8)
    return _request(tid, uid, FC.READ_COILS, bytes([byte_count]) + bytes(result))


def read_registers_response(tid: int, uid: int, fc: int, values: list[int]) -> bytes:
    byte_count = len(values) * 2
    data = bytes([byte_count]) + struct.pack(f">{len(values)}H", *values)
    return _request(tid, uid, fc, data)


def write_single_coil_response(tid: int, uid: int, address: int, value: bool) -> bytes:
    val = 0xFF00 if value else 0x0000
    return _request(tid, uid, FC.WRITE_SINGLE_COIL, struct.pack(">HH", address, val))


def write_single_register_response(tid: int, uid: int, address: int, value: int) -> bytes:
    return _request(tid, uid, FC.WRITE_SINGLE_REGISTER, struct.pack(">HH", address, value))


def error_response(tid: int, uid: int, fc: int, exception_code: int) -> bytes:
    return _request(tid, uid, fc | ERROR_FLAG, bytes([exception_code]))


# Exception codes
ILLEGAL_FUNCTION = 0x01
ILLEGAL_DATA_ADDRESS = 0x02
ILLEGAL_DATA_VALUE = 0x03


# Modbus exception codes (IEC 61158).
# Used for classifying PLC error responses in the traffic monitor.
EXCEPTION_CODES = {
    0x01: "ILLEGAL_FUNCTION",
    0x02: "ILLEGAL_DATA_ADDRESS",
    0x03: "ILLEGAL_DATA_VALUE",
    0x04: "SERVER_DEVICE_FAILURE",
    0x05: "ACKNOWLEDGE",
    0x06: "SERVER_DEVICE_BUSY",
    0x08: "MEMORY_PARITY_ERROR",
    0x0A: "GATEWAY_PATH_UNAVAILABLE",
    0x0B: "GATEWAY_TARGET_DEVICE_FAILED",
}


def describe_exception(code: int) -> str:
    """Return human-readable name for a Modbus exception code."""
    return EXCEPTION_CODES.get(code, f"UNKNOWN_EXCEPTION(0x{code:02X})")

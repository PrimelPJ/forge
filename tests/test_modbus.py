"""Tests for the Modbus TCP protocol layer."""

from forge.protocol.modbus import (
    FC,
    Frame,
    MBAPHeader,
    frame_length,
    parse_frame,
    read_coils,
    read_holding_registers,
    read_input_registers,
    write_single_coil,
    write_single_register,
)


def test_mbap_pack_unpack():
    hdr = MBAPHeader(transaction_id=1, protocol_id=0, length=6, unit_id=1)
    raw = hdr.pack()
    assert len(raw) == 7
    parsed = MBAPHeader.unpack(raw)
    assert parsed.transaction_id == 1
    assert parsed.unit_id == 1
    assert parsed.length == 6


def test_frame_round_trip():
    req = read_input_registers(42, 1, 0, 5)
    frame = parse_frame(req)
    assert frame is not None
    assert frame.transaction_id == 42
    assert frame.unit_id == 1
    assert frame.function_code == FC.READ_INPUT_REGISTERS
    assert frame.is_read
    assert not frame.is_write


def test_write_single_coil_frame():
    req = write_single_coil(10, 1, 0, True)
    frame = parse_frame(req)
    assert frame is not None
    assert frame.is_write
    assert not frame.is_read
    assert frame.function_code == FC.WRITE_SINGLE_COIL


def test_write_single_register_frame():
    req = write_single_register(11, 1, 2, 500)
    frame = parse_frame(req)
    assert frame is not None
    assert frame.is_write


def test_frame_length():
    req = read_coils(1, 1, 0, 4)
    assert frame_length(req) == len(req)
    assert frame_length(req[:3]) is None  # incomplete


def test_parse_garbage():
    assert parse_frame(b"\x00\x01") is None
    assert parse_frame(b"") is None

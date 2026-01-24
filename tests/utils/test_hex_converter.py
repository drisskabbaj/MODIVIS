import pytest

import src.utils.hex_converter as hex_converter


# Test that bytes_from_hex accepts spaces/newlines/tabs and returns the same bytes.
def test_bytes_from_hex_accepts_spaces_newlines_tabs(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(hex_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(hex_converter, "log_error", lambda msg: error_calls.append(msg))

    s1 = "0a ff 10"
    s2 = "0A\nFF\t10"
    s3 = "0aff10"

    b1 = hex_converter.bytes_from_hex(s1)
    b2 = hex_converter.bytes_from_hex(s2)
    b3 = hex_converter.bytes_from_hex(s3)

    assert b1 == b2 == b3 == b"\x0a\xff\x10"
    assert error_calls == []
    assert len(debug_calls) == 3


# Test empty input:
# - it should return b""
# - log a success message (caller mainly viewmodel validates required lengths later).
def test_bytes_from_hex_empty_string_returns_empty_bytes(monkeypatch):
    warning_calls: list[str] = []
    error_calls: list[str] = []

    # hex_converter logs empty as DEBUG (not warning)
    monkeypatch.setattr(hex_converter, "log_debug", lambda msg: warning_calls.append(msg))
    monkeypatch.setattr(hex_converter, "log_error", lambda msg: error_calls.append(msg))

    out = hex_converter.bytes_from_hex(" \n\t ")

    assert out == b""
    assert error_calls == []
    assert len(warning_calls) == 1
    assert "len=0" in warning_calls[0]
    assert "Converting empty hex to bytes" in warning_calls[0]


# Test odd hex length:
# - must log error
# - raise ValueError
# - not log success.
def test_bytes_from_hex_odd_length_raises_and_logs_error(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(hex_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(hex_converter, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="even number of characters"):
        hex_converter.bytes_from_hex("0af")  # 3 chars is ofc logicly invalid

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "odd length" in error_calls[0]


# Test non-hex characters:
# - must log error
# - raise ValueError with the clear friendly message :)
def test_bytes_from_hex_non_hex_characters_raises_and_logs_error(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(hex_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(hex_converter, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="non-hex characters"):
        hex_converter.bytes_from_hex("zz11")  # invalid non hex

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "non-hex characters" in error_calls[0]


# Test wrong input type:
# - must log error
# - raise TypeError with clear friendly message :)
@pytest.mark.parametrize("value", [123, None, b"0aff", bytearray(b"0aff")])
def test_bytes_from_hex_wrong_type_raises_and_logs_error(monkeypatch, value):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(hex_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(hex_converter, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(TypeError, match="Conversion from HEX to Bytes failed: input must be a string."):
        hex_converter.bytes_from_hex(value)

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "invalid type" in error_calls[0]
    assert "type(s)=" in error_calls[0]


# Test "full" workflow: bytes to hex, then hex to bytes must give the same original bytes.
def test_hex_from_bytes_workflow(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(hex_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(hex_converter, "log_error", lambda msg: error_calls.append(msg))

    original = b"\x00\x10\xff"
    h = hex_converter.hex_from_bytes(original)
    back = hex_converter.bytes_from_hex(h)

    assert h == "0010ff"
    assert back == original
    assert error_calls == []
    assert len(debug_calls) == 2  # one for hex_from_bytes + one for bytes_from_hex


# Test that hex_from_bytes accepts bytearray and always returns lowercase hex.
def test_hex_from_bytes_accepts_bytearray_and_lowercase(monkeypatch):
    debug_calls: list[str] = []
    monkeypatch.setattr(hex_converter, "log_debug", lambda msg: debug_calls.append(msg))

    out = hex_converter.hex_from_bytes(bytearray(b"\x0A\xFF"))

    assert out == "0aff"
    assert len(debug_calls) == 1
    assert "Converted Bytes to HEX" in debug_calls[0]


# Test wrong type for hex_from_bytes:
# - must log error
# - raise TypeError
# - not log success
@pytest.mark.parametrize("value", ["00ff", 123, None])
def test_hex_from_bytes_wrong_type_raises_and_logs_error(monkeypatch, value):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(hex_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(hex_converter, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(TypeError, match="Conversion from Bytes to HEX failed: input must be bytes."):
        hex_converter.hex_from_bytes(value)

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "invalid type" in error_calls[0]
    assert "type(b)=" in error_calls[0]


# Test empty bytes input:
# - it should return ""
# - log a warning message (empty input).
def test_hex_from_bytes_empty_bytes_returns_empty_string(monkeypatch):
    warning_calls: list[str] = []
    error_calls: list[str] = []

    # hex_converter logs empty as DEBUG (not warning)
    monkeypatch.setattr(hex_converter, "log_debug", lambda msg: warning_calls.append(msg))
    monkeypatch.setattr(hex_converter, "log_error", lambda msg: error_calls.append(msg))

    out = hex_converter.hex_from_bytes(b"")

    assert out == ""
    assert error_calls == []
    assert len(warning_calls) == 1
    assert "len=0" in warning_calls[0]
    assert "Converting empty bytes to HEX" in warning_calls[0]

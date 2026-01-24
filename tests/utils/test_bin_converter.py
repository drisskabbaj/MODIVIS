import pytest

import src.utils.bin_converter as bin_converter


# Test that bytes_from_bin accepts spaces/newlines/tabs and returns the same bytes.
def test_bytes_from_bin_accepts_spaces_newlines_tabs(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(bin_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(bin_converter, "log_error", lambda msg: error_calls.append(msg))

    s1 = "01000001 11110000"
    s2 = "0B01000001\n11110000"
    s3 = "0100000111110000"

    b1 = bin_converter.bytes_from_bin(s1)
    b2 = bin_converter.bytes_from_bin(s2)
    b3 = bin_converter.bytes_from_bin(s3)

    assert b1 == b2 == b3 == b"\x41\xf0"
    assert error_calls == []
    assert len(debug_calls) == 3


# Test empty input:
# - it should return b""
# - log a success message (caller mainly viewmodel validates required lengths later).
def test_bytes_from_bin_empty_string_returns_empty_bytes(monkeypatch):
    warning_calls: list[str] = []
    error_calls: list[str] = []

    # bin_converter logs empty as DEBUG (not warning)
    monkeypatch.setattr(bin_converter, "log_debug", lambda msg: warning_calls.append(msg))
    monkeypatch.setattr(bin_converter, "log_error", lambda msg: error_calls.append(msg))

    out = bin_converter.bytes_from_bin(" \n\t ")

    assert out == b""
    assert error_calls == []
    assert len(warning_calls) == 1
    assert "len=0" in warning_calls[0]
    assert "Converting empty bin to bytes" in warning_calls[0]


# Test not byte-aligned BIN length:
# - must log error
# - raise ValueError
# - not log success.
def test_bytes_from_bin_not_byte_aligned_raises_and_logs_error(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(bin_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(bin_converter, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="multiple of 8"):
        bin_converter.bytes_from_bin("0101")  # 4 bits so not a full byte

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "not byte-aligned" in error_calls[0]


# Test non-binary characters:
# - must log error
# - raise ValueError with the clear friendly message :)
def test_bytes_from_bin_non_binary_characters_raises_and_logs_error(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(bin_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(bin_converter, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="non-binary characters"):
        bin_converter.bytes_from_bin("01000002")  # invalid bc contains 2

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "non-binary characters" in error_calls[0]


# Test wrong input type:
# - must log error
# - raise TypeError with clear friendly message :)
@pytest.mark.parametrize("value", [123, None, b"01000001", bytearray(b"01000001")])
def test_bytes_from_bin_wrong_type_raises_and_logs_error(monkeypatch, value):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(bin_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(bin_converter, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(TypeError, match="Conversion from BIN to Bytes failed: input must be a string."):
        bin_converter.bytes_from_bin(value)

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "invalid type" in error_calls[0]
    assert "type(s)=" in error_calls[0]


# Test "full" workflow: bytes to bin, then bin to bytes must give the same original bytes.
def test_bin_from_bytes_workflow(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(bin_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(bin_converter, "log_error", lambda msg: error_calls.append(msg))

    original = b"\x00\x10\xff"
    bstr = bin_converter.bin_from_bytes(original)
    back = bin_converter.bytes_from_bin(bstr)

    assert bstr == "000000000001000011111111"
    assert back == original
    assert error_calls == []
    assert len(debug_calls) == 2  # one for bin_from_bytes + one for bytes_from_bin


# Test that bin_from_bytes accepts bytearray and always returns only 0/1.
def test_bin_from_bytes_accepts_bytearray(monkeypatch):
    debug_calls: list[str] = []
    monkeypatch.setattr(bin_converter, "log_debug", lambda msg: debug_calls.append(msg))

    out = bin_converter.bin_from_bytes(bytearray(b"\x41\xf0"))

    assert out == "0100000111110000"
    assert set(out) <= {"0", "1"}
    assert len(debug_calls) == 1
    assert "Converted Bytes to BIN" in debug_calls[0]


# Test wrong type for bin_from_bytes:
# - must log error
# - raise TypeError
# - not log success
@pytest.mark.parametrize("value", ["0101", 123, None])
def test_bin_from_bytes_wrong_type_raises_and_logs_error(monkeypatch, value):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(bin_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(bin_converter, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(TypeError, match="Conversion from Bytes to BIN failed: input must be bytes."):
        bin_converter.bin_from_bytes(value)

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "invalid type" in error_calls[0]
    assert "type(b)=" in error_calls[0]


# Test empty bytes input:
# - it should return ""
# - log a warning message (empty input).
def test_bin_from_bytes_empty_bytes_returns_empty_string(monkeypatch):
    warning_calls: list[str] = []
    error_calls: list[str] = []

    # bin_converter logs empty as DEBUG (not warning)
    monkeypatch.setattr(bin_converter, "log_debug", lambda msg: warning_calls.append(msg))
    monkeypatch.setattr(bin_converter, "log_error", lambda msg: error_calls.append(msg))

    out = bin_converter.bin_from_bytes(b"")

    assert out == ""
    assert error_calls == []
    assert len(warning_calls) == 1
    assert "len=0" in warning_calls[0]
    assert "Converting empty bytes to BIN" in warning_calls[0]

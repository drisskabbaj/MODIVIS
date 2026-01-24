import pytest

import src.utils.nibble_formatting as nibble_formatting


# Test that format_symbol returns uppercase HEX for valid nibble values.
def test_format_symbol_hex_returns_uppercase_hex(monkeypatch):
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_formatting, "log_error", lambda msg: error_calls.append(msg))

    assert nibble_formatting.format_symbol(0, "HEX") == "0"
    assert nibble_formatting.format_symbol(10, "HEX") == "A"
    assert nibble_formatting.format_symbol(15, "HEX") == "F"
    assert error_calls == []


# Test that format_symbol returns 4-bit BIN for valid nibble values.
def test_format_symbol_bin_returns_4bit_bin(monkeypatch):
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_formatting, "log_error", lambda msg: error_calls.append(msg))

    assert nibble_formatting.format_symbol(0, "BIN") == "0000"
    assert nibble_formatting.format_symbol(10, "BIN") == "1010"
    assert nibble_formatting.format_symbol(15, "BIN") == "1111"
    assert error_calls == []


# Test invalid fmt in format_symbol:
# - must log error
# - raise ValueError with the clear friendly message :)
def test_format_symbol_invalid_fmt_raises_and_logs_error(monkeypatch):
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_formatting, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="Nibble formatting failed: fmt must be HEX or BIN."):
        nibble_formatting.format_symbol(10, "DEC")

    assert len(error_calls) == 1
    assert "invalid fmt" in error_calls[0]
    assert "module=nibble_formatting" in error_calls[0]
    assert "func=format_symbol" in error_calls[0]
    assert "fmt='DEC'" in error_calls[0]


# Test wrong input type for format_symbol:
# - must log error
# - raise TypeError with the clear friendly message :)
@pytest.mark.parametrize("value", ["10", None, 10.5, b"\x0a", bytearray(b"\x0a")])
def test_format_symbol_wrong_type_raises_and_logs_error(monkeypatch, value):
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_formatting, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(TypeError, match="Nibble formatting failed: x must be an integer."):
        nibble_formatting.format_symbol(value, "HEX")

    assert len(error_calls) == 1
    assert "invalid type" in error_calls[0]
    assert "module=nibble_formatting" in error_calls[0]
    assert "func=format_symbol" in error_calls[0]
    assert "type(x)=" in error_calls[0]
    assert "fmt='HEX'" in error_calls[0]


# Test out-of-range x for format_symbol:
# - must log error
# - raise ValueError with the clear friendly message :)
@pytest.mark.parametrize("x", [-1, 16, 999])
def test_format_symbol_out_of_range_raises_and_logs_error(monkeypatch, x):
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_formatting, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="Nibble formatting failed: x must be in range 0..15."):
        nibble_formatting.format_symbol(x, "BIN")

    assert len(error_calls) == 1
    assert "out of range" in error_calls[0]
    assert "module=nibble_formatting" in error_calls[0]
    assert "func=format_symbol" in error_calls[0]
    assert f"x={x}" in error_calls[0]
    assert "fmt='BIN'" in error_calls[0]


# Test that format_tuple returns the correct HEX tuple format.
def test_format_tuple_hex_returns_tuple_string(monkeypatch):
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_formatting, "log_error", lambda msg: error_calls.append(msg))

    out = nibble_formatting.format_tuple([15, 0, 10, 3], "HEX")

    assert out == "(F, 0, A, 3)"
    assert error_calls == []


# Test that format_tuple returns the correct BIN tuple format.
def test_format_tuple_bin_returns_tuple_string(monkeypatch):
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_formatting, "log_error", lambda msg: error_calls.append(msg))

    out = nibble_formatting.format_tuple([15, 0, 10, 3], "BIN")

    assert out == "(1111, 0000, 1010, 0011)"
    assert error_calls == []


# Test that format_tuple accepts empty list and returns "()".
def test_format_tuple_empty_list_returns_empty_tuple(monkeypatch):
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_formatting, "log_error", lambda msg: error_calls.append(msg))

    out = nibble_formatting.format_tuple([], "HEX")

    assert out == "()"
    assert error_calls == []


# Test invalid fmt in format_tuple:
# - must log error
# - raise ValueError with the clear friendly message :)
def test_format_tuple_invalid_fmt_raises_and_logs_error(monkeypatch):
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_formatting, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="Nibble formatting failed: fmt must be HEX or BIN."):
        nibble_formatting.format_tuple([1, 2, 3], "DEC")

    assert len(error_calls) == 1
    assert "invalid fmt" in error_calls[0]
    assert "module=nibble_formatting" in error_calls[0]
    assert "func=format_tuple" in error_calls[0]
    assert "fmt='DEC'" in error_calls[0]


# Test wrong input type for values in format_tuple:
# - must log error
# - raise TypeError with the clear friendly message :)
@pytest.mark.parametrize("value", ["(1,2)", None, 123, b"\x01\x02", bytearray(b"\x01\x02")])
def test_format_tuple_wrong_type_for_values_raises_and_logs_error(monkeypatch, value):
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_formatting, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(TypeError, match="Nibble formatting failed: values must be a list of integers."):
        nibble_formatting.format_tuple(value, "HEX")

    assert len(error_calls) == 1
    assert "invalid type" in error_calls[0]
    assert "module=nibble_formatting" in error_calls[0]
    assert "func=format_tuple" in error_calls[0]
    assert "type(values)=" in error_calls[0]
    assert "fmt='HEX'" in error_calls[0]


# Test invalid element type inside values:
# - must log error
# - raise TypeError with the clear friendly message :)
def test_format_tuple_invalid_element_type_raises_and_logs_error(monkeypatch):
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_formatting, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(TypeError, match="Nibble formatting failed: values must contain only integers."):
        nibble_formatting.format_tuple([1, "2", 3], "BIN")

    assert len(error_calls) == 1
    assert "invalid element type" in error_calls[0]
    assert "module=nibble_formatting" in error_calls[0]
    assert "func=format_tuple" in error_calls[0]
    assert "index=1" in error_calls[0]
    assert "type(x)=" in error_calls[0]
    assert "fmt='BIN'" in error_calls[0]


# Test out-of-range element inside values:
# - must log error
# - raise ValueError with the clear friendly message :)
def test_format_tuple_element_out_of_range_raises_and_logs_error(monkeypatch):
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_formatting, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="Nibble formatting failed: all values must be in range 0..15."):
        nibble_formatting.format_tuple([0, 16, 1], "HEX")

    assert len(error_calls) == 1
    assert "element out of range" in error_calls[0]
    assert "module=nibble_formatting" in error_calls[0]
    assert "func=format_tuple" in error_calls[0]
    assert "index=1" in error_calls[0]
    assert "x=16" in error_calls[0]
    assert "fmt='HEX'" in error_calls[0]


# Test full workflow: format_tuple should call format_symbol on each element and produce stable output.
def test_format_tuple_workflow_is_stable(monkeypatch):
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_formatting, "log_error", lambda msg: error_calls.append(msg))

    out_hex = nibble_formatting.format_tuple([15, 0, 10, 1], "HEX")
    out_bin = nibble_formatting.format_tuple([15, 0, 10, 1], "BIN")

    assert out_hex == "(F, 0, A, 1)"
    assert out_bin == "(1111, 0000, 1010, 0001)"
    assert error_calls == []
import pytest

import src.utils.nibble_operations as nibble_operations


# Test that xor_nibble returns the correct XOR result for valid nibble inputs.
def test_xor_nibble_valid_inputs_returns_correct_result(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_operations, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_operations, "log_error", lambda msg: error_calls.append(msg))

    out = nibble_operations.xor_nibble(0xA, 0x5, a_label="a", b_label="b", purpose="xor")

    assert out == (0xA ^ 0x5) & 0xF
    assert error_calls == []
    assert len(debug_calls) == 1
    assert "Nibble XOR done" in debug_calls[0]
    assert "func=xor_nibble" in debug_calls[0]
    assert "a=10" in debug_calls[0]
    assert "b=5" in debug_calls[0]
    assert "res=15" in debug_calls[0]
    assert "a_label=a" in debug_calls[0]
    assert "b_label=b" in debug_calls[0]
    assert "purpose=xor" in debug_calls[0]


# Test that xor_nibble always keeps result in range 0..15.
def test_xor_nibble_masks_result_to_nibble(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_operations, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_operations, "log_error", lambda msg: error_calls.append(msg))

    out = nibble_operations.xor_nibble(15, 15, purpose="mask")

    assert out == 0
    assert 0 <= out <= 15
    assert error_calls == []
    assert len(debug_calls) == 1


# Test wrong type for xor_nibble:
# - must log error
# - raise TypeError with the clear friendly message :)
def test_xor_nibble_wrong_type_raises_and_logs_error(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_operations, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_operations, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(TypeError, match="Nibble XOR failed: inputs must be integers."):
        nibble_operations.xor_nibble("A", 1, a_label="a", b_label="b", purpose="type")

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "invalid types" in error_calls[0]
    assert "module=nibble_operations" in error_calls[0]
    assert "func=xor_nibble" in error_calls[0]
    assert "type(a)=str" in error_calls[0]
    assert "type(b)=int" in error_calls[0]
    assert "a_label=a" in error_calls[0]
    assert "b_label=b" in error_calls[0]
    assert "purpose=type" in error_calls[0]


# Test out of range inputs for xor_nibble:
# - must log error
# - raise ValueError with the clear friendly message :)
@pytest.mark.parametrize("a,b", [(-1, 0), (0, 16), (99, 1), (1, -5)])
def test_xor_nibble_out_of_range_raises_and_logs_error(monkeypatch, a, b):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_operations, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_operations, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="Nibble XOR failed: inputs must be in range 0..15."):
        nibble_operations.xor_nibble(a, b, a_label="a", b_label="b", purpose="range")

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "out of range" in error_calls[0]
    assert "module=nibble_operations" in error_calls[0]
    assert "func=xor_nibble" in error_calls[0]
    assert f"a={a}" in error_calls[0]
    assert f"b={b}" in error_calls[0]
    assert "a_label=a" in error_calls[0]
    assert "b_label=b" in error_calls[0]
    assert "purpose=range" in error_calls[0]


# Test that add_mod_16 returns the correct modulo-16 result for valid inputs.
def test_add_mod_16_valid_inputs_returns_correct_result(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_operations, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_operations, "log_error", lambda msg: error_calls.append(msg))

    out = nibble_operations.add_mod_16(14, 3, label="x", inc_label="inc", purpose="add")

    assert out == (14 + 3) & 0xF
    assert out == 1
    assert error_calls == []
    assert len(debug_calls) == 1
    assert "Add mod 16 done" in debug_calls[0]
    assert "func=add_mod_16" in debug_calls[0]
    assert "x=14" in debug_calls[0]
    assert "inc=3" in debug_calls[0]
    assert "inc_mod=3" in debug_calls[0]
    assert "res=1" in debug_calls[0]
    assert "label=x" in debug_calls[0]
    assert "inc_label=inc" in debug_calls[0]
    assert "purpose=add" in debug_calls[0]


# Test that add_mod_16 correctly wraps around for large increments.
def test_add_mod_16_large_increment_wraps_around(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_operations, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_operations, "log_error", lambda msg: error_calls.append(msg))

    out = nibble_operations.add_mod_16(1, 999, purpose="wrap")

    assert out == (1 + 999) & 0xF
    assert 0 <= out <= 15
    assert error_calls == []
    assert len(debug_calls) == 1
    assert "inc_mod=" in debug_calls[0]


# Test wrong type for add_mod_16:
# - must log error
# - raise TypeError with the clear friendly message :)
@pytest.mark.parametrize("x,inc", [("1", 1), (1, "1"), (None, 1), (1, None)])
def test_add_mod_16_wrong_type_raises_and_logs_error(monkeypatch, x, inc):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_operations, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_operations, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(TypeError, match="Add mod 16 failed: inputs must be integers."):
        nibble_operations.add_mod_16(x, inc, label="x", inc_label="inc", purpose="type")

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "invalid types" in error_calls[0]
    assert "module=nibble_operations" in error_calls[0]
    assert "func=add_mod_16" in error_calls[0]
    assert "type(x)=" in error_calls[0]
    assert "type(inc)=" in error_calls[0]
    assert "label=x" in error_calls[0]
    assert "inc_label=inc" in error_calls[0]
    assert "purpose=type" in error_calls[0]


# Test out-of-range x for add_mod_16:
# - must log error
# - raise ValueError with the clear friendly message :)
@pytest.mark.parametrize("x", [-1, 16, 999])
def test_add_mod_16_out_of_range_x_raises_and_logs_error(monkeypatch, x):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_operations, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_operations, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="Add mod 16 failed: x must be in range 0..15."):
        nibble_operations.add_mod_16(x, 1, label="x", inc_label="inc", purpose="range")

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "out of range" in error_calls[0]
    assert "module=nibble_operations" in error_calls[0]
    assert "func=add_mod_16" in error_calls[0]
    assert f"x={x}" in error_calls[0]
    assert "inc=1" in error_calls[0]
    assert "label=x" in error_calls[0]
    assert "inc_label=inc" in error_calls[0]
    assert "purpose=range" in error_calls[0]


# Test full workflow: XOR then add_mod_16 should log twice and produce stable results.
def test_nibble_operations_workflow_xor_then_add_mod_16(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_operations, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_operations, "log_error", lambda msg: error_calls.append(msg))

    x = nibble_operations.xor_nibble(9, 6, a_label="a", b_label="b", purpose="wf_xor")
    y = nibble_operations.add_mod_16(x, 5, label="x", inc_label="inc", purpose="wf_add")

    assert x == (9 ^ 6) & 0xF
    assert y == (x + 5) & 0xF
    assert error_calls == []
    assert len(debug_calls) == 2
    assert "func=xor_nibble" in debug_calls[0]
    assert "func=add_mod_16" in debug_calls[1]

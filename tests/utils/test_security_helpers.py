import pytest

import src.utils.security_helpers as security_helpers


def test_generate_random_iv_length_and_uniqueness(monkeypatch):
    debug_calls: list[str] = []

    monkeypatch.setattr(security_helpers, "log_debug", lambda msg: debug_calls.append(msg))

    iv1 = security_helpers.generate_random_iv()
    iv2 = security_helpers.generate_random_iv()

    assert isinstance(iv1, bytes)
    assert isinstance(iv2, bytes)
    assert len(iv1) == 16
    assert len(iv2) == 16
    assert iv1 != iv2  # should almost never be equal

    assert len(debug_calls) == 2
    assert "Generated random IV" in debug_calls[0]
    assert "module=security_helpers" in debug_calls[0]
    assert "func=generate_random_iv" in debug_calls[0]
    assert "bytes=16" in debug_calls[0]


@pytest.mark.parametrize("length", [16, 24, 32])
def test_generate_random_key_valid_lengths(monkeypatch, length):
    success_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(security_helpers, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(security_helpers, "log_error", lambda msg: error_calls.append(msg))

    key = security_helpers.generate_random_key(length)

    assert isinstance(key, bytes)
    assert len(key) == length

    assert error_calls == []
    assert len(success_calls) == 1
    assert "Generated random AES key" in success_calls[0]
    assert "module=security_helpers" in success_calls[0]
    assert "func=generate_random_key" in success_calls[0]
    assert f"bytes={length}" in success_calls[0]
    assert f"aes=AES-{length * 8}" in success_calls[0]
    assert "preview=" in success_calls[0]


@pytest.mark.parametrize("length", [0, 8, 15, 17, 31, 33, 100])
def test_generate_random_key_invalid_lengths(monkeypatch, length):
    success_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(security_helpers, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(security_helpers, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match=r"key length must be 16, 24, or 32"):
        security_helpers.generate_random_key(length)

    assert success_calls == []
    assert len(error_calls) == 1
    assert "invalid AES key length" in error_calls[0]
    assert "module=security_helpers" in error_calls[0]
    assert "func=generate_random_key" in error_calls[0]
    assert f"length={length}" in error_calls[0]


@pytest.mark.parametrize("length", ["16", None, 16.0])
def test_generate_random_key_invalid_type_raises_and_logs_error(monkeypatch, length):
    success_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(security_helpers, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(security_helpers, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(TypeError, match=r"key length must be an integer"):
        security_helpers.generate_random_key(length)

    assert success_calls == []
    assert len(error_calls) == 1
    assert "invalid key length type" in error_calls[0]
    assert "module=security_helpers" in error_calls[0]
    assert "func=generate_random_key" in error_calls[0]
    assert f"type(length)={type(length).__name__}" in error_calls[0]

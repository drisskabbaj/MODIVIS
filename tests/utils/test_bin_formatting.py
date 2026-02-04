import pytest

import src.utils.bin_formatting as bin_formatting
import src.utils.bin_converter as bin_converter


# normalize_bin should:
# remove 0b
# remove whitespace
def test_normalize_bin_removes_prefix_whitespace():
    assert bin_formatting.normalize_bin("0b0100 0001\n") == "01000001"
    assert bin_formatting.normalize_bin("  1111 0000 \t") == "11110000"


# normalize_bin should be safe with None and return empty string
def test_normalize_bin_none_is_safe():
    assert bin_formatting.normalize_bin(None) == ""

# bin_tokens should convert bytes to tokens (formatting check)
def test_bin_tokens_from_bytes():
    assert bin_formatting.bin_tokens(b"\x0a\xff") == ["00001010", "11111111"]


# bin_tokens should raise on wrong type and log an error
@pytest.mark.parametrize("value", ["00001010", 123, None])
def test_bin_tokens_wrong_type_raises_and_logs_error(monkeypatch, value):
    error_calls: list[str] = []
    monkeypatch.setattr(bin_formatting, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(TypeError, match="input must be bytes"):
        bin_formatting.bin_tokens(value)

    assert len(error_calls) == 1
    assert "invalid type" in error_calls[0]

import pytest

import src.utils.hex_formatting as hex_formatting
import src.utils.hex_converter as hex_converter


# normalize_hex should:
# remove 0x
# remove whitespace
# lowercase everything
def test_normalize_hex_removes_prefix_whitespace_and_lowercases():
    assert hex_formatting.normalize_hex("0xAA BB\nCC") == "aabbcc"
    assert hex_formatting.normalize_hex("  DE AD\tBE EF ") == "deadbeef"


# normalize_hex should be safe with None and return empty string
def test_normalize_hex_none_is_safe():
    assert hex_formatting.normalize_hex(None) == ""


# format_hex_blocks should return "" for empty / None input
def test_format_hex_blocks_empty_returns_empty_string():
    assert hex_formatting.format_hex_blocks(None) == ""
    assert hex_formatting.format_hex_blocks("   ") == ""


# format_hex_blocks should group into blocks of block_bytes
def test_format_hex_blocks_groups_correctly(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(hex_formatting, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(hex_formatting, "log_error", lambda msg: error_calls.append(msg))

    # 4 bytes are 8 hex chars, with block_bytes=2 we ahve 4 hex chars per block
    out = hex_formatting.format_hex_blocks("aabbccdd", block_bytes=2)

    assert out == "aabb ccdd"
    assert error_calls == []
    assert len(debug_calls) == 1
    assert "block_bytes=2" in debug_calls[0]


# format_hex_blocks should raise if block_bytes is invalid and log an error
@pytest.mark.parametrize("block_bytes", [0, -1, "16"])
def test_format_hex_blocks_invalid_block_bytes_raises_and_logs_error(monkeypatch, block_bytes):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(hex_formatting, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(hex_formatting, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="block_bytes must be a positive integer"):
        hex_formatting.format_hex_blocks("aabb", block_bytes=block_bytes)

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "invalid block_bytes" in error_calls[0]


# format_hex_blocks should reject non-hex characters and log an error
def test_format_hex_blocks_non_hex_raises_and_logs_error(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(hex_formatting, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(hex_formatting, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="non-hex characters"):
        hex_formatting.format_hex_blocks("zz11", block_bytes=16)

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "non-hex characters" in error_calls[0]


# format_hex_blocks should reject odd length hex and log an error
def test_format_hex_blocks_odd_length_raises_and_logs_error(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(hex_formatting, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(hex_formatting, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="length must be even"):
        hex_formatting.format_hex_blocks("abc", block_bytes=16)

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "odd length" in error_calls[0]

# hex_tokens_from_raw_hex should split into byte tokens
def test_hex_tokens_from_raw_hex_splits_correctly():
    assert hex_formatting.hex_tokens_from_raw_hex("aabbcc") == ["aa", "bb", "cc"]
    assert hex_formatting.hex_tokens_from_raw_hex("") == []


# hex_tokens_from_raw_hex should reject invalid inputs: odd length + non-hex as exemples
def test_hex_tokens_from_raw_hex_rejects_invalid(monkeypatch):
    error_calls: list[str] = []
    monkeypatch.setattr(hex_formatting, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="length must be even"):
        hex_formatting.hex_tokens_from_raw_hex("abc")

    with pytest.raises(ValueError, match="non-hex characters"):
        hex_formatting.hex_tokens_from_raw_hex("zz")

    assert len(error_calls) == 2
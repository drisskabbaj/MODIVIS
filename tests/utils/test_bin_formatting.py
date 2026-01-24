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


# format_bin_blocks should return "" for empty / None input
def test_format_bin_blocks_empty_returns_empty_string():
    assert bin_formatting.format_bin_blocks(None) == ""
    assert bin_formatting.format_bin_blocks("   ") == ""


# format_bin_blocks should group into blocks of block_bytes
def test_format_bin_blocks_groups_correctly(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(bin_formatting, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(bin_formatting, "log_error", lambda msg: error_calls.append(msg))

    # 4 bytes are 32 bits, with block_bytes=2 we have 16 bits per block
    out = bin_formatting.format_bin_blocks("00000000111111110000000011111111", block_bytes=2)

    assert out == "0000000011111111 0000000011111111"
    assert error_calls == []
    assert len(debug_calls) == 1
    assert "block_bytes=2" in debug_calls[0]


# format_bin_blocks should raise if block_bytes is invalid and log an error
@pytest.mark.parametrize("block_bytes", [0, -1, "16"])
def test_format_bin_blocks_invalid_block_bytes_raises_and_logs_error(monkeypatch, block_bytes):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(bin_formatting, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(bin_formatting, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="block_bytes must be a positive integer"):
        bin_formatting.format_bin_blocks("01000001", block_bytes=block_bytes)

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "invalid block_bytes" in error_calls[0]


# format_bin_blocks should reject non-binary characters and log an error
def test_format_bin_blocks_non_binary_raises_and_logs_error(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(bin_formatting, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(bin_formatting, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="non-binary characters"):
        bin_formatting.format_bin_blocks("01000002", block_bytes=16)

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "non-binary characters" in error_calls[0]


# format_bin_blocks should reject not byte-aligned bin and log an error
def test_format_bin_blocks_not_byte_aligned_raises_and_logs_error(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(bin_formatting, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(bin_formatting, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="multiple of 8"):
        bin_formatting.format_bin_blocks("0101", block_bytes=16)

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "not byte-aligned" in error_calls[0]


# format_bin_bytes should format bytes into bin blocks (and rely ofc on bin_converter for conversion)
def test_format_bin_bytes_formats_bytes(monkeypatch):
    monkeypatch.setattr(bin_formatting, "bin_from_bytes", lambda b, **kwargs: "00000000000100000000001000000011")

    out = bin_formatting.format_bin_bytes(b"\x00\x10\x02\x03", block_bytes=2)

    assert out == "0000000000010000 0000001000000011"


# format_bin_bytes should return "" for empty bytes
def test_format_bin_bytes_empty_returns_empty_string():
    assert bin_formatting.format_bin_bytes(b"") == ""


# format_bin_bytes should raise on wrong type and log an error (logged by bin_converter.bin_from_bytes)
@pytest.mark.parametrize("value", ["0101", 123, None])
def test_format_bin_bytes_wrong_type_raises_and_logs_error(monkeypatch, value):
    error_calls: list[str] = []
    debug_calls: list[str] = []

    monkeypatch.setattr(bin_converter, "log_error", lambda msg: error_calls.append(msg))
    monkeypatch.setattr(bin_converter, "log_debug", lambda msg: debug_calls.append(msg))

    with pytest.raises(TypeError, match="input must be bytes"):
        bin_formatting.format_bin_bytes(value)

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "invalid type" in error_calls[0]


# bin_tokens_from_raw_bin should split into byte tokens
def test_bin_tokens_from_raw_bin_splits_correctly():
    assert bin_formatting.bin_tokens_from_raw_bin("0100000111110000") == ["01000001", "11110000"]
    assert bin_formatting.bin_tokens_from_raw_bin("") == []


# bin_tokens_from_raw_bin should reject invalid inputs: not byte aligned + non-binary as exemples
def test_bin_tokens_from_raw_bin_rejects_invalid(monkeypatch):
    error_calls: list[str] = []
    monkeypatch.setattr(bin_formatting, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="multiple of 8"):
        bin_formatting.bin_tokens_from_raw_bin("0101")

    with pytest.raises(ValueError, match="non-binary characters"):
        bin_formatting.bin_tokens_from_raw_bin("01000002")

    assert len(error_calls) == 2


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

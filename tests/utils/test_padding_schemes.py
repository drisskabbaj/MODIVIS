import pytest

import src.utils.padding_schemes as padding_schemes


# Test block_size validator
# - should reject non positive and wrong types
# - log an error
@pytest.mark.parametrize("block_size", [0, -1, "16", None])
def test_validate_block_size_invalid_raises_and_logs_error(monkeypatch, block_size):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(padding_schemes, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match=r"Padding failed: block_size must be a positive integer\."):
        padding_schemes._validate_block_size(block_size, func="test")

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "Padding failed: invalid block_size" in error_calls[0]
    assert "module=padding" in error_calls[0]
    assert "func=test" in error_calls[0]


# Test block_size validator
# - should reject too large sizes (>255)
# - log an error
def test_validate_block_size_too_large_raises_and_logs_error(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(padding_schemes, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match=r"Padding failed: block_size must be <= 255\."):
        padding_schemes._validate_block_size(256, func="test")

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "Padding failed: block_size too large" in error_calls[0]
    assert "block_size=256" in error_calls[0]

# Test pad_with_info with NONE
# - must not change data
# - no debug or error logs expected
def test_pad_with_info_none_returns_original_and_no_logs(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(padding_schemes, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: error_calls.append(msg))

    out, n, pad = padding_schemes.pad_with_info(b"ABC", 16, "NONE")

    assert out == b"ABC"
    assert n == 0
    assert pad == b""
    assert debug_calls == []
    assert error_calls == []


# Test pad_with_info
# - must reject wrong data type
# - log an error
def test_pad_with_info_rejects_wrong_data_type(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(padding_schemes, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(TypeError, match=r"Padding failed: data must be bytes \(or bytearray\)\."):
        padding_schemes.pad_with_info("ABC", 16, "PKCS7")  

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "Padding failed: invalid type" in error_calls[0]
    assert "func=pad_with_info" in error_calls[0]
    assert "type(data)=str" in error_calls[0]


# Test pad_with_info
# - must reject wrong mode type
# - log an error
def test_pad_with_info_rejects_wrong_mode_type(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(padding_schemes, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(TypeError, match=r"Padding failed: mode must be a string\."):
        padding_schemes.pad_with_info(b"ABC", 16, 123)  

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "Padding failed: invalid mode type" in error_calls[0]
    assert "func=pad_with_info" in error_calls[0]


# Test PKCS7 padding
# - empty input must produce full block padding (16 bytes of 0x10)
# - must log debug: Padding applied
def test_pad_with_info_pkcs7_full_block_on_empty(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(padding_schemes, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: error_calls.append(msg))

    out, n, pad = padding_schemes.pad_with_info(b"", 16, "PKCS7")

    assert n == 16
    assert pad == bytes([16]) * 16
    assert out == pad
    assert error_calls == []
    assert len(debug_calls) == 1
    assert "Padding applied" in debug_calls[0]
    assert "mode=PKCS7" in debug_calls[0]
    assert "pad_len=16" in debug_calls[0]


# Test PKCS7 padding
# - 15 bytes adds 1 byte padding of 0x01
# - must log debug: Padding applied
def test_pad_with_info_pkcs7_one_byte_padding(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(padding_schemes, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: error_calls.append(msg))

    data = b"A" * 15
    out, n, pad = padding_schemes.pad_with_info(data, 16, "PKCS7")

    assert n == 1
    assert pad == b"\x01"
    assert out == data + b"\x01"
    assert error_calls == []
    assert len(debug_calls) == 1
    assert "mode=PKCS7" in debug_calls[0]
    assert "pad_len=1" in debug_calls[0]


# Test X923 padding bytes
# - for n==1: [0x01]
# - for n==2: [0x00, 0x02]
def test_pad_with_info_x923_padding_vectors(monkeypatch):
    monkeypatch.setattr(padding_schemes, "log_debug", lambda msg: None)
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: None)

    # n == 1
    out, n, pad = padding_schemes.pad_with_info(b"A" * 15, 16, "X923")
    assert n == 1
    assert pad == b"\x01"
    assert out.endswith(b"\x01")

    # n == 2
    out, n, pad = padding_schemes.pad_with_info(b"A" * 14, 16, "X923")
    assert n == 2
    assert pad == b"\x00\x02"
    assert out.endswith(b"\x00\x02")


# Test ISO/IEC 7816-4 padding bytes
# - for n==1: [0x80]
# - for n==3: [0x80, 0x00, 0x00]
def test_pad_with_info_iso7816_padding_vectors(monkeypatch):
    monkeypatch.setattr(padding_schemes, "log_debug", lambda msg: None)
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: None)

    # n == 1
    out, n, pad = padding_schemes.pad_with_info(b"A" * 15, 16, "ISO/IEC 7816-4")
    assert n == 1
    assert pad == b"\x80"
    assert out.endswith(b"\x80")

    # n == 3
    out, n, pad = padding_schemes.pad_with_info(b"A" * 13, 16, "ISO/IEC 7816-4")
    assert n == 3
    assert pad == b"\x80\x00\x00"
    assert out.endswith(b"\x80\x00\x00")


# Test unsupported padding mode
# - must raise ValueError
# - must log error
def test_pad_with_info_unsupported_mode_raises_and_logs_error(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(padding_schemes, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match=r"Padding failed: unsupported padding mode"):
        padding_schemes.pad_with_info(b"ABC", 16, "BLA")  

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "Padding failed: unsupported mode" in error_calls[0]
    assert "mode=BLA" in error_calls[0]


# Test unpad_with_info with NONE
# - must not change data
# - must remove nothing
def test_unpad_with_info_none_returns_original(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(padding_schemes, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: error_calls.append(msg))

    out, removed = padding_schemes.unpad_with_info(b"ABC", 16, "NONE")

    assert out == b"ABC"
    assert removed == b""
    assert debug_calls == []
    assert error_calls == []


# Test unpad_with_info
# - must reject empty data for padded modes
# - must log error
def test_unpad_with_info_empty_data_raises_and_logs_error(monkeypatch):
    error_calls: list[str] = []
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(padding_schemes.PaddingError, match=r"cannot unpad empty data"):
        padding_schemes.unpad_with_info(b"", 16, "PKCS7")

    assert len(error_calls) == 1
    assert "Unpadding failed: empty data" in error_calls[0]


# Test unpad_with_info
# - unpadding requires full blocks
# - must log error
def test_unpad_with_info_length_not_multiple_raises_and_logs_error(monkeypatch):
    error_calls: list[str] = []
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(padding_schemes.PaddingError, match=r"multiple of 16 bytes"):
        padding_schemes.unpad_with_info(b"A" * 15, 16, "PKCS7")

    assert len(error_calls) == 1
    assert "length not multiple of block_size" in error_calls[0]


# Test PKCS7 unpadding
# - valid padding must return original data and removed bytes
# - must log debug: Unpadding done
def test_unpad_with_info_pkcs7_valid(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(padding_schemes, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: error_calls.append(msg))

    data = b"A" * 15 + b"\x01"
    out, removed = padding_schemes.unpad_with_info(data, 16, "PKCS7")

    assert out == b"A" * 15
    assert removed == b"\x01"
    assert error_calls == []
    assert len(debug_calls) == 1
    assert "Unpadding done" in debug_calls[0]
    assert "mode=PKCS7" in debug_calls[0]
    assert "removed=1B" in debug_calls[0]


# Test PKCS7 unpadding
# - invalid length N must raise PaddingError
# - must log error
def test_unpad_with_info_pkcs7_invalid_length_raises_and_logs_error(monkeypatch):
    error_calls: list[str] = []
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: error_calls.append(msg))

    bad = b"A" * 15 + b"\x00"
    with pytest.raises(padding_schemes.PaddingError, match=r"invalid PKCS#7 padding length"):
        padding_schemes.unpad_with_info(bad, 16, "PKCS7")

    assert len(error_calls) == 1
    assert "invalid PKCS7 length" in error_calls[0]


# Test PKCS7 unpadding
# - invalid bytes must raise PaddingError
# - must log error
def test_unpad_with_info_pkcs7_invalid_bytes_raises_and_logs_error(monkeypatch):
    error_calls: list[str] = []
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: error_calls.append(msg))

    bad = b"A" * 14 + b"\x02\x03"
    with pytest.raises(padding_schemes.PaddingError, match=r"invalid PKCS#7 padding bytes"):
        padding_schemes.unpad_with_info(bad, 16, "PKCS7")

    assert len(error_calls) == 1
    assert "invalid PKCS7 bytes" in error_calls[0]


# Test X923 unpadding
# - valid padding must return original data and removed bytes
def test_unpad_with_info_x923_valid(monkeypatch):
    monkeypatch.setattr(padding_schemes, "log_debug", lambda msg: None)
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: None)

    data = b"A" * 14 + b"\x00\x02"
    out, removed = padding_schemes.unpad_with_info(data, 16, "X923")

    assert out == b"A" * 14
    assert removed == b"\x00\x02"


# Test X923 unpadding
# - non-zero bytes before last must raise PaddingError
# - must log error
def test_unpad_with_info_x923_invalid_zeros_raises_and_logs_error(monkeypatch):
    error_calls: list[str] = []
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: error_calls.append(msg))

    bad = b"A" * 14 + b"\x11\x02"
    with pytest.raises(padding_schemes.PaddingError, match=r"invalid X\.923 padding bytes"):
        padding_schemes.unpad_with_info(bad, 16, "X923")

    assert len(error_calls) == 1
    assert "invalid X923 bytes" in error_calls[0]


# Test ISO/IEC 7816-4 unpadding
# - valid padding must return original data and removed bytes
def test_unpad_with_info_iso7816_valid(monkeypatch):
    monkeypatch.setattr(padding_schemes, "log_debug", lambda msg: None)
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: None)

    data = b"A" * 13 + b"\x80\x00\x00"
    out, removed = padding_schemes.unpad_with_info(data, 16, "ISO/IEC 7816-4")

    assert out == b"A" * 13
    assert removed == b"\x80\x00\x00"


# Test ISO/IEC 7816-4 unpadding
# - missing 0x80 marker must raise PaddingError
# - must log error
def test_unpad_with_info_iso7816_missing_marker_raises_and_logs_error(monkeypatch):
    error_calls: list[str] = []
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: error_calls.append(msg))

    bad = b"A" * 16
    with pytest.raises(padding_schemes.PaddingError, match=r"missing 0x80 marker"):
        padding_schemes.unpad_with_info(bad, 16, "ISO/IEC 7816-4")

    assert len(error_calls) == 1
    assert "missing 0x80 marker" in error_calls[0]


# Test unsupported unpadding mode
# - must raise ValueError
# - must log error
def test_unpad_with_info_unsupported_mode_raises_and_logs_error(monkeypatch):
    error_calls: list[str] = []
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match=r"Unpadding failed: unsupported padding mode"):
        padding_schemes.unpad_with_info(b"A" * 16, 16, "BLA")  

    assert len(error_calls) == 1
    assert "Unpadding failed: unsupported mode" in error_calls[0]

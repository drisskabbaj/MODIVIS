import pytest

import src.utils.input_parsers as input_parsers
import src.utils.logger as app_logger


@pytest.fixture(autouse=True)
def _silence_app_logger(monkeypatch):
    monkeypatch.setattr(app_logger.logger, "disabled", True)


# text mode test: should return UTF-8 bytes including for non-ascii
def test_parse_plaintext_text_mode_utf8():
    assert input_parsers.parse_plaintext("ABC", "TEXT") == b"ABC"
    assert input_parsers.parse_plaintext("äöü", "TEXT") == "äöü".encode("utf-8")


# hex mode test: should accept spaces/newlines and optional 0x prefix then normalize + convert
def test_parse_plaintext_hex_mode_accepts_spaces_newlines_and_0x():
    out = input_parsers.parse_plaintext("0x0A ff\n10", "HEX")
    assert out == b"\x0a\xff\x10"


# hex mode test: empty input is allowed for plaintext and returns b""
def test_parse_plaintext_hex_mode_empty_returns_empty_bytes():
    assert input_parsers.parse_plaintext("", "HEX") == b""
    assert input_parsers.parse_plaintext("   \n\t", "HEX") == b""


# bin mode test: should accept spaces/newlines and optional 0b prefix then normalize + convert
def test_parse_plaintext_bin_mode_accepts_spaces_newlines_and_0b():
    out = input_parsers.parse_plaintext("0b01000001 11110000\n", "BIN")
    assert out == b"\x41\xf0"


# bin mode test: empty input is allowed for plaintext and returns b""
def test_parse_plaintext_bin_mode_empty_returns_empty_bytes():
    assert input_parsers.parse_plaintext("", "BIN") == b""
    assert input_parsers.parse_plaintext("   \n\t", "BIN") == b""


# bin mode test: invalid BIN should raise a user friendly message
def test_parse_plaintext_bin_mode_invalid_bin_raises():
    with pytest.raises(ValueError, match="Plaintext \\(BIN\\) is invalid BIN"):
        input_parsers.parse_plaintext("01000002", "BIN")  # contains non-binary char


# invalid fmt should raise the user friendly error
def test_parse_plaintext_invalid_fmt_raises():
    with pytest.raises(ValueError, match="Input parsing failed: fmt must be 'TEXT', 'HEX' or 'BIN'."):
        input_parsers.parse_plaintext("AA", "BLA")


# AES key parser converts HEX to bytes (length validation happens in AESCore)
@pytest.mark.parametrize(
    "key_hex",
    [
        "00" * 16,  # 16 bytes (AES-128)
        "11" * 24,  # 24 bytes (AES-192)
        "aa" * 32,  # 32 bytes (AES-256)
    ],
)
def test_parse_aes_key_hex_valid_lengths(key_hex):
    key = input_parsers.parse_aes_key_hex(key_hex)
    assert len(key) in (16, 24, 32)


# AES key parser does not enforce AES key sizes (that is done by AESCore)
@pytest.mark.parametrize("key_hex", ["00" * 15, "00" * 17, "00" * 31, "00" * 33])
def test_parse_aes_key_hex_other_lengths_are_parsed_but_validated_later(key_hex):
    key = input_parsers.parse_aes_key_hex(key_hex)
    assert len(key) == len(key_hex) // 2


# AES key parser should reject empty and show field name
def test_parse_aes_key_hex_empty_raises():
    with pytest.raises(ValueError, match="Key \\(HEX\\) is empty"):
        input_parsers.parse_aes_key_hex("")


# AES key parser should reject non-hex and show field name
def test_parse_aes_key_hex_non_hex_raises():
    with pytest.raises(ValueError, match="Key \\(HEX\\) is invalid HEX"):
        input_parsers.parse_aes_key_hex("zz11")


# IV parser converts HEX to bytes (exact 16 byte validation happens in AESCore for CBC/CTR)
def test_parse_iv_hex_valid():
    iv = input_parsers.parse_iv_hex("00" * 16)
    assert len(iv) == 16


# IV parser does not enforce 16 bytes (AESCore enforce it)
@pytest.mark.parametrize("iv_hex", ["00" * 15, "00" * 17])
def test_parse_iv_hex_other_lengths_are_parsed_but_validated_later(iv_hex):
    iv = input_parsers.parse_iv_hex(iv_hex)
    assert len(iv) == len(iv_hex) // 2


# IV parser empty is not allowed and must show the field name
@pytest.mark.parametrize("iv_hex", ["", "   \n\t "])
def test_parse_iv_hex_empty_raises(iv_hex):
    with pytest.raises(ValueError, match="IV/Counter \\(HEX\\) is empty"):
        input_parsers.parse_iv_hex(iv_hex)


# IV parser should include custom field name in error messages
def test_parse_iv_hex_custom_field_name_used_in_error():
    with pytest.raises(ValueError, match="Counter \\(HEX\\) is empty"):
        input_parsers.parse_iv_hex("", field_name="Counter (HEX)")


# ciphertext parser:
# - empty not allowed
# - must show field name
def test_parse_ciphertext_hex_empty_raises():
    with pytest.raises(ValueError, match="Ciphertext \\(HEX\\) is empty"):
        input_parsers.parse_ciphertext_hex(" \n\t ")


# ciphertext parser: should accept 0x prefix and whitespace.
def test_parse_ciphertext_hex_accepts_0x_and_whitespace():
    ct = input_parsers.parse_ciphertext_hex("0xAA BB CC")
    assert ct == b"\xaa\xbb\xcc"


# ciphertext parser: should reject non-hex.
def test_parse_ciphertext_hex_non_hex_raises():
    with pytest.raises(ValueError, match="Ciphertext \\(HEX\\) is invalid HEX"):
        input_parsers.parse_ciphertext_hex("gg")

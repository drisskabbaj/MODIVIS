from __future__ import annotations # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types

from src.domain.input_types import InputFormat

from src.utils.hex_converter import bytes_from_hex
from src.utils.hex_formatting import normalize_hex
from src.utils.bin_formatting import normalize_bin
from src.utils.bin_converter import bytes_from_bin

# ---------------------------------------------------------------------------------------------
#                                 INPUT PARSERS
# ---------------------------------------------------------------------------------------------
# Why this?
#   - UI gives strings but AES code needs bytes.
#   - User paste HEX with spaces/newlines and sometimes with 0x prefix.
#   - User paste BIN with spaces/newlines and sometimes with 0b prefix.
#   - We need to centralize parsing so the ViewModel stays clean and have MVVM-Model.
#
# Tested?
#   - Yes 
#   - Unit test inside tests/utils/test_input_parsers.py 
# ---------------------------------------------------------------------------------------------

def _parse_hex_bytes(value: str | None, *, field_name: str, allow_empty: bool, purpose: str = "") -> bytes:
    """
    Internal helper (hex):
      - normalize user HEX (remove 0x + whitespace)
      - convert using bytes_from_hex
      - wrap errors with field_name
      - empty is allowed with bool allow_empty: useful when plaintext input in HEX mode
    """
    try:
        h = normalize_hex(value, label=field_name, purpose=purpose)
    except TypeError:
        raise ValueError(f"{field_name} must be HEX text (string).") from None

    if h == "" and not allow_empty:
        raise ValueError(f"{field_name} is empty.")

    try:
        return bytes_from_hex(h, label=field_name, purpose=purpose, assume_clean=True)
    except ValueError:
        raise ValueError(f"{field_name} is invalid HEX (check length and characters).") from None
    
def _parse_bin_bytes(value: str | None, *, field_name: str, allow_empty: bool, purpose: str = "") -> bytes:
    """
    Internal helper (binary):
      - normalize user BIN (remove 0b + whitespace)
      - convert using bytes_from_bin
      - wrap errors with field_name
      - empty is allowed with bool allow_empty: useful when plaintext input in BIN mode
    """
    try:
        bits = normalize_bin(value, label=field_name, purpose=purpose)
    except TypeError:
        raise ValueError(f"{field_name} must be BIN text (string).") from None

    if bits == "" and not allow_empty:
        raise ValueError(f"{field_name} is empty.")

    try:
        return bytes_from_bin(bits, label=field_name, purpose=purpose, assume_clean=True)
    except ValueError:
        # bytes_from_bin already logs the root cause (not byte-aligned or bad chars)
        raise ValueError(f"{field_name} is invalid BIN (check length and characters).") from None

def parse_plaintext(value: str | None, fmt: InputFormat) -> bytes:
    """
    Plaintext input parser for the playground:
      - TEXT: UTF-8 bytes
      - HEX: interpreted as raw bytes (spaces/newlines/0x allowed)
      - BIN: interpreted as raw bytes (spaces/newlines/0b allowed)
    """
    if fmt == "TEXT":
        return (value or "").encode("utf-8")

    if fmt == "HEX":
        return _parse_hex_bytes(value, field_name="Plaintext (HEX)", allow_empty=True, purpose="parse_plaintext")
    
    if fmt == "BIN":
        return _parse_bin_bytes(value, field_name="Plaintext (BIN)", allow_empty=True, purpose="parse_plaintext")

    raise ValueError("Input parsing failed: fmt must be 'TEXT', 'HEX' or 'BIN'.")


def parse_aes_key_hex(key_hex: str | None) -> bytes:
    """
    Parse AES key from HEX into bytes
    Key length is validated by AESCore. It is either:
      - 16 bytes (32 hex chars)  aka. AES-128
      - 24 bytes (48 hex chars)  aka. AES-192
      - 32 bytes (64 hex chars)  aka. AES-256
    """
    key = _parse_hex_bytes(key_hex, field_name="Key (HEX)", allow_empty=False, purpose="parse_aes_key_hex")
    
    return key


def parse_iv_hex(iv_hex: str | None, *, field_name: str = "IV/Counter (HEX)") -> bytes:
    """
    Parse IV/Counter from HEX into bytes
    Exact 16-byte validation happens in AESCore (CBC/CTR)
    """
    iv = _parse_hex_bytes(iv_hex, field_name=field_name, allow_empty=False, purpose="parse_iv_hex")

    return iv


def parse_ciphertext_hex(ciphertext_hex: str | None) -> bytes:
    """
    Ciphertext is provided as HEX ofc. 
    Spaces/newlines/0x allowed.
    Empty is not allowed for future decrypt purpouse.
    """
    return _parse_hex_bytes(ciphertext_hex, field_name="Ciphertext (HEX)", allow_empty=False, purpose="parse_ciphertext_hex")

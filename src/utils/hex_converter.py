from __future__ import annotations # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types

from src.utils.logger import (
    log_debug,
    log_error,
) # needed to log error/debug

# ---------------------------------------------------------------------------------------------
#                              HEX / BYTES CONVERTER
# ---------------------------------------------------------------------------------------------
# Why this?
#   - AES works on bytes, but user could use HEX vectors. Also results are with HEX, so converting backward is also mandatory.
#   - This helper makes HEX input/output flexible (spaces/newlines/tabs allowed) and safe.
#
# Logging:
#   - log_debug: conversion worked (useful for trace)
#   - log_error: conversion failed (so the user sees the real cause)
#
# Tested?
#   - Yes
#   - Unit test inside tests/utils/test_hex_converter.py
# ---------------------------------------------------------------------------------------------


def bytes_from_hex(s: str, *, label: str = "", purpose: str = "", assume_clean: bool = False) -> bytes:
    """
    Convert a hex string into bytes.

    Accepted formats (spaces/newlines/tabs allowed):
      - "0a ff 10"   becomes b'\\x0a\\xff\\x10' (raw binary form would have been 0000101011111111)
      - "0aff10"     becomes b'\\x0a\\xff\\x10' (raw binary form would have been 0000101011111111)
      - "0A\\nFF\\t10" becomes b'\\x0a\\xff\\x10' (raw binary form would have been 0000101011111111)

    Raises:
        TypeError: if input is not a string.
        ValueError: if hex length is odd or if it contains non-hex characters.
    """
    # Defensive check: in case user gives input as bytes/int by mistake from UI parsing with declared type hex.
    if not isinstance(s, str):
        log_error(f"Conversion from HEX to Bytes failed: invalid type | module=hex_converter | type(s)={type(s).__name__} | label={label} | purpose={purpose}")
        raise TypeError("Conversion from HEX to Bytes failed: input must be a string.")

    # Remove all whitespace (spaces, newlines, tabs). This keeps copy/paste blocks flexible.
    # Fast path: if caller already removed whitespace/0x (ex: normalize_hex) we will avoid doing it twice.
    cleaned = s.strip() if assume_clean else "".join(s.split())

    # Allow empty input whitch gives empty bytes. 
    # PS: Caller (mainly viewmodel) must validate required lengths for key/iv of course.
    if cleaned == "":
        log_debug(f"Converting empty hex to bytes | len=0 | module=hex_converter | label={label} | purpose={purpose}")
        return b""

    # Mandatory check: Hex must be in pairs (2 chars per byte)
    if len(cleaned) % 2 != 0:
        log_error(f"Conversion from HEX to Bytes failed: odd length | module=hex_converter | len={len(cleaned)} | value='{cleaned}' | label={label} | purpose={purpose}")
        raise ValueError(
            "bytes_from_hex: hex string must have an even number of characters "
            "(2 hex chars = 1 byte). Example: '0a ff 10' or '0aff10'."
        )

    try:
        out = bytes.fromhex(cleaned)
    except ValueError as exc:
        # User friendly error  because sometimes bytes.fromhex error text can be too technical.
        log_error(f"Conversion from HEX to Bytes failed: non-hex characters | module=hex_converter | value='{cleaned}' | label={label} | purpose={purpose}")
        raise ValueError(
            "bytes_from_hex: input contains non-hex characters. "
            "Allowed characters are 0-9 and a-f (case-insensitive)."
        ) from exc

    log_debug(f"Converted HEX to Bytes | len={len(out)} | module=hex_converter | label={label} | purpose={purpose}")
    return out


def hex_from_bytes(b: bytes, *, label: str = "", purpose: str = "") -> str:
    """
    Convert bytes into a lowercase hex string without spaces.

    Example:
        b'\\x0a\\xff' becomes "0aff"

    Raises:
        TypeError: if input is not bytes-like.
    """
    # Defensive check: in case user gives input as text/hex/int by mistake from UI parsing with declared type hex.
    if not isinstance(b, (bytes, bytearray)):
        log_error(f"Conversion from Bytes to HEX failed: invalid type | module=hex_converter | type(b)={type(b).__name__} | label={label} | purpose={purpose}")
        raise TypeError("Conversion from Bytes to HEX failed: input must be bytes.")

    raw = bytes(b)

    if raw == b"":
        log_debug(f"Converting empty bytes to HEX | len=0 | module=hex_converter | label={label} | purpose={purpose}")
        return ""
    
    h = raw.hex()  # lowercase, no spaces

    log_debug(f"Converted Bytes to HEX | len={len(raw)} | module=hex_converter | label={label} | purpose={purpose}")

    return h

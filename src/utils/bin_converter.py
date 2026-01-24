from __future__ import annotations  # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types

from src.utils.logger import (
    log_debug,
    log_error,
)  # needed to log error/debug

# ---------------------------------------------------------------------------------------------
#                              BIN / BYTES CONVERTER
# ---------------------------------------------------------------------------------------------
# Why this?
#   - AES works on bytes, but user could use BIN vectors. Also results are with BIN, so converting backward is also mandatory.
#   - This helper makes BIN input/output flexible (spaces/newlines/tabs allowed) and safe.
#
# Logging:
#   - log_debug: conversion worked (useful for trace)
#   - log_error: conversion failed (so the user sees the real cause)
#
# Tested?
#   - Yes
#   - Unit test inside tests/utils/test_bin_converter.py
# ---------------------------------------------------------------------------------------------


def bytes_from_bin(s: str, *, label: str = "", purpose: str = "", assume_clean: bool = False) -> bytes:
    """
    Convert a binary string into bytes.

    Accepted formats (spaces/newlines/tabs allowed):
      - "01000001 11110000"   becomes b'\\x41\\xf0'
      - "0100000111110000"    becomes b'\\x41\\xf0'
      - "0b01000001\\n11110000" becomes b'\\x41\\xf0'

    Raises:
        TypeError: if input is not a string.
        ValueError: if bit-length is not multiple of 8 or if it contains non-binary characters.
    """
    # Defensive check: in case user gives input as bytes/int by mistake from UI parsing with declared type bin.
    if not isinstance(s, str):
        log_error(
            f"Conversion from BIN to Bytes failed: invalid type | module=bin_converter | type(s)={type(s).__name__} | label={label} | purpose={purpose}"
        )
        raise TypeError("Conversion from BIN to Bytes failed: input must be a string.")

    # Remove all whitespace (spaces, newlines, tabs). This keeps copy/paste blocks flexible.
    # Fast path: if caller already removed whitespace/0b (ex: normalize_bin) we will avoid doing it twice.
    cleaned = s.strip() if assume_clean else "".join(s.split())

    # Allow optional 0b prefix (only when we didn't assume the input is already cleaned).
    if not assume_clean and cleaned.startswith(("0b", "0B")):
        cleaned = cleaned[2:]

    # Allow empty input which gives empty bytes.
    # PS: Caller (mainly viewmodel) must validate required lengths for key/iv of course.
    if cleaned == "":
        log_debug(f"Converting empty bin to bytes | len=0 | module=bin_converter | label={label} | purpose={purpose}")
        return b""
    
    # Mandatory check: only 0/1 allowed (like bytes_from_hex checks non-hex chars)
    bad = next((ch for ch in cleaned if ch not in "01"), None)
    if bad is not None:
        log_error(
            f"Conversion from BIN to Bytes failed: non-binary characters | module=bin_converter | value='{cleaned}' | label={label} | purpose={purpose}"
        )
        raise ValueError(
            "bytes_from_bin: input contains non-binary characters. "
            "Allowed characters are only '0' and '1'."
        )

    # Mandatory check: BIN must be byte-aligned (8 bits per byte)
    if len(cleaned) % 8 != 0:
        log_error(
            f"Conversion from BIN to Bytes failed: not byte-aligned | module=bin_converter | bits={len(cleaned)} | value='{cleaned}' | label={label} | purpose={purpose}"
        )
        raise ValueError(
            "bytes_from_bin: bit string length must be a multiple of 8 "
            "(8 bits = 1 byte). Example: '01000001 11110000' or '0100000111110000'."
        )

    try:
        out = bytearray()
        for i in range(0, len(cleaned), 8):
            out.append(int(cleaned[i : i + 8], 2))
        out_b = bytes(out)
    except Exception as exc:
        # Should never happen after validation, but keep a stable boundary.
        log_error(
            f"Conversion from BIN to Bytes failed: internal parse error | module=bin_converter | value='{cleaned}' | label={label} | purpose={purpose}"
        )
        raise ValueError("bytes_from_bin: failed to parse binary input due to an internal error.") from exc

    log_debug(f"Converted BIN to Bytes | len={len(out_b)} | module=bin_converter | label={label} | purpose={purpose}")
    return out_b


def bin_from_bytes(b: bytes, *, label: str = "", purpose: str = "") -> str:
    """
    Convert bytes into a binary string without spaces.

    Example:
        b'\\x41\\xf0' becomes "0100000111110000"

    Raises:
        TypeError: if input is not bytes-like.
    """
    # Defensive check: in case user gives input as text/hex/int by mistake from UI parsing with declared type bin.
    if not isinstance(b, (bytes, bytearray)):
        log_error(
            f"Conversion from Bytes to BIN failed: invalid type | module=bin_converter | type(b)={type(b).__name__} | label={label} | purpose={purpose}"
        )
        raise TypeError("Conversion from Bytes to BIN failed: input must be bytes.")

    raw = bytes(b)

    if raw == b"":
        log_debug(f"Converting empty bytes to BIN | len=0 | module=bin_converter | label={label} | purpose={purpose}")
        return ""

    s = "".join(f"{byte:08b}" for byte in raw)

    log_debug(f"Converted Bytes to BIN | len={len(raw)} | module=bin_converter | label={label} | purpose={purpose}")

    return s

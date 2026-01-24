from __future__ import annotations # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types

import re  # needed for regex manipulations: strip all whitespace and validate only hex characters

from typing import Optional  # needed to mark a value as str or None (existing or missing both possible)

from src.utils.logger import (
    log_debug,
    log_error,
) # needed to log error/success

from src.utils.hex_converter import hex_from_bytes # needed to use our built-in hex to bin converter

# ---------------------------------------------------------------------------------------------
#                              HEX FORMATTING HELPERS
# ---------------------------------------------------------------------------------------------
# Why this?
#   - The converter is responsible for conversion + validation + logging.
#   - This file is complementary and only for:
#       1) normalizing user input strings (no 0x prefixes or whitespaces)
#       2) formatting output nicely (block grouping)
#       3) splitting hex into byte tokens (for coloring/visualization)
#
# Tested?
#   - Yes
#   - Unit test inside tests/utils/test_hex_formatting.py
# ---------------------------------------------------------------------------------------------

 # matches a string made of:
 # only hex digits (0-9, a-f, A-F)
 # from start (^) to end ($)
 # * allows empty string too
_HEX_RE = re.compile(r"^[0-9a-fA-F]*$")

def normalize_hex(s: Optional[str], *, label: str = "", purpose: str = "") -> str:
    """
    User friendly HEX cleaner:
      - trims
      - removes optional 0x prefix
      - removes all whitespace (spaces/newlines/tabs)
      - lowercases

    Examples:
      - "0xAA BB\nCC" becomes "aabbcc"
      - "  DE AD BE EF " becomes "deadbeef"
    """
    if s is not None and not isinstance(s, str):
        log_error(f"HEX Formatting failed: invalid type | module=hex_formatting | func=normalize_hex | type(s)={type(s).__name__} | label={label} | purpose={purpose}")
        raise TypeError("HEX Formatting failed: input must be text (string) or empty.")

    # use input value if not empty and if s is None use "" instead, then remove spaces/newlines at the ends
    s = (s or "").strip()
    if s.lower().startswith("0x"): # if it begins with 0x prefix (checking with lowecase)
        s = s[2:]                  # remove the 0x prefix (first 2 chars)
    s = re.sub(r"\s+", "", s)      # remove all whitespaces anywhere inside including spaces, tabs and newlines

    out = s.lower()

    return out

def format_hex_blocks(hex_str: Optional[str], block_bytes: int = 16, *, label: str = "", purpose: str = "", assume_normalized: bool = False,) -> str:
    """
    Format HEX into blocks separated by a single space.
      - 16 bytes = 32 hex chars per block

    NB:
      - function expects HEX format input.
      - conversion and strong validation is implemented in hex_converter methods when parsing user input.
    """
    # Block bytes is always positif and a number (int = 16)
    if not isinstance(block_bytes, int) or block_bytes <= 0:
        log_error(f"HEX Formatting failed: invalid block_bytes | module=hex_formatting | func=format_hex_blocks | block_bytes={block_bytes} | label={label} | purpose={purpose}")
        raise ValueError("HEX Formatting failed: block_bytes must be a positive integer.")
    
    h = (hex_str or "")
    if not assume_normalized:
        h = normalize_hex(h, label=label, purpose=purpose)

    # extra output check for empty value even if already implimented on normalize_hex
    if not h:
        return ""

    if not assume_normalized:
        # Sanity check of HEX format using RREGEX
        if not _HEX_RE.match(h):
            log_error(f"HEX Formatting failed: non-hex characters | module=hex_formatting | func=format_hex_blocks | value='{h}' | label={label} | purpose={purpose}")
            raise ValueError("HEX Formatting failed: input contains non-hex characters.")
        # Parity check for HEX blocks
        if len(h) % 2 != 0:
            log_error(f"HEX Formatting failed: odd length | module=hex_formatting | func=format_hex_blocks | len={len(h)} | value='{h}' | label={label} | purpose={purpose}")
            raise ValueError("HEX Formatting failed: HEX length must be even (2 hex chars = 1 byte).")

    # how many hex characters per block (since 1 byte = 2 hex chars)
    block_chars = block_bytes * 2

    # glue all pieces together with one space between them
    out = " ".join(
    # take a chunk of the hex string from position i, length = block_chars
    h[i : i + block_chars]
    # i goes 0, block_chars, 2*block_chars, ... until the end
    for i in range(0, len(h), block_chars)
    )

    log_debug(f"Formatted hex blocks | module=hex_formatting | func=format_hex_blocks | block_bytes={block_bytes} | len={len(h)//2}B | label={label} | purpose={purpose}")
    return out


def format_hex_bytes(data: bytes, block_bytes: int = 16, *, label: str = "", purpose: str = "") -> str:
    """
    Convenience: bytes are formatted hex blocks.
    Uses hex_converter.hex_from_bytes as the single source for bytes hex conversion.
    """
    h = hex_from_bytes(data, label=label, purpose=purpose)  # logs debug on empty also
    if not h:
        return ""
    
    # Conversion happens in hex_converter and logged there.
    return format_hex_blocks(h, block_bytes=block_bytes, label=label, purpose=purpose, assume_normalized=True)


def hex_tokens_from_raw_hex(raw_hex: str, *, label: str = "", purpose: str = "") -> list[str]:
    """
    Takes exemple "aabbcc" and return ["aa", "bb", "cc"] (each item is 1 byte written as 2 hex chars :)
    """
    if not isinstance(raw_hex, str):
        log_error(f"HEX Formatting failed: invalid type | module=hex_formatting | func=hex_tokens_from_raw_hex | type(raw_hex)={type(raw_hex).__name__} | label={label} | purpose={purpose}")
        raise TypeError("HEX Formatting failed: raw HEX must be a string.")

    # Empty check and ready output return
    if raw_hex == "":
        return []

    # REGEX check
    if not _HEX_RE.match(raw_hex):
        log_error(f"HEX Formatting failed: non-hex characters | module=hex_formatting | func=hex_tokens_from_raw_hex | value='{raw_hex}' | label={label} | purpose={purpose}")
        raise ValueError("HEX Formatting failed: input contains non-hex characters.")

    # Parity check
    if len(raw_hex) % 2 != 0:
        log_error(f"HEX Formatting failed: odd length | module=hex_formatting | func=hex_tokens_from_raw_hex | len={len(raw_hex)} | label={label} | purpose={purpose}")
        raise ValueError("HEX Formatting failed: HEX length must be even (2 hex chars = 1 byte).")

    return [raw_hex[i : i + 2] for i in range(0, len(raw_hex), 2)]


def hex_tokens(data: bytes, *, label: str = "", purpose: str = "") -> list[str]:
    """
    Takes bytes like b"\x0a\xff" and return ["0a", "ff"]
    """
    # Defensive check (matches style of other utils)
    if not isinstance(data, (bytes, bytearray)):
        log_error(
            f"HEX Formatting failed: invalid type | module=hex_formatting | func=hex_tokens | type(data)={type(data).__name__} | label={label} | purpose={purpose}"
        )
        raise TypeError("HEX Formatting failed: input must be bytes.")
    
    # making sure it's plain bytes (convert bytearray to bytes)
    raw = bytes(data)
    if not raw:
        return []

    # Fast path: bytes to ex. ["0a","ff",...]. Bytes already guarantee even-length and valid values.
    out = [f"{x:02x}" for x in raw]

    log_debug(f"HEX tokens generated | module=hex_formatting | func=hex_tokens | bytes={len(raw)} | label={label} | purpose={purpose}")

    return out

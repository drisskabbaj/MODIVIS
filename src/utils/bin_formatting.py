from __future__ import annotations  # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types

import re  # needed for regex manipulations: strip all whitespace and validate only binary characters

from typing import Optional  # needed to mark a value as str or None (existing or missing both possible)

from src.utils.logger import (
    log_debug,
    log_error,
)  # needed to log error/success

from src.utils.bin_converter import bin_from_bytes  # needed to use our built-in bytes to bin converter

# ---------------------------------------------------------------------------------------------
#                              BIN FORMATTING HELPERS
# ---------------------------------------------------------------------------------------------
# Why this?
#   - The converter is responsible for conversion + validation + logging.
#   - This file is complementary and only for:
#       1) normalizing user input strings (no 0b prefixes or whitespaces)
#       2) formatting output nicely (block grouping)
#       3) splitting bin into byte tokens (for coloring/visualization)
#
# Tested?
#   - Yes
#   - Unit test inside tests/utils/test_bin_formatting.py
# ---------------------------------------------------------------------------------------------

# matches a string made of:
# only binary digits (0, 1)
# from start (^) to end ($)
# * allows empty string too
_BIN_RE = re.compile(r"^[01]*$")


def normalize_bin(s: Optional[str], *, label: str = "", purpose: str = "") -> str:
    """
    User friendly BIN cleaner:
      - trims
      - removes optional 0b prefix
      - removes all whitespace (spaces/newlines/tabs)

    Examples:
      - "0b0100 0001\n" becomes "01000001"
      - "  1111 0000  " becomes "11110000"
    """
    if s is not None and not isinstance(s, str):
        log_error(
            f"BIN Formatting failed: invalid type | module=bin_formatting | func=normalize_bin | type(s)={type(s).__name__} | label={label} | purpose={purpose}"
        )
        raise TypeError("BIN Formatting failed: input must be text (string) or empty.")

    # use input value if not empty and if s is None use "" instead, then remove spaces/newlines at the ends
    s = (s or "").strip()
    if s.startswith(("0b", "0B")):  # if it begins with 0b prefix
        s = s[2:]  # remove the 0b prefix (first 2 chars)
    s = re.sub(r"\s+", "", s)  # remove all whitespaces anywhere inside including spaces, tabs and newlines

    out = s
    return out


def format_bin_blocks(
    bin_str: Optional[str],
    block_bytes: int = 16,
    *,
    label: str = "",
    purpose: str = "",
    assume_normalized: bool = False,
) -> str:
    """
    Format BIN into blocks separated by a single space.
      - 16 bytes = 128 bits per block

    NB:
      - function expects BIN format input.
      - conversion and strong validation is implemented in bin_converter methods when parsing user input.
    """
    # Block bytes is always positif and a number (int = 16)
    if not isinstance(block_bytes, int) or block_bytes <= 0:
        log_error(
            f"BIN Formatting failed: invalid block_bytes | module=bin_formatting | func=format_bin_blocks | block_bytes={block_bytes} | label={label} | purpose={purpose}"
        )
        raise ValueError("BIN Formatting failed: block_bytes must be a positive integer.")

    b = (bin_str or "")
    if not assume_normalized:
        b = normalize_bin(b, label=label, purpose=purpose)

    # extra output check for empty value even if already implimented on normalize_bin
    if not b:
        return ""

    if not assume_normalized:
        # Sanity check of BIN format using REGEX
        if not _BIN_RE.match(b):
            log_error(
                f"BIN Formatting failed: non-binary characters | module=bin_formatting | func=format_bin_blocks | value='{b}' | label={label} | purpose={purpose}"
            )
            raise ValueError("BIN Formatting failed: input contains non-binary characters (only 0/1 allowed).")
        # Alignment check for BIN blocks
        if len(b) % 8 != 0:
            log_error(
                f"BIN Formatting failed: not byte-aligned | module=bin_formatting | func=format_bin_blocks | len={len(b)} | label={label} | purpose={purpose}"
            )
            raise ValueError("BIN Formatting failed: BIN length must be a multiple of 8 (8 bits = 1 byte).")

    # how many bits per block (since 1 byte = 8 bits)
    block_bits = block_bytes * 8

    # glue all pieces together with one space between them
    out = " ".join(
        # take a chunk of the bin string from position i, length = block_bits
        b[i : i + block_bits]
        # i goes 0, block_bits, 2*block_bits, ... until the end
        for i in range(0, len(b), block_bits)
    )

    log_debug(
        f"Formatted bin blocks | module=bin_formatting | func=format_bin_blocks | block_bytes={block_bytes} | len={len(b)//8}B | label={label} | purpose={purpose}"
    )
    return out


def format_bin_bytes(data: bytes, block_bytes: int = 16, *, label: str = "", purpose: str = "") -> str:
    """
    Convenience: bytes are formatted bin blocks.
    Uses bin_converter.bin_from_bytes as the single source for bytes bin conversion.
    """
    b = bin_from_bytes(data, label=label, purpose=purpose)  # logs debug on empty also
    if not b:
        return ""

    # Conversion happens in bin_converter and logged there.
    return format_bin_blocks(b, block_bytes=block_bytes, label=label, purpose=purpose, assume_normalized=True)


def bin_tokens_from_raw_bin(raw_bin: str, *, label: str = "", purpose: str = "") -> list[str]:
    """
    Takes exemple "01000001" and return ["01000001"] (each item is 1 byte written as 8 bits)
    """
    if not isinstance(raw_bin, str):
        log_error(
            f"BIN Formatting failed: invalid type | module=bin_formatting | func=bin_tokens_from_raw_bin | type(raw_bin)={type(raw_bin).__name__} | label={label} | purpose={purpose}"
        )
        raise TypeError("BIN Formatting failed: raw BIN must be a string.")

    # Empty check and ready output return
    if raw_bin == "":
        return []

    # REGEX check
    if not _BIN_RE.match(raw_bin):
        log_error(
            f"BIN Formatting failed: non-binary characters | module=bin_formatting | func=bin_tokens_from_raw_bin | value='{raw_bin}' | label={label} | purpose={purpose}"
        )
        raise ValueError("BIN Formatting failed: input contains non-binary characters (only 0/1 allowed).")

    # Alignment check
    if len(raw_bin) % 8 != 0:
        log_error(
            f"BIN Formatting failed: not byte-aligned | module=bin_formatting | func=bin_tokens_from_raw_bin | len={len(raw_bin)} | label={label} | purpose={purpose}"
        )
        raise ValueError("BIN Formatting failed: BIN length must be a multiple of 8 (8 bits = 1 byte).")

    return [raw_bin[i : i + 8] for i in range(0, len(raw_bin), 8)]


def bin_tokens(data: bytes, *, label: str = "", purpose: str = "") -> list[str]:
    """
    Takes bytes like b"\x41" and return ["01000001"]
    """
    # Defensive check (matches style of other utils)
    if not isinstance(data, (bytes, bytearray)):
        log_error(
            f"BIN Formatting failed: invalid type | module=bin_formatting | func=bin_tokens | type(data)={type(data).__name__} | label={label} | purpose={purpose}"
        )
        raise TypeError("BIN Formatting failed: input must be bytes.")

    # making sure it's plain bytes (convert bytearray to bytes)
    raw = bytes(data)
    if not raw:
        return []

    # Fast path: bytes to ex. ["01000001","11110000",...]. Bytes already guarantee valid values.
    out = [f"{x:08b}" for x in raw]

    log_debug(f"BIN tokens generated | module=bin_formatting | func=bin_tokens | bytes={len(raw)} | label={label} | purpose={purpose}")

    return out

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

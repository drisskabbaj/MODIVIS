from __future__ import annotations  # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types

from typing import Optional  # needed to mark a value as str or None (existing or missing both possible)

from src.utils.logger import (
    log_debug,
    log_error,
)  # needed to log debug/error

from src.domain.exercises_types import ExerciseFmt  # needed for strict fmt typing

# ---------------------------------------------------------------------------------------------
#                               NIBBLE CONVERTER
# ---------------------------------------------------------------------------------------------
# Why this?
#   - Exercises operate on 4-bit symbols (nibbles): values from 0 to 15.
#   - Users write answers either:
#       - HEX: 0..9, A..F (1 char per symbol)
#       - BIN: 0000..1111 (4 bits per symbol)
#   - One single reliable parser for:
#       - expected answers stored internally as HEX digits (e.g. F0A1)
#       - user answers typed in UI (with flexible separators)
#
# Logging:
#   - log_error: on validation failures so the reason is visible
#   - log_debug: on successful parsing for trace
#
# Tested?
#   - Yes
#   - Unit test inside tests/utils/test_nibble_converter.py
# ---------------------------------------------------------------------------------------------

# Defining HEX chars (uppercase only and input is normalized to uppercase)
_HEX_CHARS = "0123456789ABCDEF"


def _preview(s: str, *, limit: int = 96) -> str:
    """
    Create a short preview for logs to avoid huge payloads.
    """
    if len(s) <= limit:
        return s
    return s[:limit] + "..."


def _normalize_user_separators(s: str) -> str:
    """
    Normalize common separators to whitespace so split() becomes reliable.
    """
    # Allow common separators: (), commas, semicolons, pipes, newlines, tabs
    for sep in ("(", ")", ",", ";", "|", "\n", "\r", "\t"):
        s = s.replace(sep, " ")
    return s.strip()


def parse_expected_hex_nibbles(expected_hex_raw: str, *, label: str = "", purpose: str = "") -> list[int]:
    """
    Parse an internal expected answer written as HEX digits.

    Example:
        F0A1 becomes [15, 0, 10, 1]

    Raises:
        TypeError: if input is not a string.
        ValueError: if it contains invalid hex chars.
    """
    # Defensive check: expected answers should be strings, but keep a stable boundary.
    if not isinstance(expected_hex_raw, str):
        log_error(
            "Nibble parse failed: invalid type for expected answer | module=nibble_converter | "
            "func=parse_expected_hex_nibbles | "
            f"type(expected_hex_raw)={type(expected_hex_raw).__name__} | label={label} | purpose={purpose}"
        )
        raise TypeError("parse_expected_hex_nibbles: expected_hex_raw must be a string.")

    # Normalize: ignore whitespace and force uppercase so validation is stable.
    s = expected_hex_raw.strip().replace(" ", "").upper()

    if s == "":
        log_debug(
            "Parsed empty expected HEX nibbles | module=nibble_converter | func=parse_expected_hex_nibbles | "
            f"symbols=0 | label={label} | purpose={purpose}"
        )
        return []

    out: list[int] = []
    for ch in s:
        if ch not in _HEX_CHARS:
            log_error(
                "Nibble parse failed: invalid HEX in expected answer | module=nibble_converter | "
                "func=parse_expected_hex_nibbles | "
                f"ch='{ch}' | value='{_preview(s)}' | label={label} | purpose={purpose}"
            )
            raise ValueError("parse_expected_hex_nibbles: internal expected answer contains invalid HEX.")
        out.append(int(ch, 16))

    log_debug(
        "Parsed expected HEX nibbles | module=nibble_converter | func=parse_expected_hex_nibbles | "
        f"symbols={len(out)} | label={label} | purpose={purpose}"
    )
    return out


def parse_user_nibbles(
    raw: Optional[str],
    *,
    fmt: ExerciseFmt | str,
    label: str = "",
    purpose: str = "",
) -> list[int]:
    """
    Parse users answer into nibble values (0..15).

    Supported separators:
      - commas, semicolons, pipes, parentheses, whitespace, newlines

    HEX mode:
      - "F,0,A,1" or "F0A1" or "(F, 0, A, 1)" are all accepted.

    BIN mode:
      - 4-bit groups: "1111 0000 1010 0001"
      - packed bit strings are also accepted if length is a multiple of 4:
          "1111000010100001"
      - optional 0b prefix per group is allowed:
          "0b1111 0b0000 ..."
      - optional 0b prefix for a packed bit string is allowed:
          "0b1111000010100001"

    Returns:
        list[int]: nibble values 0..15

    Raises:
        TypeError: if raw is not a string (and not None).
        ValueError: on missing answer, invalid fmt or invalid formatting.
    """
    fmt_u = (str(fmt) if fmt is not None else "").strip().upper()

    # Strict fmt validation
    if fmt_u not in ("HEX", "BIN"):
        log_error(
            "Nibble parse failed: invalid fmt | module=nibble_converter | func=parse_user_nibbles | "
            f"fmt='{fmt_u}' | label={label} | purpose={purpose}"
        )
        raise ValueError("parse_user_nibbles: fmt must be 'HEX' or 'BIN'.")

    if raw is None:
        log_error(
            "Nibble parse failed: missing answer | module=nibble_converter | func=parse_user_nibbles | "
            f"fmt='{fmt_u}' | label={label} | purpose={purpose}"
        )
        raise ValueError("parse_user_nibbles: answer is missing.")

    # Defensive check: keep errors readable and logged if UI passes wrong types.
    if not isinstance(raw, str):
        log_error(
            "Nibble parse failed: invalid type for answer | module=nibble_converter | func=parse_user_nibbles | "
            f"fmt='{fmt_u}' | type(raw)={type(raw).__name__} | label={label} | purpose={purpose}"
        )
        raise TypeError("parse_user_nibbles: answer must be a string.")

    s = raw.strip()

    # Keep behavior identical: empty answer is allowed and becomes [].
    if s == "":
        log_debug(
            "Parsed empty user answer | module=nibble_converter | func=parse_user_nibbles | "
            f"fmt='{fmt_u}' | symbols=0 | label={label} | purpose={purpose}"
        )
        return []

    # Normalize separators so tokenization is stable.
    s = _normalize_user_separators(s)

    if fmt_u == "BIN":
        tokens = [t for t in s.split() if t]
        out: list[int] = []

        for token in tokens:
            t = token.strip()

            # Allow 0b prefix on each token.
            if t.startswith(("0b", "0B")):
                t = t[2:]

            # Case 1: a single 4-bit group
            if len(t) == 4:
                if any(ch not in "01" for ch in t):
                    log_error(
                        "Nibble parse failed: invalid BIN group characters | module=nibble_converter | func=parse_user_nibbles | "
                        f"fmt=BIN | token='{_preview(t)}' | label={label} | purpose={purpose}"
                    )
                    raise ValueError("parse_user_nibbles: BIN groups must contain only 0 and 1 (example: 1010).")
                out.append(int(t, 2))
                continue

            # Case 2: packed bit string, must be multiple of 4
            if any(ch not in "01" for ch in t) or (len(t) % 4 != 0):
                log_error(
                    "Nibble parse failed: invalid BIN token | module=nibble_converter | func=parse_user_nibbles | "
                    f"fmt=BIN | token='{_preview(t)}' | bits={len(t)} | label={label} | purpose={purpose}"
                )
                raise ValueError(
                    "parse_user_nibbles: BIN answers must be written as 4-bit groups (example: 1010) "
                    "or as a packed bit string whose length is a multiple of 4."
                )

            for i in range(0, len(t), 4):
                out.append(int(t[i : i + 4], 2))

        log_debug(
            "Parsed user BIN nibbles | module=nibble_converter | func=parse_user_nibbles | "
            f"fmt=BIN | symbols={len(out)} | label={label} | purpose={purpose}"
        )
        return out

    # Default: HEX (fmt_u == "HEX")
    tokens = [t for t in s.split() if t]
    out: list[int] = []

    for token in tokens:
        t = token.strip().upper()

        # Allow compact strings like "F0A3", as well as separated input like "F 0 A 3".
        for ch in t:
            if ch not in _HEX_CHARS:
                log_error(
                    "Nibble parse failed: invalid HEX char | module=nibble_converter | func=parse_user_nibbles | "
                    f"fmt=HEX | ch='{ch}' | token='{_preview(t)}' | label={label} | purpose={purpose}"
                )
                raise ValueError("parse_user_nibbles: HEX answers must use symbols 0 to 9 and A to F.")
            out.append(int(ch, 16))

    log_debug(
        "Parsed user HEX nibbles | module=nibble_converter | func=parse_user_nibbles | "
        f"fmt=HEX | symbols={len(out)} | label={label} | purpose={purpose}"
    )
    return out

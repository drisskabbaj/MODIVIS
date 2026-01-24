from __future__ import annotations  # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types

from src.utils.logger import (
    log_error,
)  # needed to log error

from src.domain.exercises_types import ExerciseFmt  # needed for strict fmt typing

# ---------------------------------------------------------------------------------------------
#                               NIBBLE FORMATTING
# ---------------------------------------------------------------------------------------------
# Why this?
#   - Exercises display nibbles in either HEX or BIN.
#   - We keep formatting stable so UI output stays consistent.
#
# Logging:
#   - log_error: on validation failures so the reason is visible
#
# Tested?
#   - Yes
#   - Unit test inside: tests/utils/test_nibble_formatting.py
# ---------------------------------------------------------------------------------------------


def format_symbol(x: int, fmt: ExerciseFmt | str) -> str:
    """
    Format a single nibble (0..15) in HEX or BIN.

    HEX: 0..F
    BIN: 0000..1111

    Raises:
        TypeError: if x is not an integer.
        ValueError: if x is outside 0..15 or fmt is invalid.
    """
    fmt_u = (str(fmt) if fmt is not None else "").strip().upper()
    
    if not isinstance(x, int):
        log_error(
            "Nibble formatting failed: invalid type | module=nibble_formatting | func=format_symbol | "
            f"type(x)={type(x).__name__} | fmt='{fmt_u}'"
        )
        raise TypeError("Nibble formatting failed: x must be an integer.")

    if fmt_u not in ("HEX", "BIN"):
        log_error(
            "Nibble formatting failed: invalid fmt | module=nibble_formatting | func=format_symbol | "
            f"fmt='{fmt_u}'"
        )
        raise ValueError("Nibble formatting failed: fmt must be HEX or BIN.")

    if x < 0 or x > 15:
        log_error(
            "Nibble formatting failed: out of range | module=nibble_formatting | func=format_symbol | "
            f"x={x} | fmt='{fmt_u}'"
        )
        raise ValueError("Nibble formatting failed: x must be in range 0..15.")

    if fmt_u == "BIN":
        return f"{x:04b}"
    
    return f"{x:X}"


def format_tuple(values: list[int], fmt: ExerciseFmt | str) -> str:
    """
    Format a list of nibbles as a tuple-like string.

    Example:
      HEX: (F, 0, A, 3)
      BIN: (1111, 0000, 1010, 0011)

    Raises:
        TypeError: if values is not a list of integers.
        ValueError: if any value is outside 0..15 or fmt is invalid.
    """
    fmt_u = (str(fmt) if fmt is not None else "").strip().upper()

    if fmt_u not in ("HEX", "BIN"):
        log_error(
            "Nibble formatting failed: invalid fmt | module=nibble_formatting | func=format_tuple | "
            f"fmt='{fmt_u}'"
        )
        raise ValueError("Nibble formatting failed: fmt must be HEX or BIN.")

    if not isinstance(values, list):
        log_error(
            "Nibble formatting failed: invalid type | module=nibble_formatting | func=format_tuple | "
            f"type(values)={type(values).__name__} | fmt='{fmt_u}'"
        )
        raise TypeError("Nibble formatting failed: values must be a list of integers.")

    # Validate elements up front so failures are clean and consistent.
    for i, x in enumerate(values):
        if not isinstance(x, int):
            log_error(
                "Nibble formatting failed: invalid element type | module=nibble_formatting | func=format_tuple | "
                f"index={i} | type(x)={type(x).__name__} | fmt='{fmt_u}'"
            )
            raise TypeError("Nibble formatting failed: values must contain only integers.")

        if x < 0 or x > 15:
            log_error(
                "Nibble formatting failed: element out of range | module=nibble_formatting | func=format_tuple | "
                f"index={i} | x={x} | fmt='{fmt_u}'"
            )
            raise ValueError("Nibble formatting failed: all values must be in range 0..15.")

    parts = [format_symbol(v, fmt_u) for v in values]
    return "(" + ", ".join(parts) + ")"

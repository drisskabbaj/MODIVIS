from __future__ import annotations  # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types

from src.utils.logger import (
    log_debug,
    log_error,
)  # needed to log debug/error

# ---------------------------------------------------------------------------------------------
#                                  NIBBLE OPERATIONS
# ---------------------------------------------------------------------------------------------
# Why this?
#   - Exercises operate on 4-bit symbols (nibbles): values from 0 to 15.
#   - Simple helper operations that are easy to explain and verify:
#       - XOR between two nibbles (used in CBC style mixing)
#       - Increment modulo 16 (used for CTR counters)
#
# Logging:
#   - log_error: on validation failures so the reason is visible
#   - log_debug: on successful operations for trace
#
# Tested?
#   - Yes
#   - Unit test inside: tests/utils/test_nibble_operations.py
# ---------------------------------------------------------------------------------------------


def xor_nibble(a: int, b: int, *, a_label: str = "", b_label: str = "", purpose: str = "") -> int:
    """
    XOR two nibbles (0..15) and return a nibble (0..15).

    Raises:
        TypeError: if a or b are not integers.
        ValueError: if a or b are outside 0..15.
    """
    # Defensive check: UI inputs might be TEXT by mistake.
    if not isinstance(a, int) or not isinstance(b, int):
        log_error(
            "Nibble XOR failed: invalid types | module=nibble_operations | func=xor_nibble | "
            f"type(a)={type(a).__name__} | type(b)={type(b).__name__} | a_label={a_label} | b_label={b_label} | purpose={purpose}"
        )
        raise TypeError("Nibble XOR failed: inputs must be integers.")

    # Defensive check: keep mistakes visible.
    if a < 0 or a > 15 or b < 0 or b > 15:
        log_error(
            "Nibble XOR failed: out of range | module=nibble_operations | func=xor_nibble | "
            f"a={a} | b={b} | a_label={a_label} | b_label={b_label} | purpose={purpose}"
        )
        raise ValueError("Nibble XOR failed: inputs must be in range 0..15.")

    res = (a ^ b) & 0xF

    log_debug(
        "Nibble XOR done | module=nibble_operations | func=xor_nibble | "
        f"a={a} | b={b} | res={res} | a_label={a_label} | b_label={b_label} | purpose={purpose}"
    )
    return res


def add_mod_16(x: int, inc: int, *, label: str = "", inc_label: str = "", purpose: str = "") -> int:
    """
    Add inc to x modulo 16 and return a nibble (0..15).

    Raises:
        TypeError: if x or inc are not integers.
        ValueError: if x is outside 0..15.
    """
    # Defensive check: UI inputs might be TEXT by mistake.
    if not isinstance(x, int) or not isinstance(inc, int):
        log_error(
            "Add mod 16 failed: invalid types | module=nibble_operations | func=add_mod_16 | "
            f"type(x)={type(x).__name__} | type(inc)={type(inc).__name__} | label={label} | inc_label={inc_label} | purpose={purpose}"
        )
        raise TypeError("Add mod 16 failed: inputs must be integers.")

    # x represents a nibble state in the exercises, we keep mistakes visibe.
    if x < 0 or x > 15:
        log_error(
            "Add mod 16 failed: out of range | module=nibble_operations | func=add_mod_16 | "
            f"x={x} | inc={inc} | label={label} | inc_label={inc_label} | purpose={purpose}"
        )
        raise ValueError("Add mod 16 failed: x must be in range 0..15.")

    inc_mod = inc & 0xF
    res = (x + inc) & 0xF

    log_debug(
        "Add mod 16 done | module=nibble_operations | func=add_mod_16 | "
        f"x={x} | inc={inc} | inc_mod={inc_mod} | res={res} | label={label} | inc_label={inc_label} | purpose={purpose}"
    )
    return res

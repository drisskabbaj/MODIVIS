from __future__ import annotations # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types

import random # needed to randomize exercises and oracle table order
import secrets # needed to generate secure random keys and IV nibbles
from dataclasses import dataclass # helps simplifying building classes

from src.domain.crypto_types import Mode  # needed to reuse the same Mode literals as the rest of the app
from src.domain.exercises_types import (
    ExerciseAction,
    ExerciseFmt,
    ExerciseLevel,
)  # needed to avoid duplicated magic strings for exercises

from src.utils.nibble_converter import (
    parse_expected_hex_nibbles,
    parse_user_nibbles,
)  # needed to parse answers reliably (HEX/BIN)

from src.utils.nibble_formatting import (
    format_symbol,
)  # needed to format oracle tables consistently

from src.utils.nibble_operations import (
    xor_nibble,
    add_mod_16,
)  # needed for CBC/CTR nibble math with consistent masking


# -------------------------------------------------------------------------------------
#                           EXERCISES ENGINE (SERVICE)
# -------------------------------------------------------------------------------------
# Why??
#   - provides a single backend entry point for exercise generation and checking
#   - keeps mode rules and oracle table building out of the ViewModel
#   - ensures deterministic toy crypto behavior for exercises
#
# NB:
#   - this is a didactic engine (not real AES)
#   - units are 4-bit nibbles (0..15)
#
# Tested?
#   - Yes
#   - Unit test inside tests/services/test_exercises_engine.py
# -------------------------------------------------------------------------------------


# -------------------------------------------------------------------------------------
# Stable domain error for UI
# -------------------------------------------------------------------------------------
# Why?
#     - UI needs predictable error codes and field names
#     - avoid random exception types to leak into the view layer
# -------------------------------------------------------------------------------------
@dataclass(slots=True)
class ExercisesError(Exception):
    code: str         # stable machine readable code for the UI
    field: str        # which input field caused the error
    message: str      # user friendly message
    details: str = "" # optional technical details for debugging

    def __str__(self) -> str:
        return self.message


def _wrap(*, code: str, field: str, e: Exception) -> ExercisesError:
    # helper to convert internal exceptions into a stable UI error
    # keep the original exception type inside details for debugging
    return ExercisesError(
        code=code,
        field=field,
        message=str(e),
        details=f"{type(e).__name__}: {e}",
    )


# -------------------------------------------------------------------------------------
# Exercise core data container
# -------------------------------------------------------------------------------------
# Why?
#   - holds all exercise values without any UI widget dependencies
# -------------------------------------------------------------------------------------
@dataclass(slots=True)
class ExerciseCore:
    """
    Pure backend data for one exercise (no UI widgets, no Qt).

    - Symbols are 4-bit nibbles (0..15).
    - key_bytes define the toy keyed-permutation (oracle).
    """
    action: ExerciseAction          # ENCRYPT || DECRYPT
    mode: Mode                      # ECB || CBC || CTR
    fmt: ExerciseFmt                # HEX || BIN
    key_bytes: bytes
    iv_nibble: int                  

    pt: list[int]                   # plaintext nibbles
    ct: list[int]                   # ciphertext nibbles

    oracle_label: str
    oracle_table: str

    expected_hex_raw: str           # expected answer as HEX nibbles


# -------------------------------------------------------------------------------------
# Toy keyed-permutation (oracle)
# -------------------------------------------------------------------------------------
# Why?
#   - models a deterministic black-box function E_K / D_K for exercises
#   - invertible so decryption exercises are possible
# -------------------------------------------------------------------------------------
class _ToyNibblePermutation:
    """
    Didactic black-box function for exercises (not real AES).

    - Domain: 4-bit symbols (0..15).
    - Deterministic per key.
    - Invertible permutation, so D_K exists.
    """

    def __init__(self, key_bytes: bytes) -> None:
        seed = int.from_bytes(self._seed_from_key(key_bytes), "big")
        rng = random.Random(seed)

        perm = list(range(16))
        rng.shuffle(perm)

        inv = [0] * 16
        for x, y in enumerate(perm):
            inv[y] = x

        self._perm = perm
        self._inv = inv

    @staticmethod
    def _seed_from_key(key_bytes: bytes) -> bytes:
        # Small deterministic mixer (didactic; not cryptographic)
        out = bytearray(16)
        for i, b in enumerate(key_bytes):
            out[i % 16] ^= (b + i) & 0xFF
            out[(i * 5) % 16] ^= (b * 17) & 0xFF
        return bytes(out)

    def ek(self, x: int) -> int:
        return self._perm[x & 0xF]

    def dk(self, y: int) -> int:
        return self._inv[y & 0xF]


# -------------------------------------------------------------------------------------
# Exercises engine
# -------------------------------------------------------------------------------------
# Why?
#   - generates exercises
#   - builds oracle lookup tables for students
#   - validates answers and keeps parsing centralized
# -------------------------------------------------------------------------------------
class ExercisesEngine:
    """
    Backend engine:

    - Generates a random exercise core.
    - Builds the oracle table.
    - Checks answers (HEX/BIN input parsing).
    """

    def generate(self, level: str) -> ExerciseCore:
        # normalize difficulty level so we only handle normal/hard internally
        lvl = (level or "").strip().upper()
        level_norm: ExerciseLevel = "HARD" if lvl == "HARD" else "NORMAL"

        # pick randomized exercise parameters
        action: ExerciseAction = random.choice(["ENCRYPT", "DECRYPT"])
        mode: Mode = random.choice(["ECB", "CBC", "CTR"])
        fmt: ExerciseFmt = random.choice(["HEX", "BIN"])

        # build a deterministic toy cipher for this exercise
        key_bytes = secrets.token_bytes(random.choice([16, 24, 32]))
        cipher = _ToyNibblePermutation(key_bytes)

        # choose a small number of symbols (3–5)
        n = self._pick_len(level_norm)

        # CBC/CTR need a start value (4-bit IV nibble)
        iv_nibble = secrets.randbelow(16) if mode in ("CBC", "CTR") else 0

        # Always generate Plaintext first, then derive Ciphertext by mode rules
        pt = [secrets.randbelow(16) for _ in range(n)]
        ct, oracle_label, oracle_table = self._encrypt_and_oracle(mode, pt, iv_nibble, cipher, fmt, level_norm)

        if action == "ENCRYPT":
            expected_hex_raw = "".join(f"{x:X}" for x in ct)
            return ExerciseCore(
                action="ENCRYPT",
                mode=mode,
                fmt=fmt,
                key_bytes=key_bytes,
                iv_nibble=iv_nibble,
                pt=pt,
                ct=ct,
                oracle_label=oracle_label,
                oracle_table=oracle_table,
                expected_hex_raw=expected_hex_raw,
            )

        # DECRYPT exercise: prompt shows Ciphertext, expected answer is Plaintext
        oracle_label_d, oracle_table_d = self._decrypt_oracle(mode, ct, iv_nibble, cipher, fmt, level_norm)
        expected_hex_raw = "".join(f"{x:X}" for x in pt)
        return ExerciseCore(
            action="DECRYPT",
            mode=mode,
            fmt=fmt,
            key_bytes=key_bytes,
            iv_nibble=iv_nibble,
            pt=pt,
            ct=ct,
            oracle_label=oracle_label_d,
            oracle_table=oracle_table_d,
            expected_hex_raw=expected_hex_raw,
        )

    # ---------------------------
    # Exercise core (mode rules)
    # ---------------------------

    @staticmethod
    def _pick_len(level: ExerciseLevel) -> int:
        # 3–5 symbols only
        if level == "HARD":
            return random.randint(4, 5)
        return random.randint(3, 5)

    def _encrypt_and_oracle(
        self,
        mode: Mode,
        pt: list[int],
        iv: int,
        cipher: _ToyNibblePermutation,
        fmt: ExerciseFmt,
        level: ExerciseLevel,
    ) -> tuple[list[int], str, str]:
        # limit oracle table size by difficulty
        max_rows = 10 if (level == "HARD") else 8

        if mode == "ECB":
            ct = [cipher.ek(p) for p in pt]
            label, table = self._oracle_E(cipher, needed=pt, fmt=fmt, max_rows=max_rows)
            return ct, label, table

        if mode == "CBC":
            ct: list[int] = []
            prev = iv & 0xF
            needed_x: list[int] = []
            for p in pt:
                x = xor_nibble(p, prev, purpose="CBC: P_i XOR prev")
                needed_x.append(x)
                c = cipher.ek(x)
                ct.append(c)
                prev = c
            label, table = self._oracle_E(cipher, needed=needed_x, fmt=fmt, max_rows=max_rows)
            return ct, label, table

        # CTR
        ct: list[int] = []
        counters: list[int] = []
        for i, p in enumerate(pt):
            ctr = add_mod_16(iv, i, purpose="CTR: ctr_i = (IV + i) mod 16")
            counters.append(ctr)
            s = cipher.ek(ctr)
            ct.append(xor_nibble(p, s, purpose="CTR: P_i XOR S_i"))

        label, table = self._oracle_E(
            cipher,
            needed=counters,
            fmt=fmt,
            max_rows=max_rows,
            header="Keyed-permutation values (lookup table)",
        )
        return ct, label, table

    def _decrypt_oracle(
        self,
        mode: Mode,
        ct: list[int],
        iv: int,
        cipher: _ToyNibblePermutation,
        fmt: ExerciseFmt,
        level: ExerciseLevel,
    ) -> tuple[str, str]:
        # limit oracle table size by difficulty
        max_rows = 10 if (level == "HARD") else 8

        if mode == "ECB":
            return self._oracle_D(cipher, needed=ct, fmt=fmt, max_rows=max_rows)

        if mode == "CBC":
            return self._oracle_D(cipher, needed=ct, fmt=fmt, max_rows=max_rows)

        # CTR: same keystream as encrypt
        counters = [add_mod_16(iv, i, purpose="CTR decrypt: counters") for i in range(len(ct))]
        return self._oracle_E(
            cipher,
            needed=counters,
            fmt=fmt,
            max_rows=max_rows,
            header="Keyed-permutation values (lookup table)",
        )

    # -------------------------
    # Oracle tables
    # -------------------------

    def _oracle_E(
        self,
        cipher: _ToyNibblePermutation,
        *,
        needed: list[int],
        fmt: ExerciseFmt,
        max_rows: int,
        header: str = "Keyed-permutation values (lookup table)",
    ) -> tuple[str, str]:
        # build a randomized oracle table around needed values
        base = self._unique_4bit(needed)
        rows = self._with_decoys(base, max_rows=max_rows)

        pairs = [(x, cipher.ek(x)) for x in rows]
        random.shuffle(pairs)

        lines = [f"E_K({format_symbol(x, fmt)}) = {format_symbol(y, fmt)}" for x, y in pairs]
        return header, "\n" + "\n".join(lines)

    def _oracle_D(
        self,
        cipher: _ToyNibblePermutation,
        *,
        needed: list[int],
        fmt: ExerciseFmt,
        max_rows: int,
    ) -> tuple[str, str]:
        # build a randomized oracle table around needed values
        base = self._unique_4bit(needed)
        rows = self._with_decoys(base, max_rows=max_rows)

        pairs = [(y, cipher.dk(y)) for y in rows]
        random.shuffle(pairs)

        lines = [f"D_K({format_symbol(y, fmt)}) = {format_symbol(x, fmt)}" for y, x in pairs]
        return "Keyed-permutation values (lookup table)", "\n" + "\n".join(lines)

    @staticmethod
    def _unique_4bit(values: list[int]) -> list[int]:
        # keep order but remove duplicates after masking to 4-bit
        seen: set[int] = set()
        out: list[int] = []
        for v in values:
            x = v & 0xF
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    @staticmethod
    def _with_decoys(needed: list[int], *, max_rows: int) -> list[int]:
        # Add decoys so the table isn't trivially "the answer list"
        if len(needed) >= max_rows:
            return random.sample(needed, k=max_rows)

        out = set(needed)
        while len(out) < max_rows:
            out.add(secrets.randbelow(16))
        return list(out)

    # -----------------------------
    # Parsing / checking (answers)
    # -----------------------------

    @staticmethod
    def parse_expected_hex_nibbles(expected_hex_raw: str) -> list[int]:
        # wrapper to keep stable error codes in this service
        try:
            return parse_expected_hex_nibbles(expected_hex_raw)
        except Exception as e:
            raise _wrap(code="INVALID_EXPECTED", field="expected", e=e) from e

    def check_answer(self, *, expected_hex_raw: str, fmt: ExerciseFmt | str, user_answer: str, label: str = "", purpose: str = "",) -> bool:
        # parse expected answer and user answer using shared utilities
        try:
            expected = parse_expected_hex_nibbles(expected_hex_raw,  label=label, purpose=purpose)
        except Exception as e:
            raise _wrap(code="INVALID_EXPECTED", field="expected", e=e) from e

        try:
            got = parse_user_nibbles(user_answer, fmt=fmt, label=label, purpose=purpose)
        except Exception as e:
            raise _wrap(code="INVALID_ANSWER", field="answer", e=e) from e
        return got == expected

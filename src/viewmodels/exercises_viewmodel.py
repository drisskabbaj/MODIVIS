from __future__ import annotations  # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types

from dataclasses import dataclass  # needed to build simple classes

from src.domain.crypto_types import Mode  # needed for strict mode typing
from src.domain.padding_types import PaddingMode  # needed for UI compatibility fields (even if exercises do not use padding)
from src.domain.exercises_types import ExerciseFmt  # needed for strict fmt typing

from src.services.exercises_engine import (
    ExercisesEngine,  # needed to generate exercises and validate answers
    ExerciseCore,  # needed as the backend exercise DTO that we map to a UI DTO
)

from src.utils.nibble_formatting import (
    format_symbol,  # needed to format a single nibble in HEX or BIN for UI labels (IV)
    format_tuple,  # needed to format a list of nibbles into tuple-like output for UI
)

from src.utils.logger import (
    log_debug,
    log_error,
)  # needed to log debug/error for traceability and consistent UI-safe failures

# ---------------------------------------------------------------------------------------------
#                                  EXERCISES VIEWMODEL
# ---------------------------------------------------------------------------------------------
# Why this?
#   - UI needs a stable bridge to the exercises backend (generation + answer checking).
#   - Users practice mode mechanics (ECB, CBC, CTR) using 4-bit symbols (nibbles), not full AES rounds.
#   - ViewModel keeps UI code simple by:
#       - mapping backend ExerciseCore to a UI-friendly Exercise object
#       - keeping session state (level, score, answered_correctly)
#       - returning stable CheckResult objects for answer submission
#
# Logging:
#   - log_debug: exercise generated, level changes, answer checked (trace)
#   - log_error: invalid internal state or unexpected backend errors (visibility)
#
# Tested?
#   - Yes
#   - Unit test inside: tests/viewmodels/test_exercises_viewmodel.py
# ---------------------------------------------------------------------------------------------

_PURPOSE = "exercises_viewmodel"


# ---------------------------------------------------------------------------------------------
#                              VIEWMODEL EXERCISE DTO
# ---------------------------------------------------------------------------------------------
# Why this?
#   - UI needs one stable object representing the current exercise.
#   - Keeps labels, prompt/oracle text, and the internal expected answer (HEX digits) together.
# ---------------------------------------------------------------------------------------------
@dataclass(slots=True)
class Exercise:
    action: str          # "ENCRYPT" | "DECRYPT"
    mode: Mode           # "ECB" | "CBC" | "CTR"
    fmt: ExerciseFmt     # "HEX" | "BIN"

    # kept for UI compatibility (exercises do not use padding here)
    padding_mode: PaddingMode
    unpadding_mode: PaddingMode

    # shown for completeness (user does not need it to solve)
    key_hex: str

    # shown only for CBC/CTR (4-bit start value displayed in current fmt)
    iv_hex: str

    prompt_label: str
    prompt_value: str

    oracle_label: str
    oracle_table: str

    answer_label: str

    # internal expected answer as HEX digits (nibbles), e.g. F0A1
    expected_hex_raw: str


# ---------------------------------------------------------------------------------------------
#                             VIEWMODEL CHECK RESULT
# ---------------------------------------------------------------------------------------------
# Why this?
#   - UI needs one stable object representing a submission attempt.
#   - ok:
#       - True  : correct
#       - False : wrong
#       - None  : invalid input / parse error (UI shows message, score unchanged)
# ---------------------------------------------------------------------------------------------
@dataclass(slots=True)
class CheckResult:
    ok: bool | None
    message: str
    score: int
    score_delta: int


class ExercisesViewModel:
    """
    - Students do NOT compute AES rounds.
    - Modeled the cipher as a black-box function E_K / D_K.
    - Units are 4-bit symbols (nibbles): 0..F (BIN: 0000..1111).
    - User practices mode mechanics: XOR, chaining (CBC), counter/keystream (CTR).
    """

    def __init__(self) -> None:
        self._engine = ExercisesEngine()
        self._level = "NORMAL"
        self._score = 0
        self._exercise: Exercise | None = None
        self._answered_correctly = False

        log_debug(f"ExercisesViewModel created | module=exercises_viewmodel | func=__init__ | level={self._level}")

    # -----------------------------------------------------------------------------------------
    # Session state
    # -----------------------------------------------------------------------------------------
    # Why this?
    #   - The ViewModel owns the session state so UI stays dumb and predictable.
    #   - Score and answered_correctly must survive UI re-renders.
    # -----------------------------------------------------------------------------------------

    @property
    def level(self) -> str:
        return self._level

    def set_level(self, level: str) -> None:
        lvl = (level or "").strip().upper()
        new_level = "HARD" if lvl == "HARD" else "NORMAL"

        if new_level != self._level:
            log_debug(
                "Exercise level changed | module=exercises_viewmodel | func=set_level | "
                f"old={self._level} | new={new_level}"
            )

        self._level = new_level

    @property
    def score(self) -> int:
        return self._score

    def current_exercise(self) -> Exercise | None:
        return self._exercise

    def reset(self) -> None:
        self._score = 0
        self.new_exercise()
        log_debug("Exercise session reset | module=exercises_viewmodel | func=reset | score=0")

    def new_exercise(self) -> Exercise:
        core = self._engine.generate(self._level)
        ex = self._to_view(core)

        self._exercise = ex
        self._answered_correctly = False

        log_debug(
            "New exercise generated | module=exercises_viewmodel | func=new_exercise | "
            f"level={self._level} | action={ex.action} | mode={ex.mode} | fmt={ex.fmt}"
        )
        return ex

    def can_check(self, user_text: str) -> bool:
        if self._answered_correctly:
            return False
        return bool((user_text or "").strip())

    # -----------------------------------------------------------------------------------------
    # Submit answer
    # -----------------------------------------------------------------------------------------
    # Why this?
    #   - Single entry point for the UI when the user presses Check.
    #   - Uses engine.check_answer and maps the result to a stable CheckResult shape.
    # -----------------------------------------------------------------------------------------
    def submit_answer(self, user_answer: str) -> CheckResult:
        if not self._exercise:
            log_error(
                "Submit failed: no current exercise | module=exercises_viewmodel | func=submit_answer"
            )
            return CheckResult(ok=None, message="Answer is missing.", score=self._score, score_delta=0)

        if self._answered_correctly:
            # View should already disable but here kept safe behavior
            return CheckResult(ok=True, message="Correct. The score increases by one.", score=self._score, score_delta=0)

        try:
            ok = self._engine.check_answer(
                expected_hex_raw=self._exercise.expected_hex_raw,
                fmt=(self._exercise.fmt or "HEX"),
                user_answer=user_answer,
                label="Exercises answer",
                purpose=_PURPOSE,
            )
        except Exception as e:
            log_error(
                "Submit failed: check_answer raised | module=exercises_viewmodel | func=submit_answer | "
                f"error={type(e).__name__}: {e}"
            )
            return CheckResult(ok=None, message=str(e), score=self._score, score_delta=0)

        if ok:
            self._score += 1
            self._answered_correctly = True

            log_debug(
                "Answer correct | module=exercises_viewmodel | func=submit_answer | "
                f"level={self._level} | new_score={self._score}"
            )

            return CheckResult(
                ok=True,
                message="Correct. The score increases by one.",
                score=self._score,
                score_delta=1,
            )

        # wrong
        delta = 0
        if self._level == "HARD":
            self._score -= 1
            delta = -1

        log_debug(
            "Answer wrong | module=exercises_viewmodel | func=submit_answer | "
            f"level={self._level} | score_delta={delta} | new_score={self._score}"
        )

        return CheckResult(
            ok=False,
            message="Wrong answer.",
            score=self._score,
            score_delta=delta,
        )

    # -----------------------------------------------------------------------------------------
    # Legacy API
    # -----------------------------------------------------------------------------------------
    def check_answer(self, exercise: Exercise, user_answer: str) -> bool:
        return self._engine.check_answer(
            expected_hex_raw=exercise.expected_hex_raw,
            fmt=(exercise.fmt or "HEX"),
            user_answer=user_answer,
            label="Exercises answer (legacy)",
            purpose=_PURPOSE,
        )

    # -----------------------------------------------------------------------------------------
    # Formatting
    # -----------------------------------------------------------------------------------------
    def _to_view(self, core: ExerciseCore) -> Exercise:
        # Normalize fmt so nibble_formatting never receives invalid values.
        fmt_u = (core.fmt or "HEX").strip().upper()
        if fmt_u not in ("HEX", "BIN"):
            log_error(
                "Invalid exercise fmt from engine, defaulting to HEX | module=exercises_viewmodel | func=_to_view | "
                f"fmt='{fmt_u}'"
            )
            fmt_u = "HEX"

        fmt: ExerciseFmt = fmt_u

        iv_disp = format_symbol(core.iv_nibble, fmt) if core.mode in ("CBC", "CTR") else ""

        if core.action == "ENCRYPT":
            prompt_label = "Plaintext"
            prompt_value = format_tuple(core.pt, fmt)
            answer_label = f"Ciphertext in {fmt} format"
        else:
            prompt_label = "Ciphertext"
            prompt_value = format_tuple(core.ct, fmt)
            answer_label = f"Plaintext in {fmt} format"

        return Exercise(
            action=core.action,
            mode=core.mode,
            fmt=fmt,
            padding_mode="NONE",
            unpadding_mode="NONE",
            key_hex=core.key_bytes.hex(),
            iv_hex=iv_disp,
            prompt_label=prompt_label,
            prompt_value=prompt_value,
            oracle_label=core.oracle_label,
            oracle_table=core.oracle_table,
            answer_label=answer_label,
            expected_hex_raw=core.expected_hex_raw,
        )
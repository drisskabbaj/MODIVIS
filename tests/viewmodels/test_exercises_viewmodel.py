import pytest
from dataclasses import dataclass

import src.viewmodels.exercises_viewmodel as xvm


@dataclass(slots=True)
class DummyExerciseCore:
    action: str                 # "ENCRYPT" | "DECRYPT"
    mode: str                   # "ECB" | "CBC" | "CTR"
    fmt: str                    # "HEX" | "BIN" | anything (to test fallback)

    iv_nibble: int              # 0..15
    pt: list[int]               # plaintext nibbles
    ct: list[int]               # ciphertext nibbles

    key_bytes: bytes
    oracle_label: str
    oracle_table: str
    expected_hex_raw: str


class DummyExercisesEngine:
    def __init__(self) -> None:
        self.generate_calls: list[str] = []
        self.check_calls: list[dict] = []

        self.next_core: DummyExerciseCore | None = None
        self.next_ok: bool = False
        self.raise_on_check: Exception | None = None

    def generate(self, level: str):
        self.generate_calls.append(level)
        if self.next_core is None:
            raise RuntimeError("DummyExercisesEngine.next_core was not set.")
        return self.next_core

    def check_answer(self, **kwargs):
        self.check_calls.append(kwargs)
        if self.raise_on_check is not None:
            raise self.raise_on_check
        return self.next_ok


# Autoapplied
@pytest.fixture(autouse=True)
def _patch_engine(monkeypatch):
    # ExercisesViewModel should use our DummyExercisesEngine instead of the real backend.
    monkeypatch.setattr(xvm, "ExercisesEngine", DummyExercisesEngine)


# ExercisesViewModel should have stable initial session state.
def test_exercises_viewmodel_initial_state_is_stable():
    vm = xvm.ExercisesViewModel()

    assert vm.level == "NORMAL"
    assert vm.score == 0
    assert vm.current_exercise() is None

    assert vm.can_check("") is False
    assert vm.can_check("   ") is False
    assert vm.can_check("A") is True


# set_level should normalize to HARD only for HARD otherwise NORMAL.
def test_set_level_normalizes_to_hard_or_normal():
    vm = xvm.ExercisesViewModel()

    vm.set_level("hard")
    assert vm.level == "HARD"

    vm.set_level("   HARD   ")
    assert vm.level == "HARD"

    vm.set_level("nope")
    assert vm.level == "NORMAL"

    vm.set_level("")
    assert vm.level == "NORMAL"

    vm.set_level(None)
    assert vm.level == "NORMAL"


# new_exercise should call engine.generate(level) and map ENCRYPT ECB HEX into Exercise correctly.
def test_new_exercise_encrypt_ecb_hex_maps_fields(monkeypatch):
    calls: list[tuple[str, object]] = []

    def fake_format_tuple(values: list[int], fmt: str) -> str:
        calls.append(("tuple", (values, fmt)))
        return f"TUP({values}|{fmt})"

    def fake_format_symbol(x: int, fmt: str) -> str:
        calls.append(("symbol", (x, fmt)))
        return f"SYM({x}|{fmt})"

    monkeypatch.setattr(xvm, "format_tuple", fake_format_tuple)
    monkeypatch.setattr(xvm, "format_symbol", fake_format_symbol)

    vm = xvm.ExercisesViewModel()
    engine: DummyExercisesEngine = vm._engine
    engine.next_core = DummyExerciseCore(
        action="ENCRYPT",
        mode="ECB",
        fmt="HEX",
        iv_nibble=7,
        pt=[15, 0, 10, 1],
        ct=[0, 0, 0, 0],
        key_bytes=b"\x11" * 16,
        oracle_label="Oracle",
        oracle_table="TABLE",
        expected_hex_raw="F0A1",
    )

    ex = vm.new_exercise()

    assert engine.generate_calls == ["NORMAL"]
    assert ex.action == "ENCRYPT"
    assert ex.mode == "ECB"
    assert ex.fmt == "HEX"

    assert ex.padding_mode == "NONE"
    assert ex.unpadding_mode == "NONE"

    assert ex.key_hex == ("11" * 16)
    assert ex.iv_hex == ""  # ECB shows no IV

    assert ex.prompt_label == "Plaintext"
    assert ex.prompt_value == "TUP([15, 0, 10, 1]|HEX)"
    assert ex.answer_label == "Ciphertext in HEX format"

    assert ex.oracle_label == "Oracle"
    assert ex.oracle_table == "TABLE"
    assert ex.expected_hex_raw == "F0A1"

    assert calls == [
        ("tuple", ([15, 0, 10, 1], "HEX")),
    ]


# new_exercise should map DECRYPT CBC BIN and include the IV display via format_symbol.
def test_new_exercise_decrypt_cbc_bin_includes_iv_and_maps_fields(monkeypatch):
    calls: list[tuple[str, object]] = []

    def fake_format_tuple(values: list[int], fmt: str) -> str:
        calls.append(("tuple", (values, fmt)))
        return f"TUP({values}|{fmt})"

    def fake_format_symbol(x: int, fmt: str) -> str:
        calls.append(("symbol", (x, fmt)))
        return f"SYM({x}|{fmt})"

    monkeypatch.setattr(xvm, "format_tuple", fake_format_tuple)
    monkeypatch.setattr(xvm, "format_symbol", fake_format_symbol)

    vm = xvm.ExercisesViewModel()
    engine: DummyExercisesEngine = vm._engine
    engine.next_core = DummyExerciseCore(
        action="DECRYPT",
        mode="CBC",
        fmt="BIN",
        iv_nibble=3,
        pt=[0, 0, 0, 0],
        ct=[15, 0, 10, 3],
        key_bytes=b"\xaa" * 16,
        oracle_label="Oracle",
        oracle_table="TABLE",
        expected_hex_raw="F0A3",
    )

    ex = vm.new_exercise()

    assert engine.generate_calls == ["NORMAL"]
    assert ex.action == "DECRYPT"
    assert ex.mode == "CBC"
    assert ex.fmt == "BIN"

    assert ex.iv_hex == "SYM(3|BIN)"
    assert ex.prompt_label == "Ciphertext"
    assert ex.prompt_value == "TUP([15, 0, 10, 3]|BIN)"
    assert ex.answer_label == "Plaintext in BIN format"

    assert calls == [
        ("symbol", (3, "BIN")),
        ("tuple", ([15, 0, 10, 3], "BIN")),
    ]


# _to_view should default invalid fmt to HEX and log an error.
def test_to_view_invalid_fmt_defaults_to_hex_and_logs_error(monkeypatch):
    error_calls: list[str] = []
    calls: list[tuple[str, object]] = []

    monkeypatch.setattr(xvm, "log_error", lambda msg: error_calls.append(msg))

    def fake_format_tuple(values: list[int], fmt: str) -> str:
        calls.append(("tuple", (values, fmt)))
        return f"TUP({values}|{fmt})"

    def fake_format_symbol(x: int, fmt: str) -> str:
        calls.append(("symbol", (x, fmt)))
        return f"SYM({x}|{fmt})"

    monkeypatch.setattr(xvm, "format_tuple", fake_format_tuple)
    monkeypatch.setattr(xvm, "format_symbol", fake_format_symbol)

    vm = xvm.ExercisesViewModel()
    core = DummyExerciseCore(
        action="ENCRYPT",
        mode="CTR",
        fmt="DEC",
        iv_nibble=9,
        pt=[1, 2, 3, 4],
        ct=[0, 0, 0, 0],
        key_bytes=b"\x10" * 16,
        oracle_label="O",
        oracle_table="T",
        expected_hex_raw="01020304",
    )

    ex = vm._to_view(core)  # testing the mapping boundary directly

    assert ex.fmt == "HEX"
    assert ex.iv_hex == "SYM(9|HEX)"
    assert ex.prompt_value == "TUP([1, 2, 3, 4]|HEX)"

    assert len(error_calls) == 1
    assert "Invalid exercise fmt from engine, defaulting to HEX" in error_calls[0]
    assert "func=_to_view" in error_calls[0]
    assert "fmt='DEC'" in error_calls[0]

    assert calls == [
        ("symbol", (9, "HEX")),
        ("tuple", ([1, 2, 3, 4], "HEX")),
    ]


# reset should set score to 0 and generate a new exercise.
def test_reset_sets_score_to_zero_and_generates_new_exercise(monkeypatch):
    monkeypatch.setattr(xvm, "format_tuple", lambda values, fmt: "TUP")
    monkeypatch.setattr(xvm, "format_symbol", lambda x, fmt: "SYM")

    vm = xvm.ExercisesViewModel()
    engine: DummyExercisesEngine = vm._engine
    engine.next_core = DummyExerciseCore(
        action="ENCRYPT",
        mode="ECB",
        fmt="HEX",
        iv_nibble=0,
        pt=[0],
        ct=[0],
        key_bytes=b"\x01" * 16,
        oracle_label="O",
        oracle_table="T",
        expected_hex_raw="0",
    )

    vm._score = 7  # force non-zero score
    vm.reset()

    assert vm.score == 0
    assert vm.current_exercise() is not None
    assert engine.generate_calls == ["NORMAL"]


# submit_answer should return ok=None if there is no current exercise and log error.
def test_submit_answer_without_exercise_returns_ok_none_and_logs_error(monkeypatch):
    error_calls: list[str] = []

    monkeypatch.setattr(xvm, "log_error", lambda msg: error_calls.append(msg))

    vm = xvm.ExercisesViewModel()
    r = vm.submit_answer("A")

    assert r.ok is None
    assert r.message == "Answer is missing."
    assert r.score == 0
    assert r.score_delta == 0

    assert len(error_calls) == 1
    assert "Submit failed: no current exercise" in error_calls[0]
    assert "func=submit_answer" in error_calls[0]


# submit_answer should forward arguments into engine.check_answer unchanged.
def test_submit_answer_forwards_arguments_to_engine_check_answer(monkeypatch):
    monkeypatch.setattr(xvm, "format_tuple", lambda values, fmt: "TUP")
    monkeypatch.setattr(xvm, "format_symbol", lambda x, fmt: "SYM")

    vm = xvm.ExercisesViewModel()
    engine: DummyExercisesEngine = vm._engine
    engine.next_core = DummyExerciseCore(
        action="ENCRYPT",
        mode="ECB",
        fmt="HEX",
        iv_nibble=0,
        pt=[15],
        ct=[0],
        key_bytes=b"\x00" * 16,
        oracle_label="O",
        oracle_table="T",
        expected_hex_raw="F",
    )
    vm.new_exercise()

    engine.next_ok = False
    out = vm.submit_answer("F")

    assert out.ok is False
    assert len(engine.check_calls) == 1
    assert engine.check_calls[0] == {
        "expected_hex_raw": "F",
        "fmt": "HEX",
        "user_answer": "F",
        "label": "Exercises answer",
        "purpose": "exercises_viewmodel",
    }


# submit_answer should increment score and lock further checks when answer is correct.
def test_submit_answer_correct_increments_score_and_locks(monkeypatch):
    monkeypatch.setattr(xvm, "format_tuple", lambda values, fmt: "TUP")
    monkeypatch.setattr(xvm, "format_symbol", lambda x, fmt: "SYM")

    vm = xvm.ExercisesViewModel()
    engine: DummyExercisesEngine = vm._engine
    engine.next_core = DummyExerciseCore(
        action="DECRYPT",
        mode="CBC",
        fmt="HEX",
        iv_nibble=1,
        pt=[0],
        ct=[1],
        key_bytes=b"\x00" * 16,
        oracle_label="O",
        oracle_table="T",
        expected_hex_raw="A",
    )
    vm.new_exercise()

    engine.next_ok = True
    r1 = vm.submit_answer("A")

    assert r1.ok is True
    assert r1.message == "Correct. The score increases by one."
    assert r1.score == 1
    assert r1.score_delta == 1

    assert vm.score == 1
    assert vm.can_check("A") is False  # locked after correct answer
    assert len(engine.check_calls) == 1

    # Second submit should not call engine again and should not increase score again.
    r2 = vm.submit_answer("A")
    assert r2.ok is True
    assert r2.score == 1
    assert r2.score_delta == 0
    assert len(engine.check_calls) == 1


# submit_answer should not penalize wrong answers in NORMAL.
def test_submit_answer_wrong_normal_has_no_penalty(monkeypatch):
    monkeypatch.setattr(xvm, "format_tuple", lambda values, fmt: "TUP")
    monkeypatch.setattr(xvm, "format_symbol", lambda x, fmt: "SYM")

    vm = xvm.ExercisesViewModel()
    engine: DummyExercisesEngine = vm._engine
    engine.next_core = DummyExerciseCore(
        action="ENCRYPT",
        mode="ECB",
        fmt="HEX",
        iv_nibble=0,
        pt=[1],
        ct=[2],
        key_bytes=b"\x00" * 16,
        oracle_label="O",
        oracle_table="T",
        expected_hex_raw="1",
    )
    vm.new_exercise()

    engine.next_ok = False
    r = vm.submit_answer("0")

    assert r.ok is False
    assert r.message == "Wrong answer."
    assert r.score == 0
    assert r.score_delta == 0
    assert vm.can_check("0") is True


# submit_answer should penalize wrong answers in HARD by decrementing score.
def test_submit_answer_wrong_hard_decrements_score(monkeypatch):
    monkeypatch.setattr(xvm, "format_tuple", lambda values, fmt: "TUP")
    monkeypatch.setattr(xvm, "format_symbol", lambda x, fmt: "SYM")

    vm = xvm.ExercisesViewModel()
    vm.set_level("HARD")

    engine: DummyExercisesEngine = vm._engine
    engine.next_core = DummyExerciseCore(
        action="ENCRYPT",
        mode="ECB",
        fmt="HEX",
        iv_nibble=0,
        pt=[1],
        ct=[2],
        key_bytes=b"\x00" * 16,
        oracle_label="O",
        oracle_table="T",
        expected_hex_raw="1",
    )
    vm.new_exercise()

    engine.next_ok = False
    r = vm.submit_answer("0")

    assert r.ok is False
    assert r.message == "Wrong answer."
    assert r.score == -1
    assert r.score_delta == -1
    assert vm.score == -1


# submit_answer should map unexpected backend errors to ok=None with a safe message and unchanged score.
def test_submit_answer_engine_exception_returns_ok_none_and_does_not_change_score(monkeypatch):
    error_calls: list[str] = []

    monkeypatch.setattr(xvm, "log_error", lambda msg: error_calls.append(msg))
    monkeypatch.setattr(xvm, "format_tuple", lambda values, fmt: "TUP")
    monkeypatch.setattr(xvm, "format_symbol", lambda x, fmt: "SYM")

    vm = xvm.ExercisesViewModel()
    engine: DummyExercisesEngine = vm._engine
    engine.next_core = DummyExerciseCore(
        action="ENCRYPT",
        mode="ECB",
        fmt="HEX",
        iv_nibble=0,
        pt=[1],
        ct=[2],
        key_bytes=b"\x00" * 16,
        oracle_label="O",
        oracle_table="T",
        expected_hex_raw="1",
    )
    vm.new_exercise()

    engine.raise_on_check = ValueError("Bad answer format")
    r = vm.submit_answer("whatever")

    assert r.ok is None
    assert r.message == "Bad answer format"
    assert r.score == 0
    assert r.score_delta == 0
    assert vm.score == 0

    assert len(error_calls) == 1
    assert "Submit failed: check_answer raised" in error_calls[0]
    assert "ValueError: Bad answer format" in error_calls[0]


# check_answer legacy API should forward into engine.check_answer with legacy label.
def test_check_answer_legacy_forwards_arguments(monkeypatch):
    monkeypatch.setattr(xvm, "format_tuple", lambda values, fmt: "TUP")
    monkeypatch.setattr(xvm, "format_symbol", lambda x, fmt: "SYM")

    vm = xvm.ExercisesViewModel()
    engine: DummyExercisesEngine = vm._engine

    ex = xvm.Exercise(
        action="ENCRYPT",
        mode="ECB",
        fmt="HEX",
        padding_mode="NONE",
        unpadding_mode="NONE",
        key_hex="00",
        iv_hex="",
        prompt_label="Plaintext",
        prompt_value="(0)",
        oracle_label="O",
        oracle_table="T",
        answer_label="Ciphertext in HEX format",
        expected_hex_raw="F0A1",
    )

    engine.next_ok = True
    out = vm.check_answer(ex, "F0A1")

    assert out is True
    assert len(engine.check_calls) == 1
    assert engine.check_calls[0] == {
        "expected_hex_raw": "F0A1",
        "fmt": "HEX",
        "user_answer": "F0A1",
        "label": "Exercises answer (legacy)",
        "purpose": "exercises_viewmodel",
    }

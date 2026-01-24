import pytest

import src.services.exercises_engine as exercises_engine

# helper to create fresh ExercisesEngine instance for tests
def _make_engine():
    return exercises_engine.ExercisesEngine()


# generate should return ExerciseCore with consistent fields for ECB encrypt path
def test_generate_returns_core_for_ecb_encrypt(monkeypatch):
    monkeypatch.setattr(exercises_engine.random, "choice", lambda seq: seq[0])
    monkeypatch.setattr(exercises_engine.random, "shuffle", lambda pairs: None)
    monkeypatch.setattr(exercises_engine.ExercisesEngine, "_pick_len", lambda self, level: 3)
    monkeypatch.setattr(exercises_engine.secrets, "token_bytes", lambda n: b"\xAA" * n)
    monkeypatch.setattr(exercises_engine.secrets, "randbelow", lambda n: 1)
    monkeypatch.setattr(
        exercises_engine.ExercisesEngine,
        "_with_decoys",
        staticmethod(lambda needed, *, max_rows: list(needed)),
    )

    core = _make_engine().generate("NORMAL")

    assert core.action == "ENCRYPT"
    assert core.mode == "ECB"
    assert core.fmt == "HEX"
    assert core.iv_nibble == 0
    assert len(core.pt) == 3
    assert len(core.ct) == 3
    assert core.expected_hex_raw == "".join(f"{x:X}" for x in core.ct)


# generate should return ExerciseCore with expected answer based on plaintext for DECRYPT
def test_generate_returns_core_for_cbc_decrypt(monkeypatch):
    picks = iter(["DECRYPT", "CBC", "HEX", 16])

    def _pick(seq):
        return next(picks)

    monkeypatch.setattr(exercises_engine.random, "choice", _pick)
    monkeypatch.setattr(exercises_engine.random, "shuffle", lambda pairs: None)
    monkeypatch.setattr(exercises_engine.ExercisesEngine, "_pick_len", lambda self, level: 4)
    monkeypatch.setattr(exercises_engine.secrets, "token_bytes", lambda n: b"\xBB" * n)
    monkeypatch.setattr(exercises_engine.secrets, "randbelow", lambda n: 5)
    monkeypatch.setattr(
        exercises_engine.ExercisesEngine,
        "_with_decoys",
        staticmethod(lambda needed, *, max_rows: list(needed)),
    )

    core = _make_engine().generate("HARD")

    assert core.action == "DECRYPT"
    assert core.mode == "CBC"
    assert core.fmt == "HEX"
    assert core.iv_nibble == 5
    assert len(core.pt) == 4
    assert len(core.ct) == 4
    assert core.expected_hex_raw == "".join(f"{x:X}" for x in core.pt)


# check_answer should return True for matching HEX answers
def test_check_answer_hex_is_correct():
    ok = _make_engine().check_answer(expected_hex_raw="F0A1", fmt="HEX", user_answer="F, 0, A, 1")
    assert ok is True


# check_answer should return False for wrong answers
def test_check_answer_hex_is_wrong():
    ok = _make_engine().check_answer(expected_hex_raw="F0A1", fmt="HEX", user_answer="F, 0, A, 2")
    assert ok is False


# check_answer should return True for matching BIN answers
def test_check_answer_bin_is_correct():
    ok = _make_engine().check_answer(
        expected_hex_raw="F0A1",
        fmt="BIN",
        user_answer="1111 0000 1010 0001",
    )
    assert ok is True


# check_answer should return False for wrong BIN answers
def test_check_answer_bin_is_wrong():
    ok = _make_engine().check_answer(
        expected_hex_raw="F0A1",
        fmt="BIN",
        user_answer="1111 0000 1010 0010",
    )
    assert ok is False


# check_answer should wrap invalid expected HEX into ExercisesError INVALID_EXPECTED
def test_check_answer_wraps_invalid_expected_hex():
    with pytest.raises(exercises_engine.ExercisesError) as ei:
        _make_engine().check_answer(expected_hex_raw="G1", fmt="HEX", user_answer="0")

    e = ei.value
    assert e.code == "INVALID_EXPECTED"
    assert e.field == "expected"
    assert "invalid HEX" in e.message


# check_answer should wrap invalid user answer into ExercisesError INVALID_ANSWER
def test_check_answer_wraps_invalid_user_answer():
    with pytest.raises(exercises_engine.ExercisesError) as ei:
        _make_engine().check_answer(expected_hex_raw="F0", fmt="HEX", user_answer="Z")

    e = ei.value
    assert e.code == "INVALID_ANSWER"
    assert e.field == "answer"
    assert "HEX answers" in e.message


# parse_expected_hex_nibbles should wrap invalid expected into ExercisesError INVALID_EXPECTED
def test_parse_expected_hex_nibbles_wraps_invalid_expected():
    with pytest.raises(exercises_engine.ExercisesError) as ei:
        exercises_engine.ExercisesEngine.parse_expected_hex_nibbles("GG")

    e = ei.value
    assert e.code == "INVALID_EXPECTED"
    assert e.field == "expected"
    assert "invalid HEX" in e.message


# _unique_4bit should remove duplicates and mask to 4-bit
def test_unique_4bit_dedupes_and_masks():
    out = exercises_engine.ExercisesEngine._unique_4bit([0, 1, 17, 31, 1])
    assert out == [0, 1, 15]


# _with_decoys should include needed values and return max_rows entries
def test_with_decoys_fills_to_max_rows(monkeypatch):
    picks = iter([7, 8, 9])
    monkeypatch.setattr(exercises_engine.secrets, "randbelow", lambda n: next(picks))

    out = exercises_engine.ExercisesEngine._with_decoys([1, 2], max_rows=4)

    assert len(out) == 4
    assert 1 in out
    assert 2 in out


# _with_decoys should sample when needed is already large enough
def test_with_decoys_uses_sample_when_needed_is_large(monkeypatch):
    calls: list[tuple[list[int], int]] = []

    def _fake_sample(values, k):
        calls.append((values, k))
        return values[:k]

    monkeypatch.setattr(exercises_engine.random, "sample", _fake_sample)

    out = exercises_engine.ExercisesEngine._with_decoys([1, 2, 3, 4, 5], max_rows=3)

    assert out == [1, 2, 3]
    assert calls == [([1, 2, 3, 4, 5], 3)]


# generate should return ExerciseCore for CTR encrypt with CTR oracle label
def test_generate_returns_core_for_ctr_encrypt(monkeypatch):
    picks = iter(["ENCRYPT", "CTR", "BIN", 16])

    def _pick(seq):
        return next(picks)

    randbelow_values = iter([2, 3, 4, 5])

    monkeypatch.setattr(exercises_engine.random, "choice", _pick)
    monkeypatch.setattr(exercises_engine.random, "shuffle", lambda pairs: None)
    monkeypatch.setattr(exercises_engine.ExercisesEngine, "_pick_len", lambda self, level: 3)
    monkeypatch.setattr(exercises_engine.secrets, "token_bytes", lambda n: b"\xCC" * n)
    monkeypatch.setattr(exercises_engine.secrets, "randbelow", lambda n: next(randbelow_values))
    monkeypatch.setattr(
        exercises_engine.ExercisesEngine,
        "_with_decoys",
        staticmethod(lambda needed, *, max_rows: list(needed)),
    )

    core = _make_engine().generate("NORMAL")

    assert core.action == "ENCRYPT"
    assert core.mode == "CTR"
    assert core.fmt == "BIN"
    assert core.iv_nibble == 2
    assert len(core.pt) == 3
    assert len(core.ct) == 3
    assert core.expected_hex_raw == "".join(f"{x:X}" for x in core.ct)
    assert core.oracle_label == "Keyed-permutation values (lookup table)"
    assert core.oracle_table.startswith("\nE_K(")


# _decrypt_oracle CTR should use counters based on iv and ciphertext length
def test_decrypt_oracle_ctr_uses_iv_counters(monkeypatch):
    calls: list[dict] = []

    def _fake_oracle_e(self, cipher, *, needed, fmt, max_rows, header):
        calls.append(
            {
                "needed": needed,
                "fmt": fmt,
                "max_rows": max_rows,
                "header": header,
            }
        )
        return ("HDR", "TABLE")

    monkeypatch.setattr(exercises_engine.ExercisesEngine, "_oracle_E", _fake_oracle_e)

    engine = _make_engine()
    label, table = engine._decrypt_oracle(
        "CTR",
        ct=[1, 2, 3, 4],
        iv=14,
        cipher=exercises_engine._ToyNibblePermutation(b"\x00" * 16),
        fmt="HEX",
        level="NORMAL",
    )

    assert label == "HDR"
    assert table == "TABLE"
    assert calls == [
        {
            "needed": [14, 15, 0, 1],
            "fmt": "HEX",
            "max_rows": 8,
            "header": "Keyed-permutation values (lookup table)",
        }
    ]


# _wrap should keep stable fields and include original exception type in details
def test_wrap_includes_exception_type_in_details():
    e = exercises_engine._wrap(code="X", field="Y", e=ValueError("boom"))
    assert e.code == "X"
    assert e.field == "Y"
    assert e.message == "boom"
    assert "ValueError" in e.details


# ExercisesError __str__ should return message
def test_exerciseserror_str_returns_message():
    e = exercises_engine.ExercisesError(code="X", field="Y", message="hello")
    assert str(e) == "hello"

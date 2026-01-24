import pytest

import src.utils.nibble_converter as nibble_converter


# Test that _preview returns the original string when it is within the limit.
def test_preview_within_limit_returns_same_string():
    s = "ABCDEF"
    out = nibble_converter._preview(s, limit=96)

    assert out == "ABCDEF"


# Test that _preview truncates and appends "..." when input exceeds the limit.
def test_preview_exceeds_limit_truncates_and_appends_ellipsis():
    s = "A" * 120
    out = nibble_converter._preview(s, limit=96)

    assert out == ("A" * 96) + "..."


# Test that _normalize_user_separators replaces common separators with whitespace and strips the result.
def test_normalize_user_separators_replaces_separators_and_strips():
    raw = " (F,0;A|1)\n\t"
    out = nibble_converter._normalize_user_separators(raw)

    assert out.split() == ["F", "0", "A", "1"]


# Test that parse_expected_hex_nibbles accepts whitespace and lowercase and returns correct nibble values.
def test_parse_expected_hex_nibbles_accepts_whitespace_and_lowercase(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_converter, "log_error", lambda msg: error_calls.append(msg))

    out = nibble_converter.parse_expected_hex_nibbles(" f0 a1 ", label="exp", purpose="test")

    assert out == [15, 0, 10, 1]
    assert error_calls == []
    assert len(debug_calls) == 1
    assert "Parsed expected HEX nibbles" in debug_calls[0]
    assert "symbols=4" in debug_calls[0]
    assert "label=exp" in debug_calls[0]
    assert "purpose=test" in debug_calls[0]


# Test empty expected input:
# - it should return []
# - log a debug message (empty expected is allowed).
def test_parse_expected_hex_nibbles_empty_string_returns_empty_list(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_converter, "log_error", lambda msg: error_calls.append(msg))

    out = nibble_converter.parse_expected_hex_nibbles(" \n\t  ", label="exp", purpose="empty")

    assert out == []
    assert error_calls == []
    assert len(debug_calls) == 1
    assert "Parsed empty expected HEX nibbles" in debug_calls[0]
    assert "symbols=0" in debug_calls[0]
    assert "label=exp" in debug_calls[0]
    assert "purpose=empty" in debug_calls[0]


# Test wrong input type for parse_expected_hex_nibbles:
# - must log error
# - raise TypeError with clear friendly message
# - not log success
@pytest.mark.parametrize("value", [123, None, b"F0A1", bytearray(b"F0A1")])
def test_parse_expected_hex_nibbles_wrong_type_raises_and_logs_error(monkeypatch, value):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_converter, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(TypeError, match="parse_expected_hex_nibbles: expected_hex_raw must be a string."):
        nibble_converter.parse_expected_hex_nibbles(value, label="exp", purpose="type")

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "invalid type for expected answer" in error_calls[0]
    assert "func=parse_expected_hex_nibbles" in error_calls[0]
    assert "label=exp" in error_calls[0]
    assert "purpose=type" in error_calls[0]


# Test invalid HEX character in expected answer:
# - must log error
# - raise ValueError
# - not log success
def test_parse_expected_hex_nibbles_invalid_hex_char_raises_and_logs_error(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_converter, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="parse_expected_hex_nibbles: internal expected answer contains invalid HEX."):
        nibble_converter.parse_expected_hex_nibbles("F0G1", label="exp", purpose="invalid")

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "invalid HEX in expected answer" in error_calls[0]
    assert "ch='G'" in error_calls[0]
    assert "func=parse_expected_hex_nibbles" in error_calls[0]
    assert "label=exp" in error_calls[0]
    assert "purpose=invalid" in error_calls[0]


# Test invalid fmt:
# - must log error
# - raise ValueError
# - not log success
@pytest.mark.parametrize("fmt", ["DEC", "TXT", "", "  ", None])
def test_parse_user_nibbles_invalid_fmt_raises_and_logs_error(monkeypatch, fmt):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_converter, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="parse_user_nibbles: fmt must be 'HEX' or 'BIN'."):
        nibble_converter.parse_user_nibbles("F0A1", fmt=fmt, label="ans", purpose="fmt")

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "invalid fmt" in error_calls[0]
    assert "func=parse_user_nibbles" in error_calls[0]
    assert "label=ans" in error_calls[0]
    assert "purpose=fmt" in error_calls[0]


# Test missing answer (raw is None):
# - must log error
# - raise ValueError
# - not log success
def test_parse_user_nibbles_missing_answer_raises_and_logs_error(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_converter, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="parse_user_nibbles: answer is missing."):
        nibble_converter.parse_user_nibbles(None, fmt="HEX", label="ans", purpose="missing")

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "missing answer" in error_calls[0]
    assert "func=parse_user_nibbles" in error_calls[0]
    assert "fmt='HEX'" in error_calls[0]
    assert "label=ans" in error_calls[0]
    assert "purpose=missing" in error_calls[0]


# Test wrong input type for answer:
# - must log error
# - raise TypeError
# - not log success
@pytest.mark.parametrize("value", [123, b"F0A1", bytearray(b"F0A1")])
def test_parse_user_nibbles_wrong_type_raises_and_logs_error(monkeypatch, value):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_converter, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(TypeError, match="parse_user_nibbles: answer must be a string."):
        nibble_converter.parse_user_nibbles(value, fmt="HEX", label="ans", purpose="type")

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "invalid type for answer" in error_calls[0]
    assert "func=parse_user_nibbles" in error_calls[0]
    assert "fmt='HEX'" in error_calls[0]
    assert "label=ans" in error_calls[0]
    assert "purpose=type" in error_calls[0]


# Test empty user input:
# - it should return []
# - log a debug message (empty answer is allowed and becomes []).
def test_parse_user_nibbles_empty_string_returns_empty_list(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_converter, "log_error", lambda msg: error_calls.append(msg))

    out = nibble_converter.parse_user_nibbles(" \n\t ", fmt="HEX", label="ans", purpose="empty")

    assert out == []
    assert error_calls == []
    assert len(debug_calls) == 1
    assert "Parsed empty user answer" in debug_calls[0]
    assert "fmt='HEX'" in debug_calls[0]
    assert "symbols=0" in debug_calls[0]
    assert "label=ans" in debug_calls[0]
    assert "purpose=empty" in debug_calls[0]


# Test that parse_user_nibbles accepts HEX with separators and lowercase.
def test_parse_user_nibbles_hex_accepts_separators_and_lowercase(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_converter, "log_error", lambda msg: error_calls.append(msg))

    s = "(f, 0, a, 1)\n"
    out = nibble_converter.parse_user_nibbles(s, fmt="hex", label="ans", purpose="hex_sep")

    assert out == [15, 0, 10, 1]
    assert error_calls == []
    assert len(debug_calls) == 1
    assert "Parsed user HEX nibbles" in debug_calls[0]
    assert "fmt=HEX" in debug_calls[0]
    assert "symbols=4" in debug_calls[0]
    assert "label=ans" in debug_calls[0]
    assert "purpose=hex_sep" in debug_calls[0]


# Test that parse_user_nibbles accepts compact HEX strings and split tokens and returns the same result.
def test_parse_user_nibbles_hex_accepts_compact_and_split_tokens(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_converter, "log_error", lambda msg: error_calls.append(msg))

    s1 = "F0A1"
    s2 = "F0 A1"
    s3 = "F 0 A 1"

    o1 = nibble_converter.parse_user_nibbles(s1, fmt="HEX")
    o2 = nibble_converter.parse_user_nibbles(s2, fmt="HEX")
    o3 = nibble_converter.parse_user_nibbles(s3, fmt="HEX")

    assert o1 == o2 == o3 == [15, 0, 10, 1]
    assert error_calls == []
    assert len(debug_calls) == 3


# Test invalid HEX character in user answer:
# - must log error
# - raise ValueError with the clear friendly message
# - not log success
def test_parse_user_nibbles_hex_invalid_char_raises_and_logs_error(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_converter, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="HEX answers must use symbols 0 to 9 and A to F"):
        nibble_converter.parse_user_nibbles("F0G1", fmt="HEX", label="ans", purpose="hex_bad")

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "invalid HEX char" in error_calls[0]
    assert "fmt=HEX" in error_calls[0]
    assert "ch='G'" in error_calls[0]
    assert "label=ans" in error_calls[0]
    assert "purpose=hex_bad" in error_calls[0]


# Test that parse_user_nibbles accepts BIN as 4-bit groups and returns correct nibble values.
def test_parse_user_nibbles_bin_accepts_4bit_groups(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_converter, "log_error", lambda msg: error_calls.append(msg))

    s = "1111 0000 1010 0001"
    out = nibble_converter.parse_user_nibbles(s, fmt="BIN", label="ans", purpose="bin_groups")

    assert out == [15, 0, 10, 1]
    assert error_calls == []
    assert len(debug_calls) == 1
    assert "Parsed user BIN nibbles" in debug_calls[0]
    assert "fmt=BIN" in debug_calls[0]
    assert "symbols=4" in debug_calls[0]
    assert "label=ans" in debug_calls[0]
    assert "purpose=bin_groups" in debug_calls[0]


# Test that parse_user_nibbles accepts BIN packed bit strings (multiple of 4) and returns correct nibble values.
def test_parse_user_nibbles_bin_accepts_packed_bit_string(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_converter, "log_error", lambda msg: error_calls.append(msg))

    s = "1111000010100001"
    out = nibble_converter.parse_user_nibbles(s, fmt="BIN", label="ans", purpose="bin_packed")

    assert out == [15, 0, 10, 1]
    assert error_calls == []
    assert len(debug_calls) == 1
    assert "Parsed user BIN nibbles" in debug_calls[0]
    assert "symbols=4" in debug_calls[0]


# Test that parse_user_nibbles accepts packed BIN split across tokens (each token multiple of 4).
def test_parse_user_nibbles_bin_accepts_packed_bit_string_split_into_tokens(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_converter, "log_error", lambda msg: error_calls.append(msg))

    s = "11110000 10100001"
    out = nibble_converter.parse_user_nibbles(s, fmt="BIN", label="ans", purpose="bin_packed_split")

    assert out == [15, 0, 10, 1]
    assert error_calls == []
    assert len(debug_calls) == 1
    assert "Parsed user BIN nibbles" in debug_calls[0]
    assert "symbols=4" in debug_calls[0]


# Test that parse_user_nibbles accepts 0b prefix per 4-bit group.
def test_parse_user_nibbles_bin_accepts_0b_prefix_per_group(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_converter, "log_error", lambda msg: error_calls.append(msg))

    s = "0b1111 0B0000 0b1010 0B0001"
    out = nibble_converter.parse_user_nibbles(s, fmt="BIN", label="ans", purpose="bin_0b_groups")

    assert out == [15, 0, 10, 1]
    assert error_calls == []
    assert len(debug_calls) == 1
    assert "Parsed user BIN nibbles" in debug_calls[0]
    assert "symbols=4" in debug_calls[0]


# Test that parse_user_nibbles accepts a single packed BIN string with 0b prefix.
def test_parse_user_nibbles_bin_accepts_0b_prefix_for_packed_string(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_converter, "log_error", lambda msg: error_calls.append(msg))

    s = "0b1111000010100001"
    out = nibble_converter.parse_user_nibbles(s, fmt="BIN", label="ans", purpose="bin_0b_packed")

    assert out == [15, 0, 10, 1]
    assert error_calls == []
    assert len(debug_calls) == 1
    assert "Parsed user BIN nibbles" in debug_calls[0]
    assert "symbols=4" in debug_calls[0]


# Test that parse_user_nibbles accepts BIN with common separators after normalization.
def test_parse_user_nibbles_bin_accepts_separators_after_normalization(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_converter, "log_error", lambda msg: error_calls.append(msg))

    s = "(0b1111,0B0000;0b1010|0B0001)"
    out = nibble_converter.parse_user_nibbles(s, fmt="BIN", label="ans", purpose="bin_sep")

    assert out == [15, 0, 10, 1]
    assert error_calls == []
    assert len(debug_calls) == 1
    assert "Parsed user BIN nibbles" in debug_calls[0]
    assert "symbols=4" in debug_calls[0]


# Test invalid BIN group characters (single 4-bit token with non 0/1):
# - must log error
# - raise ValueError with the clear friendly message
# - not log success
def test_parse_user_nibbles_bin_invalid_group_characters_raises_and_logs_error(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_converter, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="BIN groups must contain only 0 and 1"):
        nibble_converter.parse_user_nibbles("1012", fmt="BIN", label="ans", purpose="bin_bad_group")

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "invalid BIN group characters" in error_calls[0]
    assert "func=parse_user_nibbles" in error_calls[0]
    assert "fmt=BIN" in error_calls[0]
    assert "label=ans" in error_calls[0]
    assert "purpose=bin_bad_group" in error_calls[0]


# Test invalid BIN token (not 4 bits and not multiple of 4):
# - must log error
# - raise ValueError
# - not log success
@pytest.mark.parametrize("token", ["101", "11110", "0b101", "0B11110"])
def test_parse_user_nibbles_bin_invalid_token_length_raises_and_logs_error(monkeypatch, token):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_converter, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="length is a multiple of 4"):
        nibble_converter.parse_user_nibbles(token, fmt="BIN", label="ans", purpose="bin_bad_len")

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "invalid BIN token" in error_calls[0]
    assert "func=parse_user_nibbles" in error_calls[0]
    assert "fmt=BIN" in error_calls[0]
    assert "bits=" in error_calls[0]
    assert "label=ans" in error_calls[0]
    assert "purpose=bin_bad_len" in error_calls[0]


# Test invalid BIN token characters for a longer token:
# - must log error
# - raise ValueError
# - not log success
def test_parse_user_nibbles_bin_invalid_token_characters_raises_and_logs_error(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_converter, "log_error", lambda msg: error_calls.append(msg))

    with pytest.raises(ValueError, match="length is a multiple of 4"):
        nibble_converter.parse_user_nibbles("11110000X0100001", fmt="BIN", label="ans", purpose="bin_bad_chars")

    assert debug_calls == []
    assert len(error_calls) == 1
    assert "invalid BIN token" in error_calls[0]
    assert "func=parse_user_nibbles" in error_calls[0]
    assert "fmt=BIN" in error_calls[0]
    assert "label=ans" in error_calls[0]
    assert "purpose=bin_bad_chars" in error_calls[0]


# Test full workflow: internal expected HEX and user HEX should parse to the same nibble list.
def test_nibble_parsing_workflow_expected_hex_matches_user_hex(monkeypatch):
    debug_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(nibble_converter, "log_debug", lambda msg: debug_calls.append(msg))
    monkeypatch.setattr(nibble_converter, "log_error", lambda msg: error_calls.append(msg))

    expected = nibble_converter.parse_expected_hex_nibbles("F0A1", label="exp", purpose="wf")
    user = nibble_converter.parse_user_nibbles("(F,0,A,1)", fmt="HEX", label="ans", purpose="wf")

    assert expected == user == [15, 0, 10, 1]
    assert error_calls == []
    assert len(debug_calls) == 2

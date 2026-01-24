import json

import pytest

import src.viewmodels.ascii_table_viewmodel as ascii_vm

# write a JSON file for the tests (and create the folder if missing)
def _write_json(path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")

# VM loads the JSON from temp path
def _patch_assets_path(monkeypatch, path) -> None:
    monkeypatch.setattr(ascii_vm.AsciiTableViewModel, "_assets_ascii_path", staticmethod(lambda: path))

# builds full 0..127 ASCII JSON rows list
def _make_rows_0_127() -> list[dict]:
    rows: list[dict] = []
    for dec in range(128):
        rows.append(
            {
                "dec": dec,
                "hex": f"{dec:02X}",
                "bin": f"{dec:08b}",
                "char": chr(dec) if 32 <= dec <= 126 else "",
                "label": "SPACE" if dec == 32 else ("DEL" if dec == 127 else ("CTRL" if dec < 32 else "")),
            }
        )
    return rows

# Autoapplied
@pytest.fixture(autouse=True)
def _silence_info_logs(monkeypatch):
    # keeps unit tests clean
    monkeypatch.setattr(ascii_vm, "should_log_starts", lambda: False)
    monkeypatch.setattr(ascii_vm, "log_info", lambda msg: None)
    monkeypatch.setattr(ascii_vm, "log_warning", lambda msg: None)
    monkeypatch.setattr(ascii_vm, "log_success", lambda msg: None)
    monkeypatch.setattr(ascii_vm, "log_error", lambda msg: None)


# load_ascii_7bit should load a valid 0..127 table and return stable entries
def test_load_ascii_7bit_success_returns_entries(monkeypatch, tmp_path):
    warnings: list[str] = []
    successes: list[str] = []
    errors: list[str] = []

    monkeypatch.setattr(ascii_vm, "log_warning", lambda msg: warnings.append(str(msg)))
    monkeypatch.setattr(ascii_vm, "log_success", lambda msg: successes.append(str(msg)))
    monkeypatch.setattr(ascii_vm, "log_error", lambda msg: errors.append(str(msg)))

    p = tmp_path / "ascii_7bit.json"
    _write_json(p, {"rows": _make_rows_0_127()})
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()
    out = vm.load_ascii_7bit()

    assert isinstance(out, list)
    assert len(out) == 128
    assert out[0].dec == 0
    assert out[-1].dec == 127

    # file values should be used (and normalized)
    assert out[65].hex == "41"
    assert out[65].bin == "01000001"

    # no hard failures
    assert errors == []
    assert len(successes) == 1
    assert warnings == []


# load_ascii_7bit should return cached data and not require the file again
def test_load_ascii_7bit_returns_cached_data(monkeypatch, tmp_path):
    p = tmp_path / "ascii_7bit.json"
    _write_json(p, {"rows": _make_rows_0_127()})
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()

    out1 = vm.load_ascii_7bit()
    assert len(out1) == 128

    # delete file to prove cache is used
    p.unlink()

    out2 = vm.load_ascii_7bit()
    assert len(out2) == 128

    # returned list should be a copy, not the internal list
    out1.pop()
    out3 = vm.load_ascii_7bit()
    assert len(out3) == 128


# load_ascii_7bit should raise FileNotFoundError when the JSON file is missing
def test_load_ascii_7bit_missing_file_raises(monkeypatch, tmp_path):
    error_calls: list[str] = []
    monkeypatch.setattr(ascii_vm, "log_error", lambda msg: error_calls.append(str(msg)))

    p = tmp_path / "missing.json"
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()
    with pytest.raises(FileNotFoundError):
        vm.load_ascii_7bit()

    assert len(error_calls) >= 1


# load_ascii_7bit should raise ValueError when the JSON root is not an object
def test_load_ascii_7bit_root_not_dict_raises(monkeypatch, tmp_path):
    p = tmp_path / "ascii_7bit.json"
    _write_json(p, ["not", "a", "dict"])
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()
    with pytest.raises(ValueError):
        vm.load_ascii_7bit()


# load_ascii_7bit should raise ValueError when 'rows' is not a list
def test_load_ascii_7bit_rows_not_list_raises(monkeypatch, tmp_path):
    p = tmp_path / "ascii_7bit.json"
    _write_json(p, {"rows": {"bad": "type"}})
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()
    with pytest.raises(ValueError):
        vm.load_ascii_7bit()


# load_ascii_7bit should raise ValueError when a row is not an object
def test_load_ascii_7bit_row_not_dict_raises(monkeypatch, tmp_path):
    p = tmp_path / "ascii_7bit.json"
    _write_json(p, {"rows": [123]})
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()
    with pytest.raises(ValueError):
        vm.load_ascii_7bit()


# load_ascii_7bit should raise ValueError when a row is missing 'dec'
def test_load_ascii_7bit_missing_dec_raises(monkeypatch, tmp_path):
    p = tmp_path / "ascii_7bit.json"
    _write_json(p, {"rows": [{"hex": "00", "bin": "00000000", "char": "", "label": "NUL"}]})
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()
    with pytest.raises(ValueError):
        vm.load_ascii_7bit()


# load_ascii_7bit should raise ValueError when 'dec' is not a number
def test_load_ascii_7bit_dec_not_int_raises(monkeypatch, tmp_path):
    p = tmp_path / "ascii_7bit.json"
    _write_json(p, {"rows": [{"dec": "xx", "hex": "00", "bin": "00000000", "char": "", "label": "NUL"}]})
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()
    with pytest.raises(ValueError):
        vm.load_ascii_7bit()


# load_ascii_7bit should raise ValueError when 'dec' is out of the ASCII range
def test_load_ascii_7bit_dec_out_of_range_raises(monkeypatch, tmp_path):
    p = tmp_path / "ascii_7bit.json"
    _write_json(p, {"rows": [{"dec": 200, "hex": "C8", "bin": "11001000", "char": "", "label": ""}]})
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()
    with pytest.raises(ValueError):
        vm.load_ascii_7bit()


# load_ascii_7bit should raise ValueError when 'dec' is duplicated
def test_load_ascii_7bit_duplicate_dec_raises(monkeypatch, tmp_path):
    p = tmp_path / "ascii_7bit.json"
    _write_json(
        p,
        {
            "rows": [
                {"dec": 1, "hex": "01", "bin": "00000001", "char": "", "label": ""},
                {"dec": 1, "hex": "01", "bin": "00000001", "char": "", "label": ""},
            ]
        },
    )
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()
    with pytest.raises(ValueError):
        vm.load_ascii_7bit()


# load_ascii_7bit should raise ValueError when 'hex' is missing
def test_load_ascii_7bit_missing_hex_raises(monkeypatch, tmp_path):
    p = tmp_path / "ascii_7bit.json"
    _write_json(p, {"rows": [{"dec": 0, "bin": "00000000", "char": "", "label": "NUL"}]})
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()
    with pytest.raises(ValueError):
        vm.load_ascii_7bit()


# load_ascii_7bit should raise ValueError when 'hex' becomes empty after normalization
def test_load_ascii_7bit_empty_hex_raises(monkeypatch, tmp_path):
    p = tmp_path / "ascii_7bit.json"
    _write_json(p, {"rows": [{"dec": 0, "hex": "   ", "bin": "00000000", "char": "", "label": "NUL"}]})
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()
    with pytest.raises(ValueError):
        vm.load_ascii_7bit()


# load_ascii_7bit should raise ValueError when 'hex' is too long for ASCII (more than 2 hex chars)
def test_load_ascii_7bit_hex_too_long_raises(monkeypatch, tmp_path):
    p = tmp_path / "ascii_7bit.json"
    _write_json(p, {"rows": [{"dec": 0, "hex": "0x00AA", "bin": "00000000", "char": "", "label": "NUL"}]})
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()
    with pytest.raises(ValueError):
        vm.load_ascii_7bit()


# load_ascii_7bit should raise ValueError when 'hex' contains non-hex characters
def test_load_ascii_7bit_hex_invalid_chars_raises(monkeypatch, tmp_path):
    p = tmp_path / "ascii_7bit.json"
    _write_json(p, {"rows": [{"dec": 0, "hex": "GG", "bin": "00000000", "char": "", "label": "NUL"}]})
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()
    with pytest.raises(ValueError):
        vm.load_ascii_7bit()


# load_ascii_7bit should raise ValueError when 'bin' is missing
def test_load_ascii_7bit_missing_bin_raises(monkeypatch, tmp_path):
    p = tmp_path / "ascii_7bit.json"
    _write_json(p, {"rows": [{"dec": 0, "hex": "00", "char": "", "label": "NUL"}]})
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()
    with pytest.raises(ValueError):
        vm.load_ascii_7bit()


# load_ascii_7bit should raise ValueError when 'bin' becomes empty after normalization
def test_load_ascii_7bit_empty_bin_raises(monkeypatch, tmp_path):
    p = tmp_path / "ascii_7bit.json"
    _write_json(p, {"rows": [{"dec": 0, "hex": "00", "bin": "   ", "char": "", "label": "NUL"}]})
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()
    with pytest.raises(ValueError):
        vm.load_ascii_7bit()


# load_ascii_7bit should raise ValueError when 'bin' contains non-binary characters
def test_load_ascii_7bit_bin_invalid_chars_raises(monkeypatch, tmp_path):
    p = tmp_path / "ascii_7bit.json"
    _write_json(p, {"rows": [{"dec": 0, "hex": "00", "bin": "0102", "char": "", "label": "NUL"}]})
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()
    with pytest.raises(ValueError):
        vm.load_ascii_7bit()


# load_ascii_7bit should warn (but still load) when BIN length is unusual
def test_load_ascii_7bit_unusual_bin_length_logs_warning(monkeypatch, tmp_path):
    warnings: list[str] = []
    monkeypatch.setattr(ascii_vm, "log_warning", lambda msg: warnings.append(str(msg)))
    monkeypatch.setattr(ascii_vm, "log_success", lambda msg: None)
    monkeypatch.setattr(ascii_vm, "log_error", lambda msg: None)

    p = tmp_path / "ascii_7bit.json"
    _write_json(
        p,
        {
            "rows": [
                {"dec": 0, "hex": "00", "bin": "0000", "char": "", "label": "NUL"},
            ]
        },
    )
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()
    out = vm.load_ascii_7bit()

    assert len(out) == 1
    assert out[0].hex == "00"
    assert out[0].bin == "0000"
    assert len(warnings) >= 1


# load_ascii_7bit should warn (but still load) when DEC does not match HEX/BIN in the file
def test_load_ascii_7bit_mismatch_logs_warning(monkeypatch, tmp_path):
    warnings: list[str] = []
    monkeypatch.setattr(ascii_vm, "log_warning", lambda msg: warnings.append(str(msg)))
    monkeypatch.setattr(ascii_vm, "log_success", lambda msg: None)
    monkeypatch.setattr(ascii_vm, "log_error", lambda msg: None)

    p = tmp_path / "ascii_7bit.json"
    _write_json(
        p,
        {
            "rows": [
                # dec=1 but hex/bin say 0
                {"dec": 1, "hex": "00", "bin": "00000000", "char": "", "label": ""},
            ]
        },
    )
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()
    out = vm.load_ascii_7bit()

    assert len(out) == 1
    assert out[0].dec == 1
    assert out[0].hex == "00"
    assert out[0].bin == "00000000"
    assert len(warnings) >= 1


# load_ascii_7bit should normalize HEX/BIN values coming from the file
def test_load_ascii_7bit_normalizes_hex_and_bin_values(monkeypatch, tmp_path):
    p = tmp_path / "ascii_7bit.json"
    _write_json(
        p,
        {
            "rows": [
                {"dec": 65, "hex": "  0x41  ", "bin": "  0b0100 0001  ", "char": "A", "label": ""},
            ]
        },
    )
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()
    out = vm.load_ascii_7bit()

    assert len(out) == 1
    assert out[0].dec == 65
    assert out[0].hex == "41"
    assert out[0].bin == "01000001"


# load_ascii_7bit should return entries sorted by DEC
def test_load_ascii_7bit_sorts_entries_by_dec(monkeypatch, tmp_path):
    p = tmp_path / "ascii_7bit.json"
    _write_json(
        p,
        {
            "rows": [
                {"dec": 2, "hex": "02", "bin": "00000010", "char": "", "label": ""},
                {"dec": 0, "hex": "00", "bin": "00000000", "char": "", "label": ""},
                {"dec": 1, "hex": "01", "bin": "00000001", "char": "", "label": ""},
            ]
        },
    )
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()
    out = vm.load_ascii_7bit()

    assert [e.dec for e in out] == [0, 1, 2]


# load_ascii_7bit should log a start info when should_log_starts returns True
def test_load_ascii_7bit_logs_start_when_enabled(monkeypatch, tmp_path):
    info_calls: list[str] = []
    monkeypatch.setattr(ascii_vm, "should_log_starts", lambda: True)
    monkeypatch.setattr(ascii_vm, "log_info", lambda msg: info_calls.append(str(msg)))

    p = tmp_path / "ascii_7bit.json"
    _write_json(p, {"rows": _make_rows_0_127()})
    _patch_assets_path(monkeypatch, p)

    vm = ascii_vm.AsciiTableViewModel()
    vm.load_ascii_7bit()

    assert len(info_calls) == 1

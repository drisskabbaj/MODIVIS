from __future__ import annotations  # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types

from dataclasses import dataclass  # helps simplifying building small data containers (ASCII row entries)
from pathlib import Path  # needed to resolve the assets path safely across OS
import json  # needed to load the ascii json file

from src.utils.logger import (
    log_info,
    log_success,
    log_warning,
    log_error,
    should_log_starts,
)  # need for app log structure

from src.utils.hex_formatting import normalize_hex  # needed to use hex cleanup
from src.utils.bin_formatting import normalize_bin  # needed to use bin cleanup


# -------------------------------------------------------------------------------------
#                              ASCII DATA OBJECT
# -------------------------------------------------------------------------------------
# Why?
#   - UI needs one clean object per ASCII code
#   - each entry provides the values a user wants to see: DEC / HEX / BIN + char/label
# -------------------------------------------------------------------------------------
@dataclass(slots=True)
class AsciiEntry:
    dec: int
    hex: str
    bin: str
    char: str
    label: str


# -------------------------------------------------------------------------------------
#                              ASCII TABLE VIEWMODEL
# -------------------------------------------------------------------------------------
# Why?
#   - keeps ASCII file access out of the UI page (MVVM)
#   - raises clear errors so the UI can show a message box
#
# JSON expected format:
#   {
#     "rows": [
#       {"dec": 0, "hex": "00", "bin": "00000000", "char": "", "label": "NUL"},
#       ...
#       {"dec": 127, "hex": "7F", "bin": "01111111", "char": "", "label": "DEL"}
#     ]
#   }
#
# Note:
#   - warning is shown if HEX/BIN do not match DEC
#
# Tested?
#   - Yes
#   - Unit test inside tests/viewmodels/test_ascii_table_viewmodel.py
# -------------------------------------------------------------------------------------
class AsciiTableViewModel:
    def __init__(self) -> None:
        self._entries: list[AsciiEntry] = []  # cache so UI does not re-read JSON multiple times

    @staticmethod
    def _assets_ascii_path() -> Path:
        # project root/assets/samples/ascii_7bit.json
        root = Path(__file__).resolve().parents[2]
        return root / "assets" / "samples" / "ascii_7bit.json"

    @staticmethod
    def _safe_text(v: object | None) -> str:
        # JSON sometimes uses null
        # wanted here is "" not "None"
        if v is None:
            return ""
        return str(v)

    def load_ascii_7bit(self) -> list[AsciiEntry]:
        # return cached data if already loaded to avoid redundant disk read
        if self._entries:
            return list(self._entries)

        label = "ASCII JSON"
        purpose = "ascii_table_viewmodel.load_ascii_7bit"

        if should_log_starts():
            log_info(
                f"ASCII Table: loading entries | module=ascii_table_viewmodel | func=load_ascii_7bit | label={label} | purpose={purpose}"
            )

        p = self._assets_ascii_path()
        if not p.exists():
            log_error(
                f"ASCII Table failed: file not found | module=ascii_table_viewmodel | func=load_ascii_7bit | path='{p}' | label={label} | purpose={purpose}"
            )
            raise FileNotFoundError(f"ASCII table file not found: {p}")

        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                log_error(
                    f"ASCII Table failed: file content is not a JSON object | module=ascii_table_viewmodel | func=load_ascii_7bit | path='{p}' | label={label} | purpose={purpose}"
                )
                raise ValueError("ASCII table file is not in the expected format (root must be a JSON object).")

            rows = raw.get("rows", [])
            if not isinstance(rows, list):
                log_error(
                    f"ASCII Table failed: 'rows' is not a list | module=ascii_table_viewmodel | func=load_ascii_7bit | path='{p}' | label={label} | purpose={purpose}"
                )
                raise ValueError("ASCII table file is not in the expected format ('rows' must be a list).")

            entries: list[AsciiEntry] = []
            seen: set[int] = set()
            hexdigits = set("0123456789abcdef")

            for idx, r in enumerate(rows):
                if not isinstance(r, dict):
                    log_error(
                        f"ASCII Table failed: one row is not a JSON object | module=ascii_table_viewmodel | func=load_ascii_7bit | row={idx} | label={label} | purpose={purpose}"
                    )
                    raise ValueError(f"ASCII table file is invalid: row #{idx} must be a JSON object.")

                dec_raw = r.get("dec", None)
                if dec_raw is None:
                    log_error(
                        f"ASCII Table failed: missing DEC value | module=ascii_table_viewmodel | func=load_ascii_7bit | row={idx} | label={label} | purpose={purpose}"
                    )
                    raise ValueError(f"ASCII table file is invalid: row #{idx} is missing the DEC value.")

                try:
                    dec = int(dec_raw)
                except Exception:
                    log_error(
                        f"ASCII Table failed: DEC is not a number | module=ascii_table_viewmodel | func=load_ascii_7bit | row={idx} | dec_raw={dec_raw!r} | label={label} | purpose={purpose}"
                    )
                    raise ValueError(f"ASCII table file is invalid: row #{idx} has a DEC value that is not a number.") from None

                if dec < 0 or dec > 127:
                    log_error(
                        f"ASCII Table failed: DEC out of range | module=ascii_table_viewmodel | func=load_ascii_7bit | row={idx} | dec={dec} | label={label} | purpose={purpose}"
                    )
                    raise ValueError(f"ASCII table file is invalid: DEC must be between 0 and 127 (row #{idx}).")

                if dec in seen:
                    log_error(
                        f"ASCII Table failed: duplicated DEC value | module=ascii_table_viewmodel | func=load_ascii_7bit | row={idx} | dec={dec} | label={label} | purpose={purpose}"
                    )
                    raise ValueError(f"ASCII table file is invalid: DEC value {dec} appears more than once.")
                seen.add(dec)

                # HEX from file
                hx_raw = r.get("hex", None)
                if hx_raw is None:
                    log_error(
                        f"ASCII Table failed: missing HEX value | module=ascii_table_viewmodel | func=load_ascii_7bit | row={idx} | dec={dec} | label={label} | purpose={purpose}"
                    )
                    raise ValueError(f"ASCII table file is invalid: row #{idx} is missing the HEX value.")

                hx_norm = normalize_hex(
                    str(hx_raw),
                    label="ASCII JSON hex",
                    purpose="ascii_table_viewmodel",
                )

                if not hx_norm:
                    log_error(
                        f"ASCII Table failed: empty HEX value | module=ascii_table_viewmodel | func=load_ascii_7bit | row={idx} | dec={dec} | label={label} | purpose={purpose}"
                    )
                    raise ValueError(f"ASCII table file is invalid: row #{idx} has an empty HEX value.")

                if len(hx_norm) > 2:
                    log_error(
                        f"ASCII Table failed: HEX is too long for ASCII | module=ascii_table_viewmodel | func=load_ascii_7bit | row={idx} | dec={dec} | hex='{hx_norm}' | label={label} | purpose={purpose}"
                    )
                    raise ValueError(f"ASCII table file is invalid: row #{idx} has a HEX value that is too long for 7-bit ASCII.")

                if any(ch not in hexdigits for ch in hx_norm):
                    log_error(
                        f"ASCII Table failed: HEX contains invalid characters | module=ascii_table_viewmodel | func=load_ascii_7bit | row={idx} | dec={dec} | hex='{hx_norm}' | label={label} | purpose={purpose}"
                    )
                    raise ValueError(f"ASCII table file is invalid: row #{idx} has a HEX value with invalid characters.")

                hx = hx_norm.upper()

                # BIN from file
                bn_raw = r.get("bin", None)
                if bn_raw is None:
                    log_error(
                        f"ASCII Table failed: missing BIN value | module=ascii_table_viewmodel | func=load_ascii_7bit | row={idx} | dec={dec} | label={label} | purpose={purpose}"
                    )
                    raise ValueError(f"ASCII table file is invalid: row #{idx} is missing the BIN value.")

                bn_norm = normalize_bin(
                    str(bn_raw),
                    label="ASCII JSON bin",
                    purpose="ascii_table_viewmodel",
                )

                if not bn_norm:
                    log_error(
                        f"ASCII Table failed: empty BIN value | module=ascii_table_viewmodel | func=load_ascii_7bit | row={idx} | dec={dec} | label={label} | purpose={purpose}"
                    )
                    raise ValueError(f"ASCII table file is invalid: row #{idx} has an empty BIN value.")

                if any(ch not in "01" for ch in bn_norm):
                    log_error(
                        f"ASCII Table failed: BIN contains invalid characters | module=ascii_table_viewmodel | func=load_ascii_7bit | row={idx} | dec={dec} | bin='{bn_norm}' | label={label} | purpose={purpose}"
                    )
                    raise ValueError(f"ASCII table file is invalid: row #{idx} has a BIN value that is not binary.")

                # accept any length but warn if it looks odd for ASCII usage
                if len(bn_norm) not in (7, 8):
                    log_warning(
                        f"ASCII Table warning: BIN length looks unusual | module=ascii_table_viewmodel | func=load_ascii_7bit | row={idx} | dec={dec} | bin_len={len(bn_norm)} | label={label} | purpose={purpose}"
                    )

                char = self._safe_text(r.get("char", ""))
                label_txt = self._safe_text(r.get("label", ""))

                # warn by mismatch between DEC and file HEX/BIN
                try:
                    if int(hx, 16) != dec:
                        log_warning(
                            f"ASCII Table warning: HEX does not match the DEC value | module=ascii_table_viewmodel | func=load_ascii_7bit | row={idx} | dec={dec} | hex='{hx}' | label={label} | purpose={purpose}"
                        )
                except Exception:
                    log_warning(
                        f"ASCII Table warning: HEX value could not be read as a number | module=ascii_table_viewmodel | func=load_ascii_7bit | row={idx} | dec={dec} | hex='{hx}' | label={label} | purpose={purpose}"
                    )

                try:
                    if int(bn_norm, 2) != dec:
                        log_warning(
                            f"ASCII Table warning: BIN does not match the DEC value | module=ascii_table_viewmodel | func=load_ascii_7bit | row={idx} | dec={dec} | bin='{bn_norm}' | label={label} | purpose={purpose}"
                        )
                except Exception:
                    log_warning(
                        f"ASCII Table warning: BIN value could not be read as a number | module=ascii_table_viewmodel | func=load_ascii_7bit | row={idx} | dec={dec} | bin='{bn_norm}' | label={label} | purpose={purpose}"
                    )

                entries.append(
                    AsciiEntry(
                        dec=dec,
                        hex=hx,
                        bin=bn_norm,
                        char=char,
                        label=label_txt,
                    )
                )

            # sanity checks
            if len(entries) != 128:
                log_warning(
                    f"ASCII Table warning: expected 128 entries | module=ascii_table_viewmodel | func=load_ascii_7bit | got={len(entries)} | label={label} | purpose={purpose}"
                )

            entries.sort(key=lambda e: e.dec)
            if entries and (entries[0].dec != 0 or entries[-1].dec != 127):
                log_warning(
                    f"ASCII Table warning: entries are not covering 0..127 cleanly | module=ascii_table_viewmodel | func=load_ascii_7bit | first={entries[0].dec if entries else 'n/a'} | last={entries[-1].dec if entries else 'n/a'} | label={label} | purpose={purpose}"
                )

            self._entries = entries
            log_success(
                f"ASCII Table loaded successfully | module=ascii_table_viewmodel | func=load_ascii_7bit | entries={len(self._entries)} | label={label} | purpose={purpose}"
            )
            return list(self._entries)

        except Exception as e:
            log_error(
                f"ASCII Table failed: {type(e).__name__}: {e} | module=ascii_table_viewmodel | func=load_ascii_7bit | path='{p}' | label={label} | purpose={purpose}"
            )
            raise

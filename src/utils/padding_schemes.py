from __future__ import annotations # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types

from src.utils.logger import (
    log_debug,
    log_error,
)  # needed to log debug/error

from src.domain.padding_types import PaddingMode # needed to import covered Padding Modes

# ---------------------------------------------------------------------------------------------
#                                   PADDING SCHEMES
# ---------------------------------------------------------------------------------------------
# Why this?
#   - AES modes work on fixed size blocks (AES block size = 16 bytes = 128 bits).
#   - If plaintext is not aligned to the block size, we must pad it (for ECB/CBC).
#   - For both learning and visualization purposes: we also want to return "what bytes were added or removed".
#
# Tested?
#   - Yes
#   - Unit test inside tests/utils/test_padding_schemes.py
# ---------------------------------------------------------------------------------------------

class PaddingError(ValueError):
    """Raised when padding/unpadding validation fails."""


def _validate_block_size(block_size: int, *, label: str = "", purpose: str = "", func: str = "") -> None:
    """
    Internal validator:
      - block_size must be positive integer
      - block_size must be <= 255 because PKCS7/X923 store pad length in one byte
    """
    if not isinstance(block_size, int) or block_size <= 0:
        log_error(f"Padding failed: invalid block_size | module=padding | func={func or '_validate_block_size'} | block_size={block_size} | label={label} | purpose={purpose}")
        raise ValueError("Padding failed: block_size must be a positive integer.")
    if block_size > 255:
        log_error(f"Padding failed: block_size too large | module=padding | func={func or '_validate_block_size'} | block_size={block_size} | label={label} | purpose={purpose}")
        raise ValueError("Padding failed: block_size must be <= 255.")

def pad_with_info(
    data: bytes,
    block_size: int,
    mode: PaddingMode,
    *,
    label: str = "",
    purpose: str = "",
) -> tuple[bytes, int, bytes]:
    """
    Returns: (padded_data, pad_len, pad_bytes)

    pad_len:
      - 0 only for mode="NONE"
      - otherwise 1..block_size

    pad_bytes:
      - b"" only for mode="NONE"
      - otherwise the exact bytes appended at the end
    """
    _validate_block_size(block_size, label=label, purpose=purpose, func="pad_with_info")

    # defensive type check
    if not isinstance(data, (bytes, bytearray)):
        log_error(f"Padding failed: invalid type | module=padding | func=pad_with_info | type(data)={type(data).__name__} | label={label} | purpose={purpose}")
        raise TypeError("Padding failed: data must be bytes (or bytearray).")

    if not isinstance(mode, str):
        log_error(f"Padding failed: invalid mode type | module=padding | func=pad_with_info | type(mode)={type(mode).__name__} | label={label} | purpose={purpose}")
        raise TypeError("Padding failed: mode must be a string.")

    raw = bytes(data)
    block_bits = block_size * 8  # AES block size is 128 bits (16 bytes), regardless of key size (AES-128/192/256)

    # NONE means "do not pad"
    if mode == "NONE":
        return raw, 0, b""

    # compute how many bytes we must add
    r = len(raw) % block_size
    n = block_size - r if r != 0 else block_size

    # PKCS7: N bytes all equal to N
    if mode == "PKCS7":
        pad = bytes([n]) * n
        out = raw + pad
        log_debug(f"Padding applied | module=padding | func=pad_with_info | mode=PKCS7 | block_bytes={block_size} | block_bits={block_bits} | in={len(raw)}B | pad_len={n} | out={len(out)}B | label={label} | purpose={purpose}")
        return out, n, pad

    # X923: N bytes gets 00 00 ... 00 N (last byte holds N)
    if mode == "X923":
        pad = bytes([1]) if n == 1 else (b"\x00" * (n - 1) + bytes([n]))
        out = raw + pad
        log_debug(f"Padding applied | module=padding | func=pad_with_info | mode=X923 | block_bytes={block_size} | block_bits={block_bits} | in={len(raw)}B | pad_len={n} | out={len(out)}B | label={label} | purpose={purpose}")
        return out, n, pad

    # ISO/IEC 7816-4: 0x80 then zeros until block boundary
    if mode == "ISO/IEC 7816-4":
        pad = b"\x80" if n == 1 else (b"\x80" + b"\x00" * (n - 1))
        out = raw + pad
        log_debug(f"Padding applied | module=padding | func=pad_with_info | mode=ISO/IEC 7816-4 | block_bytes={block_size} | block_bits={block_bits} | in={len(raw)}B | pad_len={n} | out={len(out)}B | label={label} | purpose={purpose}")
        return out, n, pad

    # unsupported mode
    log_error(f"Padding failed: unsupported mode | module=padding | func=pad_with_info | mode={mode} | label={label} | purpose={purpose}")
    raise ValueError(f"Padding failed: unsupported padding mode: {mode}")


def pad_data(data: bytes, block_size: int, mode: PaddingMode, *, label: str = "", purpose: str = "") -> bytes:
    """
    Wrapper for pad_with_info:
      - returns only padded bytes
    """
    return pad_with_info(data, block_size, mode, label=label, purpose=purpose)[0]


def unpad_with_info(
    data: bytes,
    block_size: int,
    mode: PaddingMode,
    *,
    label: str = "",
    purpose: str = "",
) -> tuple[bytes, bytes]:
    """
    Returns:
        - unpadded_data 
        - removed_bytes

    Validation rules:
      - NONE: returns (data, b"")
      - PKCS7: last byte N, and last N bytes must all equal N
      - X923: last byte N, previous N-1 bytes must be 0x00
      - ISO/IEC 7816-4: scan backwards over 0x00 until we find 0x80
    """
    _validate_block_size(block_size, label=label, purpose=purpose, func="unpad_with_info")

    # defensive type check
    if not isinstance(data, (bytes, bytearray)):
        log_error(f"Unpadding failed: invalid type | module=padding | func=unpad_with_info | type(data)={type(data).__name__} | label={label} | purpose={purpose}")
        raise TypeError("Unpadding failed: data must be bytes (or bytearray).")

    if not isinstance(mode, str):
        log_error(f"Unpadding failed: invalid mode type | module=padding | func=unpad_with_info | type(mode)={type(mode).__name__} | label={label} | purpose={purpose}")
        raise TypeError("Unpadding failed: mode must be a string.")

    raw = bytes(data)
    block_bits = block_size * 8

    # NONE means we remove nothing
    if mode == "NONE":
        return raw, b""

    # cannot unpad empty
    if not raw:
        log_error(f"Unpadding failed: empty data | module=padding | func=unpad_with_info | mode={mode} | block_bytes={block_size} | block_bits={block_bits} | label={label} | purpose={purpose}")
        raise PaddingError("Unpadding failed: cannot unpad empty data.")

    # unpadding requires full blocks
    if len(raw) % block_size != 0:
        log_error(f"Unpadding failed: length not multiple of block_size | module=padding | func=unpad_with_info | mode={mode} | block_bytes={block_size} | block_bits={block_bits} | len={len(raw)}B | label={label} | purpose={purpose}")
        raise PaddingError(f"Unpadding failed: data length must be a multiple of {block_size} bytes. Given value has {len(raw)} bytes.")

    # PKCS7 validation
    if mode == "PKCS7":
        n = raw[-1]
        if n < 1 or n > block_size:
            log_error(f"Unpadding failed: invalid PKCS7 length | module=padding | func=unpad_with_info | N={n} | block_bytes={block_size} | label={label} | purpose={purpose}")
            raise PaddingError(f"Unpadding failed: invalid PKCS#7 padding length N={n}.")
        tail = raw[-n:]
        if any(b != n for b in tail):
            log_error(f"Unpadding failed: invalid PKCS7 bytes | module=padding | func=unpad_with_info | N={n} | label={label} | purpose={purpose}")
            raise PaddingError("Unpadding failed: invalid PKCS#7 padding bytes (not all bytes match N).")
        out = raw[:-n]
        log_debug(f"Unpadding done | module=padding | func=unpad_with_info | mode=PKCS7 | block_bytes={block_size} | block_bits={block_bits} | in={len(raw)}B | removed={len(tail)}B | out={len(out)}B | label={label} | purpose={purpose}")
        return out, tail

    # X923 validation
    if mode == "X923":
        n = raw[-1]
        if n < 1 or n > block_size:
            log_error(f"Unpadding failed: invalid X923 length | module=padding | func=unpad_with_info | N={n} | block_bytes={block_size} | label={label} | purpose={purpose}")
            raise PaddingError(f"Unpadding failed: invalid X.923 padding length N={n}.")
        tail = raw[-n:]
        if n > 1 and any(b != 0x00 for b in tail[:-1]):
            log_error(f"Unpadding failed: invalid X923 bytes | module=padding | func=unpad_with_info | N={n} | label={label} | purpose={purpose}")
            raise PaddingError("Unpadding failed: invalid X.923 padding bytes (expected 0x00 for all but last byte).")
        out = raw[:-n]
        log_debug(f"Unpadding done | module=padding | func=unpad_with_info | mode=X923 | block_bytes={block_size} | block_bits={block_bits} | in={len(raw)}B | removed={len(tail)}B | out={len(out)}B | label={label} | purpose={purpose}")
        return out, tail

    # ISO/IEC 7816-4 validation
    if mode == "ISO/IEC 7816-4":
        # from the end: zeros then 0x80 marker
        i = len(raw) - 1
        while i >= 0 and raw[i] == 0x00:
            i -= 1
        if i < 0 or raw[i] != 0x80:
            log_error(f"Unpadding failed: missing 0x80 marker | module=padding | func=unpad_with_info | mode=ISO/IEC 7816-4 | label={label} | purpose={purpose}")
            raise PaddingError("Unpadding failed: invalid ISO/IEC 7816-4 padding (missing 0x80 marker).")
        removed = raw[i:]
        # removed length must be <= block_size and >= 1
        if len(removed) < 1 or len(removed) > block_size:
            log_error(f"Unpadding failed: invalid ISO/IEC 7816-4 length | module=padding | func=unpad_with_info | removed={len(removed)}B | block_bytes={block_size} | label={label} | purpose={purpose}")
            raise PaddingError("Unpadding failed: invalid ISO/IEC 7816-4 padding length.")
        out = raw[:i]
        log_debug(f"Unpadding done | module=padding | func=unpad_with_info | mode=ISO/IEC 7816-4 | block_bytes={block_size} | block_bits={block_bits} | in={len(raw)}B | removed={len(removed)}B | out={len(out)}B | label={label} | purpose={purpose}")
        return out, removed

    # unsupported mode
    log_error(f"Unpadding failed: unsupported mode | module=padding | func=unpad_with_info | mode={mode} | label={label} | purpose={purpose}")
    raise ValueError(f"Unpadding failed: unsupported padding mode: {mode}")


def unpad_data(data: bytes, block_size: int, mode: PaddingMode, *, label: str = "", purpose: str = "") -> bytes:
    """
    Wrapper for unpad_with_info:
      - returns only unpadded bytes
    """
    return unpad_with_info(data, block_size, mode, label=label, purpose=purpose)[0]

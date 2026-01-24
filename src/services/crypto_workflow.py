from __future__ import annotations # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types

from dataclasses import dataclass # helps simplifying building classes
from typing import Optional, cast # needed to mark a value as str or None (existing or missing both possible) and safe narrowing for Mode

from src.models.mode_ecb import AESECB  # needed to run AES-ECB encryption and decryption
from src.models.mode_cbc import AESCBC  # needed to run AES-CBC encryption and decryption
from src.models.mode_ctr import AESCTR  # needed to run AES-CTR encryption and decryption

from src.utils.hex_converter import hex_from_bytes  # needed to output bytes as hex strings for the UI
from src.utils.security_helpers import generate_random_iv, generate_random_key  # needed to generate secure random IVs and AES keys
from src.utils.input_parsers import (
    parse_plaintext,  # needed to convert plaintext from UI string into bytes
    parse_aes_key_hex,  # needed to convert key hex into key bytes
    parse_iv_hex,  # needed to convert IV hex into IV bytes
    parse_ciphertext_hex,  # needed to convert ciphertext hex into bytes
)
from src.utils.padding_schemes import (
    pad_with_info,  # needed to apply padding and also return pad length and pad bytes for visualization
    unpad_with_info,  # needed to remove padding and return removed bytes for visualization
    PaddingError,  # needed to detect padding failures and convert them into a stable UI error
)

from src.domain.crypto_constants import AES_BLOCK_BYTES, VALID_AES_KEY_SIZES  # needed to import block size and key size constants
from src.domain.crypto_types import Mode  # needed to restrict modes of operation values to ECB, CBC, CTR at type level
from src.domain.input_types import InputFormat # needed to know if plaintext is TEXT or HEX or BIN
from src.domain.padding_types import PaddingMode # needed to restrict padding choices to supported modes

# -------------------------------------------------------------------------------------
#                               CRYPTO WORKFLOW SERVICE
# -------------------------------------------------------------------------------------
# Why??
#   - single backend entry point used by ViewModel
#   - validates inputs, applies padding rules, calls the AES mode models,
#     and returns detailed results for the UI visualization
#
# NB:
#   - Model stay focused on crypto operations and low level validation
#   - ViewModel stays focused on UI friendly output mapping
#   - This service stays responsible for the full workflow and business rules
#
# Tested?
#   - Yes 
#   - Unit test inside tests/services/test_crypto_workflow.py 
# -------------------------------------------------------------------------------------


# -------------------------------------------------------------------------------------
# Stable domain error for UI
# -------------------------------------------------------------------------------------
# Why?
#     - UI needs predictable error codes and field names
#     - avoid random exception types to leak into the view layer
# -------------------------------------------------------------------------------------
@dataclass(slots=True)
class WorkflowError(Exception):
    code: str         # stable machine readable code for the UI
    field: str        # which input field caused the error
    message: str      # user friendly message
    details: str = "" # optional technical details for debugging

    def __str__(self) -> str:
        return self.message


def _wrap(*, code: str, field: str, e: Exception) -> WorkflowError:
    # helper to convert internal exceptions into a stable UI error
    # keep the original exception type inside details for debugging
    return WorkflowError(
        code=code,
        field=field,
        message=str(e),
        details=f"{type(e).__name__}: {e}",
    )


def normalize_mode(mode: str) -> str:
    # normalize user input mode coming from the UI
    return (mode or "").strip().upper()


def ensure_supported_mode(mode: str) -> Mode:
    # validate mode early so the rest of the workflow can assume it is correct
    if mode not in ("ECB", "CBC", "CTR"):
        raise WorkflowError(
            code="UNSUPPORTED_MODE",
            field="mode",
            message="Unsupported mode. Use ECB, CBC, or CTR.",
        )
    return cast(Mode, mode)


# -------------------------------------------------------------------------------------
# Key / IV generation (done in backend)
# -------------------------------------------------------------------------------------
# Why?
#       - 2 helpers exposed to ViewModel but the actual random generation happens here
#       - that keeps crypto sensitive logic out of the ViewModel
# -------------------------------------------------------------------------------------
def generate_key_hex(bits: int) -> str:
    # UI chooses the key size in bits but the generator expects bytes
    if bits not in (128, 192, 256):
        raise WorkflowError(
            code="INVALID_KEY_SIZE",
            field="key",
            message="Key size must be 128, 192, or 256.",
        )
    try:
        key = generate_random_key(bits // 8, label="SERVICE", purpose="generate_key_hex")
        return hex_from_bytes(key, label="SERVICE", purpose="generate_key_hex")
    except Exception as e:
        raise WorkflowError(
            code="INTERNAL",
            field="",
            message="Key generation failed due to an internal error.",
            details=f"{type(e).__name__}: {e}",
        ) from e


def generate_iv_hex() -> str:
    # AES-CBC and AES-CTR need a 16 byte IV/Counter
    try:
        iv = generate_random_iv(label="SERVICE", purpose="generate_iv_hex")
        return hex_from_bytes(iv, label="SERVICE", purpose="generate_iv_hex")
    except Exception as e:
        raise WorkflowError(
            code="INTERNAL",
            field="",
            message="IV generation failed due to an internal error.",
            details=f"{type(e).__name__}: {e}",
        ) from e


# -------------------------------------------------------------------------------------
# Result objects returned by workflows
# -------------------------------------------------------------------------------------
# Why?
#    - holds all intermediate values that the UI wants to visualize
# -------------------------------------------------------------------------------------

# Encryption related
@dataclass(slots=True)
class EncryptDetails:
    mode: Mode
    key: bytes
    plaintext: bytes
    padded_plaintext: bytes
    pad_len: int
    pad_bytes: bytes
    ciphertext: bytes
    used_iv: Optional[bytes]

# Decryption related
@dataclass(slots=True)
class DecryptDetails:
    mode: Mode
    key: bytes
    ciphertext: bytes
    raw_decrypted: bytes
    plaintext_final: bytes
    removed_pad: bytes
    used_iv: Optional[bytes]


def encrypt_workflow(
    *,
    mode: Mode,
    plaintext: str,
    input_format: InputFormat,
    key_hex: str,
    iv_hex: Optional[str],
    padding_mode: PaddingMode,
) -> EncryptDetails:
    # full encryption workflow used by the ViewModel
    m = ensure_supported_mode(normalize_mode(mode))

    # parse key from HEX into bytes
    # NB: only parsing errors are wrapped so the UI gets a clean INVALID_KEY error
    try:
        key = parse_aes_key_hex(key_hex)
    except Exception as e:
        raise _wrap(code="INVALID_KEY", field="key", e=e) from e

    # enforce valid AES key sizes for a stable error message
    if len(key) not in VALID_AES_KEY_SIZES:
        raise WorkflowError(
            code="INVALID_KEY",
            field="key",
            message="Invalid AES key length. Must be 16/24/32 bytes (AES-128/192/256).",
            details=f"len={len(key)}",
        )

    # parse plaintext from UI according to the selected input format
    try:
        pt = parse_plaintext(plaintext, input_format)
    except Exception as e:
        raise _wrap(code="INVALID_INPUT", field="plaintext", e=e) from e

    # CTR must not use padding
    if m == "CTR" and padding_mode != "NONE":
        raise WorkflowError(
            code="PADDING_NOT_ALLOWED",
            field="padding",
            message="CTR does not use padding. Set Padding = NONE.",
        )

    # AES-ECB and AES-CBC require block alignment when padding is disabled
    if m in ("ECB", "CBC") and padding_mode == "NONE" and (len(pt) % AES_BLOCK_BYTES != 0):
        raise WorkflowError(
            code="PLAINTEXT_NOT_BLOCK_ALIGNED",
            field="plaintext",
            message=(
                "Padding is set to NONE, but AES-ECB/CBC require plaintext length to be a multiple of 16 bytes.\n"
                f"Plaintext length = {len(pt)} bytes.\n"
                "\nFix:\n"
                "  - choose PKCS7 / X923 / ISO/IEC 7816-4 padding, or\n"
                "  - provide input whose length is a multiple of 16 bytes."
            ),
        )

    # For ECB and CBC we compute padding details for the UI.
    pad_len = 0
    pad_bytes = b""
    padded_pt = pt
    if m in ("ECB", "CBC"):
        try:
            padded_pt, pad_len, pad_bytes = pad_with_info(
                pt, AES_BLOCK_BYTES, padding_mode, label="Plaintext", purpose="encrypt_workflow"
            )
        except Exception as e:
            raise _wrap(code="INVALID_PADDING", field="padding", e=e) from e

    # parse IV if provided
    # CBC and CTR encryption allow missing IV which will be auto generated by model
    iv: Optional[bytes] = None
    if iv_hex and iv_hex.strip():
        try:
            iv = parse_iv_hex(iv_hex, field_name="IV/Counter (HEX)")
        except Exception as e:
            raise _wrap(code="INVALID_IV", field="iv", e=e) from e

        if len(iv) != AES_BLOCK_BYTES:
            raise WorkflowError(
                code="INVALID_IV",
                field="iv",
                message="IV/Counter must be exactly 16 bytes (32 hex chars).",
                details=f"len={len(iv)}",
            )

    # run selected mode
    # models log their own operations and stable WorkflowError boundaries are kept here
    try:
        used_iv: Optional[bytes] = None

        if m == "ECB":
            ct = AESECB(key).encrypt(padded_pt, padding="NONE")

        elif m == "CBC":
            ct, used_iv = AESCBC(key).encrypt_with_iv(padded_pt, iv=iv, padding="NONE")

        else:
            ct, used_iv = AESCTR(key).encrypt_with_iv(pt, iv=iv, padding="NONE")

        return EncryptDetails(
            mode=m,
            key=key,
            plaintext=pt,
            padded_plaintext=padded_pt,
            pad_len=pad_len,
            pad_bytes=pad_bytes,
            ciphertext=ct,
            used_iv=used_iv,
        )

    except WorkflowError:
        raise
    except Exception as e:
        raise WorkflowError(
            code="INTERNAL",
            field="",
            message="Encryption failed due to an internal error.",
            details=f"{type(e).__name__}: {e}",
        ) from e


def decrypt_workflow(
    *,
    mode: Mode,
    ciphertext_hex: str,
    key_hex: str,
    iv_hex: Optional[str],
    unpadding_mode: PaddingMode,
) -> DecryptDetails:
    # full decryption workflow used by the ViewModel
    m = ensure_supported_mode(normalize_mode(mode))

    # parse key from HEX into bytes
    try:
        key = parse_aes_key_hex(key_hex)
    except Exception as e:
        raise _wrap(code="INVALID_KEY", field="key", e=e) from e

    # enforce valid AES key sizes for a stable error message
    if len(key) not in VALID_AES_KEY_SIZES:
        raise WorkflowError(
            code="INVALID_KEY",
            field="key",
            message="Invalid AES key length. Must be 16/24/32 bytes (AES-128/192/256).",
            details=f"len={len(key)}",
        )

    # parse ciphertext from HEX into bytes
    try:
        ct = parse_ciphertext_hex(ciphertext_hex)
    except Exception as e:
        raise _wrap(code="INVALID_CIPHERTEXT", field="ciphertext", e=e) from e

    # CTR must never use unpadding
    if m == "CTR" and unpadding_mode != "NONE":
        raise WorkflowError(
            code="UNPADDING_NOT_ALLOWED",
            field="unpadding",
            message="CTR does not use unpadding. Set Unpadding = NONE.",
        )

    # AES-ECB and AES-CBC require ciphertext to be block aligned
    if m in ("ECB", "CBC") and (len(ct) % AES_BLOCK_BYTES != 0):
        raise WorkflowError(
            code="CIPHERTEXT_NOT_BLOCK_ALIGNED",
            field="ciphertext",
            message=(
                f"Ciphertext length is {len(ct)} bytes, which is not a multiple of 16.\n"
                "AES-ECB/CBC require full 16-byte blocks.\n"
                "Fix: ensure the ciphertext was produced by AES-ECB/CBC and is not corrupted."
            ),
        )

    # CBC and CTR require the same IV or counter used during encryption
    iv: Optional[bytes] = None
    if m in ("CBC", "CTR"):
        if not iv_hex or not iv_hex.strip():
            raise WorkflowError(
                code="MISSING_IV",
                field="iv",
                message=f"{m} decryption requires the same IV/Counter used for encryption.",
            )

        try:
            iv = parse_iv_hex(iv_hex, field_name="IV/Counter (HEX)")
        except Exception as e:
            raise _wrap(code="INVALID_IV", field="iv", e=e) from e

        if len(iv) != AES_BLOCK_BYTES:
            raise WorkflowError(
                code="INVALID_IV",
                field="iv",
                message="IV/Counter must be exactly 16 bytes (32 hex chars).",
                details=f"len={len(iv)}",
            )

    # run the selected mode and optionally unpad (if unpadding mode is not NONE)
    try:
        used_iv: Optional[bytes] = iv
        removed = b""

        if m == "ECB":
            raw = AESECB(key).decrypt(ct, unpadding="NONE")
            pt_final = raw

        elif m == "CBC":
            raw = AESCBC(key).decrypt(ct, iv=iv, unpadding="NONE")
            pt_final = raw

        else:
            pt_final = AESCTR(key).decrypt(ct, iv=iv, unpadding="NONE")
            raw = pt_final

        # unpadding is done here in the workflow so models stay pure
        if m in ("ECB", "CBC") and unpadding_mode != "NONE":
            try:
                pt_final, removed = unpad_with_info(
                    raw, AES_BLOCK_BYTES, unpadding_mode, label="Decrypted data", purpose="decrypt_workflow"
                )
            except PaddingError as pe:
                raise WorkflowError(
                    code="BAD_PADDING",
                    field="unpadding",
                    message=(
                        "Unpadding failed.\n"
                        "Possible reasons:\n"
                        "  1) Wrong key\n"
                        "  2) Wrong IV (CBC)\n"
                        "  3) Wrong unpadding mode selected (PKCS7 or X923 or ISO/IEC 7816-4)\n"
                        "  4) Ciphertext was modified or corrupted\n"
                        f"\nDetails: {pe}"
                    ),
                    details=str(pe),
                ) from pe
            except Exception as e:
                raise _wrap(code="INVALID_UNPADDING", field="unpadding", e=e) from e

        return DecryptDetails(
            mode=m,
            key=key,
            ciphertext=ct,
            raw_decrypted=raw,
            plaintext_final=pt_final,
            removed_pad=removed,
            used_iv=used_iv,
        )

    except WorkflowError:
        raise
    except Exception as e:
        raise WorkflowError(
            code="INTERNAL",
            field="",
            message="Decryption failed due to an internal error.",
            details=f"{type(e).__name__}: {e}",
        ) from e

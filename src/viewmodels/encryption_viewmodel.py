from __future__ import annotations  # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types

from dataclasses import dataclass, field  # helps simplifying building classes and add field for list default_factory
from typing import Optional  # needed to mark a value as str or None (existing or missing both possible)

from src.domain.crypto_constants import AES_BLOCK_BYTES  # needed to import block size constant

from src.services.crypto_workflow import (
    encrypt_workflow,  # needed to run the full backend encryption workflow (validation + padding rules + mode call)
    decrypt_workflow,  # needed to run the full backend decryption workflow (validation + padding rules + mode call)
    generate_key_hex as svc_generate_key_hex,  # needed to generate secure random AES keys in the backend and return HEX for UI
    generate_iv_hex as svc_generate_iv_hex,  # needed to generate secure random IV/Counter in the backend and return HEX for UI
    WorkflowError,  # needed to convert backend workflow errors into predictable UI error fields
)

from src.utils.hex_formatting import (
    format_hex_blocks,  # needed to format HEX output as 16-byte blocks for visualization
    normalize_hex,  # needed to normalize ciphertext
    hex_tokens_from_raw_hex,  # needed to build tokens
)

from src.domain.input_types import InputFormat  # needed to know if plaintext is TEXT or HEX
from src.domain.padding_types import PaddingMode  # needed to restrict padding and unpadding choices to supported modes
from src.domain.crypto_types import Mode  # needed to restrict mode values to ECB, CBC, CTR at type level


# -------------------------------------------------------------------------------------
#                           VIEWMODEL RESULT OBJECT (UI OUTPUT)
# -------------------------------------------------------------------------------------
# Why??
#   - UI needs one stable object for both encryption and decryption results
#   - keeps error info, final outputs, and visualization fields in one place
#
# NB:
#   - ok = True means output fields are valid
#   - ok = False means error_* fields are filled and UI should show them
#
# Tested?
#   - Yes
#   - Unit test inside tests/viewmodels/test_encryption_viewmodel.py
# -------------------------------------------------------------------------------------

# Class of needed vars
@dataclass(slots=True)
class CryptoResult:
    ok: bool
    error: str = ""

    error_code: str = ""
    error_field: str = ""
    error_details: str = ""

    output_hex: str = ""
    output_hex_raw: str = ""
    output_text: str = ""

    used_key_hex: str = ""
    used_iv_hex: str = ""

    input_format: InputFormat = "TEXT"
    padding_mode: PaddingMode = "PKCS7"
    unpadding_mode: PaddingMode = "PKCS7"

    input_hex_raw: str = ""
    padded_input_hex_raw: str = ""
    pad_hex_raw: str = ""
    pad_len: int = 0

    decrypted_raw_hex_raw: str = ""
    removed_pad_hex_raw: str = ""
    removed_pad_len: int = 0

    used_key_hex_blocks: str = ""
    used_iv_hex_blocks: str = ""

    input_hex_blocks: str = ""
    padded_input_hex_blocks: str = ""
    pad_hex_blocks: str = ""

    decrypted_raw_hex_blocks: str = ""
    removed_pad_hex_blocks: str = ""

    ciphertext_used_hex_raw: str = ""
    ciphertext_used_hex_blocks: str = ""

    output_tokens: list[str] = field(default_factory=list)

    input_tokens: list[str] = field(default_factory=list)
    pad_tokens: list[str] = field(default_factory=list)
    padded_tokens: list[str] = field(default_factory=list)

    decrypted_raw_tokens: list[str] = field(default_factory=list)
    removed_pad_tokens: list[str] = field(default_factory=list)

    pad_start_index: int = 0
    removed_pad_start_index: int = 0


# -------------------------------------------------------------------------------------
#                              ENCRYPTION VIEWMODEL
# -------------------------------------------------------------------------------------
# Why??
#   - UI friendly bridge between the frontend and the backend workflows
#   - calls encrypt_workflow and/or decrypt_workflow and maps bytes into HEX and text
#   - keeps UI stable by catching WorkflowError and returning clean CryptoResult
#
# NB:
#   - workflow handles validation and crypto rules
#   - viewmodel handles formatting and display-friendly mapping
# -------------------------------------------------------------------------------------

class EncryptionViewModel:
    @staticmethod
    def _best_effort_utf8(data: bytes) -> str:
        # try to show decrypted data as readable text
        # if bytes are not valid UTF-8 fall back to a clear UI hint message
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return "(UTF-8 decoding failed: data is not valid UTF-8. Use hex instead.)"

    @staticmethod
    def _fail(*, code: str, message: str, field: str = "", details: str = "") -> CryptoResult:
        # one place to build an error result so the UI always gets the same shape
        # code and field are used by the UI to highlight the right input box
        return CryptoResult(
            ok=False,
            error=message if message else "Operation failed.",
            error_code=code,
            error_field=field,
            error_details=details,
        )

    @staticmethod
    def _unexpected_error(e: Exception) -> CryptoResult:
        # safe fallback for unknown errors
        # we do not leak stack traces but keep a small technical hint in details
        return EncryptionViewModel._fail(
            code="INTERNAL",
            field="",
            message="An unexpected internal error occurred.",
            details=f"{type(e).__name__}: {e}",
        )

    # -----------------------------------------------------------------------------
    # Key / IV generation (done in backend)
    # -----------------------------------------------------------------------------
    # Why?
    #   - UI needs buttons "Generate Key" and "Generate IV"
    #   - keep the actual random generation inside backend services
    #   - viewmodel only forwards the call and converts backend errors to UI errors
    # -----------------------------------------------------------------------------
    def generate_key_hex(self, bits: int) -> str:
        # bits comes from UI (128/192/256)
        # backend returns a HEX string ready to be placed in the key input field
        try:
            return svc_generate_key_hex(bits)
        except WorkflowError as we:
            raise ValueError(we.message) from None

    def generate_iv_hex(self) -> str:
        # IV is always 16 bytes for CBC and CTR
        # backend returns a HEX string ready to be placed in the IV input field
        try:
            return svc_generate_iv_hex()
        except WorkflowError as we:
            raise ValueError(we.message) from None

    # -----------------------------------------------------------------------------
    # ENCRYPT
    # -----------------------------------------------------------------------------
    # Why?
    #   - takes UI inputs, runs the backend workflow, and returns display-ready fields
    #   - returns ciphertext as raw HEX and also formatted block HEX for visualization
    # -----------------------------------------------------------------------------
    def encrypt(
        self,
        mode: Mode,
        plaintext: str,
        input_format: InputFormat,
        key_hex: str,
        iv_hex: Optional[str],
        padding_mode: PaddingMode,
    ) -> CryptoResult:
        try:
            # backend workflow validates everything and runs the correct AES mode
            d = encrypt_workflow(
                mode=mode,
                plaintext=plaintext,
                input_format=input_format,
                key_hex=key_hex,
                iv_hex=iv_hex,
                padding_mode=padding_mode,
            )

            # ciphertext is returned as bytes from backend but UI wants hex strings
            ct_hex = d.ciphertext.hex()
            key_hex_raw = d.key.hex()
            iv_hex_raw = (d.used_iv.hex() if d.used_iv else "")

            input_hex_raw = d.plaintext.hex()
            padded_hex_raw = d.padded_plaintext.hex()
            pad_hex_raw = d.pad_bytes.hex()

            input_tokens = (
                hex_tokens_from_raw_hex(input_hex_raw, label="Plaintext", purpose="encrypt_viewmodel")
                if input_hex_raw
                else []
            )
            pad_tokens = (
                hex_tokens_from_raw_hex(pad_hex_raw, label="Padding bytes", purpose="encrypt_viewmodel")
                if pad_hex_raw
                else []
            )
            padded_tokens = input_tokens + pad_tokens

            return CryptoResult(
                ok=True,

                # final ciphertext (already display formatted)
                output_hex=format_hex_blocks(ct_hex, AES_BLOCK_BYTES, label="Ciphertext", purpose="encrypt_viewmodel"),
                output_hex_raw=ct_hex,
                output_tokens=(
                    hex_tokens_from_raw_hex(ct_hex, label="Ciphertext", purpose="encrypt_viewmodel")
                    if ct_hex
                    else []
                ),

                # key / iv raw + blocks
                used_key_hex=key_hex_raw,
                used_key_hex_blocks=format_hex_blocks(key_hex_raw, AES_BLOCK_BYTES, label="Key", purpose="encrypt_viewmodel"),
                used_iv_hex=iv_hex_raw,
                used_iv_hex_blocks=(
                    format_hex_blocks(iv_hex_raw, AES_BLOCK_BYTES, label="IV", purpose="encrypt_viewmodel")
                    if iv_hex_raw
                    else ""
                ),

                # UI selections
                input_format=input_format,
                padding_mode=padding_mode,

                # padding visualization raw + blocks + tokens
                input_hex_raw=input_hex_raw,
                input_hex_blocks=(
                    format_hex_blocks(input_hex_raw, AES_BLOCK_BYTES, label="Plaintext", purpose="encrypt_viewmodel")
                    if input_hex_raw
                    else ""
                ),
                input_tokens=input_tokens,

                padded_input_hex_raw=padded_hex_raw,
                padded_input_hex_blocks=(
                    format_hex_blocks(padded_hex_raw, AES_BLOCK_BYTES, label="Padded plaintext", purpose="encrypt_viewmodel")
                    if padded_hex_raw
                    else ""
                ),
                padded_tokens=padded_tokens,

                pad_hex_raw=pad_hex_raw,
                pad_hex_blocks=(
                    format_hex_blocks(pad_hex_raw, AES_BLOCK_BYTES, label="Padding bytes", purpose="encrypt_viewmodel")
                    if pad_hex_raw
                    else ""
                ),
                pad_tokens=pad_tokens,
                pad_start_index=len(input_tokens),
                pad_len=d.pad_len,
            )

        except WorkflowError as we:
            return self._fail(code=we.code, field=we.field, message=we.message, details=we.details)

        except Exception as e:
            return self._unexpected_error(e)

    # -----------------------------------------------------------------------------
    # DECRYPT
    # -----------------------------------------------------------------------------
    # Why?
    #   - takes UI inputs, runs backend workflow and returns display-ready fields
    #   - returns plaintext both as HEX and as best-effort UTF-8 text
    # -----------------------------------------------------------------------------
    def decrypt(
        self,
        mode: Mode,
        ciphertext_hex: str,
        key_hex: str,
        iv_hex: Optional[str],
        unpadding_mode: PaddingMode,
    ) -> CryptoResult:
        try:
            ct_used_norm = normalize_hex(ciphertext_hex, label="Ciphertext input", purpose="decrypt_viewmodel")

            # backend workflow validates inputs, decrypts, and optionally unpads
            d = decrypt_workflow(
                mode=mode,
                ciphertext_hex=ct_used_norm,
                key_hex=key_hex,
                iv_hex=iv_hex,
                unpadding_mode=unpadding_mode,
            )

            # plaintext is returned as bytes from backend and UI needs hex and text
            pt_hex = d.plaintext_final.hex()
            key_hex_raw = d.key.hex()
            iv_hex_raw = (d.used_iv.hex() if d.used_iv else "")

            raw_hex = d.raw_decrypted.hex()
            removed_hex = d.removed_pad.hex()

            # compute tokens once (avoid duplicate work)
            raw_tokens = (
                hex_tokens_from_raw_hex(raw_hex, label="Raw decrypted", purpose="decrypt_viewmodel")
                if raw_hex
                else []
            )
            removed_len = len(d.removed_pad)

            return CryptoResult(
                ok=True,

                # plaintext after unpadding (display formatted)
                output_hex=format_hex_blocks(pt_hex, AES_BLOCK_BYTES, label="Plaintext final", purpose="decrypt_viewmodel"),
                output_hex_raw=pt_hex,
                output_tokens=(
                    hex_tokens_from_raw_hex(pt_hex, label="Plaintext final", purpose="decrypt_viewmodel")
                    if pt_hex
                    else []
                ),
                output_text=self._best_effort_utf8(d.plaintext_final),

                # key / iv raw + blocks
                used_key_hex=key_hex_raw,
                used_key_hex_blocks=format_hex_blocks(key_hex_raw, AES_BLOCK_BYTES, label="Key", purpose="decrypt_viewmodel"),
                used_iv_hex=iv_hex_raw,
                used_iv_hex_blocks=(
                    format_hex_blocks(iv_hex_raw, AES_BLOCK_BYTES, label="IV", purpose="decrypt_viewmodel")
                    if iv_hex_raw
                    else ""
                ),

                # ciphertext used (normalized) raw + blocks
                ciphertext_used_hex_raw=ct_used_norm,
                ciphertext_used_hex_blocks=format_hex_blocks(
                    ct_used_norm,
                    AES_BLOCK_BYTES,
                    assume_normalized=True,
                    label="Ciphertext used",
                    purpose="decrypt_viewmodel",
                ),

                # UI selection
                unpadding_mode=unpadding_mode,

                # before/removed padding (raw + blocks + tokens)
                decrypted_raw_hex_raw=raw_hex,
                decrypted_raw_hex_blocks=(
                    format_hex_blocks(raw_hex, AES_BLOCK_BYTES, label="Raw decrypted", purpose="decrypt_viewmodel")
                    if raw_hex
                    else ""
                ),
                decrypted_raw_tokens=raw_tokens,

                removed_pad_hex_raw=removed_hex,
                removed_pad_hex_blocks=(
                    format_hex_blocks(removed_hex, AES_BLOCK_BYTES, label="Removed padding", purpose="decrypt_viewmodel")
                    if removed_hex
                    else ""
                ),
                removed_pad_tokens=(
                    hex_tokens_from_raw_hex(removed_hex, label="Removed padding", purpose="decrypt_viewmodel")
                    if removed_hex
                    else []
                ),

                removed_pad_len=removed_len,
                removed_pad_start_index=max(0, len(raw_tokens) - removed_len),
            )

        except WorkflowError as we:
            return self._fail(code=we.code, field=we.field, message=we.message, details=we.details)

        except Exception as e:
            return self._unexpected_error(e)

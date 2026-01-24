# -------------------------------------------------------------------------------------
#                                AES CBC MODE
# -------------------------------------------------------------------------------------
# Why AES-CBC??
#   - hides patterns by chaining blocks together
#   - uses an IV to randomize the first block
#
# NB:
#   - requires a random and unique IV
#   - IV must be exactly 16 bytes
#   - AES-ECB/CBC need padding if plaintext is not block-aligned
#
# Tested?
#   - Yes 
#   - Unit test inside tests/models/test_mode_cbc.py 
# -------------------------------------------------------------------------------------

from __future__ import annotations # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types
from typing import Optional # needed to mark a value as str or None (existing or missing both possible)
from dataclasses import dataclass # helps simplifying building classes

from src.domain.crypto_constants import AES_BLOCK_BYTES # needed to import block size constant

from .aes_base import (
    AESCore,
    _ensure_bytes,
) # needed to import AES Core Logic file

from src.utils.logger import (
    log_success,
    log_warning,
    log_error,
    log_info,
    should_log_starts,
) # needed to import Log System

from src.utils.security_helpers import generate_random_iv # needed to import IV Generator

from src.utils.padding_schemes import (
    PaddingMode,
    pad_data,
    unpad_data,
    PaddingError,
) # needed to import Padding related methods

@dataclass(slots=True)
class AESCBC(AESCore):
    """
    CBC wrapper around AESCore
    """

    def encrypt_with_iv(
        self,
        plaintext: bytes | bytearray | str,
        iv: Optional[bytes | bytearray] = None,
        padding: PaddingMode = "PKCS7",
    ) -> tuple[bytes, bytes]:
        # IV: generate if missing (IV is not secret but must be unique and unpredictable)
        if iv is None:
            log_warning("CBC: IV is missing. Generating secure random IV... | module=mode_cbc | func=encrypt_with_iv | iv=missing, generating secure random IV")
            iv = generate_random_iv(label="CBC", purpose="encrypt_with_iv")

        if should_log_starts():
            log_info("Starting CBC encryption | module=mode_cbc | func=encrypt_with_iv")

        try:
            pt = _ensure_bytes(plaintext)
        except Exception as e:
            log_error("CBC validation failed | module=mode_cbc | func=encrypt_with_iv | step=plaintext_type | " f"error={e}")
            raise


        # Padding is optional
        # If padding is NONE, AESCore will enforce block alignment
        if padding == "NONE":
            padded = pt
        else:
            padded = pad_data(pt, block_size=AES_BLOCK_BYTES, mode=padding, label="Plaintext", purpose="CBC encrypt")

        try:
            ct = self.encrypt_raw(padded, "CBC", iv)
        except Exception as e:
            log_error(
                "CBC encrypt_raw failed | module=mode_cbc | func=encrypt_with_iv | step=encrypt_raw | "
                f"error={e}"
            )
            raise

        iv_bytes = bytes(iv)

        log_success(
            "CBC encryption done | module=mode_cbc | func=encrypt_with_iv | "
            f"key_bits={len(self.key) * 8} | padding={padding} | iv={iv_bytes.hex()} | "
            f"in={len(padded)}B | out={len(ct)}B"
        )
        return ct, iv_bytes

    def decrypt(
        self,
        ciphertext: bytes | bytearray,
        iv: Optional[bytes | bytearray] = None,
        unpadding: PaddingMode = "PKCS7",
    ) -> bytes:
        if iv is None:
            log_error("CBC validation failed | module=mode_cbc | func=decrypt | step=iv | error=missing_iv")
            raise ValueError(
                "CBC decryption requires the same IV used for encryption.\n"
                "Tip: Copy the IV from the encryption output (32 hex characters)."
            )

        if not isinstance(ciphertext, (bytes, bytearray)):
            log_error(
                "CBC validation failed | module=mode_cbc | func=decrypt | step=ciphertext_type | "
                f"type={type(ciphertext).__name__}"
            )
            raise TypeError("CBC decrypt failed: ciphertext must be bytes (or bytearray).")


        ct = bytes(ciphertext)

        if should_log_starts():
            log_info("Starting CBC decryption | module=mode_cbc | func=decrypt")

        try:
            data = self.decrypt_raw(ct, "CBC", iv)
        except Exception as e:
            log_error(
                "CBC decrypt_raw failed | module=mode_cbc | func=decrypt | step=decrypt_raw | "
                f"error={e}"
            )
            raise

        iv_bytes = bytes(iv)

        if unpadding == "NONE":
            pt = data
        else:
            try:
                pt = unpad_data(data, block_size=AES_BLOCK_BYTES, mode=unpadding, label="Decrypted data", purpose="CBC decrypt")
            except PaddingError as pe:
                raise ValueError(
                    "Unpadding failed.\n"
                    "Possible reasons:\n"
                    "  1) Wrong key\n"
                    "  2) Wrong IV (CBC needs the exact same IV)\n"
                    "  3) Wrong unpadding mode selected\n"
                    "  4) Ciphertext was modified or corrupted\n"
                    f"\nDetails: {pe}"
                ) from pe

        log_success(
            "CBC decryption done | module=mode_cbc | func=decrypt | "
            f"key_bits={len(self.key) * 8} | unpadding={unpadding} | iv={iv_bytes.hex()} | "
            f"out={len(pt)}B"
        )

        return pt

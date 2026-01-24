# -------------------------------------------------------------------------------------
#                                AES CTR MODE
# -------------------------------------------------------------------------------------
# Why AES-CTR??
#   - turns AES into a stream cipher
#   - no padding is needed (any length works)
#   - encryption and decryption use the same operation internally
#
# NB:
#   - requires unique IV/Counter per encryption with the same key
#   - IV/Counter must be exactly 16 bytes
#
# Tested?
#   - Yes 
#   - Unit test inside tests/models/test_mode_ctr.py 
#  -------------------------------------------------------------------------------------

from __future__ import annotations # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types
from typing import Optional # needed to mark a value as str or None (existing or missing both possible)
from dataclasses import dataclass # helps simplifying building classes

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

from src.utils.padding_schemes import PaddingMode # needed to import Padding related methods

@dataclass(slots=True)
class AESCTR(AESCore):
    """
    CTR wrapper around AESCore (no padding)
    """

    def encrypt_with_iv(
        self,
        plaintext: bytes | bytearray | str,
        iv: Optional[bytes | bytearray] = None,
        padding: PaddingMode = "NONE",
    ) -> tuple[bytes, bytes]:
        # CTR strictly does not use padding.
        if padding != "NONE":
            log_error(
                "CTR validation failed | module=mode_ctr | func=encrypt_with_iv | step=padding | "
                f"padding={padding}"
            )
            raise ValueError(
                "Padding must strictly not be used in CTR mode.\n"
                "CTR can encrypt any length without padding.\n"
                "Fix: set Padding = NONE for CTR."
            )

        # IV: generate if missing (IV is not secret but must be unique and unpredictable)
        if iv is None:
            log_warning(
                "CTR warning | module=mode_ctr | func=encrypt_with_iv | iv=missing -> generating secure random IV/counter"
            )
            iv = generate_random_iv(label="CTR", purpose="encrypt_with_iv")

        if should_log_starts():
            log_info("Starting CTR encryption | module=mode_ctr | func=encrypt_with_iv")

        try:
            pt = _ensure_bytes(plaintext)
        except Exception as e:
            log_error(
                "CTR validation failed | module=mode_ctr | func=encrypt_with_iv | step=plaintext_type | "
                f"error={e}"
            )
            raise

        try:
            ct = self.encrypt_raw(pt, "CTR", iv)
        except Exception as e:
            log_error(
                "CTR encrypt_raw failed | module=mode_ctr | func=encrypt_with_iv | step=encrypt_raw | "
                f"error={e}"
            )
            raise

        iv_bytes = bytes(iv)

        log_success(
            "CTR encryption done | module=mode_ctr | func=encrypt_with_iv | "
            f"key_bits={len(self.key) * 8} | iv={iv_bytes.hex()} | in={len(pt)}B | out={len(ct)}B"
        )
        return ct, iv_bytes

    def decrypt(
        self,
        ciphertext: bytes | bytearray,
        iv: Optional[bytes | bytearray] = None,
        unpadding: PaddingMode = "NONE",
    ) -> bytes:
        # CTR does not use unpadding also
        if unpadding != "NONE":
            log_error(
                "CTR validation failed | module=mode_ctr | func=decrypt | step=unpadding | "
                f"unpadding={unpadding}"
            )
            raise ValueError(
                "Unpadding is not used in CTR mode.\n"
                "CTR decryption outputs the exact same number of bytes as the ciphertext.\n"
                "Fix: set Unpadding = NONE for CTR."
            )

        if iv is None:
            log_error("CTR validation failed | module=mode_ctr | func=decrypt | step=iv | error=missing_iv")
            raise ValueError(
                "CTR decryption requires an IV/Counter.\n"
                "Tip: Copy the IV/Counter from the encryption output (32 hex characters)."
            )

        if not isinstance(ciphertext, (bytes, bytearray)):
            log_error(
                "CTR validation failed | module=mode_ctr | func=decrypt | step=ciphertext_type | "
                f"type={type(ciphertext).__name__}"
            )
            raise TypeError("CTR decrypt failed: ciphertext must be bytes (or bytearray).")

        ct = bytes(ciphertext)

        if should_log_starts():
            log_info("Starting CTR decryption | module=mode_ctr | func=decrypt")

        try:
            pt = self.decrypt_raw(ct, "CTR", iv)
        except Exception as e:
            log_error(
                "CTR decrypt_raw failed | module=mode_ctr | func=decrypt | step=decrypt_raw | "
                f"error={e}"
            )
            raise

        iv_bytes = bytes(iv)

        log_success(
            "CTR decryption done | module=mode_ctr | func=decrypt | "
            f"key_bits={len(self.key) * 8} | iv={iv_bytes.hex()} | out={len(pt)}B"
        )
        return pt

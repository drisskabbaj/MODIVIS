# -------------------------------------------------------------------------------------
#                                AES ECB MODE
# -------------------------------------------------------------------------------------
# Why AES-ECB??
#   - simplest mode (no IV)
#
# NB:
#   - equal plaintext blocks produce equal ciphertext blocks (pattern leak)
#
# Tested?
#   - Yes 
#   - Unit test inside tests/models/test_mode_ecb.py  
# -------------------------------------------------------------------------------------

from __future__ import annotations # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types
from dataclasses import dataclass # helps simplifying building classes

from src.domain.crypto_constants import AES_BLOCK_BYTES # needed to import block size constant

from .aes_base import (
    AESCore,
    _ensure_bytes,
) # needed to import AES Core Logic file

from src.utils.logger import (
    log_success,
    log_error,
    log_info,
    should_log_starts,
) # needed to import Log System

from src.utils.padding_schemes import PaddingMode, pad_data, unpad_data, PaddingError # needed to import Padding related methods


@dataclass(slots=True)
class AESECB(AESCore):
    """
    ECB wrapper around AESCore
    """

    def encrypt(self, plaintext: bytes | bytearray | str, padding: PaddingMode = "PKCS7") -> bytes:
        if should_log_starts():
            log_info("Starting ECB encryption | module=mode_ecb | func=encrypt")

        # plaintext type and conversion
        try:
            pt = _ensure_bytes(plaintext)
        except Exception as e:
            log_error(
                "ECB validation failed | module=mode_ecb | func=encrypt | step=plaintext_type | "
                f"error={e}"
            )
            raise

        # if padding is NONE, AESCore will enforce block alignment.
        if padding == "NONE":
            padded = pt
        else:
            padded = pad_data(pt, block_size=AES_BLOCK_BYTES, mode=padding, label="Plaintext", purpose="ECB encrypt")


        try:
            ct = self.encrypt_raw(padded, "ECB")
        except Exception as e:
            log_error(
                "ECB encrypt_raw failed | module=mode_ecb | func=encrypt | step=encrypt_raw | "
                f"error={e}"
            )
            raise

        log_success(
            "ECB encryption done | module=mode_ecb | func=encrypt | "
            f"key_bits={len(self.key) * 8} | padding={padding} | in={len(padded)}B | out={len(ct)}B"
        )
        return ct

    def decrypt(self, ciphertext: bytes | bytearray, unpadding: PaddingMode = "PKCS7") -> bytes:
        if should_log_starts():
            log_info("Starting ECB decryption | module=mode_ecb | func=decrypt")

        if not isinstance(ciphertext, (bytes, bytearray)):
            log_error(
                "ECB validation failed | module=mode_ecb | func=decrypt | step=ciphertext_type | "
                f"type={type(ciphertext).__name__}"
            )
            raise TypeError("ECB decrypt failed: ciphertext must be bytes (or bytearray).")

        ct = bytes(ciphertext)

        try:
            data = self.decrypt_raw(ct, "ECB")
        except Exception as e:
            log_error(
                "ECB decrypt_raw failed | module=mode_ecb | func=decrypt | step=decrypt_raw | "
                f"error={e}"
            )
            raise

        if unpadding == "NONE":
            res = data
        else:
            try:
                res = unpad_data(data, block_size=AES_BLOCK_BYTES, mode=unpadding, label="Decrypted data", purpose="ECB decrypt")
            except PaddingError as pe:
                # no log and only raise to avoid duplicate error logs: padding_schemes already logs the root cause
                raise ValueError(
                    "Unpadding failed.\n"
                    "Possible reasons:\n"
                    "  1) Wrong key\n"
                    "  2) Wrong unpadding mode selected\n"
                    "  3) Ciphertext was modified or corrupted\n"
                    f"\nDetails: {pe}"
                ) from pe

        log_success(
            "ECB decryption done | module=mode_ecb | func=decrypt | "
            f"key_bits={len(self.key) * 8} | unpadding={unpadding} | out={len(res)}B"
        )
        return res

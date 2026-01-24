# -------------------------------------------------------------------------------------
#                                AES CORE
# -------------------------------------------------------------------------------------
# Why AES Core??
#   - centralizes all low level AES logic
#   - validates key sizes: 128 / 192 / 256 bits
#   - provides cipher builders: ECB / CBC / CTR
#   - provides strict "raw" encryption helpers (no padding logic here)
#
# NB:
#   - AES block size is always 16 bytes
#   - this class does NOT generate IVs
#   - padding/unpadding is handled outside (see utils/padding_schemes.py)
#
# Tested?
#   - Yes 
#   - Unit test inside tests/models/test_aes_base.py 
# -------------------------------------------------------------------------------------

from __future__ import annotations # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types

from dataclasses import dataclass # helps simplifying building classes
from typing import Optional # needed to mark a value as str or None (existing or missing both possible)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # needed for cryptography backend library

from src.domain.crypto_constants import AES_BLOCK_BYTES, VALID_AES_KEY_SIZES # needed to import block size and key size constants

def _ensure_bytes(x: bytes | bytearray | str) -> bytes:
    """
    Ensure input is bytes.

    Why?
      - cryptography expects bytes as input
    """
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, str):
        return x.encode("utf-8")
    raise TypeError("Expected bytes, bytearray, or string.")

def _check_key(key: bytes) -> None:
    """
    Validate AES key length.

    Why?
    AES supports only:
      - 16 bytes (AES-128)
      - 24 bytes (AES-192)
      - 32 bytes (AES-256)
    """
    if len(key) not in VALID_AES_KEY_SIZES:
        raise ValueError(
            "Invalid AES key length.\n"
            "AES key must be 16 / 24 / 32 bytes (AES-128 / AES-192 / AES-256).\n"
            "Tip: If you type HEX in the UI, that means 32 / 48 / 64 hex characters."
        )


def _require_iv(iv: Optional[bytes | bytearray], mode_name: str) -> bytes:
    """
    Small helper to validate IV/Counter presence and size.
    NB: CBC and CTR require an IV/Counter of exactly 16 bytes.
    """
    if iv is None:
        raise ValueError(
            f"{mode_name} requires an IV/Counter.\n"
            f"Tip: Generate one in the app, or paste 32 hex characters (16 bytes)."
        )

    if not isinstance(iv, (bytes, bytearray)):
        raise TypeError(
            f"{mode_name} IV/Counter must be bytes (or bytearray)."
        )

    iv_bytes = bytes(iv)

    if len(iv_bytes) != AES_BLOCK_BYTES:
        raise ValueError(
            f"{mode_name} IV/Counter must be exactly {AES_BLOCK_BYTES} bytes.\n"
            f"Right now it is {len(iv_bytes)} bytes."
        )

    return iv_bytes

def _require_block_aligned(data: bytes, *, context: str = "Data") -> None:
    """
    Small helper to validate block aligned input.

    Why?
        - AES-ECB and AES-CBC operate on full 16-byte blocks.
        - If padding is disabled (=NONE), the user must provide block-aligned input.
    """
    if len(data) % AES_BLOCK_BYTES != 0:
        raise ValueError(
            f"{context} length is {len(data)} bytes, which is not a multiple of {AES_BLOCK_BYTES}.\n"
            "AES-ECB/CBC require full 16-byte blocks when padding is disabled.\n"
            "Fix: enable padding OR provide input whose length is 16, 32, 48, ... bytes."
        )


@dataclass(slots=True)
class AESCore:
    """
    Low-level AES core (cipher builders + strict raw encryption helpers).

    This class intentionally does not implement padding.
    Padding/unpadding is a separate concern handled by dedicated helpers.
    """

    key: bytes | bytearray | str

    def __post_init__(self) -> None:
        self.key = _ensure_bytes(self.key)
        _check_key(self.key)

    # -------------------------------------------------------------------------
    # Cipher builders
    # -------------------------------------------------------------------------
    def _cipher_ecb(self) -> Cipher:
        """Create an AES cipher in ECB mode (no IV)."""
        return Cipher(algorithms.AES(self.key), modes.ECB())

    def _cipher_cbc(self, iv: bytes) -> Cipher:
        """Create an AES cipher in CBC mode (requires 16-byte IV)."""
        return Cipher(algorithms.AES(self.key), modes.CBC(iv))

    def _cipher_ctr(self, iv: bytes) -> Cipher:
        """Create an AES cipher in CTR mode (requires 16-byte counter/IV)."""
        return Cipher(algorithms.AES(self.key), modes.CTR(iv))

    # -------------------------------------------------------------------------
    # Raw encryption (no padding here)
    # -------------------------------------------------------------------------
    def encrypt_raw(self, plaintext: bytes | bytearray, mode: str, iv: Optional[bytes | bytearray] = None) -> bytes:
        """
        Encrypt bytes without adding padding in this layer.

        Rules:
          - AES-ECB/CBC: plaintext must be block-aligned (multiple of 16 bytes)
          - AES-CTR: any length is allowed

        Why??
          - Padding (if used) is applied in the mode wrappers (AES-ECB/CBC)
          - This method is the silent crypto engine: it raises exceptions but does not log
        """
        mode = str(mode or "").strip().upper()

        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("Plaintext must be bytes (or bytearray).")
        plaintext = bytes(plaintext)

        if mode == "ECB":
            _require_block_aligned(plaintext, context="Plaintext")
            enc = self._cipher_ecb().encryptor()

        elif mode == "CBC":
            _require_block_aligned(plaintext, context="Plaintext")
            iv_bytes = _require_iv(iv, "CBC")
            enc = self._cipher_cbc(iv_bytes).encryptor()

        elif mode == "CTR":
            iv_bytes = _require_iv(iv, "CTR")
            enc = self._cipher_ctr(iv_bytes).encryptor()

        else:
            raise ValueError("Invalid AES mode. Supported modes are: ECB / CBC / CTR.")

        return enc.update(plaintext) + enc.finalize()

    def decrypt_raw(self, ciphertext: bytes | bytearray, mode: str, iv: Optional[bytes | bytearray] = None) -> bytes:
        """
        Decrypt bytes without removing padding in this layer.

        Rules:
          - AES-ECB/CBC: ciphertext length must be a multiple of 16 bytes
          - AES-CTR: any length is allowed

        Why??
          - Padding (if used) is applied in the mode wrappers (AES-ECB/CBC)
          - This method is the silent crypto engine: it raises exceptions but does not log
        """
        mode = str(mode or "").strip().upper()

        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError("Ciphertext must be bytes (or bytearray).")
        ciphertext = bytes(ciphertext)

        if mode == "ECB":
            _require_block_aligned(ciphertext, context="Ciphertext")
            dec = self._cipher_ecb().decryptor()

        elif mode == "CBC":
            _require_block_aligned(ciphertext, context="Ciphertext")
            iv_bytes = _require_iv(iv, "CBC")
            dec = self._cipher_cbc(iv_bytes).decryptor()

        elif mode == "CTR":
            iv_bytes = _require_iv(iv, "CTR")
            dec = self._cipher_ctr(iv_bytes).decryptor()

        else:
            raise ValueError("Invalid AES mode. Supported modes are: ECB / CBC / CTR.")

        return dec.update(ciphertext) + dec.finalize()

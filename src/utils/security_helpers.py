import os  # Needed for cryptographically secure random bytes (keys and initialization vectors [IVs]): usage exemple is os.urandom()

from src.utils.logger import (
    log_debug,
    log_error,
    log_success,
)  # Needed for building logs logic

from src.domain.crypto_constants import AES_BLOCK_BYTES, VALID_AES_KEY_SIZES # needed to import block size and key size constants

# -------------------------------------------------------------------------------------
#                                SECURITY HELPERS
# -------------------------------------------------------------------------------------
# Why here?
#   - Tiny safe helpers to create random IVs and random AES keys.
#
# Advantages of using??
#   - Good randomness. If the dice is predictable, attackers can guess
#     secrets. Used os.urandom(), which talks to the OS and gives us
#     cryptographically strong bytes.
#
# Notes:
#   - AES works on 16-byte blocks. That's why IVs are exactly 16 bytes.
#   - Valid AES key lengths are 16, 24, or 32 bytes mapped exactly to 128/192/256 bits.
#   - IVs are not secret, but they must be unpredictable and unique for each
#     encryption. But Keys are in fact secret. This is why we never log full keys.
# -------------------------------------------------------------------------------------

def generate_random_iv(*, label: str = "", purpose: str = "") -> bytes:
    """
    Create a random IV of 16 bytes.

    Args:
        None.

    Returns:
      bytes: 16 random bytes (e.g., b'\\x12\\x34...') suitable for AES-CBC/CTR-Modes.

    Logging:
      - IV in hex for visibility during development. That's fine because IVs are not secrets.
    """
    iv = os.urandom(AES_BLOCK_BYTES)  # Secure random bytes generation

    log_debug(
        f"Generated random IV | module=security_helpers | func=generate_random_iv | bytes={AES_BLOCK_BYTES} | hex={iv.hex()} | label={label} | purpose={purpose}"
    )
    return iv


def generate_random_key(length: int = 16, *, label: str = "", purpose: str = "") -> bytes:
    """
    Create a random AES key.

    Args:
      length (int): Desired key length in bytes. Must be one of:
                    16 (AES-128), 24 (AES-192), 32 (AES-256).
                    Default: 16 (AES-128)

    Returns:
      bytes: random key of given length.

    Raises:
      ValueError: if length is not 16, 24, or 32 (not logic).

    Logging:
      - Short preview (first 8 bytes in hex) to avoid leaking the full key in logs.
    """
    if not isinstance(length, int):
        log_error(
            f"Security helper failed: invalid key length type | module=security_helpers | func=generate_random_key | type(length)={type(length).__name__} | label={label} | purpose={purpose}"
        )
        raise TypeError("Security helper failed: key length must be an integer (16/24/32 mapped for AES-128/192/256).")

    if length not in VALID_AES_KEY_SIZES:
        log_error(
            f"Security helper failed: invalid AES key length | module=security_helpers | func=generate_random_key | length={length} | label={label} | purpose={purpose}"
        )
        raise ValueError("Security helper failed: key length must be 16, 24, or 32 bytes (AES-128/192/256).")

    key = os.urandom(length)  # Secure random key generation
    preview = key[:8].hex()  # Preview of first 8 bytes only

    aes_bits = length * 8
    log_success(
        f"Generated random AES key | module=security_helpers | func=generate_random_key | aes=AES-{aes_bits} | bytes={length} | preview={preview}... | label={label} | purpose={purpose}"
    )

    return key

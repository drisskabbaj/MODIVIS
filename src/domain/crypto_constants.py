from __future__ import annotations # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types

# These constants are used across the app to guarantee only supported AES parameters are passed
# They help avoid false typos
AES_BLOCK_BYTES = 16
VALID_AES_KEY_SIZES = (16, 24, 32)
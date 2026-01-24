from __future__ import annotations # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types
from typing import Literal # needed to restrict fmt aka. format to only allowed accepted formats (string)

# This type is used across the app to guarantee we only pass supported Padding mode names
# It helps avoid false typos
PaddingMode = Literal["NONE", "PKCS7", "X923", "ISO/IEC 7816-4"]
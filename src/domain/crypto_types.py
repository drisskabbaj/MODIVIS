from __future__ import annotations # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types
from typing import Literal # needed to restrict fmt aka. format to only allowed accepted formats (string)

# This type is used across the app to guarantee we only pass supported modes of operation
# It helps avoid false typos
Mode = Literal["ECB", "CBC", "CTR"]
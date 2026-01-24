from __future__ import annotations # needed so type hints are treated like simple labels (aka. strings), preventing issues with not yet defined types

from typing import Literal # needed to define strict string unions for exercises

# These types are used across the app to guarantee we only pass supported exercise values
# They help avoid false typos
ExerciseAction = Literal["ENCRYPT", "DECRYPT"]
ExerciseLevel = Literal["NORMAL", "HARD"]
ExerciseFmt = Literal["HEX", "BIN"]
import typing as typ
from typing import *  # noqa: F401, F403


# Python 3.5 support
if not hasattr(typ, 'Collection'):
    Collection = typ.Sequence

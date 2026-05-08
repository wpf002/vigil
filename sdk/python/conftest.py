"""Test bootstrap for the VIGIL Python SDK.

Adds the package directory to sys.path so absolute imports (`from vigil_sdk
import …`) work when running pytest from the sdk/python folder.
"""

from __future__ import annotations
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

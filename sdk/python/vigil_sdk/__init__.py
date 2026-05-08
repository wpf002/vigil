"""Public Python SDK for VIGIL."""

from .client import VIGILClient
from .exceptions import (
    VIGILAPIError,
    VIGILAuthError,
    VIGILNotFoundError,
    VIGILRateLimitError,
)
from .models import AttackState, DetectionVersion, ExecutiveSummary, PlaybookRun
from .webhook import verify_webhook_signature

__version__ = "0.1.0"

__all__ = [
    "VIGILClient",
    "VIGILAPIError",
    "VIGILAuthError",
    "VIGILNotFoundError",
    "VIGILRateLimitError",
    "AttackState",
    "DetectionVersion",
    "ExecutiveSummary",
    "PlaybookRun",
    "verify_webhook_signature",
]

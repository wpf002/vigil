"""Exception hierarchy for the VIGIL SDK."""


class VIGILAPIError(Exception):
    """Base for all VIGIL API errors."""

    def __init__(self, message: str, status_code: int | None = None, body: object = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class VIGILAuthError(VIGILAPIError):
    """401/403 from the VIGIL API."""


class VIGILNotFoundError(VIGILAPIError):
    """404 from the VIGIL API."""


class VIGILRateLimitError(VIGILAPIError):
    """429 from the VIGIL API."""
